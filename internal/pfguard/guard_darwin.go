//go:build darwin

package pfguard

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/castiel/dns/internal/alerts"
	"github.com/castiel/dns/internal/config"
	"github.com/castiel/dns/internal/metrics"
)

// Guard monitors PF firewall rules for unauthorized changes that could
// block Apple's certificate validation endpoints. In the Phase 3 attack,
// Gatebreaker installs PF rules blocking 17.0.0.0/8 on ports 80/443 to
// prevent trustd from reaching OCSP servers, causing Gatekeeper to fail-open.
//
// Guard periodically dumps all PF rules (excluding Castiel's own anchor)
// and scans for block rules targeting Apple's IP ranges or ports 80/443
// to Apple-owned subnets.
type Guard struct {
	cfg            config.PFGuardConfig
	alertMgr       *alerts.Manager
	knownAppleNets []string
	blockRe        *regexp.Regexp
}

// NewGuard creates a PF rules integrity monitor.
func NewGuard(cfg config.PFGuardConfig, alertMgr *alerts.Manager) *Guard {
	g := &Guard{
		cfg:      cfg,
		alertMgr: alertMgr,
		knownAppleNets: []string{
			"17.0.0.0/8",
		},
	}

	// Match block rules: "block drop ... to <ip> port {80, 443}" or similar
	g.blockRe = regexp.MustCompile(`(?i)block.*\b(in|out|drop)\b.*\b(to|from)\s+(\S+).*port\s*=?\s*[{]?\s*(80|443)`)

	return g
}

// Start runs the PF guard in a background goroutine.
func (g *Guard) Start(ctx context.Context) {
	if !g.cfg.Enabled {
		return
	}

	interval := time.Duration(g.cfg.CheckInterval) * time.Second
	if interval < 5*time.Second {
		interval = 30 * time.Second
	}

	log.Printf("PF guard: monitoring for unauthorized rules every %s", interval)

	// Initial check
	g.checkRules()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			g.checkRules()
		}
	}
}

func (g *Guard) checkRules() {
	// Dump all PF rules from the main ruleset and all anchors
	output, err := exec.Command("pfctl", "-s", "rules", "-a", "").CombinedOutput()
	if err != nil {
		// PF might not be enabled — that's fine
		return
	}

	rules := string(output)
	if rules == "" {
		return
	}

	// Also check all anchors
	anchorOutput, err := exec.Command("pfctl", "-s", "Anchors").CombinedOutput()
	if err == nil {
		for _, anchor := range strings.Split(string(anchorOutput), "\n") {
			anchor = strings.TrimSpace(anchor)
			if anchor == "" || anchor == g.cfg.CastielAnchor {
				continue
			}
			anchorRules, err := exec.Command("pfctl", "-a", anchor, "-s", "rules").CombinedOutput()
			if err == nil {
				rules += "\n" + string(anchorRules)
			}
		}
	}

	// Scan for suspicious block rules
	suspicious := g.scanRules(rules)
	for _, s := range suspicious {
		metrics.UnauthorizedPFAlerts.WithLabelValues(s.ruleType).Inc()

		log.Printf("[critical] unauthorized_pf_rule: %s", s.description)

		if g.alertMgr != nil {
			g.alertMgr.Send(alerts.Alert{
				Type:     "unauthorized_pf_rule",
				Severity: "critical",
				Source:   "pf-guard",
				Message:  s.description,
				Time:     time.Now(),
			})
		}
	}
}

type suspiciousRule struct {
	ruleType    string
	description string
}

func (g *Guard) scanRules(rules string) []suspiciousRule {
	var found []suspiciousRule

	for _, line := range strings.Split(rules, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Skip Castiel's own anchor rules
		if strings.Contains(line, g.cfg.CastielAnchor) {
			continue
		}

		// Check for block rules targeting Apple's 17.0.0.0/8
		if !strings.Contains(strings.ToLower(line), "block") {
			continue
		}

		for _, appleNet := range g.knownAppleNets {
			if strings.Contains(line, appleNet) {
				// Check if it's blocking ports 80 or 443
				if g.blockRe.MatchString(line) || strings.Contains(line, "80") || strings.Contains(line, "443") {
					found = append(found, suspiciousRule{
						ruleType:    "apple_endpoint_block",
						description: fmt.Sprintf("Unauthorized PF rule blocking Apple network %s on cert validation ports: %s", appleNet, line),
					})
				} else {
					// Blocking Apple network on any port is suspicious
					found = append(found, suspiciousRule{
						ruleType:    "apple_network_block",
						description: fmt.Sprintf("Unauthorized PF rule blocking Apple network %s: %s", appleNet, line),
					})
				}
			}
		}

		// Check for block rules to specific Apple service IPs on 80/443
		// (covers cases where attacker uses individual IPs instead of CIDR)
		if g.blockRe.MatchString(line) {
			// Extract the target IP/network from the rule
			if hasAppleIP(line) {
				found = append(found, suspiciousRule{
					ruleType:    "apple_ip_block",
					description: fmt.Sprintf("Unauthorized PF rule blocking Apple endpoint on cert validation port: %s", line),
				})
			}
		}
	}

	return found
}

// hasAppleIP checks if a PF rule line contains an IP in Apple's 17.0.0.0/8 range.
func hasAppleIP(line string) bool {
	// Match 17.x.x.x patterns
	ipRe := regexp.MustCompile(`\b17\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b`)
	return ipRe.MatchString(line)
}
