package endpointmonitor

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/castiel/dns/internal/alerts"
	"github.com/castiel/dns/internal/config"
	"github.com/castiel/dns/internal/metrics"
)

// Monitor periodically checks connectivity to Apple's certificate validation
// endpoints (OCSP, CRL, notarization). If DNS resolves but TCP connections
// fail, this indicates IP-level blocking — the Phase 3 attack where an
// attacker installs PF rules to block Apple's OCSP subnets, causing trustd
// to fail-open and bypass Gatekeeper revocation checks.
type Monitor struct {
	cfg        config.EndpointMonitorConfig
	alertMgr   *alerts.Manager
	endpoints  []appleEndpoint
	mu         sync.Mutex
	failedSet  map[string]bool // currently-failing endpoints (for dedup)
}

type appleEndpoint struct {
	Host string
	Port int
}

// defaultAppleEndpoints returns the critical Apple endpoints that trustd and
// syspolicyd use for certificate revocation checking and notarization.
// If these are unreachable while DNS resolves, it indicates IP-level blocking.
func defaultAppleEndpoints() []appleEndpoint {
	return []appleEndpoint{
		{Host: "ocsp.apple.com", Port: 80},
		{Host: "ocsp2.apple.com", Port: 443},
		{Host: "certs.apple.com", Port: 443},
		{Host: "valid.apple.com", Port: 443},
		{Host: "crl.apple.com", Port: 80},
		{Host: "api.apple-cloudkit.com", Port: 443},
	}
}

func NewMonitor(cfg config.EndpointMonitorConfig, alertMgr *alerts.Manager) *Monitor {
	return &Monitor{
		cfg:       cfg,
		alertMgr:  alertMgr,
		endpoints: defaultAppleEndpoints(),
		failedSet: make(map[string]bool),
	}
}

// Start runs the endpoint health monitor in a background goroutine.
func (m *Monitor) Start(ctx context.Context) {
	if !m.cfg.Enabled {
		return
	}

	interval := time.Duration(m.cfg.CheckInterval) * time.Second
	if interval < 10*time.Second {
		interval = 30 * time.Second
	}

	log.Printf("Endpoint monitor: checking %d Apple endpoints every %s", len(m.endpoints), interval)

	// Run an initial check immediately
	m.checkAll()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.checkAll()
		}
	}
}

func (m *Monitor) checkAll() {
	for _, ep := range m.endpoints {
		m.checkEndpoint(ep)
	}
}

func (m *Monitor) checkEndpoint(ep appleEndpoint) {
	key := fmt.Sprintf("%s:%d", ep.Host, ep.Port)

	// Step 1: DNS resolve the endpoint
	ips, err := net.LookupHost(ep.Host)
	if err != nil {
		// DNS failure — Castiel's DNS proxy handles that case separately.
		// Don't alert here; DNS issues are caught by the rebinding/DNSSEC detectors.
		return
	}

	if len(ips) == 0 {
		return
	}

	// Step 2: TCP probe each resolved IP on the target port
	timeout := time.Duration(m.cfg.ConnectTimeout) * time.Second
	if timeout < 1*time.Second {
		timeout = 3 * time.Second
	}

	allFailed := true
	var failedIPs []string
	for _, ip := range ips {
		addr := net.JoinHostPort(ip, fmt.Sprintf("%d", ep.Port))
		conn, err := net.DialTimeout("tcp", addr, timeout)
		if err != nil {
			failedIPs = append(failedIPs, ip)
			continue
		}
		conn.Close()
		allFailed = false
		break
	}

	if allFailed {
		m.handleFailure(key, ep, ips, failedIPs)
	} else {
		metrics.AppleEndpointStatus.WithLabelValues(ep.Host).Set(1)
		m.handleRecovery(key, ep)
	}
}

func (m *Monitor) handleFailure(key string, ep appleEndpoint, resolvedIPs, failedIPs []string) {
	m.mu.Lock()
	wasFailing := m.failedSet[key]
	m.failedSet[key] = true
	m.mu.Unlock()

	metrics.AppleEndpointUnreachable.WithLabelValues(ep.Host).Inc()
	metrics.AppleEndpointStatus.WithLabelValues(ep.Host).Set(0)

	if !wasFailing {
		// New failure — send alert
		msg := fmt.Sprintf("Apple certificate endpoint unreachable: %s:%d (resolved to %d IPs, all TCP connections failed: %s) — possible IP-level blocking of Apple OCSP/CRL traffic",
			ep.Host, ep.Port, len(resolvedIPs), strings.Join(failedIPs, ", "))

		log.Printf("[critical] apple_endpoint_unreachable: %s", msg)

		if m.alertMgr != nil {
			m.alertMgr.Send(alerts.Alert{
				Type:     "apple_endpoint_unreachable",
				Severity: "critical",
				Source:   "endpoint-monitor",
				Domain:   ep.Host,
				Message:  msg,
				Time:     time.Now(),
			})
		}
	}
}

func (m *Monitor) handleRecovery(key string, ep appleEndpoint) {
	m.mu.Lock()
	wasFailing := m.failedSet[key]
	delete(m.failedSet, key)
	m.mu.Unlock()

	if wasFailing {
		log.Printf("Endpoint monitor: %s recovered — TCP connection successful", key)
		if m.alertMgr != nil {
			m.alertMgr.Send(alerts.Alert{
				Type:     "apple_endpoint_recovered",
				Severity: "info",
				Source:   "endpoint-monitor",
				Domain:   ep.Host,
				Message:  fmt.Sprintf("Apple certificate endpoint recovered: %s", key),
				Time:     time.Now(),
			})
		}
	}
}
