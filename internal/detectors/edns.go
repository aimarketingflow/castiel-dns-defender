package detectors

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// EDNSInspector parses and validates EDNS0 options in DNS queries
// to detect covert data exfiltration via non-standard EDNS0 fields
// (SiphonDNS-style attacks using ECS, cookies, SVCB, unknown options).
type EDNSInspector struct {
	mu              sync.Mutex
	clientSubnets   map[string]*subnetTracker // clientIP -> last seen ECS
	ecsMismatchAlerts map[string]time.Time    // clientIP -> last ECS mismatch alert
	cookieAlerts    map[string]time.Time       // clientIP -> last cookie alert time
	unknownAlerts   map[string]time.Time       // clientIP -> last unknown opt alert time
	maxCookieLen    int
	alertCooldown   time.Duration
}

type subnetTracker struct {
	subnet   string
	lastSeen time.Time
}

// EDNSFinding represents a suspicious EDNS0 pattern detected.
type EDNSFinding struct {
	Type     string // "ecs_mismatch", "oversized_cookie", "unknown_option", "suspicious_ecs_volume"
	Detail   string
	ClientIP string
	Option   string
}

func NewEDNSInspector() *EDNSInspector {
	return &EDNSInspector{
		clientSubnets:     make(map[string]*subnetTracker),
		ecsMismatchAlerts: make(map[string]time.Time),
		cookieAlerts:      make(map[string]time.Time),
		unknownAlerts:     make(map[string]time.Time),
		maxCookieLen:      8, // RFC 7873: server cookie typically 8-32 bytes; client cookie is 8 bytes
		alertCooldown:     5 * time.Minute,
	}
}

// Inspect analyzes the EDNS0 OPT record in a DNS query for suspicious patterns.
// Returns a finding if something suspicious is detected, nil otherwise.
func (e *EDNSInspector) Inspect(msg *dns.Msg, clientIP string) *EDNSFinding {
	if msg == nil {
		return nil
	}

	opt := msg.IsEdns0()
	if opt == nil {
		return nil
	}

	for _, o := range opt.Option {
		switch v := o.(type) {

		case *dns.EDNS0_SUBNET:
			// ECS validation: check if the subnet matches the client's actual IP
			finding := e.validateECS(v, clientIP)
			if finding != nil {
				return finding
			}

		case *dns.EDNS0_COOKIE:
			// DNS cookie monitoring: client cookies should be 8 bytes.
			// Larger cookies may carry exfiltrated data.
			cookieLen := len(v.Cookie)
			if cookieLen > e.maxCookieLen {
				if !e.cooldownPassed(e.cookieAlerts, clientIP) {
					continue
				}
				e.markAlert(e.cookieAlerts, clientIP)
				return &EDNSFinding{
					Type:     "oversized_cookie",
					Detail:   fmt.Sprintf("DNS cookie length %d exceeds expected %d bytes (possible data exfiltration)", cookieLen, e.maxCookieLen),
					ClientIP: clientIP,
					Option:   "COOKIE",
				}
			}

		default:
			// Unknown/custom EDNS0 option codes — could carry arbitrary data
			code := o.Option()
			// Known safe option codes: 3 (NSID), 10 (COOKIE), 8 (ECS), 12 (DAU), etc.
			if !isKnownEDNSOption(code) {
				if !e.cooldownPassed(e.unknownAlerts, clientIP) {
					continue
				}
				e.markAlert(e.unknownAlerts, clientIP)
				return &EDNSFinding{
					Type:     "unknown_option",
					Detail:   fmt.Sprintf("Unknown EDNS0 option code %d (possible covert data channel)", code),
					ClientIP: clientIP,
					Option:   fmt.Sprintf("OPTION_%d", code),
				}
			}
		}
	}

	return nil
}

// validateECS checks if the EDNS Client Subnet matches the client's actual IP.
// SiphonDNS encodes exfiltrated data as fake ECS values.
func (e *EDNSInspector) validateECS(ecs *dns.EDNS0_SUBNET, clientIP string) *EDNSFinding {
	// Parse the client's actual IP
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return nil
	}

	// The ECS address should be in the same /24 (IPv4) or /48 (IPv6) as the client
	ecsIP := ecs.Address
	if ecsIP == nil {
		return nil
	}

	// Check if ECS IP version matches client IP version
	if (ecs.Family == 1 && ip.To4() == nil) || (ecs.Family == 2 && ip.To4() != nil) {
		if !e.cooldownPassed(e.ecsMismatchAlerts, clientIP) {
			return nil
		}
		e.markAlert(e.ecsMismatchAlerts, clientIP)
		return &EDNSFinding{
			Type:     "ecs_mismatch",
			Detail:   fmt.Sprintf("ECS family %d does not match client IP %s (possible data exfiltration via ECS)", ecs.Family, clientIP),
			ClientIP: clientIP,
			Option:   "ECS",
		}
	}

	// For IPv4: check if the first 3 octets match (public resolvers strip last octet)
	if ecs.Family == 1 && ip.To4() != nil && ecsIP.To4() != nil {
		clientBytes := ip.To4()
		ecsBytes := ecsIP.To4()
		mismatch := false
		// Check the first sourcePrefixLength bits
		prefixLen := int(ecs.SourceNetmask)
		if prefixLen > 32 {
			prefixLen = 32
		}
		if prefixLen >= 8 && clientBytes[0] != ecsBytes[0] {
			mismatch = true
		}
		if prefixLen >= 16 && clientBytes[1] != ecsBytes[1] {
			mismatch = true
		}
		if prefixLen >= 24 && clientBytes[2] != ecsBytes[2] {
			mismatch = true
		}

		if mismatch {
			if !e.cooldownPassed(e.ecsMismatchAlerts, clientIP+"_mismatch") {
				return nil
			}
			e.markAlert(e.ecsMismatchAlerts, clientIP+"_mismatch")
			return &EDNSFinding{
				Type:     "ecs_mismatch",
				Detail:   fmt.Sprintf("ECS %s does not match client IP %s (possible data exfiltration via ECS)", ecsIP.String(), clientIP),
				ClientIP: clientIP,
				Option:   "ECS",
			}
		}
	}

	// Track ECS for volume analysis
	e.mu.Lock()
	e.clientSubnets[clientIP] = &subnetTracker{
		subnet:   ecsIP.String(),
		lastSeen: time.Now(),
	}
	e.mu.Unlock()

	return nil
}

// StripEDNSOptions removes suspicious EDNS0 options before forwarding upstream.
// This prevents exfiltrated data from reaching an attacker's authoritative server.
func StripEDNSOptions(msg *dns.Msg) {
	if msg == nil {
		return
	}
	opt := msg.IsEdns0()
	if opt == nil {
		return
	}

	var cleaned []dns.EDNS0
	for _, o := range opt.Option {
		switch o.(type) {
		case *dns.EDNS0_SUBNET:
			// Strip ECS to prevent data exfiltration via fake subnets
			continue
		case *dns.EDNS0_COOKIE:
			// Strip oversized cookies
			if c, ok := o.(*dns.EDNS0_COOKIE); ok && len(c.Cookie) > 8 {
				continue
			}
			cleaned = append(cleaned, o)
		default:
			// Keep known safe options, strip unknown
			if isKnownEDNSOption(o.Option()) {
				cleaned = append(cleaned, o)
			}
		}
	}
	opt.Option = cleaned
}

// isKnownEDNSOption returns true for EDNS0 option codes defined in published RFCs.
func isKnownEDNSOption(code uint16) bool {
	switch code {
	case 1:  // LLQ (RFC 8764)
		return true
	case 2:  // UL (Update Lease, draft)
		return true
	case 3:  // NSID (RFC 5001)
		return true
	case 5:  // DAU (RFC 6975)
		return true
	case 6:  // DHU (RFC 6975)
		return true
	case 7:  // N3U (RFC 6975)
		return true
	case 8:  // ECS (RFC 7871)
		return true
	case 9:  // EXPIRE (RFC 7314)
		return true
	case 10: // COOKIE (RFC 7873)
		return true
	case 11: // TCP KEEPALIVE (RFC 7828)
		return true
	case 12: // PADDING (RFC 7830)
		return true
	case 13: // CHAIN (RFC 7901)
		return true
	case 14: // KEY TAG (RFC 8145)
		return true
	case 15: // EDE (RFC 8914)
		return true
	case 16: // CLIENT TAG (draft)
		return true
	case 17: // SERVER TAG (draft)
		return true
	case 19: // EXTENDED DNS ERROR (RFC 8914)
		return true
	case 26946: // DEVICEID (Apple)
		return true
	default:
		return false
	}
}

func (e *EDNSInspector) cooldownPassed(alerts map[string]time.Time, key string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	last, exists := alerts[key]
	if !exists {
		return true
	}
	return time.Since(last) > e.alertCooldown
}

func (e *EDNSInspector) markAlert(alerts map[string]time.Time, key string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	alerts[key] = time.Now()
}

// ExtractApexDomain returns the apex (registrable) domain from a FQDN.
// e.g., "a.b.example.com" -> "example.com"
func ExtractApexDomain(fqdn string) string {
	fqdn = strings.TrimSuffix(fqdn, ".")
	labels := strings.Split(fqdn, ".")
	if len(labels) <= 2 {
		return fqdn
	}
	// Handle common multi-part TLDs
	lastTwo := strings.Join(labels[len(labels)-2:], ".")
	multiPartTLDs := map[string]bool{
		"co.uk": true, "ac.uk": true, "gov.uk": true, "org.uk": true,
		"co.jp": true, "or.jp": true, "ne.jp": true,
		"com.au": true, "net.au": true, "org.au": true,
		"co.nz": true, "net.nz": true,
		"co.kr": true, "or.kr": true,
		"com.br": true, "net.br": true, "org.br": true,
		"co.in": true, "net.in": true, "org.in": true,
		"com.cn": true, "net.cn": true, "org.cn": true,
		"co.za": true, "net.za": true, "org.za": true,
	}
	if multiPartTLDs[lastTwo] && len(labels) >= 3 {
		return strings.Join(labels[len(labels)-3:], ".")
	}
	return lastTwo
}
