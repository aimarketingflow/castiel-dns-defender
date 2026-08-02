package detectors

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// DNSCalculationDetector detects DNS Calculation attacks (APT12-style) where
// malware uses DNS responses as covert signaling channels. The attack works by:
//   1. Malware queries a specific domain
//   2. The C2 server responds with specific IP addresses that encode commands
//   3. The malware interprets the IP octets as command data
//
// Detection approach:
//   - Track DNS responses where the returned IPs are subsequently connected to
//   - Flag domains where response IPs show unusual patterns (sequential octets,
//     encoded data in IP addresses, non-routable IPs for public domains)
//   - Detect "calculated" patterns: IPs that look like encoded data rather than
//     real infrastructure (e.g., 1.2.3.4, 10.0.0.1 for a public domain)
type DNSCalculationDetector struct {
	mu              sync.Mutex
	domainIPHistory map[string][]ipObservation
	maxHistory      int
	window          time.Duration
}

type ipObservation struct {
	ip        string
	timestamp time.Time
}

func NewDNSCalculationDetector() *DNSCalculationDetector {
	return &DNSCalculationDetector{
		domainIPHistory: make(map[string][]ipObservation),
		maxHistory:      50,
		window:          24 * time.Hour,
	}
}

// DNSCalculationFinding describes a DNS calculation attack detection result.
type DNSCalculationFinding struct {
	Domain  string
	Reason  string // "sequential_octets", "encoded_data", "non_routable_public", "rapid_change"
	IPs     []string
	Detail  string
}

// AnalyzeResponse checks a DNS response for DNS calculation attack indicators.
// domain is the queried domain, ips are the A/AAAA IPs from the response,
// isPublicDomain indicates if the domain is expected to have public IPs.
func (d *DNSCalculationDetector) AnalyzeResponse(domain string, ips []string, isPublicDomain bool) *DNSCalculationFinding {
	domain = strings.TrimSuffix(domain, ".")
	if len(ips) == 0 {
		return nil
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()

	// Record IPs
	history := d.domainIPHistory[domain]
	for _, ip := range ips {
		history = append(history, ipObservation{ip: ip, timestamp: now})
	}
	// Trim old entries
	cutoff := now.Add(-d.window)
	pruned := history[:0]
	for _, h := range history {
		if h.timestamp.After(cutoff) {
			pruned = append(pruned, h)
		}
	}
	if len(pruned) > d.maxHistory {
		pruned = pruned[len(pruned)-d.maxHistory:]
	}
	d.domainIPHistory[domain] = pruned

	// 1. Check for sequential octets (e.g., 1.2.3.4, 5.6.7.8 — encoded data)
	if finding := d.checkSequentialOctets(domain, ips); finding != nil {
		return finding
	}

	// 2. Check for non-routable IPs returned for public domains
	if isPublicDomain {
		if finding := d.checkNonRoutableForPublic(domain, ips); finding != nil {
			return finding
		}
	}

	// 3. Check for encoded data patterns in IP octets
	if finding := d.checkEncodedData(domain, ips); finding != nil {
		return finding
	}

	// 4. Check for rapid IP changes with short TTLs (signaling pattern)
	if finding := d.checkRapidChange(domain, pruned); finding != nil {
		return finding
	}

	return nil
}

// checkSequentialOctets detects IPs like 1.2.3.4 or 10.20.30.40 where
// octets form a sequential or arithmetic pattern — likely encoded data.
func (d *DNSCalculationDetector) checkSequentialOctets(domain string, ips []string) *DNSCalculationFinding {
	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		v4 := ip.To4()
		if v4 == nil {
			continue
		}

		octets := []int{int(v4[0]), int(v4[1]), int(v4[2]), int(v4[3])}

		// Check arithmetic sequence (e.g., 1.2.3.4, 10.20.30.40)
		diff := octets[1] - octets[0]
		if diff > 0 && diff < 20 {
			if octets[2]-octets[1] == diff && octets[3]-octets[2] == diff {
				return &DNSCalculationFinding{
					Domain: domain,
					Reason: "sequential_octets",
					IPs:    ips,
					Detail: fmt.Sprintf("IP %s has sequential octets (arithmetic sequence, diff=%d) — likely encoded data", ipStr, diff),
				}
			}
		}

		// Check simple sequential (1.2.3.4)
		if octets[0]+1 == octets[1] && octets[1]+1 == octets[2] && octets[2]+1 == octets[3] {
			return &DNSCalculationFinding{
				Domain: domain,
				Reason: "sequential_octets",
				IPs:    ips,
				Detail: fmt.Sprintf("IP %s has sequential octets (1.2.3.4 pattern) — likely encoded data", ipStr),
			}
		}
	}
	return nil
}

// checkNonRoutableForPublic detects private/loopback IPs for public domains.
func (d *DNSCalculationDetector) checkNonRoutableForPublic(domain string, ips []string) *DNSCalculationFinding {
	for _, ip := range ips {
		if IsPrivateIP(ip) {
			return &DNSCalculationFinding{
				Domain: domain,
				Reason: "non_routable_public",
				IPs:    ips,
				Detail: fmt.Sprintf("Public domain %s resolved to private IP %s — possible DNS calculation or rebinding", domain, ip),
			}
		}
	}
	return nil
}

// checkEncodedData detects IP patterns that look like encoded command data.
// Common patterns: all octets < 20, octets that map to ASCII control chars,
// or IPs where the first octet is 0 or 127.
func (d *DNSCalculationDetector) checkEncodedData(domain string, ips []string) *DNSCalculationFinding {
	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		v4 := ip.To4()
		if v4 == nil {
			continue
		}

		// Check if all octets are small numbers (1-30) — could encode short commands
		allSmall := true
		for _, b := range v4 {
			if b > 30 || b == 0 {
				allSmall = false
				break
			}
		}
		if allSmall && len(ips) > 1 {
			return &DNSCalculationFinding{
				Domain: domain,
				Reason: "encoded_data",
				IPs:    ips,
				Detail: fmt.Sprintf("IP %s has all octets in 1-30 range — possible encoded command data", ipStr),
			}
		}

		// First octet 0 or 127 is suspicious for a public domain
		if v4[0] == 0 || v4[0] == 127 {
			return &DNSCalculationFinding{
				Domain: domain,
				Reason: "encoded_data",
				IPs:    ips,
				Detail: fmt.Sprintf("IP %s has unusual first octet %d — possible encoded data", ipStr, v4[0]),
			}
		}
	}
	return nil
}

// checkRapidChange detects domains that change IPs very frequently,
// which can indicate the IPs are being used as a signaling channel.
func (d *DNSCalculationDetector) checkRapidChange(domain string, history []ipObservation) *DNSCalculationFinding {
	if len(history) < 5 {
		return nil
	}

	// Count unique IPs in the history
	uniqueIPs := make(map[string]bool)
	for _, h := range history {
		uniqueIPs[h.ip] = true
	}

	// If > 10 unique IPs in 24h, it's suspicious
	if len(uniqueIPs) > 10 {
		var ips []string
		for ip := range uniqueIPs {
			ips = append(ips, ip)
		}
		return &DNSCalculationFinding{
			Domain: domain,
			Reason: "rapid_change",
			IPs:    ips,
			Detail: fmt.Sprintf("Domain %s resolved to %d unique IPs in 24h — possible DNS calculation signaling", domain, len(uniqueIPs)),
		}
	}

	return nil
}

// Cleanup removes stale entries.
func (d *DNSCalculationDetector) Cleanup() {
	d.mu.Lock()
	defer d.mu.Unlock()
	cutoff := time.Now().Add(-d.window * 2)
	for domain, history := range d.domainIPHistory {
		if len(history) == 0 || history[len(history)-1].timestamp.Before(cutoff) {
			delete(d.domainIPHistory, domain)
		}
	}
}
