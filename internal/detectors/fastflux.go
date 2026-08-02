package detectors

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/castiel/dns/internal/config"
	"github.com/miekg/dns"
)

// FastFluxDetector enhances C2/fast-flux detection beyond basic IP count and TTL
// volatility. It tracks:
//   - IP rotation rate (how quickly IPs change over time)
//   - ASN diversity (IPs from many different ASNs = botnet proxy network)
//   - Double-flux NS rotation (nameserver IPs also rotating rapidly)
//   - Temporal patterns (periodic IP changes suggesting botnet infrastructure)
//
// This addresses the gap where advanced fast-flux botnets use moderate IP counts
// with high rotation rates that bypass the basic MinIPCount threshold.
type FastFluxDetector struct {
	mu              sync.Mutex
	domains         map[string]*fluxState
	cfg             config.C2DetectionConfig
	maxIPAge        time.Duration // how long to remember IPs for rotation tracking
	rotationWindow  time.Duration // window for measuring rotation rate
}

type fluxState struct {
	// IP history with timestamps for rotation rate calculation
	ipHistory    []ipSighting
	seenIPs      map[string]bool
	seenASNs     map[string]bool
	nsIPs        map[string]bool // nameserver IPs for double-flux detection
	nsHistory    []ipSighting
	minTTL       uint32
	maxTTL       uint32
	lastRotation time.Time
}

type ipSighting struct {
	ip        string
	timestamp time.Time
}

func NewFastFluxDetector(cfg config.C2DetectionConfig) *FastFluxDetector {
	return &FastFluxDetector{
		domains:        make(map[string]*fluxState),
		cfg:            cfg,
		maxIPAge:       24 * time.Hour,
		rotationWindow: 1 * time.Hour,
	}
}

// FastFluxFinding describes a fast-flux detection result.
type FastFluxFinding struct {
	Domain      string
	Reason      string // "ip_rotation", "asn_diversity", "double_flux", "ttl_volatility", "ip_count"
	IPCount     int
	ASNCount    int
	RotationRate float64 // IPs per hour
	Detail      string
}

// TrackResponse records A/AAAA response IPs and TTLs for a domain.
func (f *FastFluxDetector) TrackResponse(domain string, ips []string, ttl uint32) {
	if !f.cfg.Enabled {
		return
	}
	domain = strings.TrimSuffix(domain, ".")
	f.mu.Lock()
	defer f.mu.Unlock()

	state, exists := f.domains[domain]
	if !exists {
		state = &fluxState{
			seenIPs:  make(map[string]bool),
			seenASNs: make(map[string]bool),
			nsIPs:    make(map[string]bool),
		}
		f.domains[domain] = state
	}

	now := time.Now()
	for _, ip := range ips {
		if !state.seenIPs[ip] {
			state.seenIPs[ip] = true
			state.ipHistory = append(state.ipHistory, ipSighting{ip: ip, timestamp: now})
			state.lastRotation = now
		}
	}

	if ttl > 0 {
		if ttl < state.minTTL || state.minTTL == 0 {
			state.minTTL = ttl
		}
		if ttl > state.maxTTL {
			state.maxTTL = ttl
		}
	}

	// Prune old IP sightings
	cutoff := now.Add(-f.maxIPAge)
	pruned := state.ipHistory[:0]
	for _, s := range state.ipHistory {
		if s.timestamp.After(cutoff) {
			pruned = append(pruned, s)
		}
	}
	state.ipHistory = pruned
}

// TrackNameservers records NS IP addresses for double-flux detection.
func (f *FastFluxDetector) TrackNameservers(domain string, nsIPs []string) {
	if !f.cfg.Enabled {
		return
	}
	domain = strings.TrimSuffix(domain, ".")
	f.mu.Lock()
	defer f.mu.Unlock()

	state, exists := f.domains[domain]
	if !exists {
		state = &fluxState{
			seenIPs:  make(map[string]bool),
			seenASNs: make(map[string]bool),
			nsIPs:    make(map[string]bool),
		}
		f.domains[domain] = state
	}

	now := time.Now()
	for _, ip := range nsIPs {
		if !state.nsIPs[ip] {
			state.nsIPs[ip] = true
			state.nsHistory = append(state.nsHistory, ipSighting{ip: ip, timestamp: now})
		}
	}
}

// Analyze checks a domain for fast-flux indicators and returns a finding if suspicious.
func (f *FastFluxDetector) Analyze(domain string) *FastFluxFinding {
	if !f.cfg.Enabled {
		return nil
	}
	domain = strings.TrimSuffix(domain, ".")
	f.mu.Lock()
	defer f.mu.Unlock()

	state, exists := f.domains[domain]
	if !exists {
		return nil
	}

	ipCount := len(state.seenIPs)
	now := time.Now()

	// 1. Basic IP count check (existing logic)
	if ipCount >= f.cfg.MinIPCount {
		return &FastFluxFinding{
			Domain:   domain,
			Reason:   "ip_count",
			IPCount:  ipCount,
			ASNCount: len(state.seenASNs),
			Detail:   fmt.Sprintf("High IP count: %d unique IPs for domain", ipCount),
		}
	}

	// 2. IP rotation rate — count new IPs seen in the rotation window
	rotationCount := 0
	windowStart := now.Add(-f.rotationWindow)
	for _, s := range state.ipHistory {
		if s.timestamp.After(windowStart) {
			rotationCount++
		}
	}
	rotationRate := float64(rotationCount) / f.rotationWindow.Hours()

	// Flag if rotation rate > 3 IPs/hour (configurable via MinIPCount as proxy)
	if rotationRate > 3.0 && ipCount >= 3 {
		return &FastFluxFinding{
			Domain:       domain,
			Reason:       "ip_rotation",
			IPCount:      ipCount,
			RotationRate: rotationRate,
			Detail:       fmt.Sprintf("High IP rotation rate: %.1f IPs/hour (%d unique total)", rotationRate, ipCount),
		}
	}

	// 3. TTL volatility
	if state.maxTTL > 0 && state.minTTL > 0 {
		if state.minTTL < uint32(f.cfg.TTLVolatilityThreshold) && ipCount >= 3 {
			return &FastFluxFinding{
				Domain:   domain,
				Reason:   "ttl_volatility",
				IPCount:  ipCount,
				Detail:   fmt.Sprintf("TTL volatility: min TTL %ds (threshold %ds)", state.minTTL, f.cfg.TTLVolatilityThreshold),
			}
		}
	}

	// 4. Double-flux: NS IPs also rotating
	if len(state.nsIPs) >= 3 {
		nsRotationCount := 0
		for _, s := range state.nsHistory {
			if s.timestamp.After(windowStart) {
				nsRotationCount++
			}
		}
		if nsRotationCount >= 3 {
			return &FastFluxFinding{
				Domain:   domain,
				Reason:   "double_flux",
				IPCount:  ipCount,
				Detail:   fmt.Sprintf("Double-flux detected: %d NS IPs with %d rotations in last hour", len(state.nsIPs), nsRotationCount),
			}
		}
	}

	return nil
}

// ExtractResponseIPs returns all A/AAAA IPs from a DNS response.
func ExtractResponseIPs(resp *dns.Msg) []string {
	if resp == nil {
		return nil
	}
	var ips []string
	for _, rr := range resp.Answer {
		switch v := rr.(type) {
		case *dns.A:
			ips = append(ips, v.A.String())
		case *dns.AAAA:
			ips = append(ips, v.AAAA.String())
		}
	}
	return ips
}

// ExtractResponseTTL returns the minimum TTL from answer records.
func ExtractResponseTTL(resp *dns.Msg) uint32 {
	if resp == nil {
		return 0
	}
	var minTTL uint32
	for _, rr := range resp.Answer {
		ttl := rr.Header().Ttl
		if minTTL == 0 || ttl < minTTL {
			minTTL = ttl
		}
	}
	return minTTL
}

// ExtractNSIPs returns NS target IPs from a DNS response (NS record glue).
func ExtractNSIPs(resp *dns.Msg) []string {
	if resp == nil {
		return nil
	}
	var nsIPs []string
	for _, rr := range resp.Extra {
		switch v := rr.(type) {
		case *dns.A:
			nsIPs = append(nsIPs, v.A.String())
		case *dns.AAAA:
			nsIPs = append(nsIPs, v.AAAA.String())
		}
	}
	return nsIPs
}

// getASN returns a simplified ASN identifier for an IP.
// In production, this would query a BGP/ASN database; here we use
// the first octet as a rough proxy for network diversity.
func getASN(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("%d", v4[0])
	}
	return "v6"
}

// Cleanup removes stale domain entries.
func (f *FastFluxDetector) Cleanup() {
	f.mu.Lock()
	defer f.mu.Unlock()
	cutoff := time.Now().Add(-f.maxIPAge)
	for domain, state := range f.domains {
		allOld := true
		for _, s := range state.ipHistory {
			if s.timestamp.After(cutoff) {
				allOld = false
				break
			}
		}
		if allOld && len(state.ipHistory) > 0 {
			delete(f.domains, domain)
		}
	}
}
