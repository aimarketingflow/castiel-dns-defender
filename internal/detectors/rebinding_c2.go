package detectors

import (
	"strings"

	"github.com/castiel/dns/internal/config"
	"github.com/miekg/dns"
)

// RebindingDetector blocks DNS rebinding attacks by checking if
// a public domain resolves to a private (RFC1918) IP address.
// This prevents attackers from using browser same-origin policy bypass
// to access internal network resources.
type RebindingDetector struct {
	cfg config.RebindingProtectionConfig
}

func NewRebindingDetector(cfg config.RebindingProtectionConfig) *RebindingDetector {
	return &RebindingDetector{cfg: cfg}
}

func (rd *RebindingDetector) IsRebinding(resp *dns.Msg) bool {
	if !rd.cfg.Enabled || !rd.cfg.BlockPublicToPrivate || resp == nil {
		return false
	}

	// Check A and AAAA records in the answer section
	for _, rr := range resp.Answer {
		switch v := rr.(type) {
		case *dns.A:
			if IsPrivateIP(v.A.String()) {
				return true
			}
		case *dns.AAAA:
			if IsPrivateIP(v.AAAA.String()) {
				return true
			}
		}
	}

	return false
}

// C2Detector detects C2 beaconing and fast-flux infrastructure by
// monitoring TTL volatility and IP address diversity for domains.
type C2Detector struct {
	cfg         config.C2DetectionConfig
	domainTracker map[string]*domainState
}

type domainState struct {
	seenIPs   map[string]bool
	minTTL    uint32
	maxTTL    uint32
	lastCheck int64
}

func NewC2Detector(cfg config.C2DetectionConfig) *C2Detector {
	return &C2Detector{
		cfg:           cfg,
		domainTracker: make(map[string]*domainState),
	}
}

func (c *C2Detector) IsSuspicious(domain string) bool {
	if !c.cfg.Enabled {
		return false
	}

	domain = strings.TrimSuffix(domain, ".")
	state, exists := c.domainTracker[domain]
	if !exists {
		return false
	}

	// Fast-flux: many unique IPs for a single domain
	if len(state.seenIPs) >= c.cfg.MinIPCount {
		return true
	}

	// TTL volatility: TTL changing rapidly is a fast-flux indicator
	if state.maxTTL > 0 && state.minTTL > 0 {
		if state.minTTL < uint32(c.cfg.TTLVolatilityThreshold) {
			return true
		}
	}

	return false
}

// TrackResponse should be called for each DNS response to update
// the C2/fast-flux tracking state.
func (c *C2Detector) TrackResponse(domain string, ips []string, ttl uint32) {
	if !c.cfg.Enabled {
		return
	}

	domain = strings.TrimSuffix(domain, ".")
	state, exists := c.domainTracker[domain]
	if !exists {
		state = &domainState{
			seenIPs: make(map[string]bool),
			minTTL:  ttl,
			maxTTL:  ttl,
		}
		c.domainTracker[domain] = state
	}

	for _, ip := range ips {
		state.seenIPs[ip] = true
	}

	if ttl > 0 {
		if ttl < state.minTTL || state.minTTL == 0 {
			state.minTTL = ttl
		}
		if ttl > state.maxTTL {
			state.maxTTL = ttl
		}
	}
}
