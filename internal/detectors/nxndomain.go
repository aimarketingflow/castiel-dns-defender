package detectors

import (
	"sync"
	"time"

	"github.com/castiel/dns/internal/config"
)

// NXDomainTracker tracks NXDOMAIN response rates per apex domain
// to detect distributed DNS water torture attacks. Unlike per-IP
// rate limiting, this catches attacks distributed across many source IPs
// all targeting the same apex domain with random non-existent subdomains.
type NXDomainTracker struct {
	mu          sync.Mutex
	domains     map[string]*nxdomainCounter
	threshold   int           // max NXDOMAINs per domain per window
	window      time.Duration // rolling window for counting
	blockAction bool          // if true, block all queries to the domain when threshold exceeded
}

type nxdomainCounter struct {
	count      int
	firstSeen  time.Time
	lastSeen   time.Time
	blocked    bool
	blockUntil time.Time
}

// NXDomainConfig is an alias for the config type to avoid circular deps.
type NXDomainConfig = config.NXDomainTrackingConfig

func NewNXDomainTracker(cfg NXDomainConfig) *NXDomainTracker {
	window := time.Duration(cfg.WindowSecs) * time.Second
	if window <= 0 {
		window = 60 * time.Second
	}
	threshold := cfg.Threshold
	if threshold <= 0 {
		threshold = 100
	}
	return &NXDomainTracker{
		domains:     make(map[string]*nxdomainCounter),
		threshold:   threshold,
		window:      window,
		blockAction: cfg.BlockMode,
	}
}

// RecordNXDomain records an NXDOMAIN response for the given apex domain.
// Returns true if the domain has exceeded the NXDOMAIN threshold (water torture detected).
func (n *NXDomainTracker) RecordNXDomain(apexDomain string) bool {
	n.mu.Lock()
	defer n.mu.Unlock()

	now := time.Now()
	counter, exists := n.domains[apexDomain]
	if !exists || now.Sub(counter.firstSeen) > n.window {
		n.domains[apexDomain] = &nxdomainCounter{
			count:     1,
			firstSeen: now,
			lastSeen:  now,
		}
		return false
	}

	counter.count++
	counter.lastSeen = now

	if counter.count > n.threshold {
		counter.blocked = true
		counter.blockUntil = now.Add(n.window)
		return true
	}

	return false
}

// IsBlocked returns true if the domain is currently blocked due to
// exceeding the NXDOMAIN threshold.
func (n *NXDomainTracker) IsBlocked(apexDomain string) bool {
	if !n.blockAction {
		return false
	}
	n.mu.Lock()
	defer n.mu.Unlock()

	counter, exists := n.domains[apexDomain]
	if !exists {
		return false
	}
	if !counter.blocked {
		return false
	}
	if time.Now().After(counter.blockUntil) {
		counter.blocked = false
		return false
	}
	return true
}

// Cleanup removes expired entries to prevent unbounded memory growth.
func (n *NXDomainTracker) Cleanup() {
	n.mu.Lock()
	defer n.mu.Unlock()

	now := time.Now()
	for domain, counter := range n.domains {
		if now.Sub(counter.lastSeen) > n.window*2 {
			delete(n.domains, domain)
		}
	}
}

// StartCleanup launches a background goroutine that periodically removes expired entries.
func (n *NXDomainTracker) StartCleanup(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			n.Cleanup()
		}
	}()
}
