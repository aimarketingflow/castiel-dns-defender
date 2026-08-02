package detectors

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// LowSlowExfilDetector detects low-and-slow DNS exfiltration that operates
// over 24+ hours (FrameworkPOS-style). Instead of detecting high entropy
// in individual queries, it analyzes domain behavior patterns over time:
//
//   - High query volume to a single domain over 24h (beaconing)
//   - Gradually increasing subdomain length (data accumulation)
//   - Periodic query patterns (regular intervals = C2 beaconing)
//   - Many unique subdomains under a single apex (data exfil channel)
//   - Low total bytes per query but high aggregate over time
type LowSlowExfilDetector struct {
	mu          sync.Mutex
	domains     map[string]*exfilState
	window      time.Duration
	maxSubdomains int // threshold for unique subdomain count
	beaconThreshold float64 // regularity score threshold (0-1)
}

type exfilState struct {
	apex           string
	subdomains     map[string]bool
	queryTimes     []time.Time
	totalQueries   int64
	firstSeen      time.Time
	lastSeen       time.Time
	maxSubdomainLen int
}

func NewLowSlowExfilDetector() *LowSlowExfilDetector {
	return &LowSlowExfilDetector{
		domains:        make(map[string]*exfilState),
		window:         24 * time.Hour,
		maxSubdomains:  50,    // >50 unique subdomains in 24h is suspicious
		beaconThreshold: 0.7,  // 70% regularity = beaconing
	}
}

// LowSlowFinding describes a low-and-slow exfiltration detection result.
type LowSlowFinding struct {
	Domain        string
	Reason        string // "many_subdomains", "beaconing", "increasing_length", "high_volume"
	SubdomainCount int
	TotalQueries   int64
	Detail         string
}

// RecordQuery records a DNS query for a domain.
func (l *LowSlowExfilDetector) RecordQuery(domain string) {
	domain = strings.TrimSuffix(domain, ".")
	apex := ExtractApexDomain(domain)

	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	state, exists := l.domains[apex]
	if !exists || now.Sub(state.firstSeen) > l.window {
		l.domains[apex] = &exfilState{
			apex:       apex,
			subdomains: map[string]bool{domain: true},
			queryTimes: []time.Time{now},
			firstSeen:  now,
			lastSeen:   now,
			totalQueries: 1,
			maxSubdomainLen: len(domain),
		}
		return
	}

	state.totalQueries++
	state.subdomains[domain] = true
	state.queryTimes = append(state.queryTimes, now)
	state.lastSeen = now

	if len(domain) > state.maxSubdomainLen {
		state.maxSubdomainLen = len(domain)
	}

	// Prune old query times
	cutoff := now.Add(-l.window)
	pruned := state.queryTimes[:0]
	for _, t := range state.queryTimes {
		if t.After(cutoff) {
			pruned = append(pruned, t)
		}
	}
	state.queryTimes = pruned
}

// Analyze checks a domain for low-and-slow exfiltration patterns.
func (l *LowSlowExfilDetector) Analyze(domain string) *LowSlowFinding {
	domain = strings.TrimSuffix(domain, ".")
	apex := ExtractApexDomain(domain)

	l.mu.Lock()
	defer l.mu.Unlock()

	state, exists := l.domains[apex]
	if !exists {
		return nil
	}

	// Check if window has expired
	if time.Since(state.firstSeen) > l.window {
		return nil
	}

	subdomainCount := len(state.subdomains)

	// 1. Many unique subdomains under one apex — exfil channel indicator
	if subdomainCount >= l.maxSubdomains {
		return &LowSlowFinding{
			Domain:         apex,
			Reason:         "many_subdomains",
			SubdomainCount: subdomainCount,
			TotalQueries:   state.totalQueries,
			Detail:         fmt.Sprintf("High subdomain diversity: %d unique subdomains under %s in 24h (possible exfil channel)", subdomainCount, apex),
		}
	}

	// 2. Beaconing detection — queries at regular intervals
	if len(state.queryTimes) >= 10 {
		regularity := l.computeRegularity(state.queryTimes)
		if regularity >= l.beaconThreshold && state.totalQueries >= 20 {
			return &LowSlowFinding{
				Domain:         apex,
				Reason:         "beaconing",
				SubdomainCount: subdomainCount,
				TotalQueries:   state.totalQueries,
				Detail:         fmt.Sprintf("Beaconing detected: %d queries with %.0f%% regularity to %s", state.totalQueries, regularity*100, apex),
			}
		}
	}

	// 3. High query volume to single domain over 24h
	if state.totalQueries >= 500 && subdomainCount < 5 {
		return &LowSlowFinding{
			Domain:         apex,
			Reason:         "high_volume",
			SubdomainCount: subdomainCount,
			TotalQueries:   state.totalQueries,
			Detail:         fmt.Sprintf("High query volume: %d queries to %s with only %d unique subdomains in 24h", state.totalQueries, apex, subdomainCount),
		}
	}

	return nil
}

// computeRegularity measures how evenly spaced the query intervals are.
// Returns a score 0-1 where 1.0 = perfectly regular intervals (beaconing).
func (l *LowSlowExfilDetector) computeRegularity(times []time.Time) float64 {
	if len(times) < 3 {
		return 0
	}

	// Calculate intervals
	intervals := make([]float64, len(times)-1)
	for i := 1; i < len(times); i++ {
		intervals[i-1] = times[i].Sub(times[i-1]).Seconds()
	}

	// Calculate mean interval
	var sum float64
	for _, iv := range intervals {
		sum += iv
	}
	mean := sum / float64(len(intervals))
	if mean == 0 {
		return 0
	}

	// Calculate coefficient of variation (CV = stdDev / mean)
	var sqSum float64
	for _, iv := range intervals {
		diff := iv - mean
		sqSum += diff * diff
	}
	stdDev := sqrt(sqSum / float64(len(intervals)))
	cv := stdDev / mean

	// Low CV = high regularity. Convert to 0-1 score.
	// CV < 0.1 = very regular (score ~1.0)
	// CV > 1.0 = random (score ~0.0)
	if cv < 0.01 {
		return 1.0
	}
	regularity := 1.0 / (1.0 + cv)
	return regularity
}

// Cleanup removes stale entries.
func (l *LowSlowExfilDetector) Cleanup() {
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := time.Now().Add(-l.window * 2)
	for apex, state := range l.domains {
		if state.lastSeen.Before(cutoff) {
			delete(l.domains, apex)
		}
	}
}

// StartCleanup launches a background goroutine.
func (l *LowSlowExfilDetector) StartCleanup(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			l.Cleanup()
		}
	}()
}

func sqrt(x float64) float64 {
	if x <= 0 {
		return 0
	}
	// Newton's method for sqrt
	z := x
	for i := 0; i < 10; i++ {
		z = z - (z*z-x)/(2*z)
	}
	return z
}
