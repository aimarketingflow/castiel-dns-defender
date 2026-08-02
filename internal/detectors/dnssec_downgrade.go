package detectors

import (
	"sync"
	"time"
)

// DNSSECDowngradeDetector tracks DNSSEC validation success/failure per domain.
// Alerts when a previously-validating domain suddenly starts failing validation,
// which may indicate a DNSSEC stripping or downgrade attack.
type DNSSECDowngradeDetector struct {
	mu          sync.Mutex
	domains     map[string]*dnssecState
	alertCooldown time.Duration
}

type dnssecState struct {
	lastValid    time.Time
	lastFailure  time.Time
	failureCount int
	totalValid   int
	alerted      bool
	alertTime    time.Time
}

func NewDNSSECDowngradeDetector() *DNSSECDowngradeDetector {
	return &DNSSECDowngradeDetector{
		domains:      make(map[string]*dnssecState),
		alertCooldown: 10 * time.Minute,
	}
}

// RecordValidation records a DNSSEC validation result for a domain.
// Returns true if a downgrade attack is suspected (previously-validating domain now failing).
func (d *DNSSECDowngradeDetector) RecordValidation(domain string, valid bool) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	state, exists := d.domains[domain]
	if !exists {
		state = &dnssecState{}
		d.domains[domain] = state
	}

	if valid {
		state.lastValid = time.Now()
		state.totalValid++
		state.alerted = false
		state.failureCount = 0
		return false
	}

	// Failure case
	state.lastFailure = time.Now()
	state.failureCount++

	// Only alert if the domain previously validated successfully
	// and has now failed multiple times in a row
	if state.totalValid > 0 && state.failureCount >= 2 {
		if !state.alerted || time.Since(state.alertTime) > d.alertCooldown {
			state.alerted = true
			state.alertTime = time.Now()
			return true
		}
	}

	return false
}

// IsDowngradeAttempt returns true if the domain is currently in a suspected downgrade state.
func (d *DNSSECDowngradeDetector) IsDowngradeAttempt(domain string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	state, exists := d.domains[domain]
	if !exists {
		return false
	}
	return state.alerted && state.failureCount >= 2
}

// Cleanup removes stale entries.
func (d *DNSSECDowngradeDetector) Cleanup(maxAge time.Duration) {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()
	for domain, state := range d.domains {
		latest := state.lastValid
		if state.lastFailure.After(latest) {
			latest = state.lastFailure
		}
		if now.Sub(latest) > maxAge {
			delete(d.domains, domain)
		}
	}
}

// StartCleanup launches a background goroutine.
func (d *DNSSECDowngradeDetector) StartCleanup(interval, maxAge time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			d.Cleanup(maxAge)
		}
	}()
}
