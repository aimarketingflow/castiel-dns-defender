package detectors

import (
	"fmt"
	"sync"
	"time"
)

// SparseDGADetector detects sparse/low-frequency DGA domains that query
// only a few domains per hour (e.g., 3 queries/hour) to evade rate-based
// detection. It tracks the NXDOMAIN ratio per client IP over a 24-hour
// rolling window. A high NXDOMAIN ratio with moderate query volume
// is characteristic of sparse DGA families like Ramdo, Ramnit, and Virut.
//
// Detection logic:
//   - Track total queries and NXDOMAIN responses per client IP over 24h
//   - If NXDOMAIN ratio > threshold AND total queries > minimum,
//     flag as sparse DGA
//   - Also track unique domain count — DGA generates many unique domains
type SparseDGADetector struct {
	mu             sync.Mutex
	clients        map[string]*clientQueryHistory
	nxdomainRatio  float64 // threshold (e.g., 0.6 = 60% NXDOMAIN)
	minQueries     int     // minimum queries in window to trigger
	minUniqueDomains int   // minimum unique domains to trigger
	window          time.Duration
}

type clientQueryHistory struct {
	totalQueries   int
	nxdomainCount  int
	uniqueDomains  map[string]bool
	firstSeen      time.Time
	lastSeen       time.Time
}

// SparseDGAConfig configures sparse DGA detection.
type SparseDGAConfig struct {
	Enabled          bool
	NXDomainRatio    float64 // e.g., 0.6
	MinQueries       int     // e.g., 20 queries in 24h
	MinUniqueDomains int     // e.g., 10 unique domains
	WindowHours      int     // e.g., 24
}

func NewSparseDGADetector(cfg SparseDGAConfig) *SparseDGADetector {
	window := time.Duration(cfg.WindowHours) * time.Hour
	if window <= 0 {
		window = 24 * time.Hour
	}
	ratio := cfg.NXDomainRatio
	if ratio <= 0 {
		ratio = 0.6
	}
	minQ := cfg.MinQueries
	if minQ <= 0 {
		minQ = 20
	}
	minU := cfg.MinUniqueDomains
	if minU <= 0 {
		minU = 10
	}
	return &SparseDGADetector{
		clients:          make(map[string]*clientQueryHistory),
		nxdomainRatio:    ratio,
		minQueries:       minQ,
		minUniqueDomains: minU,
		window:           window,
	}
}

// SparseDGAFinding describes a sparse DGA detection result.
type SparseDGAFinding struct {
	ClientIP       string
	NXDomainRatio  float64
	TotalQueries   int
	UniqueDomains  int
	Detail         string
}

// RecordQuery records a query from a client for a specific domain.
// isNXDOMAIN indicates if the response was NXDOMAIN.
func (s *SparseDGADetector) RecordQuery(clientIP, domain string, isNXDOMAIN bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	history, exists := s.clients[clientIP]
	if !exists || now.Sub(history.firstSeen) > s.window {
		s.clients[clientIP] = &clientQueryHistory{
			totalQueries:  1,
			uniqueDomains: map[string]bool{domain: true},
			firstSeen:     now,
			lastSeen:      now,
		}
		if isNXDOMAIN {
			s.clients[clientIP].nxdomainCount = 1
		}
		return
	}

	history.totalQueries++
	history.uniqueDomains[domain] = true
	history.lastSeen = now
	if isNXDOMAIN {
		history.nxdomainCount++
	}
}

// Analyze checks if a client's query pattern matches sparse DGA behavior.
func (s *SparseDGADetector) Analyze(clientIP string) *SparseDGAFinding {
	s.mu.Lock()
	defer s.mu.Unlock()

	history, exists := s.clients[clientIP]
	if !exists {
		return nil
	}

	// Check if window has expired
	if time.Since(history.firstSeen) > s.window {
		return nil
	}

	// Need minimum query volume to make a determination
	if history.totalQueries < s.minQueries {
		return nil
	}

	uniqueCount := len(history.uniqueDomains)
	if uniqueCount < s.minUniqueDomains {
		return nil
	}

	ratio := float64(history.nxdomainCount) / float64(history.totalQueries)
	if ratio >= s.nxdomainRatio {
		return &SparseDGAFinding{
			ClientIP:      clientIP,
			NXDomainRatio: ratio,
			TotalQueries:  history.totalQueries,
			UniqueDomains: uniqueCount,
			Detail:        formatSparseDGADetail(ratio, history.totalQueries, uniqueCount, history.nxdomainCount),
		}
	}

	return nil
}

func formatSparseDGADetail(ratio float64, total, unique, nxCount int) string {
	return fmt.Sprintf("Sparse DGA: %.0f%% NXDOMAIN ratio (%d/%d), %d unique domains in 24h", ratio*100, nxCount, total, unique)
}

// Cleanup removes stale client entries.
func (s *SparseDGADetector) Cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := time.Now().Add(-s.window * 2)
	for ip, history := range s.clients {
		if history.lastSeen.Before(cutoff) {
			delete(s.clients, ip)
		}
	}
}

// StartCleanup launches a background goroutine.
func (s *SparseDGADetector) StartCleanup(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			s.Cleanup()
		}
	}()
}
