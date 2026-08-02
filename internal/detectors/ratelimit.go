package detectors

import (
	"net"
	"sync"
	"time"

	"github.com/castiel/dns/internal/config"
)

type RateAction int

const (
	ActionAllow RateAction = iota
	ActionDrop
	ActionTruncate
	ActionDelay
)

// RateLimiter implements a token-bucket rate limiter per client IP
// and a global QPS ceiling. Also tracks NXDOMAIN response rates
// per IP to detect water torture attacks.
type RateLimiter struct {
	cfg     config.RateLimitConfig
	buckets map[string]*tokenBucket
	mu      sync.Mutex
}

type tokenBucket struct {
	tokens       float64
	nxdomainTokens float64
	lastRefill   time.Time
}

func NewRateLimiter(cfg config.RateLimitConfig) *RateLimiter {
	rl := &RateLimiter{
		cfg:     cfg,
		buckets: make(map[string]*tokenBucket),
	}
	return rl
}

func (rl *RateLimiter) Check(clientIP string) RateAction {
	if !rl.cfg.Enabled {
		return ActionAllow
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	bucket, exists := rl.buckets[clientIP]
	if !exists {
		bucket = &tokenBucket{
			tokens:       float64(rl.cfg.PerIPQPS),
			nxdomainTokens: float64(rl.cfg.NXDomainPerIPQPS),
			lastRefill:   now,
		}
		rl.buckets[clientIP] = bucket
	}

	// Refill tokens based on elapsed time
	elapsed := now.Sub(bucket.lastRefill).Seconds()
	bucket.tokens += elapsed * float64(rl.cfg.PerIPQPS)
	if bucket.tokens > float64(rl.cfg.PerIPQPS) {
		bucket.tokens = float64(rl.cfg.PerIPQPS)
	}
	bucket.lastRefill = now

	// Check if rate limit exceeded
	if bucket.tokens < 1.0 {
		switch rl.cfg.Action {
		case "drop":
			return ActionDrop
		case "truncate":
			return ActionTruncate
		case "delay":
			return ActionDelay
		default:
			return ActionDrop
		}
	}

	bucket.tokens -= 1.0
	return ActionAllow
}

// CheckNXDomain should be called when an NXDOMAIN response is received
// to track per-IP NXDOMAIN rates (water torture detection).
func (rl *RateLimiter) CheckNXDomain(clientIP string) RateAction {
	if !rl.cfg.Enabled || rl.cfg.NXDomainPerIPQPS <= 0 {
		return ActionAllow
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	bucket, exists := rl.buckets[clientIP]
	if !exists {
		bucket = &tokenBucket{
			tokens:         float64(rl.cfg.PerIPQPS),
			nxdomainTokens: float64(rl.cfg.NXDomainPerIPQPS),
			lastRefill:     now,
		}
		rl.buckets[clientIP] = bucket
	}

	elapsed := now.Sub(bucket.lastRefill).Seconds()
	bucket.nxdomainTokens += elapsed * float64(rl.cfg.NXDomainPerIPQPS)
	if bucket.nxdomainTokens > float64(rl.cfg.NXDomainPerIPQPS) {
		bucket.nxdomainTokens = float64(rl.cfg.NXDomainPerIPQPS)
	}

	if bucket.nxdomainTokens < 1.0 {
		return ActionDrop
	}

	bucket.nxdomainTokens -= 1.0
	return ActionAllow
}

// IsPrivateIP checks if an IP is in RFC1918 / private range.
func IsPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"fc00::/7",
		"fe80::/10",
	}

	for _, cidr := range privateRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}
	return false
}
