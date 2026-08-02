package detectors

import (
	"testing"

	"github.com/castiel/dns/internal/config"
)

func TestRateLimiterAllow(t *testing.T) {
	cfg := config.RateLimitConfig{
		Enabled:          true,
		PerIPQPS:         50,
		NXDomainPerIPQPS: 10,
		Action:           "drop",
	}
	rl := NewRateLimiter(cfg)

	// First request should be allowed
	for i := 0; i < 50; i++ {
		if action := rl.Check("192.168.1.1"); action != ActionAllow {
			t.Errorf("request %d: expected ActionAllow, got %v", i, action)
		}
	}
}

func TestRateLimiterDrop(t *testing.T) {
	cfg := config.RateLimitConfig{
		Enabled:          true,
		PerIPQPS:         5,
		NXDomainPerIPQPS: 10,
		Action:           "drop",
	}
	rl := NewRateLimiter(cfg)

	// Exhaust all 5 tokens
	for i := 0; i < 5; i++ {
		rl.Check("10.0.0.1")
	}
	// 6th request should be dropped
	if action := rl.Check("10.0.0.1"); action != ActionDrop {
		t.Errorf("expected ActionDrop after exhausting tokens, got %v", action)
	}
}

func TestRateLimiterTruncateAction(t *testing.T) {
	cfg := config.RateLimitConfig{
		Enabled:  true,
		PerIPQPS: 2,
		Action:   "truncate",
	}
	rl := NewRateLimiter(cfg)

	rl.Check("10.0.0.2")
	rl.Check("10.0.0.2")
	if action := rl.Check("10.0.0.2"); action != ActionTruncate {
		t.Errorf("expected ActionTruncate, got %v", action)
	}
}

func TestRateLimiterDisabled(t *testing.T) {
	cfg := config.RateLimitConfig{Enabled: false}
	rl := NewRateLimiter(cfg)

	for i := 0; i < 100; i++ {
		if action := rl.Check("10.0.0.3"); action != ActionAllow {
			t.Errorf("disabled rate limiter should always allow, got %v on request %d", action, i)
		}
	}
}

func TestRateLimiterPerIP(t *testing.T) {
	cfg := config.RateLimitConfig{
		Enabled:  true,
		PerIPQPS: 3,
		Action:   "drop",
	}
	rl := NewRateLimiter(cfg)

	// IP A exhausts its bucket
	for i := 0; i < 3; i++ {
		rl.Check("10.0.0.10")
	}
	// IP A is rate limited
	if action := rl.Check("10.0.0.10"); action != ActionDrop {
		t.Errorf("IP A should be rate limited, got %v", action)
	}
	// IP B should still be allowed (separate bucket)
	if action := rl.Check("10.0.0.20"); action != ActionAllow {
		t.Errorf("IP B should be allowed (separate bucket), got %v", action)
	}
}

func TestNXDomainRateLimit(t *testing.T) {
	cfg := config.RateLimitConfig{
		Enabled:          true,
		PerIPQPS:         100,
		NXDomainPerIPQPS: 3,
		Action:           "drop",
	}
	rl := NewRateLimiter(cfg)

	// 3 NXDOMAIN responses allowed
	for i := 0; i < 3; i++ {
		if action := rl.CheckNXDomain("10.0.0.5"); action != ActionAllow {
			t.Errorf("NXDOMAIN %d: expected ActionAllow, got %v", i, action)
		}
	}
	// 4th NXDOMAIN should be dropped
	if action := rl.CheckNXDomain("10.0.0.5"); action != ActionDrop {
		t.Errorf("4th NXDOMAIN: expected ActionDrop, got %v", action)
	}
}

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		ip       string
		expected bool
	}{
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"172.32.0.1", false},
		{"192.168.1.1", true},
		{"192.168.0.0", true},
		{"127.0.0.1", true},
		{"169.254.1.1", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"", false},
		{"not-an-ip", false},
		{"fd00::1", true},
		{"fe80::1", true},
		{"2001:4860:4860::8888", false},
	}

	for _, tt := range tests {
		got := IsPrivateIP(tt.ip)
		if got != tt.expected {
			t.Errorf("IsPrivateIP(%q) = %v, want %v", tt.ip, got, tt.expected)
		}
	}
}
