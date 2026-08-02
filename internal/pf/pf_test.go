//go:build darwin

package pf

import (
	"strings"
	"testing"

	"github.com/castiel/dns/internal/config"
)

func TestGenerateRules(t *testing.T) {
	cfg := config.PFConfig{
		Enabled:      true,
		AnchorName:   "dnsattackdefender",
		RedirectPort: 5353,
		Interface:    "en0",
	}

	m := &Manager{cfg: cfg, anchorName: cfg.AnchorName}
	rules := m.generateRules()

	// Should contain IPv4 UDP redirect
	if !strings.Contains(rules, "rdr pass on en0 inet proto udp from any to any port 53 -> 127.0.0.1 port 5353") {
		t.Error("Missing IPv4 UDP redirect rule")
	}

	// Should contain IPv4 TCP redirect
	if !strings.Contains(rules, "rdr pass on en0 inet proto tcp from any to any port 53 -> 127.0.0.1 port 5353") {
		t.Error("Missing IPv4 TCP redirect rule")
	}

	// Should contain IPv6 UDP redirect
	if !strings.Contains(rules, "rdr pass on en0 inet6 proto udp from any to any port 53 -> ::1 port 5353") {
		t.Error("Missing IPv6 UDP redirect rule")
	}

	// Should contain IPv6 TCP redirect
	if !strings.Contains(rules, "rdr pass on en0 inet6 proto tcp from any to any port 53 -> ::1 port 5353") {
		t.Error("Missing IPv6 TCP redirect rule")
	}
}

func TestGenerateRulesDifferentInterface(t *testing.T) {
	cfg := config.PFConfig{
		Enabled:      true,
		AnchorName:   "dnsattackdefender",
		RedirectPort: 5354,
		Interface:    "utun0",
	}

	m := &Manager{cfg: cfg, anchorName: cfg.AnchorName}
	rules := m.generateRules()

	if !strings.Contains(rules, "on utun0") {
		t.Error("Rules should reference interface 'utun0'")
	}

	if !strings.Contains(rules, "port 5354") {
		t.Error("Rules should reference redirect port 5354")
	}
}

func TestGenerateRulesFormat(t *testing.T) {
	cfg := config.PFConfig{
		Enabled:      true,
		AnchorName:   "test",
		RedirectPort: 5353,
		Interface:    "en0",
	}

	m := &Manager{cfg: cfg, anchorName: cfg.AnchorName}
	rules := m.generateRules()

	lines := strings.Split(strings.TrimSpace(rules), "\n")

	// Should have exactly 4 rules (IPv4 UDP, IPv4 TCP, IPv6 UDP, IPv6 TCP)
	if len(lines) != 4 {
		t.Errorf("Expected 4 redirect rules, got %d", len(lines))
	}

	// Each line should start with "rdr pass"
	for i, line := range lines {
		if !strings.HasPrefix(line, "rdr pass") {
			t.Errorf("Line %d should start with 'rdr pass', got: %s", i, line)
		}
	}
}

func TestNewManagerPfctlCheck(t *testing.T) {
	// This test just verifies that NewManager handles missing pfctl gracefully
	// On most test environments pfctl exists (macOS), so we test the error path
	// by checking that the constructor either succeeds or returns an error
	cfg := config.PFConfig{
		Enabled:      true,
		AnchorName:   "test",
		RedirectPort: 5353,
		Interface:    "en0",
	}

	m, err := NewManager(cfg)
	if err != nil {
		// pfctl not found — acceptable in CI/non-macOS environments
		t.Logf("NewManager returned error (expected on non-macOS): %v", err)
		return
	}
	if m == nil {
		t.Error("NewManager returned nil manager without error")
	}
}
