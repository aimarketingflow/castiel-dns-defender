//go:build windows

package windivert

import (
	"testing"

	"github.com/castiel/dns/internal/config"
)

func TestNewManager(t *testing.T) {
	cfg := config.DnsRedirectConfig{
		Enabled:      true,
		Method:       "system_dns",
		RedirectPort: 53,
	}

	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}
	if m == nil {
		t.Fatal("NewManager returned nil")
	}
	if m.Backend() != "system_dns" {
		t.Errorf("Backend() = %q, want %q", m.Backend(), "system_dns")
	}
}

func TestNewManagerPortProxy(t *testing.T) {
	cfg := config.DnsRedirectConfig{
		Enabled:      true,
		Method:       "portproxy",
		RedirectPort: 5300,
	}

	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}
	if m.Backend() != "portproxy" {
		t.Errorf("Backend() = %q, want %q", m.Backend(), "portproxy")
	}
}

func TestIsValidIPv4(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"127.0.0.1", true},
		{"1.1.1.1", true},
		{"8.8.8.8", true},
		{"192.168.1.1", true},
		{"256.1.1.1", false},
		{"1.1.1", false},
		{"abc", false},
		{"", false},
		{"1.1.1.1.1", false},
	}

	for _, tt := range tests {
		got := isValidIPv4(tt.input)
		if got != tt.expected {
			t.Errorf("isValidIPv4(%q) = %v, want %v", tt.input, got, tt.expected)
		}
	}
}
