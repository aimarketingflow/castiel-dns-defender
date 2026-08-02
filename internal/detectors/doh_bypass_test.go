package detectors

import (
	"testing"
)

func TestDoHBypassKnownResolver(t *testing.T) {
	d := NewDoHBypassDetector()

	tests := []struct {
		ip      string
		known   bool
	}{
		{"8.8.8.8", true},
		{"1.1.1.1", true},
		{"9.9.9.9", true},
		{"208.67.222.222", true},
		{"94.140.14.14", true},
		{"8.8.4.4", true},
		{"1.0.0.1", true},
		{"192.168.1.1", false},
		{"10.0.0.1", false},
		{"172.16.0.1", false},
	}

	for _, tt := range tests {
		got := d.IsKnownDoHResolver(tt.ip)
		if got != tt.known {
			t.Errorf("IsKnownDoHResolver(%s) = %v, want %v", tt.ip, got, tt.known)
		}
	}
}

func TestDoHBypassCheckDestination(t *testing.T) {
	d := NewDoHBypassDetector()

	finding := d.CheckDestinationIP("8.8.8.8")
	if finding == nil {
		t.Error("Expected finding for known DoH resolver 8.8.8.8")
	}
	if finding.ResolverName == "" {
		t.Error("Resolver name should not be empty")
	}
}

func TestDoHBypassCheckUnknownDestination(t *testing.T) {
	d := NewDoHBypassDetector()

	finding := d.CheckDestinationIP("192.168.1.1")
	if finding != nil {
		t.Error("Expected nil finding for non-DoH IP")
	}
}

func TestDoHBypassAddCustomResolver(t *testing.T) {
	d := NewDoHBypassDetector()

	customIP := "203.0.113.99"
	if d.IsKnownDoHResolver(customIP) {
		t.Error("Custom IP should not be known before adding")
	}

	d.AddResolver(customIP, "custom-test")
	if !d.IsKnownDoHResolver(customIP) {
		t.Error("Custom IP should be known after adding")
	}

	finding := d.CheckDestinationIP(customIP)
	if finding == nil {
		t.Error("Expected finding for custom DoH resolver")
	}
	if finding.ResolverName != "custom-test" {
		t.Errorf("Expected resolver name 'custom-test', got %s", finding.ResolverName)
	}
}

func TestDoHBypassCooldown(t *testing.T) {
	d := NewDoHBypassDetector()

	// First check should return finding
	finding1 := d.CheckDestinationIP("1.1.1.1")
	if finding1 == nil {
		t.Error("First check should return finding")
	}

	// Second check within cooldown should return nil
	finding2 := d.CheckDestinationIP("1.1.1.1")
	if finding2 != nil {
		t.Error("Second check within cooldown should return nil")
	}
}

func TestCheckIPInCIDR(t *testing.T) {
	tests := []struct {
		ip   string
		cidr string
		want bool
	}{
		{"192.168.1.100", "192.168.1.0/24", true},
		{"192.168.2.100", "192.168.1.0/24", false},
		{"10.0.0.5", "10.0.0.0/8", true},
		{"11.0.0.5", "10.0.0.0/8", false},
		{"invalid", "10.0.0.0/8", false},
		{"10.0.0.5", "invalid", false},
	}

	for _, tt := range tests {
		got := CheckIPInCIDR(tt.ip, tt.cidr)
		if got != tt.want {
			t.Errorf("CheckIPInCIDR(%s, %s) = %v, want %v", tt.ip, tt.cidr, got, tt.want)
		}
	}
}
