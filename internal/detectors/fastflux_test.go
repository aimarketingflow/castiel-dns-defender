package detectors

import (
	"testing"

	"github.com/castiel/dns/internal/config"
)

func TestFastFluxIPCount(t *testing.T) {
	cfg := config.C2DetectionConfig{
		Enabled:                true,
		MinIPCount:             5,
		TTLVolatilityThreshold: 60,
	}
	f := NewFastFluxDetector(cfg)

	// Track 6 different IPs for a domain
	ips := []string{"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4", "5.5.5.5", "6.6.6.6"}
	f.TrackResponse("evil.com", ips, 30)

	finding := f.Analyze("evil.com")
	if finding == nil {
		t.Fatal("Expected finding for high IP count")
	}
	if finding.Reason != "ip_count" {
		t.Errorf("Expected reason 'ip_count', got %s", finding.Reason)
	}
}

func TestFastFluxNoDetection(t *testing.T) {
	cfg := config.C2DetectionConfig{
		Enabled:                true,
		MinIPCount:             10,
		TTLVolatilityThreshold: 60,
	}
	f := NewFastFluxDetector(cfg)

	f.TrackResponse("normal.com", []string{"1.1.1.1", "2.2.2.2"}, 3600)
	finding := f.Analyze("normal.com")
	if finding != nil {
		t.Errorf("Expected nil for normal domain, got %+v", finding)
	}
}

func TestFastFluxTTLVolatility(t *testing.T) {
	cfg := config.C2DetectionConfig{
		Enabled:                true,
		MinIPCount:             100, // set high so IP count doesn't trigger
		TTLVolatilityThreshold: 60,
	}
	f := NewFastFluxDetector(cfg)

	f.TrackResponse("suspicious.com", []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"}, 10)
	finding := f.Analyze("suspicious.com")
	if finding == nil {
		t.Fatal("Expected finding for TTL volatility")
	}
	if finding.Reason != "ttl_volatility" {
		t.Errorf("Expected reason 'ttl_volatility', got %s", finding.Reason)
	}
}

func TestFastFluxUnknownDomain(t *testing.T) {
	cfg := config.C2DetectionConfig{
		Enabled:    true,
		MinIPCount: 5,
	}
	f := NewFastFluxDetector(cfg)

	finding := f.Analyze("unknown.com")
	if finding != nil {
		t.Error("Expected nil for unknown domain")
	}
}

func TestExtractResponseIPs(t *testing.T) {
	// Test with nil
	if ips := ExtractResponseIPs(nil); ips != nil {
		t.Error("Expected nil for nil response")
	}
}
