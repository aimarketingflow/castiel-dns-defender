package detectors

import (
	"net"
	"testing"

	"github.com/castiel/dns/internal/config"
	"github.com/miekg/dns"
)

func TestRebindingDetector(t *testing.T) {
	cfg := config.RebindingProtectionConfig{
		Enabled:              true,
		BlockPublicToPrivate: true,
	}
	detector := NewRebindingDetector(cfg)

	// Response with private IP → rebinding detected
	resp1 := new(dns.Msg)
	resp1.Answer = append(resp1.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: "evil.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   net.ParseIP("192.168.1.1"),
	})
	if !detector.IsRebinding(resp1) {
		t.Error("expected rebinding detection for 192.168.1.1 in A record")
	}

	// Response with public IP → no rebinding
	resp2 := new(dns.Msg)
	resp2.Answer = append(resp2.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: "google.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP("8.8.8.8"),
	})
	if detector.IsRebinding(resp2) {
		t.Error("expected no rebinding for public IP 8.8.8.8")
	}

	// Response with AAAA private IP → rebinding
	resp3 := new(dns.Msg)
	resp3.Answer = append(resp3.Answer, &dns.AAAA{
		Hdr:  dns.RR_Header{Name: "evil.com.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
		AAAA: net.ParseIP("fd00::1"),
	})
	if !detector.IsRebinding(resp3) {
		t.Error("expected rebinding detection for fd00::1 in AAAA record")
	}

	// Nil response
	if detector.IsRebinding(nil) {
		t.Error("expected false for nil response")
	}

	// Disabled
	detector.cfg.Enabled = false
	if detector.IsRebinding(resp1) {
		t.Error("disabled detector should not flag rebinding")
	}
}

func TestC2Detector(t *testing.T) {
	cfg := config.C2DetectionConfig{
		Enabled:              true,
		TTLVolatilityThreshold: 60,
		MinIPCount:           5,
	}
	detector := NewC2Detector(cfg)

	// New domain — not suspicious yet
	if detector.IsSuspicious("evil.com") {
		t.Error("new domain should not be suspicious")
	}

	// Track many IPs → fast-flux
	ips := []string{"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4", "5.5.5.5"}
	detector.TrackResponse("evil.com", ips, 30)
	if !detector.IsSuspicious("evil.com") {
		t.Error("domain with 5+ IPs should be suspicious (fast-flux)")
	}

	// Track low TTL → TTL volatility
	detector2 := NewC2Detector(cfg)
	detector2.TrackResponse("flux.net", []string{"1.1.1.1"}, 10)
	if !detector2.IsSuspicious("flux.net") {
		t.Error("domain with TTL < 60 should be suspicious (TTL volatility)")
	}

	// Normal domain with high TTL and few IPs
	detector3 := NewC2Detector(cfg)
	detector3.TrackResponse("normal.com", []string{"1.1.1.1"}, 3600)
	if detector3.IsSuspicious("normal.com") {
		t.Error("normal domain with high TTL and few IPs should not be suspicious")
	}

	// Disabled
	detector4 := NewC2Detector(config.C2DetectionConfig{Enabled: false})
	detector4.TrackResponse("evil.com", ips, 10)
	if detector4.IsSuspicious("evil.com") {
		t.Error("disabled C2 detector should not flag anything")
	}
}

func TestC2TrackResponseMultipleCalls(t *testing.T) {
	cfg := config.C2DetectionConfig{
		Enabled:              true,
		TTLVolatilityThreshold: 60,
		MinIPCount:           3,
	}
	detector := NewC2Detector(cfg)

	// Track same domain with different IPs over multiple calls
	detector.TrackResponse("multi.com", []string{"1.1.1.1"}, 300)
	detector.TrackResponse("multi.com", []string{"2.2.2.2"}, 300)
	detector.TrackResponse("multi.com", []string{"3.3.3.3"}, 300)

	if !detector.IsSuspicious("multi.com") {
		t.Error("domain with 3 unique IPs should be suspicious (min_ip_count=3)")
	}
}

