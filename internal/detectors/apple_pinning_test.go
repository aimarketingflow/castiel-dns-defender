package detectors

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

func TestApplePinningDetector_AllowsAppleIPs(t *testing.T) {
	d := NewApplePinningDetector(ApplePinningConfig{Enabled: true})

	// Apple's 17.x.x.x range should be allowed
	resp := &dns.Msg{
		Question: []dns.Question{{Name: "ocsp.apple.com.", Qtype: dns.TypeA}},
		Answer: []dns.RR{
			&dns.A{Hdr: dns.RR_Header{Name: "ocsp.apple.com.", Rrtype: dns.TypeA}, A: net.ParseIP("17.253.144.10")},
		},
	}

	finding := d.CheckResponse(resp)
	if finding != nil {
		t.Errorf("Expected no finding for Apple IP 17.253.144.10, got: %+v", finding)
	}
}

func TestApplePinningDetector_AllowsAkamaiCDN(t *testing.T) {
	d := NewApplePinningDetector(ApplePinningConfig{Enabled: true})

	// Akamai CDN range (23.x.x.x) should be allowed
	resp := &dns.Msg{
		Question: []dns.Question{{Name: "mesu.apple.com.", Qtype: dns.TypeA}},
		Answer: []dns.RR{
			&dns.A{Hdr: dns.RR_Header{Name: "mesu.apple.com.", Rrtype: dns.TypeA}, A: net.ParseIP("23.45.67.89")},
		},
	}

	finding := d.CheckResponse(resp)
	if finding != nil {
		t.Errorf("Expected no finding for Akamai IP 23.45.67.89, got: %+v", finding)
	}
}

func TestApplePinningDetector_DetectsAttackerPublicIP(t *testing.T) {
	d := NewApplePinningDetector(ApplePinningConfig{Enabled: true})

	// Attacker-controlled public IP (not in any Apple/CDN range)
	resp := &dns.Msg{
		Question: []dns.Question{{Name: "ocsp.apple.com.", Qtype: dns.TypeA}},
		Answer: []dns.RR{
			&dns.A{Hdr: dns.RR_Header{Name: "ocsp.apple.com.", Rrtype: dns.TypeA}, A: net.ParseIP("203.0.113.50")},
		},
	}

	finding := d.CheckResponse(resp)
	if finding == nil {
		t.Fatal("Expected pin violation for attacker IP 203.0.113.50, got nil")
	}
	if finding.IP != "203.0.113.50" {
		t.Errorf("Expected IP=203.0.113.50, got %s", finding.IP)
	}
	if finding.Domain != "ocsp.apple.com" {
		t.Errorf("Expected domain=ocsp.apple.com, got %s", finding.Domain)
	}
	if finding.Reason != "asn_pin_violation" {
		t.Errorf("Expected reason=asn_pin_violation, got %s", finding.Reason)
	}
}

func TestApplePinningDetector_IgnoresNonWatchedDomains(t *testing.T) {
	d := NewApplePinningDetector(ApplePinningConfig{Enabled: true})

	// Random domain not in watchlist should not trigger
	resp := &dns.Msg{
		Question: []dns.Question{{Name: "example.com.", Qtype: dns.TypeA}},
		Answer: []dns.RR{
			&dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA}, A: net.ParseIP("203.0.113.50")},
		},
	}

	finding := d.CheckResponse(resp)
	if finding != nil {
		t.Errorf("Expected no finding for non-watched domain, got: %+v", finding)
	}
}

func TestApplePinningDetector_SkipsPrivateIPs(t *testing.T) {
	d := NewApplePinningDetector(ApplePinningConfig{Enabled: true})

	// Private IPs are handled by rebinding detector, pinning should skip them
	resp := &dns.Msg{
		Question: []dns.Question{{Name: "ocsp.apple.com.", Qtype: dns.TypeA}},
		Answer: []dns.RR{
			&dns.A{Hdr: dns.RR_Header{Name: "ocsp.apple.com.", Rrtype: dns.TypeA}, A: net.ParseIP("192.168.0.0")},
		},
	}

	finding := d.CheckResponse(resp)
	if finding != nil {
		t.Errorf("Expected no finding for private IP (handled by rebinding), got: %+v", finding)
	}
}

func TestApplePinningDetector_DisabledReturnsNil(t *testing.T) {
	d := NewApplePinningDetector(ApplePinningConfig{Enabled: false})

	resp := &dns.Msg{
		Question: []dns.Question{{Name: "ocsp.apple.com.", Qtype: dns.TypeA}},
		Answer: []dns.RR{
			&dns.A{Hdr: dns.RR_Header{Name: "ocsp.apple.com.", Rrtype: dns.TypeA}, A: net.ParseIP("203.0.113.50")},
		},
	}

	finding := d.CheckResponse(resp)
	if finding != nil {
		t.Errorf("Expected nil when detector disabled, got: %+v", finding)
	}
}

func TestApplePinningDetector_SubdomainMatching(t *testing.T) {
	d := NewApplePinningDetector(ApplePinningConfig{Enabled: true})

	// Subdomain of apple.com should be caught via suffix matching
	resp := &dns.Msg{
		Question: []dns.Question{{Name: "some-new-service.apple.com.", Qtype: dns.TypeA}},
		Answer: []dns.RR{
			&dns.A{Hdr: dns.RR_Header{Name: "some-new-service.apple.com.", Rrtype: dns.TypeA}, A: net.ParseIP("203.0.113.99")},
		},
	}

	finding := d.CheckResponse(resp)
	if finding == nil {
		t.Fatal("Expected pin violation for subdomain of apple.com with attacker IP")
	}
	if finding.Domain != "some-new-service.apple.com" {
		t.Errorf("Expected domain=some-new-service.apple.com, got %s", finding.Domain)
	}
}

func TestApplePinningDetector_CloudflareRange(t *testing.T) {
	d := NewApplePinningDetector(ApplePinningConfig{Enabled: true})

	// Cloudflare range (used by some Apple services)
	resp := &dns.Msg{
		Question: []dns.Question{{Name: "captive.apple.com.", Qtype: dns.TypeA}},
		Answer: []dns.RR{
			&dns.A{Hdr: dns.RR_Header{Name: "captive.apple.com.", Rrtype: dns.TypeA}, A: net.ParseIP("104.16.200.5")},
		},
	}

	finding := d.CheckResponse(resp)
	if finding != nil {
		t.Errorf("Expected no finding for Cloudflare IP 104.16.200.5, got: %+v", finding)
	}
}
