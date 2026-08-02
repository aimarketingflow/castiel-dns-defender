package detectors

import (
	"testing"

	"github.com/miekg/dns"
)

func TestEDNSInspectNoOPT(t *testing.T) {
	e := NewEDNSInspector()
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)

	finding := e.Inspect(msg, "192.168.1.100")
	if finding != nil {
		t.Errorf("Expected nil finding for message without EDNS0, got %+v", finding)
	}
}

func TestEDNSInspectECSMatch(t *testing.T) {
	e := NewEDNSInspector()
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)

	opt := &dns.OPT{}
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	ecs := &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        1,
		SourceNetmask: 24,
		SourceScope:   0,
		Address:       []byte{192, 168, 1, 0},
	}
	opt.Option = append(opt.Option, ecs)
	msg.Extra = append(msg.Extra, opt)

	// Client IP 192.168.1.100, ECS 192.168.1.0/24 — should match
	finding := e.Inspect(msg, "192.168.1.100")
	if finding != nil {
		t.Errorf("Expected nil finding for matching ECS, got %+v", finding)
	}
}

func TestEDNSInspectECSMismatch(t *testing.T) {
	e := NewEDNSInspector()
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)

	opt := &dns.OPT{}
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	ecs := &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        1,
		SourceNetmask: 24,
		SourceScope:   0,
		Address:       []byte{10, 0, 0, 0},
	}
	opt.Option = append(opt.Option, ecs)
	msg.Extra = append(msg.Extra, opt)

	// Client IP 192.168.1.100, ECS 10.0.0.0/24 — mismatch
	finding := e.Inspect(msg, "192.168.1.100")
	if finding == nil {
		t.Error("Expected finding for ECS mismatch, got nil")
	}
	if finding.Type != "ecs_mismatch" {
		t.Errorf("Expected ecs_mismatch, got %s", finding.Type)
	}
}

func TestEDNSInspectOversizedCookie(t *testing.T) {
	e := NewEDNSInspector()
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)

	opt := &dns.OPT{}
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	cookie := &dns.EDNS0_COOKIE{
		Code:   dns.EDNS0COOKIE,
		Cookie: "0123456789abcdef0123456789abcdef", // 32 bytes — way too large
	}
	opt.Option = append(opt.Option, cookie)
	msg.Extra = append(msg.Extra, opt)

	finding := e.Inspect(msg, "192.168.1.100")
	if finding == nil {
		t.Error("Expected finding for oversized cookie, got nil")
	}
	if finding.Type != "oversized_cookie" {
		t.Errorf("Expected oversized_cookie, got %s", finding.Type)
	}
}

func TestEDNSInspectNormalCookie(t *testing.T) {
	e := NewEDNSInspector()
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)

	opt := &dns.OPT{}
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	cookie := &dns.EDNS0_COOKIE{
		Code:   dns.EDNS0COOKIE,
		Cookie: "01234567", // 8 bytes — normal
	}
	opt.Option = append(opt.Option, cookie)
	msg.Extra = append(msg.Extra, opt)

	finding := e.Inspect(msg, "192.168.1.100")
	if finding != nil {
		t.Errorf("Expected nil for normal cookie, got %+v", finding)
	}
}

func TestEDNSInspectUnknownOption(t *testing.T) {
	e := NewEDNSInspector()
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)

	opt := &dns.OPT{}
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	// Use a custom/unknown option code (65000)
	unknown := &dns.EDNS0_LOCAL{
		Code: 65000,
		Data: []byte("sensitive data exfil"),
	}
	opt.Option = append(opt.Option, unknown)
	msg.Extra = append(msg.Extra, opt)

	finding := e.Inspect(msg, "192.168.1.100")
	if finding == nil {
		t.Error("Expected finding for unknown EDNS0 option, got nil")
	}
	if finding.Type != "unknown_option" {
		t.Errorf("Expected unknown_option, got %s", finding.Type)
	}
}

func TestStripEDNSOptions(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)

	opt := &dns.OPT{}
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	ecs := &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        1,
		SourceNetmask: 24,
		Address:       []byte{10, 0, 0, 0},
	}
	cookie := &dns.EDNS0_COOKIE{
		Code:   dns.EDNS0COOKIE,
		Cookie: "01234567",
	}
	opt.Option = append(opt.Option, ecs, cookie)
	msg.Extra = append(msg.Extra, opt)

	StripEDNSOptions(msg)

	resultOpt := msg.IsEdns0()
	if resultOpt == nil {
		t.Fatal("OPT record should still exist after strip")
	}
	for _, o := range resultOpt.Option {
		if _, ok := o.(*dns.EDNS0_SUBNET); ok {
			t.Error("ECS option should have been stripped")
		}
	}
}

func TestExtractApexDomain(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"example.com", "example.com"},
		{"a.b.example.com", "example.com"},
		{"sub.domain.co.uk", "domain.co.uk"},
		{"deep.sub.domain.co.uk", "domain.co.uk"},
		{"x.y.z.example.org", "example.org"},
		{"single", "single"},
		{"a.b.c.d.e.f.com", "f.com"},
	}

	for _, tt := range tests {
		got := ExtractApexDomain(tt.input)
		if got != tt.expected {
			t.Errorf("ExtractApexDomain(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestIsKnownEDNSOption(t *testing.T) {
	known := []uint16{3, 8, 10, 12, 15}
	for _, code := range known {
		if !isKnownEDNSOption(code) {
			t.Errorf("Option code %d should be known", code)
		}
	}
	unknown := []uint16{0, 100, 500, 65000}
	for _, code := range unknown {
		if isKnownEDNSOption(code) {
			t.Errorf("Option code %d should be unknown", code)
		}
	}
}
