package detectors

import (
	"testing"

	"github.com/miekg/dns"
)

func TestValidateResponseValid(t *testing.T) {
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	query.Id = 12345

	resp := new(dns.Msg)
	resp.SetReply(query)
	resp.Id = 12345
	rr, _ := dns.NewRR("example.com. 300 IN A 93.184.216.34")
	resp.Answer = append(resp.Answer, rr)

	if err := ValidateResponse(resp, query); err != nil {
		t.Errorf("Valid response failed validation: %v", err)
	}
}

func TestValidateResponseIDMismatch(t *testing.T) {
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	query.Id = 12345

	resp := new(dns.Msg)
	resp.SetReply(query)
	resp.Id = 65534 // mismatched ID

	err := ValidateResponse(resp, query)
	if err == nil {
		t.Error("Expected error for mismatched ID")
	}
}

func TestValidateResponseQuestionMismatch(t *testing.T) {
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	query.Id = 12345

	resp := new(dns.Msg)
	resp.SetReply(query)
	resp.Id = 12345
	// Replace question with different domain
	resp.Question[0] = dns.Question{Name: "evil.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}

	err := ValidateResponse(resp, query)
	if err == nil {
		t.Error("Expected error for question mismatch")
	}
}

func TestValidateResponseNXDOMAINWithSOA(t *testing.T) {
	query := new(dns.Msg)
	query.SetQuestion("nonexistent.example.com.", dns.TypeA)
	query.Id = 12345

	resp := new(dns.Msg)
	resp.SetReply(query)
	resp.Id = 12345
	resp.Rcode = dns.RcodeNameError
	rr, _ := dns.NewRR("example.com. 300 IN SOA ns.example.com. admin.example.com. 1 7200 3600 1209600 3600")
	resp.Answer = append(resp.Answer, rr)

	if err := ValidateResponse(resp, query); err != nil {
		t.Errorf("NXDOMAIN with SOA should pass: %v", err)
	}
}

func TestValidateResponseNXDOMAINWithARecord(t *testing.T) {
	query := new(dns.Msg)
	query.SetQuestion("nonexistent.example.com.", dns.TypeA)
	query.Id = 12345

	resp := new(dns.Msg)
	resp.SetReply(query)
	resp.Id = 12345
	resp.Rcode = dns.RcodeNameError
	rr, _ := dns.NewRR("evil.com. 300 IN A 10.0.0.1")
	resp.Answer = append(resp.Answer, rr)

	err := ValidateResponse(resp, query)
	if err == nil {
		t.Error("NXDOMAIN with non-SOA answer should fail validation")
	}
}

func TestValidateResponseOutOfBailiwick(t *testing.T) {
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	query.Id = 12345

	resp := new(dns.Msg)
	resp.SetReply(query)
	resp.Id = 12345
	// Answer record for a completely different domain
	rr, _ := dns.NewRR("evil.com. 300 IN A 10.0.0.1")
	resp.Answer = append(resp.Answer, rr)

	err := ValidateResponse(resp, query)
	if err == nil {
		t.Error("Out-of-bailiwick answer should fail validation")
	}
}

func TestValidateResponseCNAMEChain(t *testing.T) {
	query := new(dns.Msg)
	query.SetQuestion("www.example.com.", dns.TypeA)
	query.Id = 12345

	resp := new(dns.Msg)
	resp.SetReply(query)
	resp.Id = 12345
	cname, _ := dns.NewRR("www.example.com. 300 IN CNAME example.com.")
	a, _ := dns.NewRR("example.com. 300 IN A 93.184.216.34")
	resp.Answer = append(resp.Answer, cname, a)

	if err := ValidateResponse(resp, query); err != nil {
		t.Errorf("CNAME chain should pass validation: %v", err)
	}
}

func TestValidateResponseNilResponse(t *testing.T) {
	err := ValidateResponse(nil, nil)
	if err == nil {
		t.Error("Nil response should fail validation")
	}
}

func TestValidateResponseInvalidRcode(t *testing.T) {
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	query.Id = 12345

	resp := new(dns.Msg)
	resp.SetReply(query)
	resp.Id = 12345
	resp.Rcode = 99 // invalid rcode

	err := ValidateResponse(resp, query)
	if err == nil {
		t.Error("Invalid rcode should fail validation")
	}
}

func TestIsSubdomainOf(t *testing.T) {
	tests := []struct {
		domain string
		parent string
		want   bool
	}{
		{"a.b.example.com", "example.com", true},
		{"example.com", "example.com", true},
		{"example.com", "example.org", false},
		{"notexample.com", "example.com", false},
		{"sub.example.com", "example.com", true},
	}

	for _, tt := range tests {
		got := isSubdomainOf(tt.domain, tt.parent)
		if got != tt.want {
			t.Errorf("isSubdomainOf(%q, %q) = %v, want %v", tt.domain, tt.parent, got, tt.want)
		}
	}
}
