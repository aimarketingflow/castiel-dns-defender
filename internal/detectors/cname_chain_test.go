package detectors

import (
	"testing"

	"github.com/miekg/dns"
)

func TestCNAMEChainNoCNAME(t *testing.T) {
	v := NewCNAMEChainValidator(10)

	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	resp := new(dns.Msg)
	resp.SetReply(query)
	rr, _ := dns.NewRR("example.com. 300 IN A 93.184.216.34")
	resp.Answer = append(resp.Answer, rr)

	finding := v.ValidateChain(resp, "example.com")
	if finding != nil {
		t.Errorf("Expected nil for response without CNAME, got %+v", finding)
	}
}

func TestCNAMEChainValid(t *testing.T) {
	v := NewCNAMEChainValidator(10)

	query := new(dns.Msg)
	query.SetQuestion("www.example.com.", dns.TypeA)
	resp := new(dns.Msg)
	resp.SetReply(query)
	cname, _ := dns.NewRR("www.example.com. 300 IN CNAME example.com.")
	a, _ := dns.NewRR("example.com. 300 IN A 93.184.216.34")
	resp.Answer = append(resp.Answer, cname, a)

	finding := v.ValidateChain(resp, "www.example.com")
	if finding != nil {
		t.Errorf("Valid CNAME chain should not produce finding, got %+v", finding)
	}
}

func TestCNAMEChainLoop(t *testing.T) {
	v := NewCNAMEChainValidator(10)

	query := new(dns.Msg)
	query.SetQuestion("a.example.com.", dns.TypeA)
	resp := new(dns.Msg)
	resp.SetReply(query)
	// Create a CNAME loop: a -> b -> a
	cname1, _ := dns.NewRR("a.example.com. 300 IN CNAME b.example.com.")
	cname2, _ := dns.NewRR("b.example.com. 300 IN CNAME a.example.com.")
	resp.Answer = append(resp.Answer, cname1, cname2)

	finding := v.ValidateChain(resp, "a.example.com")
	if finding == nil {
		t.Fatal("Expected loop finding")
	}
	if finding.Type != "loop" {
		t.Errorf("Expected type 'loop', got %s", finding.Type)
	}
}

func TestCNAMEChainExcessiveDepth(t *testing.T) {
	v := NewCNAMEChainValidator(3) // low max depth

	query := new(dns.Msg)
	query.SetQuestion("a.example.com.", dns.TypeA)
	resp := new(dns.Msg)
	resp.SetReply(query)

	// Create a chain: a -> b -> c -> d -> e (4 hops, exceeds max of 3)
	chain := []string{"a", "b", "c", "d", "e"}
	for i := 0; i < len(chain)-1; i++ {
		rr, _ := dns.NewRR(chain[i] + ".example.com. 300 IN CNAME " + chain[i+1] + ".example.com.")
		resp.Answer = append(resp.Answer, rr)
	}

	finding := v.ValidateChain(resp, "a.example.com")
	if finding == nil {
		t.Fatal("Expected excessive_depth finding")
	}
	if finding.Type != "excessive_depth" {
		t.Errorf("Expected type 'excessive_depth', got %s", finding.Type)
	}
}

func TestCNAMEChainDangling(t *testing.T) {
	v := NewCNAMEChainValidator(10)

	query := new(dns.Msg)
	query.SetQuestion("www.example.com.", dns.TypeA)
	resp := new(dns.Msg)
	resp.SetReply(query)
	resp.Rcode = dns.RcodeNameError
	cname, _ := dns.NewRR("www.example.com. 300 IN CNAME dead.example.com.")
	resp.Answer = append(resp.Answer, cname)

	finding := v.ValidateChain(resp, "www.example.com")
	if finding == nil {
		t.Fatal("Expected dangling finding")
	}
	if finding.Type != "dangling" {
		t.Errorf("Expected type 'dangling', got %s", finding.Type)
	}
}
