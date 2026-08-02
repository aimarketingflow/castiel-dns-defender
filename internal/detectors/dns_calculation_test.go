package detectors

import (
	"testing"
)

func TestDNSCalculationSequentialOctets(t *testing.T) {
	d := NewDNSCalculationDetector()

	// 1.2.3.4 — sequential octets
	finding := d.AnalyzeResponse("evil.com", []string{"1.2.3.4"}, true)
	if finding == nil {
		t.Fatal("Expected finding for sequential octets")
	}
	if finding.Reason != "sequential_octets" {
		t.Errorf("Expected reason 'sequential_octets', got %s", finding.Reason)
	}
}

func TestDNSCalculationArithmeticSequence(t *testing.T) {
	d := NewDNSCalculationDetector()

	// 10.20.30.40 — arithmetic sequence with diff=10
	finding := d.AnalyzeResponse("c2.evil.com", []string{"10.20.30.40"}, true)
	if finding == nil {
		t.Fatal("Expected finding for arithmetic sequence")
	}
	if finding.Reason != "sequential_octets" {
		t.Errorf("Expected reason 'sequential_octets', got %s", finding.Reason)
	}
}

func TestDNSCalculationNonRoutableForPublic(t *testing.T) {
	d := NewDNSCalculationDetector()

	finding := d.AnalyzeResponse("public.com", []string{"10.0.0.1"}, true)
	if finding == nil {
		t.Fatal("Expected finding for non-routable IP on public domain")
	}
	if finding.Reason != "non_routable_public" {
		t.Errorf("Expected reason 'non_routable_public', got %s", finding.Reason)
	}
}

func TestDNSCalculationNormalIP(t *testing.T) {
	d := NewDNSCalculationDetector()

	// Normal public IP — should not trigger
	finding := d.AnalyzeResponse("example.com", []string{"93.184.216.34"}, true)
	if finding != nil {
		t.Errorf("Normal IP should not trigger, got %+v", finding)
	}
}

func TestDNSCalculationNoIPs(t *testing.T) {
	d := NewDNSCalculationDetector()

	finding := d.AnalyzeResponse("evil.com", []string{}, true)
	if finding != nil {
		t.Error("Expected nil for no IPs")
	}
}

func TestDNSCalculationLoopbackFirstOctet(t *testing.T) {
	d := NewDNSCalculationDetector()

	finding := d.AnalyzeResponse("evil.com", []string{"127.0.0.1"}, true)
	if finding == nil {
		t.Fatal("Expected finding for 127.x.x.x on public domain")
	}
	if finding.Reason != "encoded_data" && finding.Reason != "non_routable_public" {
		t.Errorf("Expected encoded_data or non_routable_public, got %s", finding.Reason)
	}
}
