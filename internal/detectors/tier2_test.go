package detectors

import (
	"testing"
)

func TestSparseDGABelowThreshold(t *testing.T) {
	s := NewSparseDGADetector(SparseDGAConfig{
		Enabled:          true,
		NXDomainRatio:    0.6,
		MinQueries:       20,
		MinUniqueDomains: 10,
		WindowHours:      24,
	})

	// Record a few queries — not enough to trigger
	for i := 0; i < 10; i++ {
		s.RecordQuery("192.168.1.1", "host"+string(rune('a'+i))+".evil.com", true)
	}

	finding := s.Analyze("192.168.1.1")
	if finding != nil {
		t.Errorf("Should not trigger below threshold, got %+v", finding)
	}
}

func TestSparseDGAAtThreshold(t *testing.T) {
	s := NewSparseDGADetector(SparseDGAConfig{
		Enabled:          true,
		NXDomainRatio:    0.6,
		MinQueries:       10,
		MinUniqueDomains: 5,
		WindowHours:      24,
	})

	// Record 10 NXDOMAIN queries for 10 different domains
	for i := 0; i < 10; i++ {
		domain := "host" + string(rune('a'+i)) + ".evil.com"
		s.RecordQuery("10.0.0.1", domain, true)
	}

	finding := s.Analyze("10.0.0.1")
	if finding == nil {
		t.Fatal("Expected finding at threshold")
	}
	if finding.NXDomainRatio < 0.6 {
		t.Errorf("Expected NXDOMAIN ratio >= 0.6, got %.2f", finding.NXDomainRatio)
	}
}

func TestSparseDGADifferentClients(t *testing.T) {
	s := NewSparseDGADetector(SparseDGAConfig{
		Enabled:          true,
		NXDomainRatio:    0.6,
		MinQueries:       5,
		MinUniqueDomains: 3,
		WindowHours:      24,
	})

	// Client A has lots of NXDOMAINs
	for i := 0; i < 10; i++ {
		s.RecordQuery("10.0.0.1", "host"+string(rune('a'+i))+".evil.com", true)
	}

	// Client B has normal queries
	for i := 0; i < 10; i++ {
		s.RecordQuery("10.0.0.2", "normal"+string(rune('a'+i))+".good.com", false)
	}

	findingA := s.Analyze("10.0.0.1")
	if findingA == nil {
		t.Error("Client A should trigger sparse DGA")
	}

	findingB := s.Analyze("10.0.0.2")
	if findingB != nil {
		t.Error("Client B should not trigger sparse DGA")
	}
}

func TestLowSlowExfilManySubdomains(t *testing.T) {
	l := NewLowSlowExfilDetector()

	// Record 60 unique subdomains under one apex
	for i := 0; i < 60; i++ {
		domain := "data" + string(rune('A'+i%26)) + string(rune('A'+i/26)) + ".exfil.com"
		l.RecordQuery(domain)
	}

	finding := l.Analyze("exfil.com")
	if finding == nil {
		t.Fatal("Expected finding for many subdomains")
	}
	if finding.Reason != "many_subdomains" {
		t.Errorf("Expected reason 'many_subdomains', got %s", finding.Reason)
	}
}

func TestLowSlowExfilNormalDomain(t *testing.T) {
	l := NewLowSlowExfilDetector()

	// Normal domain with few subdomains
	for i := 0; i < 5; i++ {
		l.RecordQuery("www.example.com")
		l.RecordQuery("api.example.com")
	}

	finding := l.Analyze("example.com")
	if finding != nil {
		t.Errorf("Normal domain should not trigger, got %+v", finding)
	}
}

func TestLowSlowExfilHighVolume(t *testing.T) {
	l := NewLowSlowExfilDetector()

	// 600 queries to a single domain with only 3 unique subdomains
	for i := 0; i < 600; i++ {
		l.RecordQuery("beacon.evil.com")
	}

	finding := l.Analyze("evil.com")
	if finding == nil {
		t.Fatal("Expected finding for high volume")
	}
	if finding.Reason != "high_volume" {
		t.Errorf("Expected reason 'high_volume', got %s", finding.Reason)
	}
}
