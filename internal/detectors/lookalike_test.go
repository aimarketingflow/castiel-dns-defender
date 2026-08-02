package detectors

import (
	"testing"
)

func TestDictionaryDGASimple(t *testing.T) {
	d := NewDictionaryDGADetector()

	// "sunmoon.com" = "sun" + "moon" — dictionary DGA
	if !d.IsDictionaryDGA("sunmoon.com") {
		t.Error("Expected sunmoon.com to be detected as dictionary DGA")
	}
}

func TestDictionaryDGAThreeWords(t *testing.T) {
	d := NewDictionaryDGADetector()

	// "sunmoonstar.com" = "sun" + "moon" + "star" — 3 words, highly suspicious
	if !d.IsDictionaryDGA("sunmoonstar.com") {
		t.Error("Expected sunmoonstar.com to be detected as dictionary DGA")
	}
}

func TestDictionaryDGANotDGA(t *testing.T) {
	d := NewDictionaryDGADetector()

	// "google.com" is a known legitimate domain
	if d.IsDictionaryDGA("google.com") {
		t.Error("google.com should not be flagged as dictionary DGA")
	}

	// Random string that doesn't split into words
	if d.IsDictionaryDGA("xkjhsdf8923jksdf.com") {
		t.Error("Random string should not be flagged as dictionary DGA")
	}
}

func TestDictionaryDGAShortDomain(t *testing.T) {
	d := NewDictionaryDGADetector()

	// Too short for 2+ word concatenation
	if d.IsDictionaryDGA("ab.com") {
		t.Error("Short domain should not be flagged as dictionary DGA")
	}
}

func TestDictionaryDGACompoundWord(t *testing.T) {
	d := NewDictionaryDGADetector()

	// "sunshine" = "sun" + "shine" — but "sunshine" is in our word list as a compound
	// Should NOT be flagged because the combined form is a known word
	if d.IsDictionaryDGA("sunshine.com") {
		t.Error("sunshine.com is a compound word, should not be flagged")
	}
}

func TestLevenshteinDistance(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"google", "google", 0},
		{"google", "goggle", 1},
		{"google", "gogle", 1},
		{"google", "googel", 2},
		{"", "abc", 3},
		{"abc", "", 3},
	}

	for _, tt := range tests {
		got := levenshtein(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("levenshtein(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestHasHomoglyphs(t *testing.T) {
	// g00gle -> google: 0->o, 0->o (2 homoglyph substitutions)
	if !hasHomoglyphs("g00gle", "google") {
		t.Error("g00gle should be detected as homoglyph of google")
	}

	// paypal -> paypal: no substitution
	if hasHomoglyphs("paypal", "paypal") {
		t.Error("paypal vs paypal should not be homoglyph (identical)")
	}

	// paypa1 -> paypal: l->1 (1 homoglyph)
	if !hasHomoglyphs("paypa1", "paypal") {
		t.Error("paypa1 should be detected as homoglyph of paypal")
	}
}

func TestLookalikeTyposquatting(t *testing.T) {
	l := NewLookalikeDetector(nil)

	// "goggle.com" is 1 edit from "google.com"
	finding := l.CheckDomain("goggle.com")
	if finding == nil {
		t.Fatal("Expected typosquatting finding for goggle.com")
	}
	if finding.Reason != "typosquatting" {
		t.Errorf("Expected reason 'typosquatting', got %s", finding.Reason)
	}
	if finding.Protected != "google.com" {
		t.Errorf("Expected protected domain 'google.com', got %s", finding.Protected)
	}
}

func TestLookalikeHomoglyph(t *testing.T) {
	l := NewLookalikeDetector(nil)

	finding := l.CheckDomain("g00gle.com")
	if finding == nil {
		t.Fatal("Expected homoglyph finding for g00gle.com")
	}
	if finding.Reason != "homoglyph" {
		t.Errorf("Expected reason 'homoglyph', got %s", finding.Reason)
	}
}

func TestLookalikeHyphenInsertion(t *testing.T) {
	l := NewLookalikeDetector(nil)

	finding := l.CheckDomain("google-ads.com")
	if finding == nil {
		t.Fatal("Expected hyphen_insertion finding for google-ads.com")
	}
	if finding.Reason != "hyphen_insertion" {
		t.Errorf("Expected reason 'hyphen_insertion', got %s", finding.Reason)
	}
}

func TestLookalikeTLDSwap(t *testing.T) {
	l := NewLookalikeDetector(nil)

	finding := l.CheckDomain("google.co")
	if finding == nil {
		t.Fatal("Expected tld_swap finding for google.co")
	}
	if finding.Reason != "tld_swap" {
		t.Errorf("Expected reason 'tld_swap', got %s", finding.Reason)
	}
}

func TestLookalikeExactMatch(t *testing.T) {
	l := NewLookalikeDetector(nil)

	// Exact match should not be flagged
	finding := l.CheckDomain("google.com")
	if finding != nil {
		t.Error("Exact match should not be flagged as lookalike")
	}
}

func TestLookalikeUnrelated(t *testing.T) {
	l := NewLookalikeDetector(nil)

	finding := l.CheckDomain("random-unrelated-domain.com")
	if finding != nil {
		t.Error("Unrelated domain should not be flagged as lookalike")
	}
}

func TestLookalikeAddProtectedDomain(t *testing.T) {
	l := NewLookalikeDetector(nil)
	l.AddProtectedDomain("mycompany.com")

	finding := l.CheckDomain("mycompanny.com")
	if finding == nil {
		t.Fatal("Expected typosquatting finding for mycompanny.com")
	}
	if finding.Protected != "mycompany.com" {
		t.Errorf("Expected protected 'mycompany.com', got %s", finding.Protected)
	}
}
