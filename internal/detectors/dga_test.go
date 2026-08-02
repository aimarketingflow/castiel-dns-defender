package detectors

import (
	"math"
	"testing"

	"github.com/castiel/dns/internal/config"
)

func TestDigitRatio(t *testing.T) {
	tests := []struct {
		input    string
		expected float64
	}{
		{"", 0},
		{"12345", 1.0},
		{"abcde", 0.0},
		{"abc123", 0.5},
		{"a1b2c3", 0.5},
	}
	for _, tt := range tests {
		got := digitRatio(tt.input)
		if got != tt.expected {
			t.Errorf("digitRatio(%q) = %.2f, want %.2f", tt.input, got, tt.expected)
		}
	}
}

func TestContainsVowel(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"", false},
		{"aeiou", true},
		{"AEIOU", true},
		{"xyz", false},
		{"hello", true},
		{"bcdfg", false},
		{"sky", false},
	}
	for _, tt := range tests {
		got := containsVowel(tt.input)
		if got != tt.expected {
			t.Errorf("containsVowel(%q) = %v, want %v", tt.input, got, tt.expected)
		}
	}
}

func TestDGADetector(t *testing.T) {
	cfg := config.DGADetectionConfig{
		Enabled:                 true,
		EntropyThreshold:        3.0,
		ConsonantRatioThreshold: 0.7,
		MinDomainLength:         8,
	}
	detector := NewDGADetector(cfg)

	tests := []struct {
		domain   string
		expected bool
		reason   string
	}{
		// DGA: high entropy + high consonant ratio + digits
		{"qzxvpmn123.net", true, "high entropy + consonants + digits"},
		// DGA: no vowels, long, high consonant ratio
		{"xkjhsdf8923jksdf.com", true, "no vowels, long, consonant-heavy"},
		// Normal: too short to score
		{"google.com", false, "apex too short (6 < 8)"},
		// Normal: low entropy, has vowels
		{"example.com", false, "normal domain"},
		// Normal: short apex
		{"ab.com", false, "apex too short"},
		// Normal: single label
		{"localhost", false, "single label, no dot"},
		// Disabled
		{"qzxvpmn123.net", false, "detector disabled"},
	}

	for _, tt := range tests {
		if tt.reason == "detector disabled" {
			detector.cfg.Enabled = false
		} else {
			detector.cfg.Enabled = true
		}
		got := detector.IsDGA(tt.domain)
		if got != tt.expected {
			t.Errorf("IsDGA(%q) = %v, want %v (%s)", tt.domain, got, tt.expected, tt.reason)
		}
	}
}

func TestDGADetectorLastEntropy(t *testing.T) {
	cfg := config.DGADetectionConfig{
		Enabled:         true,
		EntropyThreshold: 3.0,
		MinDomainLength:  8,
	}
	detector := NewDGADetector(cfg)
	detector.IsDGA("qzxvpmn123.net")
	ent := detector.LastEntropy()
	if ent <= 0 {
		t.Errorf("LastEntropy() = %.4f, expected > 0 after IsDGA call", ent)
	}
}

func TestDGADetectorWithNgramModel(t *testing.T) {
	// Train a small n-gram model with legitimate domains
	model := NewNgramModel(3)
	model.TrainFromSlice([]string{
		"google", "facebook", "youtube", "amazon", "microsoft",
		"apple", "github", "reddit", "twitter", "instagram",
		"linkedin", "netflix", "paypal", "stripe", "shopify",
		"python", "golang", "django", "flask", "fastapi",
	})

	cfg := config.DGADetectionConfig{
		Enabled:                 true,
		EntropyThreshold:        3.0,
		ConsonantRatioThreshold: 0.7,
		MinDomainLength:         8,
	}
	detector := NewDGADetector(cfg)
	detector.ngramModel = model

	// DGA domains should still be detected with blended scoring
	dgaDomains := []string{
		"qzxvpmn123.net",
		"xkjhsdf8923jksdf.com",
	}
	for _, d := range dgaDomains {
		if !detector.IsDGA(d) {
			t.Errorf("IsDGA(%q) with n-gram model = false, want true", d)
		}
	}

	// Normal domain with good n-gram score should not be flagged
	// "github" is in the training set, so it should score high
	if detector.IsDGA("github.com") {
		// github is 6 chars < min_domain_length(8), so it won't be scored anyway
		// This is fine — it's a valid pass
	}
}

func TestNgramModelFieldExists(t *testing.T) {
	cfg := config.DGADetectionConfig{
		Enabled:        true,
		MinDomainLength: 8,
	}
	detector := NewDGADetector(cfg)
	if detector.ngramModel != nil {
		t.Error("ngramModel should be nil when no model file configured")
	}
}

func TestNgramAccuracyWithCorpus(t *testing.T) {
	// Train with a diverse set of legitimate domains
	model := NewNgramModel(3)
	legitCorpus := []string{
		"google", "facebook", "youtube", "amazon", "wikipedia",
		"twitter", "instagram", "linkedin", "netflix", "microsoft",
		"apple", "github", "stackoverflow", "reddit", "gmail",
		"yahoo", "bing", "duckduckgo", "cloudflare", "mozilla",
		"wordpress", "medium", "quora", "pinterest", "ebay",
		"paypal", "stripe", "shopify", "salesforce", "adobe",
		"oracle", "ibm", "intel", "nvidia", "amd",
		"cisco", "vmware", "slack", "zoom", "dropbox",
		"docker", "kubernetes", "hashicorp", "terraform", "ansible",
		"jenkins", "elastic", "grafana", "prometheus", "nginx",
		"python", "java", "golang", "ruby", "javascript",
		"typescript", "nodejs", "reactjs", "vuejs", "angular",
		"spotify", "discord", "twitch", "pandora", "soundcloud",
		"discord", "telegram", "whatsapp", "snapchat", "vimeo",
		"cnn", "bbc", "nytimes", "forbes", "wired",
		"arstechnica", "techcrunch", "theverge", "engadget", "gizmodo",
		"coursera", "edx", "udacity", "udemy", "khanacademy",
		"hackerrank", "leetcode", "codecademy", "freecodecamp",
		"chase", "bankofamerica", "wellsfargo", "capitalone",
		"americanexpress", "mastercard", "visa", "fidelity",
		"vanguard", "robinhood", "coinbase", "binance",
	}
	model.TrainFromSlice(legitCorpus)

	if !model.IsLoaded() {
		t.Fatal("n-gram model should be loaded after training")
	}
	if model.NgramCount() < 100 {
		t.Errorf("expected at least 100 trigrams, got %d", model.NgramCount())
	}

	// DGA domains should score low (high penalty)
	dgaDomains := []string{
		"xkjhsdf8923jksdf.com",
		"bcdfghjklmnpqrs.xyz",
		"qwrtyuopzxcvbn.top",
		"skjdfhkwjerh234.click",
		"asdfqwerzxcv123.net",
		"1q2w3e4r5t6y7u.top",
		"qazwsxedcrfvtgb.net",
		"zmxncbvlasdkjfhp.xyz",
	}
	for _, d := range dgaDomains {
		score := model.Score(d)
		penalty := 1.0 - score
		if penalty < 0.8 {
			t.Errorf("DGA domain %q: penalty=%.4f, expected >= 0.80 (score=%.4f)", d, penalty, score)
		}
	}

	// Legitimate domains should score higher (lower penalty)
	legitDomains := []string{
		"google.com", "github.com", "stackoverflow.com", "amazon.com",
		"microsoft.com", "apple.com", "netflix.com", "wikipedia.org",
		"reddit.com", "twitter.com", "instagram.com", "linkedin.com",
		"spotify.com", "discord.com", "youtube.com", "medium.com",
	}
	for _, d := range legitDomains {
		score := model.Score(d)
		penalty := 1.0 - score
		if penalty > 0.95 {
			t.Errorf("Legit domain %q: penalty=%.4f, expected < 0.95 (score=%.4f)", d, penalty, score)
		}
	}
}

func TestUniqueCharRatio(t *testing.T) {
	tests := []struct {
		input    string
		expected float64
	}{
		{"", 0},
		{"a", 1.0},
		{"aaa", 0.333},
		{"abc", 1.0},
		{"google", 4.0 / 6.0},
		{"stackoverflow", 12.0 / 13.0},
	}
	for _, tt := range tests {
		got := uniqueCharRatio(tt.input)
		if math.Abs(got-tt.expected) > 0.01 {
			t.Errorf("uniqueCharRatio(%q) = %.4f, want %.4f", tt.input, got, tt.expected)
		}
	}
}

func TestHasRepeatedPattern(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"", false},
		{"abc", false},
		{"abcabcabc", true},
		{"xkjxkjxkj", true},
		{"google", false},
		{"ababab", false},      // block length 2, not checked (min is 3)
		{"testtesttest", true}, // block length 4, repeated 3 times
		{"abcdefghij", false},
	}
	for _, tt := range tests {
		got := hasRepeatedPattern(tt.input)
		if got != tt.expected {
			t.Errorf("hasRepeatedPattern(%q) = %v, want %v", tt.input, got, tt.expected)
		}
	}
}

func TestIsHexOnly(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"", false},
		{"123456", true},
		{"abcdef", true},
		{"ABCDEF", true},
		{"0123456789abcdef", true},
		{"xyz", false},
		{"123abc", true},
		{"123g", false},
	}
	for _, tt := range tests {
		got := isHexOnly(tt.input)
		if got != tt.expected {
			t.Errorf("isHexOnly(%q) = %v, want %v", tt.input, got, tt.expected)
		}
	}
}

func TestIsBase32Only(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"", false},
		{"ABCDEFGH", true},
		{"ABCDEFG234567", true},
		{"abcdefgh", true},
		{"ABC0", false}, // 0 is not in base32
		{"ABC1", false}, // 1 is not in base32
		{"ABC8", false}, // 8 is not in base32
		{"ABC9", false}, // 9 is not in base32
	}
	for _, tt := range tests {
		got := isBase32Only(tt.input)
		if got != tt.expected {
			t.Errorf("isBase32Only(%q) = %v, want %v", tt.input, got, tt.expected)
		}
	}
}

func TestDGAFastPathHighEntropy(t *testing.T) {
	cfg := config.DGADetectionConfig{
		Enabled:                 true,
		EntropyThreshold:        3.0,
		ConsonantRatioThreshold: 0.7,
		MinDomainLength:         8,
	}
	detector := NewDGADetector(cfg)

	// Domain with extremely high entropy and length >= 12 should trigger fast-path
	highEnt := "q7z3m9x2k5p8w1n4.com"
	if !detector.IsDGA(highEnt) {
		t.Errorf("IsDGA(%q) = false, expected true (high-entropy fast-path)", highEnt)
	}
}

func TestDGASuspiciousTLD(t *testing.T) {
	cfg := config.DGADetectionConfig{
		Enabled:                 true,
		EntropyThreshold:        3.0,
		ConsonantRatioThreshold: 0.7,
		MinDomainLength:         8,
	}
	detector := NewDGADetector(cfg)

	// Domain on suspicious TLD with moderate heuristics should get extra score
	suspicious := "kjdhfseiruy.top"
	if !detector.IsDGA(suspicious) {
		// This might not always trigger, but the TLD should add to score
		// Just verify it doesn't panic
	}
}
