package detectors

import (
	"testing"

	"github.com/castiel/dns/internal/config"
)

func TestShannonEntropy(t *testing.T) {
	tests := []struct {
		input    string
		expected float64
		delta    float64
	}{
		{"", 0, 0},
		{"a", 0, 0},
		{"aaaa", 0, 0},
		{"ABCD", 2.0, 0.01},
		{"ab", 1.0, 0.01},
		{"abc", 1.585, 0.01},
	}
	for _, tt := range tests {
		got := shannonEntropy(tt.input)
		if abs(got-tt.expected) > tt.delta {
			t.Errorf("shannonEntropy(%q) = %.4f, want %.4f ± %.4f", tt.input, got, tt.expected, tt.delta)
		}
	}
}

func TestConsonantRatio(t *testing.T) {
	tests := []struct {
		input    string
		expected float64
		delta    float64
	}{
		{"", 0, 0},
		{"aeiou", 0, 0},
		{"bcdfg", 1.0, 0},
		{"google", 0.5, 0},
		{"hello", 0.6, 0.01},
		{"xkjhsdf8923jksdf", 1.0, 0}, // digits excluded from letter count
	}
	for _, tt := range tests {
		got := consonantRatio(tt.input)
		if abs(got-tt.expected) > tt.delta {
			t.Errorf("consonantRatio(%q) = %.4f, want %.4f ± %.4f", tt.input, got, tt.expected, tt.delta)
		}
	}
}

func TestEntropyDetectorTunneling(t *testing.T) {
	cfg := config.TunnelingDetectionConfig{
		Enabled:          true,
		EntropyThreshold: 3.5,
		MinLabelLength:   12,
		MaxSubdomainDepth: 5,
		CDNWhitelist:      []string{"cloudfront.net", "akamai.net"},
	}
	detector := NewEntropyDetector(cfg)

	tests := []struct {
		domain   string
		expected bool
		reason   string
	}{
		// Tunneling: high-entropy long subdomain
		{"MFRA2YTKOJQWY2LT.attacker.com", true, "high entropy subdomain"},
		// Normal: short subdomain
		{"www.google.com", false, "short subdomain"},
		// Normal: apex domain (no subdomain labels)
		{"google.com", false, "no subdomain labels"},
		// Normal: low entropy subdomain
		{"api-staging-2.example.com", false, "low entropy"},
		// CDN whitelist: high entropy but whitelisted
		{"d111111abcdef8.cloudfront.net", false, "CDN whitelisted"},
		// Tunneling: high entropy in deep subdomain
		{"OJQXG5DFONZS2LTNXYZ.evil.net", true, "high entropy deep subdomain"},
		// Disabled
		{"MFRA2YTKOJQWY2LT.attacker.com", false, "detector disabled"},
	}

	for _, tt := range tests {
		if tt.reason == "detector disabled" {
			detector.cfg.Enabled = false
		} else {
			detector.cfg.Enabled = true
		}
		got := detector.IsTunneling(tt.domain)
		if got != tt.expected {
			t.Errorf("IsTunneling(%q) = %v, want %v (%s)", tt.domain, got, tt.expected, tt.reason)
		}
	}
}

func TestEntropyDetectorDisabled(t *testing.T) {
	cfg := config.TunnelingDetectionConfig{Enabled: false}
	detector := NewEntropyDetector(cfg)
	if detector.IsTunneling("MFRA2YTKOJQWY2LT.attacker.com") {
		t.Error("disabled detector should not flag anything")
	}
}

func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}
