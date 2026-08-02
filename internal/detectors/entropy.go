package detectors

import (
	"math"
	"strings"
	"unicode"

	"github.com/castiel/dns/internal/config"
)

// EntropyDetector detects DNS tunneling by analyzing Shannon entropy
// of subdomain labels. High-entropy long subdomains are indicative of
// encoded data being smuggled through DNS (e.g., base32/hex exfiltration).
type EntropyDetector struct {
	cfg          config.TunnelingDetectionConfig
	cdnWhitelist map[string]bool
}

func NewEntropyDetector(cfg config.TunnelingDetectionConfig) *EntropyDetector {
	wl := make(map[string]bool)
	for _, d := range cfg.CDNWhitelist {
		wl[d] = true
	}
	return &EntropyDetector{cfg: cfg, cdnWhitelist: wl}
}

func (e *EntropyDetector) IsTunneling(domain string) bool {
	if !e.cfg.Enabled {
		return false
	}

	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return false
	}

	// Check CDN whitelist — skip known high-entropy legitimate domains
	suffix := strings.Join(labels[1:], ".")
	if e.cdnWhitelist[suffix] {
		return false
	}

	// Analyze subdomain labels (everything before the apex domain)
	subdomainLabels := labels[:len(labels)-2]
	if len(subdomainLabels) > e.cfg.MaxSubdomainDepth {
		subdomainLabels = subdomainLabels[len(subdomainLabels)-e.cfg.MaxSubdomainDepth:]
	}

	// If there are no subdomain labels (2-label domain like "payload.evil.com"),
	// check the apex label itself for tunneling patterns
	if len(subdomainLabels) == 0 {
		apex := labels[0]
		if len(apex) >= e.cfg.MinLabelLength {
			ent := shannonEntropy(apex)
			if ent > e.cfg.EntropyThreshold {
				return true
			}
			// Check for hex-only or base32-only charset (tunneling signature)
			if isHexOnly(apex) || isBase32Only(apex) {
				return true
			}
		}
		return false
	}

	// Total subdomain length across all labels
	totalSubdomainLen := 0
	for _, label := range subdomainLabels {
		totalSubdomainLen += len(label)
	}

	for _, label := range subdomainLabels {
		if len(label) < e.cfg.MinLabelLength {
			continue
		}
		ent := shannonEntropy(label)
		if ent > e.cfg.EntropyThreshold {
			return true
		}

		// --- Hardening: charset detection ---

		// Hex-only labels (0-9a-f) are a strong tunneling signature
		// DNS tunneling tools like iodine/dns2tcp often use hex encoding
		if isHexOnly(label) && len(label) >= 16 {
			return true
		}

		// Base32-only labels (A-Z2-7) — another common tunneling encoding
		if isBase32Only(label) && len(label) >= 16 {
			return true
		}

		// Very long single label (>50 chars) — tunneling payloads are often huge
		if len(label) > 50 {
			return true
		}
	}

	// Total subdomain length > 100 chars across labels — likely exfiltration
	if totalSubdomainLen > 100 {
		return true
	}

	return false
}

// shannonEntropy calculates the Shannon entropy of a string.
// H = -Σ p(x) * log2(p(x))
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	freq := make(map[rune]int)
	for _, c := range s {
		freq[c]++
	}

	n := float64(len(s))
	var entropy float64
	for _, count := range freq {
		p := float64(count) / n
		entropy -= p * math.Log2(p)
	}

	return entropy
}

// consonantRatio calculates the ratio of consonants to total letters.
// DGA domains often have abnormally high consonant ratios.
func consonantRatio(s string) float64 {
	vowels := "aeiouAEIOU"
	consonantCount := 0
	letterCount := 0

	for _, c := range s {
		if unicode.IsLetter(c) {
			letterCount++
			if !strings.ContainsRune(vowels, c) {
				consonantCount++
			}
		}
	}

	if letterCount == 0 {
		return 0
	}
	return float64(consonantCount) / float64(letterCount)
}

// isHexOnly returns true if the string contains only hexadecimal characters
// (0-9, a-f, A-F). DNS tunneling tools like iodine encode payloads as hex.
func isHexOnly(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// isBase32Only returns true if the string contains only base32 characters
// (A-Z, 2-7). DNS tunneling tools like dns2tcp use base32 encoding.
func isBase32Only(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, c := range s {
		if !((c >= 'A' && c <= 'Z') || (c >= '2' && c <= '7') || (c >= 'a' && c <= 'z')) {
			return false
		}
		// Check lowercase isn't mixed with uppercase base32 (legitimate domains mix case)
	}
	return true
}
