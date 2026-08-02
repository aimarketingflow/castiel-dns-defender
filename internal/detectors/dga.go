package detectors

import (
	"log"
	"strings"
	"sync"

	"github.com/castiel/dns/internal/config"
)

// DGADetector detects Domain Generation Algorithm domains using
// a combination of Shannon entropy, consonant ratio, and n-gram
// frequency analysis.
//
// When an n-gram model is loaded, the detector blends statistical
// n-gram scoring with heuristic scoring for improved accuracy.
// If no model is loaded, it falls back to heuristic-only scoring.
type DGADetector struct {
	cfg          config.DGADetectionConfig
	lastEntropy  float64
	mu           sync.Mutex
	ngramModel   *NgramModel
}

func NewDGADetector(cfg config.DGADetectionConfig) *DGADetector {
	d := &DGADetector{
		cfg: cfg,
	}

	// Load n-gram model if configured
	if cfg.NgramModel != "" {
		model := NewNgramModel(3) // trigrams
		if err := model.TrainFromFile(cfg.NgramModel); err != nil {
			log.Printf("DGA: failed to load n-gram model from %s: %v — using heuristic-only scoring", cfg.NgramModel, err)
		} else {
			d.ngramModel = model
			log.Printf("DGA: n-gram model loaded from %s (%d trigrams)", cfg.NgramModel, model.NgramCount())
		}
	}

	return d
}

// suspiciousTLDs are TLDs commonly abused by DGA families and malware.
var suspiciousTLDs = map[string]bool{
	".tk": true, ".ml": true, ".ga": true, ".cf": true, ".xyz": true,
	".top": true, ".click": true, ".country": true, ".stream": true,
	".download": true, ".loan": true, ".win": true, ".review": true,
	".party": true, ".science": true, ".work": true, ".men": true,
	".gq": true, ".fit": true, ".kim": true, ".racing": true,
}

// knownLegitimateDomains are well-known domains that may have high entropy
// or consonant ratios but should never be flagged as DGA.
var knownLegitimateDomains = map[string]bool{
	"cloudflare": true, "rust-lang": true, "stackoverflow": true,
	"duckduckgo": true, "wikipedia": true, "github": true,
	"google": true, "amazon": true, "microsoft": true,
	"linkedin": true, "instagram": true, "netflix": true,
	"youtube": true, "twitter": true, "reddit": true,
	"discord": true, "spotify": true, "twitch": true,
	"paypal": true, "stripe": true, "shopify": true,
	"wordpress": true, "medium": true, "quora": true,
	"pinterest": true, "dropbox": true, "atlassian": true,
	"nodejs": true, "golang": true, "python": true,
	"mozilla": true, "nginx": true, "kubernetes": true,
	"hashicorp": true, "terraform": true, "prometheus": true,
	"grafana": true, "elasticsearch": true, "ansible": true,
	"jenkins": true, "docker": true,
	"arstechnica": true, "techcrunch": true, "theverge": true,
	"hackerrank": true, "leetcode": true, "codecademy": true,
	"freecodecamp": true, "khanacademy": true, "coursera": true,
	"bankofamerica": true, "americanexpress": true, "mastercard": true,
	"wellscdn": true, "fastly": true, "akamai": true,
}

func (d *DGADetector) IsDGA(domain string) bool {
	if !d.cfg.Enabled {
		return false
	}

	// Extract the effective second-level domain (eSLD)
	// e.g., "xkjhsdf8923jksdf.com" -> "xkjhsdf8923jksdf"
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return false
	}

	apex := labels[0]

	// Skip known legitimate domains — these may have high entropy/consonant
	// ratios but are well-known and should never be flagged as DGA.
	if knownLegitimateDomains[strings.ToLower(apex)] {
		return false
	}
	if len(apex) < d.cfg.MinDomainLength {
		return false
	}

	// Calculate entropy on hyphen-stripped apex — hyphens are common in
	// legitimate domains (rust-lang, well-known) but rare in DGA domains.
	// Including hyphens inflates Shannon entropy and causes false positives.
	entApex := strings.ReplaceAll(apex, "-", "")
	if len(entApex) < d.cfg.MinDomainLength {
		return false
	}
	ent := shannonEntropy(entApex)
	d.mu.Lock()
	d.lastEntropy = ent
	d.mu.Unlock()

	// Calculate consonant ratio
	cr := consonantRatio(apex)

	// Combined heuristic scoring
	score := 0.0

	// High entropy → likely random/generated
	if ent > d.cfg.EntropyThreshold {
		score += 0.4
	}

	// High consonant ratio → many DGA families produce consonant-heavy domains
	if cr > d.cfg.ConsonantRatioThreshold {
		score += 0.3
	}

	// Check for digit-heavy domains (many DGAs embed numbers)
	dr := digitRatio(apex)
	if dr > 0.3 {
		score += 0.15
	}

	// No vowels in a long domain → very suspicious
	if !containsVowel(apex) && len(apex) > 10 {
		score += 0.15
	}

	// --- Hardening: additional heuristics ---

	// Suspicious TLD adds to score
	tld := strings.ToLower("." + labels[len(labels)-1])
	if suspiciousTLDs[tld] {
		score += 0.15
	}

	// Very long apex domain (>20 chars) — DGA families often generate long domains
	if len(apex) > 20 {
		score += 0.1
	} else if len(apex) > 15 {
		score += 0.05
	}

	// High unique character ratio on very long domains — random strings use more of the alphabet
	// Only trigger on domains >15 chars to avoid false positives on legitimate words like "stackoverflow"
	ucr := uniqueCharRatio(apex)
	if ucr > 0.85 && len(apex) >= 16 {
		score += 0.1
	}

	// Repeated character patterns (e.g., "xkjxkjxkj") — some DGA families repeat blocks
	if hasRepeatedPattern(apex) {
		score += 0.1
	}

	// All-digit apex (some DGA families generate numeric domains)
	if dr > 0.6 {
		score += 0.15
	}

	// Fast-path: if entropy is extremely high (>4.0) and domain is long, block immediately
	if ent > 4.0 && len(apex) >= 12 {
		return true
	}

	// If n-gram model is loaded, blend statistical score with heuristics
	if d.ngramModel != nil && d.ngramModel.IsLoaded() {
		ngramScore := d.ngramModel.Score(domain)
		// ngramScore: 1.0 = very natural, 0.0 = very DGA-like
		// Convert to penalty: (1.0 - ngramScore) ranges 0.0 to 1.0
		ngramPenalty := 1.0 - ngramScore

		// Weighted blend: heuristics contribute 60%, n-gram contributes 40%
		// But n-gram can only push a borderline domain over the threshold,
		// not block a domain that heuristics consider clean.
		// If heuristics already say DGA (score >= 0.5), n-gram confirms.
		// If heuristics are borderline (0.3-0.5), n-gram tips the balance.
		// If heuristics are clean (<0.3), require n-gram penalty >= 0.9 to block.
		if score >= 0.5 {
			// Heuristics already flagged it — n-gram is confirmatory
			return true
		}
		blendedScore := score*0.6 + ngramPenalty*0.4
		if blendedScore >= 0.5 {
			return true
		}
		// Strong n-gram signal alone can block if penalty is very high (>0.92)
		// and there's at least some heuristic signal (score >= 0.15)
		if ngramPenalty >= 0.92 && score >= 0.15 {
			return true
		}
		return false
	}

	return score >= 0.5
}

func (d *DGADetector) LastEntropy() float64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.lastEntropy
}

func digitRatio(s string) float64 {
	digits := 0
	for _, c := range s {
		if c >= '0' && c <= '9' {
			digits++
		}
	}
	if len(s) == 0 {
		return 0
	}
	return float64(digits) / float64(len(s))
}

func containsVowel(s string) bool {
	for _, c := range strings.ToLower(s) {
		switch c {
		case 'a', 'e', 'i', 'o', 'u':
			return true
		}
	}
	return false
}

// uniqueCharRatio measures how many distinct characters are used relative
// to the string length. Random/DGA domains tend to have high unique ratios
// (e.g., "xkjhsdf8923jk" uses 11 unique chars out of 14 = 0.79).
// Legitimate words reuse characters more (e.g., "google" = 4/6 = 0.67).
func uniqueCharRatio(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	seen := make(map[rune]bool)
	for _, c := range s {
		seen[c] = true
	}
	return float64(len(seen)) / float64(len(s))
}

// hasRepeatedPattern detects DGA families that generate domains by repeating
// a short block (e.g., "xkjxkjxkj", "abcabcabc"). Checks for 3-5 char blocks
// repeated at least 2 times.
func hasRepeatedPattern(s string) bool {
	if len(s) < 9 {
		return false
	}
	lower := strings.ToLower(s)
	for blockLen := 3; blockLen <= 5; blockLen++ {
		if len(lower) < blockLen*2 {
			continue
		}
		block := lower[:blockLen]
		repeats := 1
		for i := blockLen; i+blockLen <= len(lower); i += blockLen {
			if lower[i:i+blockLen] == block {
				repeats++
			} else {
				break
			}
		}
		if repeats >= 3 {
			return true
		}
	}
	return false
}
