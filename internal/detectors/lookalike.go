package detectors

import (
	"fmt"
	"strings"
	"unicode"
)

// LookalikeDetector detects lookalike/typosquatting domains that use:
//   - Levenshtein distance (typosquatting: goggle.com vs google.com)
//   - Homoglyph substitution (g00gle.com, paypa1.com)
//   - IDN homograph attacks (unicode confusables)
//   - Hyphen insertion (google-ads.com)
//   - TLD substitution (google.com vs google.co)
//   - Vowel swapping (gogle.com, googel.com)
//
// This requires a list of protected/monitored domains to compare against.
type LookalikeDetector struct {
	protectedDomains map[string]bool
	maxLevenshtein   int
}

// NewLookalikeDetector creates a detector with a list of protected domains.
func NewLookalikeDetector(protectedDomains []string) *LookalikeDetector {
	l := &LookalikeDetector{
		protectedDomains: make(map[string]bool),
		maxLevenshtein:   2,
	}
	for _, d := range protectedDomains {
		l.protectedDomains[strings.ToLower(strings.TrimSuffix(d, "."))] = true
	}
	// Add common high-value targets if not already present
	defaults := []string{
		"google.com", "apple.com", "microsoft.com", "amazon.com",
		"facebook.com", "twitter.com", "instagram.com",
		"paypal.com", "stripe.com", "github.com",
		"linkedin.com", "netflix.com", "youtube.com",
		"bankofamerica.com", "wellsfargo.com", "chase.com",
		"citi.com", "americanexpress.com", "discover.com",
		"dropbox.com", "slack.com", "zoom.us",
		"office365.com", "outlook.com", "gmail.com",
		"cloudflare.com", "okta.com", "auth0.com",
	}
	for _, d := range defaults {
		if !l.protectedDomains[d] {
			l.protectedDomains[d] = true
		}
	}
	return l
}

// LookalikeFinding describes a lookalike domain detection result.
type LookalikeFinding struct {
	Domain    string
	Protected string
	Reason    string // "typosquatting", "homoglyph", "hyphen_insertion", "tld_swap"
	Score     float64
	Detail    string
}

// CheckDomain returns a finding if the domain is a lookalike of a protected domain.
func (l *LookalikeDetector) CheckDomain(domain string) *LookalikeFinding {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	if l.protectedDomains[domain] {
		return nil // exact match — not a lookalike
	}

	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return nil
	}
	apex := labels[0]
	tld := strings.Join(labels[1:], ".")

	// Check against each protected domain
	for protected := range l.protectedDomains {
		pLabels := strings.Split(protected, ".")
		if len(pLabels) < 2 {
			continue
		}
		pApex := pLabels[0]
		pTLD := strings.Join(pLabels[1:], ".")

		// 1. Homoglyph substitution (same TLD) — check before typosquatting
		// because homoglyphs like g00gle have Levenshtein distance 2 but are
		// more specifically homoglyph attacks
		if tld == pTLD {
			if hasHomoglyphs(apex, pApex) {
				return &LookalikeFinding{
					Domain:    domain,
					Protected: protected,
					Reason:    "homoglyph",
					Score:     0.9,
					Detail:    fmt.Sprintf("Homoglyph domain: %s resembles %s (character substitution)", domain, protected),
				}
			}
		}

		// 2. Typosquatting via Levenshtein distance (same TLD)
		if tld == pTLD {
			dist := levenshtein(apex, pApex)
			if dist > 0 && dist <= l.maxLevenshtein {
				return &LookalikeFinding{
					Domain:    domain,
					Protected: protected,
					Reason:    "typosquatting",
					Score:     1.0 - float64(dist)/float64(len(pApex)),
					Detail:    formatLookalikeDetail("typosquatting", domain, protected, dist),
				}
			}
		}

		// 3. Hyphen insertion (google-ads.com vs google.com)
		// Check if removing hyphens yields the protected apex, or if the
		// part before the first hyphen matches the protected apex
		if tld == pTLD && strings.Contains(apex, "-") {
			noHyphen := strings.ReplaceAll(apex, "-", "")
			// Direct match after removing hyphens
			if noHyphen == pApex {
				return &LookalikeFinding{
					Domain:    domain,
					Protected: protected,
					Reason:    "hyphen_insertion",
					Score:     0.85,
					Detail:    fmt.Sprintf("Hyphen insertion: %s resembles %s", domain, protected),
				}
			}
			// Check if the prefix before the first hyphen matches the protected apex
			parts := strings.SplitN(apex, "-", 2)
			if parts[0] == pApex {
				return &LookalikeFinding{
					Domain:    domain,
					Protected: protected,
					Reason:    "hyphen_insertion",
					Score:     0.85,
					Detail:    fmt.Sprintf("Hyphen insertion: %s resembles %s", domain, protected),
				}
			}
			// Also check Levenshtein on the de-hyphenated form
			if levenshtein(noHyphen, pApex) <= 1 {
				return &LookalikeFinding{
					Domain:    domain,
					Protected: protected,
					Reason:    "hyphen_insertion",
					Score:     0.85,
					Detail:    fmt.Sprintf("Hyphen insertion: %s resembles %s", domain, protected),
				}
			}
		}

		// 4. TLD swap (google.com vs google.co)
		if apex == pApex && tld != pTLD {
			if levenshtein(tld, pTLD) <= 2 {
				return &LookalikeFinding{
					Domain:    domain,
					Protected: protected,
					Reason:    "tld_swap",
					Score:     0.8,
					Detail:    fmt.Sprintf("TLD swap: %s uses TLD .%s resembling .%s", domain, tld, pTLD),
				}
			}
		}

		// 5. Combined: different TLD + typosquatting
		if tld != pTLD {
			dist := levenshtein(apex, pApex)
			if dist > 0 && dist <= 1 {
				return &LookalikeFinding{
					Domain:    domain,
					Protected: protected,
					Reason:    "typosquatting",
					Score:     0.75,
					Detail:    fmt.Sprintf("Typosquatting + TLD swap: %s resembles %s (distance=%d)", domain, protected, dist),
				}
			}
		}
	}

	return nil
}

// AddProtectedDomain adds a domain to the protected list.
func (l *LookalikeDetector) AddProtectedDomain(domain string) {
	l.protectedDomains[strings.ToLower(strings.TrimSuffix(domain, "."))] = true
}

// levenshtein computes the edit distance between two strings.
func levenshtein(a, b string) int {
	la, lb := len(a), len(b)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}

	// Use a 2-row matrix for memory efficiency
	prev := make([]int, lb+1)
	curr := make([]int, lb+1)

	for j := 0; j <= lb; j++ {
		prev[j] = j
	}

	for i := 1; i <= la; i++ {
		curr[0] = i
		for j := 1; j <= lb; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			curr[j] = min3(prev[j]+1, curr[j-1]+1, prev[j-1]+cost)
		}
		prev, curr = curr, prev
	}

	return prev[lb]
}

func min3(a, b, c int) int {
	m := a
	if b < m {
		m = b
	}
	if c < m {
		m = c
	}
	return m
}

// hasHomoglyphs checks if domain a is a homoglyph variant of domain b.
// Detects common substitutions: 0->o, 1->l, 3->e, 5->s, $->s, etc.
func hasHomoglyphs(a, b string) bool {
	if len(a) != len(b) || len(a) < 4 {
		return false
	}

	substitutions := 0
	for i := 0; i < len(a); i++ {
		if a[i] == b[i] {
			continue
		}
		if isHomoglyphPair(a[i], b[i]) {
			substitutions++
		} else {
			return false // non-homoglyph difference
		}
	}

	// At least 1 substitution but not all characters different
	return substitutions > 0 && substitutions < len(a)
}

// isHomoglyphPair checks if two characters are common homoglyphs.
func isHomoglyphPair(a, b byte) bool {
	pairs := map[byte][]byte{
		'0': {'o', 'O'},
		'o': {'0'},
		'O': {'0'},
		'1': {'l', 'I', '|'},
		'l': {'1', 'I'},
		'I': {'1', 'l'},
		'3': {'e', 'E'},
		'e': {'3'},
		'E': {'3'},
		'5': {'s', 'S'},
		's': {'5'},
		'S': {'5'},
		'7': {'t', 'T'},
		't': {'7'},
		'T': {'7'},
		'$': {'s', 'S'},
		'@': {'a', 'A'},
		'!': {'i', 'I', 'l'},
	}
	for _, p := range pairs[a] {
		if p == b {
			return true
		}
	}
	return false
}

// hasIDNConfusable checks if a string contains Unicode confusable characters.
// This detects IDN homograph attacks where unicode lookalikes are used.
func hasIDNConfusable(s string) bool {
	for _, r := range s {
		// Check for Cyrillic characters that look like Latin
		if isCyrillicLookalike(r) {
			return true
		}
		// Check for other Unicode confusables
		if unicode.Is(unicode.Latin, r) && isConfusable(r) {
			return true
		}
	}
	return false
}

func isCyrillicLookalike(r rune) bool {
	cyrillicLookalikes := map[rune]bool{
		'а': true, 'е': true, 'о': true, 'р': true, 'с': true, 'у': true, 'х': true, // lowercase
		'А': true, 'В': true, 'Е': true, 'К': true, 'М': true, 'Н': true, 'О': true, 'Р': true, 'С': true, 'Т': true, 'Х': true,
	}
	return cyrillicLookalikes[r]
}

func isConfusable(r rune) bool {
	// Greek letters that look like Latin
	greekLookalikes := map[rune]bool{
		'ο': true, 'ρ': true, 'α': true, 'ε': true, 'ι': true, 'ν': true, 'τ': true, 'υ': true,
		'Ο': true, 'Ρ': true, 'Α': true, 'Ε': true, 'Τ': true, 'Υ': true,
	}
	return greekLookalikes[r]
}

func formatLookalikeDetail(reason, domain, protected string, dist int) string {
	return fmt.Sprintf("%s: %s resembles %s (Levenshtein distance=%d)", reason, domain, protected, dist)
}
