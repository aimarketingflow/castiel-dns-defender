package detectors

import (
	"bufio"
	"math"
	"os"
	"strings"
	"sync"
)

// NgramModel stores n-gram frequency counts from a corpus of legitimate
// domain names. It uses these counts to compute a probability score for
// any given domain — DGA-generated domains typically have low n-gram
// probabilities because they contain random character sequences not found
// in real domain names.
//
// The model supports configurable n-gram size (typically 3) and uses
// Laplace (add-1) smoothing to handle unseen n-grams.
type NgramModel struct {
	n           int
	ngramCounts map[string]int   // n-gram → count
	totalCount  int               // sum of all n-gram counts
	uniCounts   map[string]int   // unigram counts for first char of n-gram
	mu          sync.RWMutex
	loaded      bool
}

// NewNgramModel creates a new n-gram model with the given n value.
// n=3 (trigrams) is the recommended default.
func NewNgramModel(n int) *NgramModel {
	if n < 2 {
		n = 2
	}
	return &NgramModel{
		n:           n,
		ngramCounts: make(map[string]int),
		uniCounts:   make(map[string]int),
	}
}

// TrainFromFile trains the model from a file containing one domain per line.
// Lines starting with # or empty lines are skipped.
// The domain's apex (first label before the TLD) is used for n-gram extraction.
func (m *NgramModel) TrainFromFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	m.mu.Lock()
	defer m.mu.Unlock()

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Extract the apex (first label, works for both "google.com" and "google")
		labels := strings.Split(strings.ToLower(line), ".")
		if len(labels) < 1 {
			continue
		}
		apex := labels[0]
		if len(apex) < 3 {
			continue
		}

		// Pad with start/end markers
		padded := "^" + apex + "$"
		m.extractNgrams(padded)
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	m.loaded = true
	return nil
}

// TrainFromSlice trains the model from a slice of domain names.
// Accepts either full domains ("google.com") or bare apex names ("google").
func (m *NgramModel) TrainFromSlice(domains []string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, domain := range domains {
		domain = strings.ToLower(strings.TrimSpace(domain))
		if domain == "" {
			continue
		}
		labels := strings.Split(domain, ".")
		// Use the first label as the apex (works for both "google.com" and "google")
		apex := labels[0]
		if len(apex) < 3 {
			continue
		}
		padded := "^" + apex + "$"
		m.extractNgrams(padded)
	}
	m.loaded = true
}

// extractNgrams extracts and counts n-grams from a padded string.
// Must be called with m.mu held.
func (m *NgramModel) extractNgrams(s string) {
	if len(s) < m.n {
		return
	}
	for i := 0; i <= len(s)-m.n; i++ {
		ngram := s[i : i+m.n]
		m.ngramCounts[ngram]++
		m.totalCount++

		// Track unigram count for the first character of this n-gram
		// (used as denominator in conditional probability)
		firstChar := string(s[i])
		m.uniCounts[firstChar]++
	}
}

// Score returns a probability score for a domain's apex.
// Higher scores indicate more "natural" (legitimate) domains.
// Lower scores (< threshold) indicate likely DGA domains.
//
// The score is the average log probability of all n-grams in the domain,
// normalized to a 0-1 range using a sigmoid function.
func (m *NgramModel) Score(domain string) float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if !m.loaded || m.totalCount == 0 {
		// Model not trained — return neutral score (0.5)
		return 0.5
	}

	labels := strings.Split(strings.ToLower(domain), ".")
	if len(labels) < 1 {
		return 0.5
	}
	apex := labels[0] // Works for both "google.com" and "google"
	if len(apex) < 3 {
		return 0.5
	}

	padded := "^" + apex + "$"
	if len(padded) < m.n {
		return 0.5
	}

	var logProbSum float64
	ngramCount := 0

	for i := 0; i <= len(padded)-m.n; i++ {
		ngram := padded[i : i+m.n]
		firstChar := string(padded[i])

		// Laplace smoothing: P(ngram) = (count(ngram) + 1) / (count(firstChar) + V)
		// where V is the vocabulary size (number of unique first chars)
		count := m.ngramCounts[ngram]
		denom := m.uniCounts[firstChar]
		if denom == 0 {
			denom = m.totalCount
		}

		// V = number of possible characters (a-z, 0-9, ^, $) ≈ 38
		V := 38.0
		prob := (float64(count) + 1.0) / (float64(denom) + V)

		logProbSum += math.Log(prob)
		ngramCount++
	}

	if ngramCount == 0 {
		return 0.5
	}

	// Average log probability
	avgLogProb := logProbSum / float64(ngramCount)

	// Convert to 0-1 score using sigmoid
	// With a 1000+ domain corpus:
	//   Legitimate domains: avgLogProb ~ -2.0 to -3.0 → score 0.27–0.62
	//   DGA domains:        avgLogProb ~ -4.0 to -6.0 → score 0.04–0.18
	// Sigmoid centered at -2.5 maximizes separation
	score := 1.0 / (1.0 + math.Exp(-(avgLogProb+2.5)))

	return score
}

// IsLoaded returns whether the model has been trained.
func (m *NgramModel) IsLoaded() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.loaded
}

// NgramCount returns the number of unique n-grams in the model.
func (m *NgramModel) NgramCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.ngramCounts)
}
