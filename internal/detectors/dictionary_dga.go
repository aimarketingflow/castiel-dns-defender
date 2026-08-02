package detectors

import (
	"strings"
)

// DictionaryDGADetector detects dictionary-based DGA domains (e.g., Matsnu,
// Suppobox, Gabiya) that use concatenated dictionary words instead of
// random characters. These bypass entropy-based detection because individual
// words have low entropy, but the concatenation patterns are unnatural.
//
// Detection methods:
//   - Word boundary analysis: check if domain is composed of known dictionary words
//   - Concatenation pattern: 2-3 dictionary words concatenated is suspicious
//   - Unusual word combinations: random word pairs not seen in legitimate domains
type DictionaryDGADetector struct {
	words map[string]bool // dictionary word set
}

// NewDictionaryDGADetector creates a detector with a built-in word list.
// Additional words can be loaded from a file via LoadWords.
func NewDictionaryDGADetector() *DictionaryDGADetector {
	d := &DictionaryDGADetector{
		words: make(map[string]bool),
	}
	d.loadDefaultWords()
	return d
}

// LoadWords adds words from a newline-delimited list.
func (d *DictionaryDGADetector) LoadWords(wordList []string) {
	for _, w := range wordList {
		w = strings.ToLower(strings.TrimSpace(w))
		if len(w) >= 3 {
			d.words[w] = true
		}
	}
}

// IsDictionaryDGA checks if a domain appears to be a dictionary-based DGA.
// Returns true if the apex domain is composed of 2+ concatenated dictionary words
// in an unnatural pattern.
func (d *DictionaryDGADetector) IsDictionaryDGA(domain string) bool {
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return false
	}

	apex := strings.ToLower(labels[0])
	if len(apex) < 6 { // too short for 2+ word concatenation
		return false
	}

	// Skip known legitimate domains
	if knownLegitimateDomains[apex] {
		return false
	}

	// Try to split the apex into dictionary words
	words := d.splitIntoWords(apex)
	if len(words) < 2 {
		return false
	}

	// 2+ concatenated dictionary words is suspicious
	// But allow common compound words (e.g., "facebook", "youtube")
	if len(words) == 2 {
		combined := words[0] + words[1]
		// If the combined form is a known legitimate domain, skip
		if knownLegitimateDomains[combined] {
			return false
		}
		// Check if it's a known compound word by checking if the full
		// string appears in our word list (e.g., "sunshine" = "sun"+"shine")
		if d.words[combined] {
			return false
		}
	}

	// 3+ dictionary words concatenated is highly suspicious
	if len(words) >= 3 {
		return true
	}

	// 2 words: suspicious if both are uncommon in domain names
	// (not in our legitimate domain set)
	if len(words) == 2 {
		// Check for random word pair patterns typical of Matsnu/Suppobox
		// Both words should be >= 3 chars and the combination should not be
		// a known legitimate domain
		if len(words[0]) >= 3 && len(words[1]) >= 3 {
			return true
		}
	}

	return false
}

// splitIntoWords attempts to split a string into known dictionary words.
// Uses dynamic programming to find all valid word break combinations.
func (d *DictionaryDGADetector) splitIntoWords(s string) []string {
	n := len(s)
	if n == 0 {
		return nil
	}

	// dp[i] = list of word sequences that form s[0:i]
	dp := make([][][]string, n+1)
	dp[0] = [][]string{{}}

	for i := 1; i <= n; i++ {
		for j := 0; j < i; j++ {
			if len(dp[j]) == 0 {
				continue
			}
			word := s[j:i]
			if d.words[word] {
				for _, prev := range dp[j] {
					dp[i] = append(dp[i], append(append([]string{}, prev...), word))
				}
			}
		}
	}

	if len(dp[n]) == 0 {
		return nil
	}

	// Return the first valid split (prefer fewer, longer words)
	best := dp[n][0]
	for _, split := range dp[n] {
		if len(split) < len(best) {
			best = split
		}
	}
	return best
}

func (d *DictionaryDGADetector) loadDefaultWords() {
	// Common words used by dictionary DGA families (Matsnu, Suppobox, Gabiya)
	// This is a curated list — in production, load from a larger word file
	words := []string{
		// Common nouns
		"sun", "moon", "star", "tree", "leaf", "root", "rock", "stone",
		"fire", "water", "wind", "earth", "sky", "cloud", "rain", "snow",
		"bird", "fish", "wolf", "bear", "lion", "deer", "cat", "dog",
		"red", "blue", "green", "black", "white", "dark", "light", "gold",
		"king", "queen", "lord", "lady", "man", "woman", "boy", "girl",
		"door", "gate", "key", "lock", "wall", "roof", "room", "house",
		"road", "path", "way", "line", "side", "edge", "end", "start",
		"win", "lose", "run", "walk", "jump", "fly", "swim", "fight",
		"good", "bad", "big", "small", "old", "new", "fast", "slow",
		"hot", "cold", "hard", "soft", "high", "low", "long", "short",
		"day", "night", "week", "year", "time", "life", "world", "home",
		"work", "play", "game", "book", "word", "name", "data", "code",
		"test", "user", "help", "info", "link", "post", "view", "page",
		"mail", "news", "shop", "blog", "chat", "file", "save", "find",
		"open", "close", "move", "stop", "turn", "back", "hand", "head",
		"eye", "face", "body", "mind", "soul", "heart", "bone", "blood",
		"north", "south", "east", "west", "top", "bottom", "left", "right",
		"spring", "summer", "autumn", "winter", "morning", "evening",
		"shine", "flower", "river", "ocean", "mountain", "forest",
		"power", "force", "energy", "light", "shadow", "dream",
		"apple", "orange", "lemon", "grape", "cherry",
		"silver", "iron", "steel", "glass", "wood",
		// Common compound words — included as whole words so they aren't
		// flagged as dictionary DGA when they split into sub-words
		"sunshine", "moonlight", "starlight", "firewall", "network",
		"password", "keyboard", "software", "hardware", "freedom",
		"weekend", "birthday", "background", "framework", "platform",
		"happy", "angry", "brave", "wise", "calm",
		"city", "town", "land", "farm", "park",
		"car", "ship", "boat", "plane", "train",
		"phone", "screen", "mouse", "desk", "table",
		"money", "price", "cost", "rate", "fund",
		"team", "group", "club", "band", "crew",
		"art", "song", "film", "show", "stage",
		"law", "rule", "plan", "step", "goal",
		"war", "peace", "hope", "fear", "love",
		"one", "two", "three", "four", "five",
		"first", "second", "third", "last", "next",
		"main", "full", "half", "part", "area",
		"sea", "lake", "hill", "field", "valley",
		"son", "child", "baby", "friend", "guest",
		"mark", "sign", "note", "text", "type",
		"base", "core", "net", "web", "hub",
		"plus", "mini", "max", "pro", "lite",
		"true", "real", "fake", "auto", "self",
		"free", "paid", "pro", "pre", "post",
		"out", "in", "up", "down", "over",
	}
	d.LoadWords(words)
}
