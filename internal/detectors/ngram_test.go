package detectors

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNgramModelTrainFromSlice(t *testing.T) {
	model := NewNgramModel(3)
	domains := []string{
		"google.com",
		"facebook.com",
		"youtube.com",
		"amazon.com",
		"microsoft.com",
	}
	model.TrainFromSlice(domains)

	if !model.IsLoaded() {
		t.Error("model should be loaded after training")
	}
	if model.NgramCount() == 0 {
		t.Error("model should have n-grams after training")
	}
}

func TestNgramModelScoreLegitimateVsDGA(t *testing.T) {
	model := NewNgramModel(3)
	// Train with common legitimate domains
	legit := []string{
		"google", "facebook", "youtube", "amazon", "wikipedia",
		"twitter", "instagram", "linkedin", "netflix", "microsoft",
		"apple", "github", "stackoverflow", "reddit", "gmail",
		"yahoo", "bing", "cloudflare", "mozilla", "wordpress",
		"medium", "quora", "pinterest", "ebay", "paypal",
		"stripe", "shopify", "salesforce", "adobe", "oracle",
		"ibm", "intel", "nvidia", "cisco", "vmware",
		"slack", "zoom", "dropbox", "docker", "kubernetes",
		"python", "golang", "rustlang", "ruby", "java",
		"reactjs", "vuejs", "angular", "svelte", "nextjs",
		"django", "flask", "fastapi", "spring", "nginx",
		"apache", "grafana", "prometheus", "elastic", "hashicorp",
	}
	model.TrainFromSlice(legit)

	// Legitimate domains should score higher (more natural)
	legitScore := model.Score("github.com")
	dgaScore := model.Score("qzxvpmn123.net")

	t.Logf("Legitimate domain score:  github.com = %.4f", legitScore)
	t.Logf("DGA domain score:         qzxvpmn123.net = %.4f", dgaScore)

	if dgaScore >= legitScore {
		t.Errorf("DGA domain should score lower than legitimate: DGA=%.4f, legit=%.4f", dgaScore, legitScore)
	}

	// Another DGA domain
	dgaScore2 := model.Score("xkjhsdf8923jksdf.com")
	t.Logf("DGA domain score:         xkjhsdf8923jksdf.com = %.4f", dgaScore2)
	if dgaScore2 >= legitScore {
		t.Errorf("DGA domain should score lower than legitimate: DGA=%.4f, legit=%.4f", dgaScore2, legitScore)
	}
}

func TestNgramModelUntrained(t *testing.T) {
	model := NewNgramModel(3)
	// Untrained model should return neutral 0.5 score
	score := model.Score("anything.com")
	if score != 0.5 {
		t.Errorf("untrained model should return 0.5, got %.4f", score)
	}
}

func TestNgramModelTrainFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "domains.txt")
	content := "google.com\nfacebook.com\n# comment\n\ntwitter.com\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	model := NewNgramModel(3)
	if err := model.TrainFromFile(path); err != nil {
		t.Fatalf("TrainFromFile failed: %v", err)
	}
	if !model.IsLoaded() {
		t.Error("model should be loaded after TrainFromFile")
	}
	if model.NgramCount() == 0 {
		t.Error("model should have n-grams")
	}
}

func TestNgramModelTrainFromFileMissing(t *testing.T) {
	model := NewNgramModel(3)
	err := model.TrainFromFile("/nonexistent/path.txt")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestNgramModelShortDomain(t *testing.T) {
	model := NewNgramModel(3)
	model.TrainFromSlice([]string{"google.com"})

	// Very short domain should return neutral
	score := model.Score("a.b")
	if score != 0.5 {
		t.Errorf("short domain should return 0.5, got %.4f", score)
	}
}

func TestNgramModelNValue(t *testing.T) {
	m2 := NewNgramModel(2)
	if m2.n != 2 {
		t.Errorf("expected n=2, got %d", m2.n)
	}

	m5 := NewNgramModel(5)
	if m5.n != 5 {
		t.Errorf("expected n=5, got %d", m5.n)
	}

	// n < 2 should be clamped to 2
	m1 := NewNgramModel(1)
	if m1.n != 2 {
		t.Errorf("expected n=2 (clamped), got %d", m1.n)
	}
}
