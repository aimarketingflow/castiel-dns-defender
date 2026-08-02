package dnssec

import (
	"testing"
)

func TestLoadTrustAnchors(t *testing.T) {
	anchors, err := loadTrustAnchors("../../data/root-trust-anchor.txt")
	if err != nil {
		t.Fatalf("failed to load trust anchors: %v", err)
	}
	if len(anchors) == 0 {
		t.Fatal("expected at least one trust anchor, got 0")
	}
	for _, a := range anchors {
		if a.Flags&0x1 == 0 {
			t.Errorf("expected KSK (SEP bit set), got flags=%d", a.Flags)
		}
		t.Logf("Loaded trust anchor: name=%s keytag=%d algorithm=%d flags=%d",
			a.Hdr.Name, a.KeyTag(), a.Algorithm, a.Flags)
	}
}

func TestNewValidatorFallback(t *testing.T) {
	// Nonexistent trust anchor file should fall back to AD-bit-only mode
	v := NewValidator("/nonexistent/path.txt", []string{"1.1.1.1:53"}, 5000000000)
	if v.Mode() != ModeADBitOnly {
		t.Errorf("expected ModeADBitOnly fallback, got %v", v.Mode())
	}
}

func TestNewValidatorFullChain(t *testing.T) {
	v := NewValidator("../../data/root-trust-anchor.txt", []string{"1.1.1.1:53"}, 5000000000)
	if v.Mode() != ModeFullChain {
		t.Errorf("expected ModeFullChain, got %v", v.Mode())
	}
}

func TestValidateDisabledMode(t *testing.T) {
	v := NewValidator("", nil, 5000000000)
	v.SetMode(ModeDisabled)
	if !v.Validate(nil, "example.com") {
		t.Error("expected disabled mode to always return true")
	}
}
