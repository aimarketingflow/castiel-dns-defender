package detectors

import (
	"testing"

	"github.com/castiel/dns/internal/config"
)

func TestNXDomainTrackerBelowThreshold(t *testing.T) {
	cfg := config.NXDomainTrackingConfig{
		Enabled:    true,
		Threshold:  10,
		WindowSecs: 60,
		BlockMode:  true,
	}
	tracker := NewNXDomainTracker(cfg)

	for i := 0; i < 9; i++ {
		if tracker.RecordNXDomain("example.com") {
			t.Errorf("Should not trigger at count %d (threshold 10)", i+1)
		}
	}
	if tracker.IsBlocked("example.com") {
		t.Error("Domain should not be blocked below threshold")
	}
}

func TestNXDomainTrackerAtThreshold(t *testing.T) {
	cfg := config.NXDomainTrackingConfig{
		Enabled:    true,
		Threshold:  5,
		WindowSecs: 60,
		BlockMode:  true,
	}
	tracker := NewNXDomainTracker(cfg)

	for i := 0; i < 5; i++ {
		tracker.RecordNXDomain("evil.com")
	}
	// 6th NXDOMAIN should trigger
	if !tracker.RecordNXDomain("evil.com") {
		t.Error("Should trigger at count 6 (threshold 5)")
	}
	if !tracker.IsBlocked("evil.com") {
		t.Error("Domain should be blocked after threshold exceeded")
	}
}

func TestNXDomainTrackerDifferentDomains(t *testing.T) {
	cfg := config.NXDomainTrackingConfig{
		Enabled:    true,
		Threshold:  3,
		WindowSecs: 60,
		BlockMode:  true,
	}
	tracker := NewNXDomainTracker(cfg)

	// NXDOMAINs for different domains should not affect each other
	tracker.RecordNXDomain("a.com")
	tracker.RecordNXDomain("b.com")
	tracker.RecordNXDomain("c.com")

	if tracker.IsBlocked("a.com") {
		t.Error("a.com should not be blocked (only 1 NXDOMAIN)")
	}
	if tracker.IsBlocked("b.com") {
		t.Error("b.com should not be blocked (only 1 NXDOMAIN)")
	}
}

func TestNXDomainTrackerNoBlockMode(t *testing.T) {
	cfg := config.NXDomainTrackingConfig{
		Enabled:    true,
		Threshold:  2,
		WindowSecs: 60,
		BlockMode:  false, // alert only, no blocking
	}
	tracker := NewNXDomainTracker(cfg)

	tracker.RecordNXDomain("test.com")
	tracker.RecordNXDomain("test.com")
	tracker.RecordNXDomain("test.com") // triggers

	// Should detect but not block
	if tracker.IsBlocked("test.com") {
		t.Error("Domain should not be blocked when BlockMode is false")
	}
}

func TestNXDomainTrackerCleanup(t *testing.T) {
	cfg := config.NXDomainTrackingConfig{
		Enabled:    true,
		Threshold:  100,
		WindowSecs: 1, // very short window
		BlockMode:  true,
	}
	tracker := NewNXDomainTracker(cfg)

	tracker.RecordNXDomain("temp.com")
	tracker.Cleanup()
	// After cleanup, entry should be gone — new window starts
	if tracker.RecordNXDomain("temp.com") {
		t.Error("Should not trigger after cleanup (count reset to 1)")
	}
}
