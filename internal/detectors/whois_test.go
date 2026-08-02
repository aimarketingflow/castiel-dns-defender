package detectors

import (
	"testing"
	"time"
)

func TestWHOISCheckerDisabled(t *testing.T) {
	w := NewWHOISChecker(0) // 0 = disabled
	isNew, err := w.IsNewlyRegistered("example.com")
	if err != nil {
		t.Errorf("disabled checker should not error: %v", err)
	}
	if isNew {
		t.Error("disabled checker should never flag as new")
	}
}

func TestWHOISCheckerCacheSize(t *testing.T) {
	w := NewWHOISChecker(7)
	if w.CacheSize() != 0 {
		t.Errorf("new checker should have empty cache, got %d", w.CacheSize())
	}
}

func TestWHOISCheckerClearCache(t *testing.T) {
	w := NewWHOISChecker(7)
	w.mu.Lock()
	w.cache["test.com"] = &whoisResult{
		registrationDate: time.Now(),
		isNew:            true,
		checkedAt:        time.Now(),
	}
	w.mu.Unlock()

	if w.CacheSize() != 1 {
		t.Errorf("expected cache size 1, got %d", w.CacheSize())
	}

	w.ClearCache()
	if w.CacheSize() != 0 {
		t.Errorf("after clear, expected cache size 0, got %d", w.CacheSize())
	}
}

func TestWHOISCheckerEnabled(t *testing.T) {
	w := NewWHOISChecker(7)
	if !w.enabled {
		t.Error("checker with maxAgeDays=7 should be enabled")
	}

	w2 := NewWHOISChecker(0)
	if w2.enabled {
		t.Error("checker with maxAgeDays=0 should be disabled")
	}
}
