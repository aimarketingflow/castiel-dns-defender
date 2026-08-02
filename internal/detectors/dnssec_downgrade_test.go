package detectors

import (
	"testing"
)

func TestDNSSECDowngradeNoAlertOnFirstFailure(t *testing.T) {
	d := NewDNSSECDowngradeDetector()

	// First failure for a domain with no prior valid — should not alert
	if d.RecordValidation("example.com", false) {
		t.Error("Should not alert on first failure with no prior valid")
	}
}

func TestDNSSECDowngradeAlertAfterValidThenFail(t *testing.T) {
	d := NewDNSSECDowngradeDetector()

	// Domain validates successfully
	d.RecordValidation("example.com", true)
	d.RecordValidation("example.com", true)

	// Then starts failing — should alert after 2 consecutive failures
	d.RecordValidation("example.com", false)
	if !d.RecordValidation("example.com", false) {
		t.Error("Should alert after 2 consecutive failures following valid history")
	}
}

func TestDNSSECDowngradeNoAlertOnContinuedSuccess(t *testing.T) {
	d := NewDNSSECDowngradeDetector()

	d.RecordValidation("good.com", true)
	d.RecordValidation("good.com", true)
	d.RecordValidation("good.com", true)

	if d.IsDowngradeAttempt("good.com") {
		t.Error("Should not flag downgrade for domain that keeps validating")
	}
}

func TestDNSSECDowngradeRecovery(t *testing.T) {
	d := NewDNSSECDowngradeDetector()

	d.RecordValidation("flaky.com", true)
	d.RecordValidation("flaky.com", true)
	d.RecordValidation("flaky.com", false)
	d.RecordValidation("flaky.com", false) // triggers alert

	// Domain recovers
	d.RecordValidation("flaky.com", true)

	if d.IsDowngradeAttempt("flaky.com") {
		t.Error("Should clear downgrade flag after successful validation")
	}
}

func TestDNSSECDowngradeCooldown(t *testing.T) {
	d := NewDNSSECDowngradeDetector()
	d.alertCooldown = 0 // disable cooldown for test

	d.RecordValidation("test.com", true)
	d.RecordValidation("test.com", true)
	d.RecordValidation("test.com", false)
	first := d.RecordValidation("test.com", false)
	second := d.RecordValidation("test.com", false)

	if !first {
		t.Error("First alert should fire")
	}
	// With cooldown disabled, subsequent failures should also alert
	if !second {
		t.Error("Second alert should fire with no cooldown")
	}
}
