package alerts

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/castiel/dns/internal/config"
)

func TestAlertsDisabled(t *testing.T) {
	cfg := config.AlertsConfig{Enabled: false}
	m := NewManager(cfg)
	m.Send(Alert{
		Type:     "test",
		Severity: "critical",
		Message:  "should not be sent",
	})
	// No panic, no file — just silently ignored
}

func TestAlertsSeverityFilter(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "alerts.log")

	cfg := config.AlertsConfig{
		Enabled:     true,
		LogFile:     logPath,
		MinSeverity: "critical",
	}
	m := NewManager(cfg)
	defer m.Close()

	// "warn" should be filtered out (min severity = critical)
	m.Send(Alert{
		Type:     "test_warn",
		Severity: "warn",
		Message:  "should be filtered",
		Time:     time.Now(),
	})

	// "critical" should pass
	m.Send(Alert{
		Type:     "test_critical",
		Severity: "critical",
		Message:  "should pass",
		Time:     time.Now(),
	})

	// Read log file and verify
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("Failed to read alert log: %v", err)
	}

	lines := splitLines(string(data))
	if len(lines) != 1 {
		t.Fatalf("Expected 1 alert in log, got %d", len(lines))
	}

	var alert Alert
	if err := json.Unmarshal([]byte(lines[0]), &alert); err != nil {
		t.Fatalf("Failed to parse alert JSON: %v", err)
	}

	if alert.Type != "test_critical" {
		t.Errorf("Expected alert type 'test_critical', got '%s'", alert.Type)
	}
}

func TestAlertsRateLimit(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "alerts.log")

	cfg := config.AlertsConfig{
		Enabled:         true,
		LogFile:         logPath,
		MinSeverity:     "info",
		RateLimitAlerts: true,
	}
	m := NewManager(cfg)
	defer m.Close()

	// Send 15 alerts of the same type — only first 10 should be logged
	for i := 0; i < 15; i++ {
		m.Send(Alert{
			Type:     "rate_limited_type",
			Severity: "warn",
			Message:  "test alert",
			Time:     time.Now(),
		})
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("Failed to read alert log: %v", err)
	}

	lines := splitLines(string(data))
	if len(lines) > 11 {
		t.Errorf("Rate limit should cap at ~10 alerts, got %d", len(lines))
	}
}

func TestAlertsJSONFormat(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "alerts.jsonl")

	cfg := config.AlertsConfig{
		Enabled:     true,
		LogFile:     logPath,
		MinSeverity: "info",
	}
	m := NewManager(cfg)
	defer m.Close()

	alertTime := time.Date(2026, 8, 1, 23, 0, 0, 0, time.UTC)
	m.Send(Alert{
		Type:     "dns_tunneling",
		Severity: "critical",
		Source:   "192.168.1.100",
		Domain:   "evil.example.com",
		Message:  "High entropy subdomain detected",
		Time:     alertTime,
	})

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("Failed to read alert log: %v", err)
	}

	var alert Alert
	if err := json.Unmarshal(data[:len(data)-1], &alert); err != nil {
		t.Fatalf("Failed to parse alert JSON: %v", err)
	}

	if alert.Type != "dns_tunneling" {
		t.Errorf("Expected type 'dns_tunneling', got '%s'", alert.Type)
	}
	if alert.Severity != "critical" {
		t.Errorf("Expected severity 'critical', got '%s'", alert.Severity)
	}
	if alert.Source != "192.168.1.100" {
		t.Errorf("Expected source '192.168.1.100', got '%s'", alert.Source)
	}
	if alert.Domain != "evil.example.com" {
		t.Errorf("Expected domain 'evil.example.com', got '%s'", alert.Domain)
	}
}

func TestAlertsMeetsSeverity(t *testing.T) {
	m := &Manager{
		cfg: config.AlertsConfig{MinSeverity: "warn"},
	}

	tests := []struct {
		severity string
		expected bool
	}{
		{"debug", false},
		{"info", false},
		{"warn", true},
		{"critical", true},
		{"unknown", false},
	}

	for _, tt := range tests {
		result := m.meetsSeverity(tt.severity)
		if result != tt.expected {
			t.Errorf("meetsSeverity(%q) = %v, want %v", tt.severity, result, tt.expected)
		}
	}
}

func TestAlertsClose(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "alerts.log")

	cfg := config.AlertsConfig{
		Enabled: true,
		LogFile: logPath,
	}
	m := NewManager(cfg)

	m.Send(Alert{
		Type:     "test",
		Severity: "warn",
		Message:  "before close",
		Time:     time.Now(),
	})

	m.Close()

	// Sending after close should not panic
	m.Send(Alert{
		Type:     "test2",
		Severity: "warn",
		Message:  "after close",
		Time:     time.Now(),
	})
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i, c := range s {
		if c == '\n' {
			line := s[start:i]
			if line != "" {
				lines = append(lines, line)
			}
			start = i + 1
		}
	}
	if start < len(s) {
		line := s[start:]
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}
