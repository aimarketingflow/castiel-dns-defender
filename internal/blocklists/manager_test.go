package blocklists

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/castiel/dns/internal/config"
)

func writeTempFile(t *testing.T, name, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write %s: %v", name, err)
	}
	return path
}

func TestBlocklistExactMatch(t *testing.T) {
	blockFile := writeTempFile(t, "block.txt", "evil.com\nmalware.org\n# comment\n\n")
	cfg := config.BlocklistsConfig{
		Enabled:         true,
		CustomBlockFile: blockFile,
	}
	m := NewManager(cfg)

	if !m.IsBlocked("evil.com") {
		t.Error("expected evil.com to be blocked")
	}
	if !m.IsBlocked("malware.org") {
		t.Error("expected malware.org to be blocked")
	}
	if m.IsBlocked("good.com") {
		t.Error("good.com should not be blocked")
	}
}

func TestBlocklistCaseInsensitive(t *testing.T) {
	blockFile := writeTempFile(t, "block.txt", "evil.com\n")
	cfg := config.BlocklistsConfig{
		Enabled:         true,
		CustomBlockFile: blockFile,
	}
	m := NewManager(cfg)

	if !m.IsBlocked("EVIL.COM") {
		t.Error("expected EVIL.COM to be blocked (case insensitive)")
	}
	if !m.IsBlocked("Evil.Com") {
		t.Error("expected Evil.Com to be blocked (case insensitive)")
	}
}

func TestBlocklistTrailingDot(t *testing.T) {
	blockFile := writeTempFile(t, "block.txt", "evil.com\n")
	cfg := config.BlocklistsConfig{
		Enabled:         true,
		CustomBlockFile: blockFile,
	}
	m := NewManager(cfg)

	if !m.IsBlocked("evil.com.") {
		t.Error("expected evil.com. (with trailing dot) to be blocked")
	}
}

func TestBlocklistWildcard(t *testing.T) {
	blockFile := writeTempFile(t, "block.txt", "*.malware.com\n")
	cfg := config.BlocklistsConfig{
		Enabled:         true,
		CustomBlockFile: blockFile,
	}
	m := NewManager(cfg)

	if !m.IsBlocked("sub.malware.com") {
		t.Error("expected sub.malware.com to be blocked by wildcard *.malware.com")
	}
	if !m.IsBlocked("deep.sub.malware.com") {
		t.Error("expected deep.sub.malware.com to be blocked by wildcard")
	}
	if m.IsBlocked("malware.com") {
		t.Error("apex malware.com should NOT be blocked by *.malware.com wildcard")
	}
}

func TestBlocklistAllowlist(t *testing.T) {
	blockFile := writeTempFile(t, "block.txt", "evil.com\n")
	allowFile := writeTempFile(t, "allow.txt", "evil.com\n")
	cfg := config.BlocklistsConfig{
		Enabled:         true,
		CustomBlockFile: blockFile,
		CustomAllowFile: allowFile,
	}
	m := NewManager(cfg)

	if m.IsBlocked("evil.com") {
		t.Error("evil.com should be allowed (in allowlist)")
	}
}

func TestBlocklistDisabled(t *testing.T) {
	blockFile := writeTempFile(t, "block.txt", "evil.com\n")
	cfg := config.BlocklistsConfig{
		Enabled:         false,
		CustomBlockFile: blockFile,
	}
	m := NewManager(cfg)

	if m.IsBlocked("evil.com") {
		t.Error("disabled blocklist should not block anything")
	}
}

func TestBlocklistBlockCount(t *testing.T) {
	blockFile := writeTempFile(t, "block.txt", "evil.com\nmalware.org\n*.bad.net\n")
	cfg := config.BlocklistsConfig{
		Enabled:         true,
		CustomBlockFile: blockFile,
	}
	m := NewManager(cfg)

	count := m.BlockCount()
	if count != 3 {
		t.Errorf("expected BlockCount=3, got %d", count)
	}
}

func TestBlocklistCommentsAndEmptyLines(t *testing.T) {
	blockFile := writeTempFile(t, "block.txt", "# comment1\n\nevil.com\n  # comment2\n\ngood.com\n")
	cfg := config.BlocklistsConfig{
		Enabled:         true,
		CustomBlockFile: blockFile,
	}
	m := NewManager(cfg)

	if !m.IsBlocked("evil.com") {
		t.Error("evil.com should be blocked")
	}
	if !m.IsBlocked("good.com") {
		t.Error("good.com should be blocked")
	}
}
