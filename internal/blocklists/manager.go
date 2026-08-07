package blocklists

import (
	"bufio"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/castiel/dns/internal/config"
)

// Manager handles loading, refreshing, and querying blocklists
// from multiple threat intelligence feeds.
type Manager struct {
	cfg       config.BlocklistsConfig
	blocked   map[string]bool   // exact domain matches
	wildcard  map[string]bool   // suffix wildcards (e.g., "*.malware.com")
	allowed   map[string]bool   // allowlist overrides
	mu        sync.RWMutex
}

func NewManager(cfg config.BlocklistsConfig) *Manager {
	m := &Manager{
		cfg:      cfg,
		blocked:  make(map[string]bool),
		wildcard: make(map[string]bool),
		allowed:  make(map[string]bool),
	}

	// Load local files synchronously (fast, no network)
	if m.cfg.CustomAllowFile != "" {
		m.loadAllowFile(m.cfg.CustomAllowFile)
	}
	if m.cfg.CustomBlockFile != "" {
		m.loadBlockFile(m.cfg.CustomBlockFile)
	}

	// Load remote feeds asynchronously to avoid blocking DNS listener startup
	// (prevents bootstrap deadlock when system DNS points to Castiel)
	go m.loadFeeds()

	return m
}

func (m *Manager) loadFeeds() {
	for _, feed := range m.cfg.Feeds {
		if !feed.Enabled {
			continue
		}
		if err := m.loadFeed(feed); err != nil {
			log.Printf("Failed to load feed %s: %v", feed.Name, err)
		}
	}
	m.mu.RLock()
	count := len(m.blocked) + len(m.wildcard)
	m.mu.RUnlock()
	log.Printf("Blocklists loaded: %d domains blocked", count)
}

func (m *Manager) StartRefreshLoop() {
	if !m.cfg.Enabled || m.cfg.RefreshInterval <= 0 {
		return
	}

	ticker := time.NewTicker(time.Duration(m.cfg.RefreshInterval) * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		log.Printf("Refreshing blocklists...")
		m.loadAll()
	}
}

func (m *Manager) loadAll() {
	// Load custom allow list first
	if m.cfg.CustomAllowFile != "" {
		m.loadAllowFile(m.cfg.CustomAllowFile)
	}

	// Load custom block list
	if m.cfg.CustomBlockFile != "" {
		m.loadBlockFile(m.cfg.CustomBlockFile)
	}

	// Load feeds
	m.loadFeeds()
}

func (m *Manager) IsBlocked(domain string) bool {
	if !m.cfg.Enabled {
		return false
	}

	domain = strings.ToLower(strings.TrimSuffix(domain, "."))

	m.mu.RLock()
	defer m.mu.RUnlock()

	// Check allowlist first
	if m.allowed[domain] {
		return false
	}

	// Exact match
	if m.blocked[domain] {
		return true
	}

	// Wildcard match — check parent domains (skip i=0 which is the full domain itself)
	// *.malware.com matches sub.malware.com but NOT malware.com
	labels := strings.Split(domain, ".")
	for i := 1; i < len(labels)-1; i++ {
		suffix := strings.Join(labels[i:], ".")
		if m.wildcard[suffix] {
			return true
		}
	}

	return false
}

func (m *Manager) loadFeed(feed config.FeedConfig) error {
	resp, err := http.Get(feed.URL)
	if err != nil {
		return fmt.Errorf("fetching %s: %w", feed.Name, err)
	}
	defer resp.Body.Close()

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	count := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}

		switch feed.Format {
		case "hosts":
			// Format: "0.0.0.0 domain.com" or "127.0.0.1 domain.com"
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				domain := strings.ToLower(parts[1])
				m.addBlocked(domain)
				count++
			}
		case "domain_list":
			domain := strings.ToLower(line)
			m.addBlocked(domain)
			count++
		case "url_list":
			// Extract domain from URL
			if strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://") {
				u := line
				u = strings.TrimPrefix(u, "http://")
				u = strings.TrimPrefix(u, "https://")
				parts := strings.SplitN(u, "/", 2)
				domain := strings.ToLower(parts[0])
				m.addBlocked(domain)
				count++
			}
		}
	}

	log.Printf("Feed %s: loaded %d domains", feed.Name, count)
	return scanner.Err()
}

func (m *Manager) loadBlockFile(path string) {
	file, err := os.Open(path)
	if err != nil {
		log.Printf("Custom block file not found: %s", path)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		m.addBlocked(strings.ToLower(line))
	}
}

func (m *Manager) loadAllowFile(path string) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	m.mu.Lock()
	defer m.mu.Unlock()
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		m.allowed[strings.ToLower(line)] = true
	}
}

func (m *Manager) addBlocked(domain string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if strings.HasPrefix(domain, "*.") {
		// Wildcard entry
		m.wildcard[strings.TrimPrefix(domain, "*.")] = true
	} else {
		m.blocked[domain] = true
	}
}

func (m *Manager) BlockCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.blocked) + len(m.wildcard)
}
