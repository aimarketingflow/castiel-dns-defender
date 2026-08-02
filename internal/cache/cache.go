package cache

import (
	"sync"
	"time"

	"github.com/castiel/dns/internal/config"
	"github.com/miekg/dns"
)

// Cache is an LRU-style DNS response cache with TTL awareness.
type Cache struct {
	cfg     config.CacheConfig
	entries map[string]*cacheEntry
	mu      sync.RWMutex
}

type cacheEntry struct {
	response  *dns.Msg
	expiresAt time.Time
}

func New(cfg config.CacheConfig) *Cache {
	return &Cache{
		cfg:     cfg,
		entries: make(map[string]*cacheEntry),
	}
}

func (c *Cache) Get(q *dns.Msg) *dns.Msg {
	if !c.cfg.Enabled || len(q.Question) == 0 {
		return nil
	}

	key := cacheKey(q)

	c.mu.RLock()
	entry, exists := c.entries[key]
	c.mu.RUnlock()

	if !exists {
		return nil
	}

	if time.Now().After(entry.expiresAt) {
		c.mu.Lock()
		delete(c.entries, key)
		c.mu.Unlock()
		return nil
	}

	return entry.response.Copy()
}

func (c *Cache) Put(q *dns.Msg, resp *dns.Msg) {
	if !c.cfg.Enabled || len(q.Question) == 0 {
		return
	}

	key := cacheKey(q)
	ttl := c.cfg.DefaultTTL

	// Use minimum TTL from response records
	if len(resp.Answer) > 0 {
		minTTL := uint32(0xFFFFFFFF)
		for _, rr := range resp.Answer {
			if rr.Header().Ttl < minTTL {
				minTTL = rr.Header().Ttl
			}
		}
		if minTTL != 0xFFFFFFFF && minTTL > 0 {
			ttl = int(minTTL)
		}
	}

	// Negative caching for NXDOMAIN
	if resp.Rcode == dns.RcodeNameError {
		ttl = c.cfg.NegativeTTL
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Evict if over capacity
	if len(c.entries) >= c.cfg.MaxEntries {
		c.evictOldest()
	}

	c.entries[key] = &cacheEntry{
		response:  resp.Copy(),
		expiresAt: time.Now().Add(time.Duration(ttl) * time.Second),
	}
}

func (c *Cache) evictOldest() {
	var oldestKey string
	var oldestTime time.Time
	for k, e := range c.entries {
		if oldestKey == "" || e.expiresAt.Before(oldestTime) {
			oldestKey = k
			oldestTime = e.expiresAt
		}
	}
	delete(c.entries, oldestKey)
}

func cacheKey(q *dns.Msg) string {
	if len(q.Question) == 0 {
		return ""
	}
	qq := q.Question[0]
	return qq.Name + ":" + dns.TypeToString[qq.Qtype]
}
