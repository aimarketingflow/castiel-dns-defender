package cache

import (
	"testing"
	"time"

	"github.com/castiel/dns/internal/config"
	"github.com/miekg/dns"
)

func newTestCache(maxEntries, defaultTTL, negTTL int) *Cache {
	return New(config.CacheConfig{
		Enabled:     true,
		MaxEntries:  maxEntries,
		DefaultTTL:  defaultTTL,
		NegativeTTL: negTTL,
	})
}

func newQuery(name string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	return m
}

func newResponse(name string, qtype uint16, ttl uint32, rcode int) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	m.Rcode = rcode
	if rcode == dns.RcodeSuccess {
		rr := &dns.A{
			Hdr: dns.RR_Header{Name: name, Rrtype: qtype, Class: dns.ClassINET, Ttl: ttl},
			A:   nil,
		}
		m.Answer = append(m.Answer, rr)
	}
	return m
}

func TestCachePutGet(t *testing.T) {
	c := newTestCache(100, 300, 60)
	q := newQuery("example.com.", dns.TypeA)
	resp := newResponse("example.com.", dns.TypeA, 300, dns.RcodeSuccess)

	c.Put(q, resp)
	got := c.Get(q)
	if got == nil {
		t.Fatal("expected cache hit, got nil")
	}
	if got.Rcode != dns.RcodeSuccess {
		t.Errorf("expected RcodeSuccess, got %d", got.Rcode)
	}
}

func TestCacheMiss(t *testing.T) {
	c := newTestCache(100, 300, 60)
	q := newQuery("nonexistent.com.", dns.TypeA)
	if got := c.Get(q); got != nil {
		t.Error("expected cache miss, got response")
	}
}

func TestCacheDisabled(t *testing.T) {
	c := New(config.CacheConfig{Enabled: false, MaxEntries: 100, DefaultTTL: 300})
	q := newQuery("example.com.", dns.TypeA)
	resp := newResponse("example.com.", dns.TypeA, 300, dns.RcodeSuccess)

	c.Put(q, resp)
	if got := c.Get(q); got != nil {
		t.Error("disabled cache should not store or return entries")
	}
}

func TestCacheTTLExpiry(t *testing.T) {
	c := newTestCache(100, 1, 1) // 1 second TTL
	q := newQuery("temp.com.", dns.TypeA)
	resp := newResponse("temp.com.", dns.TypeA, 1, dns.RcodeSuccess)

	c.Put(q, resp)

	// Should be cached immediately
	if got := c.Get(q); got == nil {
		t.Fatal("expected immediate cache hit")
	}

	// Wait for expiry
	time.Sleep(2 * time.Second)

	if got := c.Get(q); got != nil {
		t.Error("expected cache miss after TTL expiry")
	}
}

func TestCacheNegativeCaching(t *testing.T) {
	c := newTestCache(100, 300, 60)
	q := newQuery("nxdomain.com.", dns.TypeA)
	resp := newResponse("nxdomain.com.", dns.TypeA, 0, dns.RcodeNameError)

	c.Put(q, resp)
	got := c.Get(q)
	if got == nil {
		t.Fatal("expected negative cache hit for NXDOMAIN")
	}
	if got.Rcode != dns.RcodeNameError {
		t.Errorf("expected RcodeNameError, got %d", got.Rcode)
	}
}

func TestCacheEviction(t *testing.T) {
	c := newTestCache(3, 300, 60)

	// Fill cache to capacity
	for i := 0; i < 3; i++ {
		name := "domain" + string(rune('a'+i)) + ".com."
		q := newQuery(name, dns.TypeA)
		resp := newResponse(name, dns.TypeA, 300, dns.RcodeSuccess)
		c.Put(q, resp)
	}

	// Add one more — should evict oldest
	q4 := newQuery("domaind.com.", dns.TypeA)
	resp4 := newResponse("domaind.com.", dns.TypeA, 300, dns.RcodeSuccess)
	c.Put(q4, resp4)

	// domaina should be evicted (oldest expiresAt)
	qA := newQuery("domaina.com.", dns.TypeA)
	if got := c.Get(qA); got != nil {
		t.Error("expected domaina to be evicted")
	}

	// domaind should be present
	if got := c.Get(q4); got == nil {
		t.Error("expected domaind to be cached")
	}
}

func TestCacheKeyGeneration(t *testing.T) {
	q1 := newQuery("example.com.", dns.TypeA)
	q2 := newQuery("example.com.", dns.TypeAAAA)

	k1 := cacheKey(q1)
	k2 := cacheKey(q2)

	if k1 == k2 {
		t.Error("different query types should have different cache keys")
	}
	if k1 != "example.com.:A" {
		t.Errorf("expected cache key 'example.com.:A', got %q", k1)
	}
}

func TestCacheEmptyQuestion(t *testing.T) {
	c := newTestCache(100, 300, 60)
	q := new(dns.Msg) // No question
	resp := newResponse("example.com.", dns.TypeA, 300, dns.RcodeSuccess)

	c.Put(q, resp) // Should be no-op
	if got := c.Get(q); got != nil {
		t.Error("cache with empty question should not store/return")
	}
}
