package dnsproxy

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// DoHClient implements DNS-over-HTTPS (RFC 8484) forwarding.
// It sends DNS wire-format messages inside HTTPS POST requests
// to a DoH endpoint (e.g., https://cloudflare-dns.com/dns-query).
//
// Safety features:
//   - Health checking: probes DoH endpoint, auto-disables on repeated failures
//   - Automatic fallback to plain DNS when DoH is unhealthy
//   - Atomic enable/disable flag — can be toggled at runtime
//   - Kill switch: SetEnabled(false) instantly reverts to plain DNS
type DoHClient struct {
	endpoint       string
	httpClient     *http.Client
	enabled        atomic.Bool
	consecutiveFails atomic.Int64
	maxFails       int           // Auto-disable after this many consecutive failures
	healthInterval time.Duration // How often to re-check DoH health
	mu             sync.Mutex
	lastHealthCheck time.Time
}

// NewDoHClient creates a new DoH client with the given endpoint.
// DoH starts enabled but will be health-checked on first use.
func NewDoHClient(endpoint string, timeout time.Duration) *DoHClient {
	c := &DoHClient{
		endpoint: endpoint,
		httpClient: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				MaxIdleConns:        10,
				MaxIdleConnsPerHost: 5,
				IdleConnTimeout:     30 * time.Second,
				TLSHandshakeTimeout: 5 * time.Second,
			},
		},
		maxFails:       5,
		healthInterval: 30 * time.Second,
	}
	c.enabled.Store(true)
	return c
}

// IsEnabled returns whether DoH is currently active.
func (c *DoHClient) IsEnabled() bool {
	return c.enabled.Load()
}

// SetEnabled atomically enables or disables DoH.
// When disabled, all queries fall back to plain DNS.
func (c *DoHClient) SetEnabled(enabled bool) {
	old := c.enabled.Swap(enabled)
	if old != enabled {
		if enabled {
			log.Printf("DoH: ENABLED (endpoint: %s)", c.endpoint)
			c.consecutiveFails.Store(0)
		} else {
			log.Printf("DoH: DISABLED — falling back to plain DNS")
		}
	}
}

// Exchange sends a DNS query via DoH (HTTPS POST, application/dns-message).
// Returns the parsed DNS response or an error.
func (c *DoHClient) Exchange(msg *dns.Msg) (*dns.Msg, error) {
	if !c.enabled.Load() {
		return nil, fmt.Errorf("DoH disabled")
	}

	// Pack the DNS message into wire format
	wireData, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("packing DNS message: %w", err)
	}

	// DoH POST method: send wire-format DNS in HTTPS body
	req, err := http.NewRequest("POST", c.endpoint, bytes.NewReader(wireData))
	if err != nil {
		return nil, fmt.Errorf("creating DoH request: %w", err)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.recordFailure()
		return nil, fmt.Errorf("DoH request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		c.recordFailure()
		return nil, fmt.Errorf("DoH HTTP status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.recordFailure()
		return nil, fmt.Errorf("reading DoH response: %w", err)
	}

	if len(body) == 0 {
		c.recordFailure()
		return nil, fmt.Errorf("DoH response empty")
	}

	// Parse the wire-format response back into dns.Msg
	response := new(dns.Msg)
	if err := response.Unpack(body); err != nil {
		c.recordFailure()
		return nil, fmt.Errorf("unpacking DoH response: %w", err)
	}

	// Success — reset failure counter
	c.consecutiveFails.Store(0)
	return response, nil
}

// ExchangeGet sends a DNS query via DoH GET method (base64url in path).
// This is used as a fallback if POST is blocked by a middlebox.
func (c *DoHClient) ExchangeGet(msg *dns.Msg) (*dns.Msg, error) {
	if !c.enabled.Load() {
		return nil, fmt.Errorf("DoH disabled")
	}

	wireData, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("packing DNS message: %w", err)
	}

	// Base64url encode without padding (RFC 8484 GET method)
	b64 := base64.RawURLEncoding.EncodeToString(wireData)
	url := fmt.Sprintf("%s?dns=%s", c.endpoint, b64)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating DoH GET request: %w", err)
	}
	req.Header.Set("Accept", "application/dns-message")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.recordFailure()
		return nil, fmt.Errorf("DoH GET request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		c.recordFailure()
		return nil, fmt.Errorf("DoH GET HTTP status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.recordFailure()
		return nil, fmt.Errorf("reading DoH GET response: %w", err)
	}

	response := new(dns.Msg)
	if err := response.Unpack(body); err != nil {
		c.recordFailure()
		return nil, fmt.Errorf("unpacking DoH GET response: %w", err)
	}

	c.consecutiveFails.Store(0)
	return response, nil
}

// HealthCheck sends a test query to the DoH endpoint to verify connectivity.
// Returns true if the endpoint is healthy.
func (c *DoHClient) HealthCheck() bool {
	c.mu.Lock()
	if time.Since(c.lastHealthCheck) < c.healthInterval {
		c.mu.Unlock()
		return c.enabled.Load()
	}
	c.lastHealthCheck = time.Now()
	c.mu.Unlock()

	// Send a simple A query for "." (root) to test connectivity
	testMsg := new(dns.Msg)
	testMsg.SetQuestion(".", dns.TypeNS)
	testMsg.RecursionDesired = true

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Use a short-timeout client for health checks
	hcClient := &http.Client{Timeout: 5 * time.Second}

	wireData, err := testMsg.Pack()
	if err != nil {
		c.recordFailure()
		return false
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.endpoint, bytes.NewReader(wireData))
	if err != nil {
		c.recordFailure()
		return false
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := hcClient.Do(req)
	if err != nil {
		log.Printf("DoH health check FAILED: %v", err)
		c.recordFailure()
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("DoH health check FAILED: HTTP %d", resp.StatusCode)
		c.recordFailure()
		return false
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.recordFailure()
		return false
	}

	if len(body) == 0 {
		c.recordFailure()
		return false
	}

	// If we got here, DoH is healthy
	if !c.enabled.Load() {
		log.Printf("DoH health check PASSED — re-enabling DoH")
		c.SetEnabled(true)
	}
	c.consecutiveFails.Store(0)
	return true
}

// recordFailure increments the failure counter and auto-disables DoH
// if the threshold is reached.
func (c *DoHClient) recordFailure() {
	fails := c.consecutiveFails.Add(1)
	if fails >= int64(c.maxFails) && c.enabled.Load() {
		log.Printf("DoH: %d consecutive failures — AUTO-DISABLING, falling back to plain DNS", fails)
		c.SetEnabled(false)
	}
}

// StartHealthChecker runs a periodic health check goroutine.
// If DoH is disabled due to failures, this will attempt to re-enable it
// once the endpoint becomes healthy again.
func (c *DoHClient) StartHealthChecker(ctx context.Context) {
	ticker := time.NewTicker(c.healthInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.HealthCheck()
		}
	}
}
