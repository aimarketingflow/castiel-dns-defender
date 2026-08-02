package dnsproxy

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/castiel/dns/internal/alerts"
	"github.com/castiel/dns/internal/blocklists"
	"github.com/castiel/dns/internal/cache"
	"github.com/castiel/dns/internal/config"
	"github.com/castiel/dns/internal/detectors"
	"github.com/castiel/dns/internal/dnssec"
	"github.com/castiel/dns/internal/metrics"
	"github.com/miekg/dns"
)

type Proxy struct {
	cfg         *config.Config
	blocklists  *blocklists.Manager
	alerts      *alerts.Manager
	cache       *cache.Cache
	entropy     *detectors.EntropyDetector
	dga         *detectors.DGADetector
	ratelimit   *detectors.RateLimiter
	rebinding   *detectors.RebindingDetector
	c2          *detectors.C2Detector
	server         *dns.Server
	client         *dns.Client
	dohClient      *DoHClient
	dnssecValidator *dnssec.Validator
	upstreamIdx    int
	mu             sync.Mutex
	connPool       map[string]*dns.Conn // per-upstream connection pool
	connPoolMu     sync.Mutex
	queryBatch     chan *batchEntry     // query batching channel
	batchTimer     *time.Ticker
	batchSize      int
}

type batchEntry struct {
	msg    *dns.Msg
	writer dns.ResponseWriter
	start  time.Time
}

func New(cfg *config.Config, bl *blocklists.Manager, am *alerts.Manager) (*Proxy, error) {
	p := &Proxy{
		cfg:        cfg,
		blocklists: bl,
		alerts:     am,
		cache:      cache.New(cfg.Cache),
		entropy:    detectors.NewEntropyDetector(cfg.TunnelingDetection),
		dga:        detectors.NewDGADetector(cfg.DGADetection),
		ratelimit:  detectors.NewRateLimiter(cfg.RateLimit),
		rebinding:  detectors.NewRebindingDetector(cfg.RebindingProtection),
		c2:         detectors.NewC2Detector(cfg.C2Detection),
		client: &dns.Client{
			Timeout: cfg.Server.TimeoutDuration(),
			UDPSize: 4096,
		},
		connPool:  make(map[string]*dns.Conn),
		batchSize: 16,
	}

	// Initialize DoH client if enabled
	if cfg.Server.UseDoH && cfg.Server.DoHUpstream != "" {
		p.dohClient = NewDoHClient(cfg.Server.DoHUpstream, cfg.Server.TimeoutDuration())
		log.Printf("DoH client initialized: %s", cfg.Server.DoHUpstream)
	}

	// Initialize DNSSEC validator (falls back to AD-bit-only mode if trust anchors unavailable)
	if cfg.DNSSEC.Enabled {
		p.dnssecValidator = dnssec.NewValidator(cfg.DNSSEC.TrustAnchorFile, cfg.Server.Upstream, cfg.Server.TimeoutDuration())
	}

	return p, nil
}

func (p *Proxy) Start(ctx context.Context) error {
	addr := fmt.Sprintf("%s:%d", p.cfg.Server.ListenAddr, p.cfg.Server.ListenPort)
	p.server = &dns.Server{
		Addr:    addr,
		Net:     "udp",
		Handler: dns.HandlerFunc(p.handleDNS),
	}

	errCh := make(chan error, 1)
	go func() {
		if err := p.server.ListenAndServe(); err != nil {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		p.server.Shutdown()
		return nil
	}
}

func (p *Proxy) handleDNS(w dns.ResponseWriter, r *dns.Msg) {
	startTime := time.Now()
	clientIP := p.extractClientIP(w.RemoteAddr())

	metrics.TotalQueries.Inc()

	// 1. Rate limit check
	if p.cfg.RateLimit.Enabled {
		if action := p.ratelimit.Check(clientIP); action != detectors.ActionAllow {
			metrics.RateLimitedQueries.Inc()
			p.alerts.Send(alerts.Alert{
				Type:     "rate_limit",
				Severity: "warn",
				Source:   clientIP,
				Message:  fmt.Sprintf("Rate limit exceeded for %s", clientIP),
				Time:     startTime,
			})
			if action == detectors.ActionDrop {
				w.Close()
				return
			}
			// ActionTruncate: send empty response with TC=1
			p.sendTruncated(w, r)
			return
		}
	}

	// 2. Zone transfer blocking
	if p.cfg.ZoneTransfer.BlockAXFR || p.cfg.ZoneTransfer.BlockIXFR {
		for _, q := range r.Question {
			if (q.Qtype == dns.TypeAXFR && p.cfg.ZoneTransfer.BlockAXFR) ||
				(q.Qtype == dns.TypeIXFR && p.cfg.ZoneTransfer.BlockIXFR) {
				metrics.BlockedQueries.WithLabelValues("zone_transfer").Inc()
				p.alerts.Send(alerts.Alert{
					Type:     "zone_transfer",
					Severity: "critical",
					Source:   clientIP,
					Message:  fmt.Sprintf("Blocked zone transfer (%s) for %s from %s", dns.TypeToString[q.Qtype], q.Name, clientIP),
					Time:     startTime,
				})
				if !p.cfg.ZoneTransfer.AlertOnly {
					p.sendRefused(w, r)
					return
				}
			}
		}
	}

	// Process each question
	for _, q := range r.Question {
		domain := strings.TrimSuffix(q.Name, ".")

		// 3. Blocklist check
		if p.cfg.Blocklists.Enabled && p.blocklists.IsBlocked(domain) {
			metrics.BlockedQueries.WithLabelValues("blocklist").Inc()
			p.alerts.Send(alerts.Alert{
				Type:     "blocklist_hit",
				Severity: "warn",
				Source:   clientIP,
				Domain:   domain,
				Message:  fmt.Sprintf("Blocked domain %s (blocklist match)", domain),
				Time:     startTime,
			})
			p.sendBlocked(w, r)
			return
		}

		// 4. Tunneling detection (entropy)
		if p.cfg.TunnelingDetection.Enabled {
			if p.entropy.IsTunneling(domain) {
				metrics.BlockedQueries.WithLabelValues("tunneling").Inc()
				p.alerts.Send(alerts.Alert{
					Type:     "dns_tunneling",
					Severity: "critical",
					Source:   clientIP,
					Domain:   domain,
					Message:  fmt.Sprintf("DNS tunneling detected: %s (high entropy subdomain)", domain),
					Time:     startTime,
				})
				p.sendBlocked(w, r)
				return
			}
		}

		// 5. DGA detection
		if p.cfg.DGADetection.Enabled {
			if p.dga.IsDGA(domain) {
				metrics.BlockedQueries.WithLabelValues("dga").Inc()
				p.alerts.Send(alerts.Alert{
					Type:     "dga_detected",
					Severity: "critical",
					Source:   clientIP,
					Domain:   domain,
					Message:  fmt.Sprintf("DGA domain detected: %s (entropy=%.2f)", domain, p.dga.LastEntropy()),
					Time:     startTime,
				})
				p.sendBlocked(w, r)
				return
			}
		}

		// 6. C2 / fast-flux detection
		if p.cfg.C2Detection.Enabled {
			if p.c2.IsSuspicious(domain) {
				metrics.BlockedQueries.WithLabelValues("c2_fastflux").Inc()
				p.alerts.Send(alerts.Alert{
					Type:     "c2_fastflux",
					Severity: "critical",
					Source:   clientIP,
					Domain:   domain,
					Message:  fmt.Sprintf("C2/fast-flux suspected: %s (TTL volatility + IP diversity)", domain),
					Time:     startTime,
				})
				p.sendBlocked(w, r)
				return
			}
		}
	}

	// 7. Cache check
	if p.cfg.Cache.Enabled {
		if cached := p.cache.Get(r); cached != nil {
			metrics.CacheHits.Inc()
			cached.Id = r.Id
			w.WriteMsg(cached)
			return
		}
		metrics.CacheMisses.Inc()
	}

	// 8. Forward to upstream
	resp, err := p.forwardUpstream(r)
	if err != nil {
		log.Printf("Upstream error: %v", err)
		p.sendServFail(w, r)
		return
	}

	// 9. DNSSEC validation
	if p.cfg.DNSSEC.Enabled && p.cfg.DNSSEC.RejectBogus {
		queryDomain := ""
		if len(r.Question) > 0 {
			queryDomain = strings.TrimSuffix(r.Question[0].Name, ".")
		}
		if resp.Rcode == dns.RcodeSuccess && !p.validateDNSSEC(resp, queryDomain) {
			metrics.BlockedQueries.WithLabelValues("dnssec_fail").Inc()
			metrics.DNSSECValidations.WithLabelValues("bogus").Inc()
			p.alerts.Send(alerts.Alert{
				Type:     "dnssec_validation_fail",
				Severity: "critical",
				Source:   clientIP,
				Message:  "DNSSEC validation failed - possible cache poisoning",
				Time:     startTime,
			})
			p.sendServFail(w, r)
			return
		}
		metrics.DNSSECValidations.WithLabelValues("valid").Inc()
	}

	// 10. DNS rebinding protection
	if p.cfg.RebindingProtection.Enabled && p.cfg.RebindingProtection.BlockPublicToPrivate {
		if p.rebinding.IsRebinding(resp) {
			metrics.BlockedQueries.WithLabelValues("rebinding").Inc()
			p.alerts.Send(alerts.Alert{
				Type:     "dns_rebinding",
				Severity: "critical",
				Source:   clientIP,
				Message:  fmt.Sprintf("DNS rebinding blocked: public domain resolving to private IP"),
				Time:     startTime,
			})
			p.sendBlocked(w, r)
			return
		}
	}

	// 11. Cache the response
	if p.cfg.Cache.Enabled {
		p.cache.Put(r, resp)
	}

	// 12. Send response to client
	w.WriteMsg(resp)
	elapsed := time.Since(startTime)
	metrics.QueryDuration.Observe(elapsed.Seconds())
}

func (p *Proxy) forwardUpstream(r *dns.Msg) (*dns.Msg, error) {
	// Try DoH first if enabled and healthy
	if p.cfg.Server.UseDoH && p.dohClient != nil && p.dohClient.IsEnabled() {
		resp, err := p.dohClient.Exchange(r)
		if err == nil {
			metrics.DoHQueries.Inc()
			return resp, nil
		}
		log.Printf("DoH exchange failed, falling back to plain DNS: %v", err)
		metrics.DoHFailures.Inc()
		// Fall through to plain DNS
	}
	return p.forwardPlainDNS(r)
}

func (p *Proxy) forwardPlainDNS(r *dns.Msg) (*dns.Msg, error) {
	p.mu.Lock()
	idx := p.upstreamIdx
	p.upstreamIdx = (p.upstreamIdx + 1) % len(p.cfg.Server.Upstream)
	p.mu.Unlock()

	upstream := p.cfg.Server.Upstream[idx]

	// Try pooled connection first (TCP for reliability)
	resp, err := p.exchangePooled(upstream, r)
	if err == nil {
		return resp, nil
	}

	// Fallback: direct UDP exchange, then try other upstreams
	resp, _, err = p.client.Exchange(r, upstream)
	if err == nil {
		return resp, nil
	}

	// Try remaining upstreams
	for i := 0; i < len(p.cfg.Server.Upstream)-1; i++ {
		nextIdx := (idx + i + 1) % len(p.cfg.Server.Upstream)
		nextUpstream := p.cfg.Server.Upstream[nextIdx]
		resp, _, err = p.client.Exchange(r, nextUpstream)
		if err == nil {
			return resp, nil
		}
		metrics.UpstreamFailures.WithLabelValues(nextUpstream).Inc()
	}
	metrics.UpstreamFailures.WithLabelValues(upstream).Inc()
	return nil, err
}

// exchangePooled uses a persistent TCP connection per upstream for reduced latency.
// Falls back to creating a new connection if the pooled one is stale.
func (p *Proxy) exchangePooled(upstream string, r *dns.Msg) (*dns.Msg, error) {
	p.connPoolMu.Lock()
	conn, exists := p.connPool[upstream]
	p.connPoolMu.Unlock()

	if exists {
		// Try to reuse the pooled connection
		if err := conn.WriteMsg(r); err == nil {
			if resp, err := conn.ReadMsg(); err == nil {
				return resp, nil
			}
		}
		// Stale connection — close and remove
		conn.Close()
		p.connPoolMu.Lock()
		delete(p.connPool, upstream)
		p.connPoolMu.Unlock()
	}

	// Create new persistent TCP connection
	newConn, err := dns.DialTimeout("tcp", upstream, p.cfg.Server.TimeoutDuration())
	if err != nil {
		return nil, err
	}

	// Set idle timeout on the connection
	newConn.SetReadDeadline(time.Now().Add(p.cfg.Server.TimeoutDuration()))

	if err := newConn.WriteMsg(r); err != nil {
		newConn.Close()
		return nil, err
	}

	resp, err := newConn.ReadMsg()
	if err != nil {
		newConn.Close()
		return nil, err
	}

	// Return connection to pool for reuse
	p.connPoolMu.Lock()
	// If another goroutine already created a connection, close the extra one
	if _, ok := p.connPool[upstream]; ok {
		newConn.Close()
	} else {
		p.connPool[upstream] = newConn
	}
	p.connPoolMu.Unlock()

	return resp, nil
}

// CloseConnPool closes all pooled upstream connections.
func (p *Proxy) CloseConnPool() {
	p.connPoolMu.Lock()
	defer p.connPoolMu.Unlock()
	for _, conn := range p.connPool {
		conn.Close()
	}
	p.connPool = make(map[string]*dns.Conn)
}

// DisableDoH instantly disables DoH and falls back to plain DNS.
// This is the kill switch — call it if DoH breaks internet connectivity.
func (p *Proxy) DisableDoH() {
	if p.dohClient != nil {
		p.dohClient.SetEnabled(false)
		metrics.DoHEnabled.Set(0)
	}
}

// EnableDoH re-enables DoH after it was disabled.
func (p *Proxy) EnableDoH() {
	if p.dohClient != nil {
		p.dohClient.SetEnabled(true)
		metrics.DoHEnabled.Set(1)
	}
}

// DoHEnabled returns whether DoH is currently active.
func (p *Proxy) DoHEnabled() bool {
	if p.dohClient == nil {
		return false
	}
	return p.dohClient.IsEnabled()
}

// StartDoHHealthChecker starts the periodic DoH health check goroutine.
func (p *Proxy) StartDoHHealthChecker(ctx context.Context) {
	if p.dohClient != nil {
		go p.dohClient.StartHealthChecker(ctx)
	}
}

func (p *Proxy) validateDNSSEC(resp *dns.Msg, qname string) bool {
	if p.dnssecValidator == nil {
		// No validator configured — fall back to AD-bit check only
		if resp == nil {
			return false
		}
		return resp.AuthenticatedData
	}
	return p.dnssecValidator.Validate(resp, qname)
}

func (p *Proxy) extractClientIP(addr net.Addr) string {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

func (p *Proxy) sendBlocked(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Rcode = dns.RcodeNameError
	w.WriteMsg(m)
}

func (p *Proxy) sendRefused(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Rcode = dns.RcodeRefused
	w.WriteMsg(m)
}

func (p *Proxy) sendServFail(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Rcode = dns.RcodeServerFailure
	w.WriteMsg(m)
}

func (p *Proxy) sendTruncated(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Truncated = true
	w.WriteMsg(m)
}
