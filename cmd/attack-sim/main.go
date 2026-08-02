package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

const banner = `
╔══════════════════════════════════════════════╗
║   DNS Attack Simulator — Castiel              ║
║   Attack traffic generator for Castiel testing║
╚══════════════════════════════════════════════╝
`

// Scenario represents a DNS attack test scenario.
type Scenario struct {
	Name        string
	Description string
	Run         func(ctx context.Context, target string, stats *Stats)
}

// Stats tracks query results across all scenarios.
type Stats struct {
	Total       atomic.Int64
	Blocked     atomic.Int64
	ServFail    atomic.Int64
	Success     atomic.Int64
	RateLimited atomic.Int64
	Errors      atomic.Int64

	mu     sync.Mutex
	byType map[string]*typeStats
}

type typeStats struct {
	total   int64
	blocked int64
}

func NewStats() *Stats {
	return &Stats{byType: make(map[string]*typeStats)}
}

func (s *Stats) Record(scenario string, rcode int) {
	s.Total.Add(1)
	s.mu.Lock()
	if _, ok := s.byType[scenario]; !ok {
		s.byType[scenario] = &typeStats{}
	}
	s.byType[scenario].total++
	s.mu.Unlock()

	switch rcode {
	case dns.RcodeSuccess:
		s.Success.Add(1)
	case dns.RcodeNameError: // NXDOMAIN — blocked
		s.Blocked.Add(1)
		s.mu.Lock()
		s.byType[scenario].blocked++
		s.mu.Unlock()
	case dns.RcodeRefused:
		s.Blocked.Add(1)
		s.mu.Lock()
		s.byType[scenario].blocked++
		s.mu.Unlock()
	case dns.RcodeServerFailure:
		s.ServFail.Add(1)
	default:
		s.Errors.Add(1)
	}
}

func (s *Stats) Print() {
	total := s.Total.Load()
	blocked := s.Blocked.Load()
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println(" ATTACK SIMULATION RESULTS")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf(" Total queries:     %d\n", total)
	fmt.Printf(" Success (pass):    %d\n", s.Success.Load())
	fmt.Printf(" Blocked (NXDOMAIN):%d\n", blocked)
	fmt.Printf(" Server failure:    %d\n", s.ServFail.Load())
	fmt.Printf(" Errors:            %d\n", s.Errors.Load())
	if total > 0 {
		fmt.Printf(" Block rate:        %.1f%%\n", float64(blocked)/float64(total)*100)
	}
	fmt.Println(strings.Repeat("-", 60))
	fmt.Println(" Per-scenario breakdown:")
	s.mu.Lock()
	for name, ts := range s.byType {
		blockRate := 0.0
		if ts.total > 0 {
			blockRate = float64(ts.blocked) / float64(ts.total) * 100
		}
		fmt.Printf("  %-25s %6d queries, %6d blocked (%5.1f%%)\n", name, ts.total, ts.blocked, blockRate)
	}
	s.mu.Unlock()
	fmt.Println(strings.Repeat("=", 60))
}

var (
	qps int
)

func main() {
	fmt.Print(banner)

	target := flag.String("target", "127.0.0.1:5300", "Castiel proxy address (ip:port)")
	scenario := flag.String("scenario", "all", "Scenario: all, normal, dga, tunneling, ratelimit, nxdomain, axfr, blocklist, rebinding, c2")
	duration := flag.Duration("duration", 30*time.Second, "Duration to run")
	concurrency := flag.Int("concurrency", 10, "Concurrent workers")
	flag.IntVar(&qps, "qps", 50, "Queries per second per worker (0 = max speed)")
	flag.Parse()

	fmt.Printf(" Target:       %s\n", *target)
	fmt.Printf(" Scenario:     %s\n", *scenario)
	fmt.Printf(" Duration:     %s\n", *duration)
	fmt.Printf(" Concurrency:  %d workers\n", *concurrency)
	fmt.Printf(" QPS/worker:   %d (0=max)\n", qps)
	fmt.Println(strings.Repeat("-", 60))

	stats := NewStats()
	ctx, cancel := context.WithTimeout(context.Background(), *duration)
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		cancel()
	}()

	scenarios := getScenarios(*scenario)
	var wg sync.WaitGroup

	for _, sc := range scenarios {
		fmt.Printf("\n[*] Running scenario: %s\n", sc.Name)
		fmt.Printf("    %s\n", sc.Description)

		for i := 0; i < *concurrency; i++ {
			wg.Add(1)
			go func(s Scenario, workerID int) {
				defer wg.Done()
				s.Run(ctx, *target, stats)
			}(sc, i)
		}
	}

	// Progress ticker
	ticker := time.NewTicker(5 * time.Second)
	go func() {
		for {
			select {
			case <-ticker.C:
				fmt.Printf("  [progress] %d queries sent, %d blocked, %d success\n",
					stats.Total.Load(), stats.Blocked.Load(), stats.Success.Load())
			case <-ctx.Done():
				ticker.Stop()
				return
			}
		}
	}()

	wg.Wait()
	stats.Print()
}

func getScenarios(name string) []Scenario {
	all := []Scenario{
		{Name: "normal", Description: "Normal DNS queries to legitimate domains", Run: runNormal},
		{Name: "dga", Description: "DGA-style random domain queries", Run: runDGA},
		{Name: "tunneling", Description: "DNS tunneling via high-entropy subdomains", Run: runTunneling},
		{Name: "ratelimit", Description: "Rapid-fire queries to trigger rate limiting", Run: runRateLimit},
		{Name: "nxdomain", Description: "NXDOMAIN flood with non-existent domains", Run: runNXDomain},
		{Name: "axfr", Description: "Zone transfer attempts (AXFR)", Run: runAXFR},
		{Name: "blocklist", Description: "Queries to known-malicious blocklisted domains", Run: runBlocklist},
		{Name: "rebinding", Description: "DNS rebinding test queries", Run: runRebinding},
		{Name: "c2", Description: "C2 fast-flux pattern queries", Run: runC2},
	}

	if name == "all" {
		return all
	}
	for _, s := range all {
		if s.Name == name {
			return []Scenario{s}
		}
	}
	fmt.Fprintf(os.Stderr, "Unknown scenario: %s\n", name)
	os.Exit(1)
	return nil
}

// sendQuery sends a DNS query and returns the response code.
func sendQuery(target string, msg *dns.Msg) int {
	c := new(dns.Client)
	c.Timeout = 3 * time.Second
	c.Net = "udp"

	resp, _, err := c.Exchange(msg, target)
	if err != nil {
		return -1
	}
	return resp.Rcode
}

func makeQuery(domain string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), qtype)
	m.RecursionDesired = true
	return m
}

func rateControl(ctx context.Context, qps int, interval *time.Ticker) {
	if qps <= 0 {
		return
	}
	select {
	case <-interval.C:
	case <-ctx.Done():
	}
}

// --- Scenarios ---

func runNormal(ctx context.Context, target string, stats *Stats) {
	domains := []string{
		"google.com", "apple.com", "github.com", "cloudflare.com",
		"amazon.com", "microsoft.com", "netflix.com", "youtube.com",
		"reddit.com", "twitter.com", "linkedin.com", "stackoverflow.com",
		"example.com", "wikipedia.org", "mozilla.org", "golang.org",
		"python.org", "rust-lang.org", "nodejs.org", "docker.com",
	}
	idx := 0
	var interval *time.Ticker
	if qps > 0 {
		interval = time.NewTicker(time.Second / time.Duration(qps))
		defer interval.Stop()
	}
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		d := domains[idx%len(domains)]
		idx++
		rcode := sendQuery(target, makeQuery(d, dns.TypeA))
		stats.Record("normal", rcode)
		rateControl(ctx, qps, interval)
	}
}

func runDGA(ctx context.Context, target string, stats *Stats) {
	tlds := []string{".com", ".net", ".org", ".info", ".xyz", ".top", ".click", ".tk", ".ml", ".ga"}
	var interval *time.Ticker
	if qps > 0 {
		interval = time.NewTicker(time.Second / time.Duration(qps))
		defer interval.Stop()
	}
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		// Generate DGA-like domain: random consonant-heavy string
		length := 12 + randInt(8)
		domain := randomDGA(length) + tlds[randInt(len(tlds))]
		rcode := sendQuery(target, makeQuery(domain, dns.TypeA))
		stats.Record("dga", rcode)
		rateControl(ctx, qps, interval)
	}
}

func runTunneling(ctx context.Context, target string, stats *Stats) {
	bases := []string{"tunnel.evil.com", "exfil.bad.net", "data.malware.org"}
	var interval *time.Ticker
	if qps > 0 {
		interval = time.NewTicker(time.Second / time.Duration(qps))
		defer interval.Stop()
	}
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		// High-entropy subdomain (simulates DNS tunneling payload)
		payload := randomHex(30) // 60 chars of hex = high entropy
		base := bases[randInt(len(bases))]
		domain := payload + "." + base
		rcode := sendQuery(target, makeQuery(domain, dns.TypeA))
		stats.Record("tunneling", rcode)
		rateControl(ctx, qps, interval)
	}
}

func runRateLimit(ctx context.Context, target string, stats *Stats) {
	// No rate control — max speed to trigger rate limiting
	domains := []string{"test1.com", "test2.com", "test3.com", "test4.com", "test5.com"}
	idx := 0
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		d := domains[idx%len(domains)]
		idx++
		rcode := sendQuery(target, makeQuery(d, dns.TypeA))
		stats.Record("ratelimit", rcode)
	}
}

func runNXDomain(ctx context.Context, target string, stats *Stats) {
	var interval *time.Ticker
	if qps > 0 {
		interval = time.NewTicker(time.Second / time.Duration(qps))
		defer interval.Stop()
	}
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		// Generate random non-existent domains
		domain := "nonexistent-" + randomHex(8) + ".invalid"
		rcode := sendQuery(target, makeQuery(domain, dns.TypeA))
		stats.Record("nxdomain", rcode)
		rateControl(ctx, qps, interval)
	}
}

func runAXFR(ctx context.Context, target string, stats *Stats) {
	domains := []string{"example.com", "test.com", "internal.corp", "company.local"}
	idx := 0
	var interval *time.Ticker
	if qps > 0 {
		interval = time.NewTicker(time.Second / time.Duration(qps))
		defer interval.Stop()
	}
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		d := domains[idx%len(domains)]
		idx++
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(d), dns.TypeAXFR)
		m.RecursionDesired = false
		rcode := sendQuery(target, m)
		stats.Record("axfr", rcode)
		rateControl(ctx, qps, interval)
	}
}

func runBlocklist(ctx context.Context, target string, stats *Stats) {
	// Known-malicious domains that should be in blocklists
	domains := []string{
		"malware.com", "phishing-site.com", "evil.ru",
		"bad-actor.cn", "c2-server.net", "botnet.org",
		"spam-site.info", "scam-page.tk", "fake-bank.ml",
		"exploit-kit.ga", "ransomware-c2.onion.ws",
		"adserver.malicious.com", "tracker.evil.net",
		"popup.bad-ads.com", "malicious-download.org",
	}
	idx := 0
	var interval *time.Ticker
	if qps > 0 {
		interval = time.NewTicker(time.Second / time.Duration(qps))
		defer interval.Stop()
	}
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		d := domains[idx%len(domains)]
		idx++
		rcode := sendQuery(target, makeQuery(d, dns.TypeA))
		stats.Record("blocklist", rcode)
		rateControl(ctx, qps, interval)
	}
}

func runRebinding(ctx context.Context, target string, stats *Stats) {
	// Query domains that might resolve to private IPs
	domains := []string{
		"rebind.test.attacker.com", "private.evil.net",
		"internal.rebind.org", "localhost.bad.com",
		"169.254.169.254.nip.io", "10.0.0.1.nip.io",
		"192.168.1.1.nip.io", "172.16.0.1.nip.io",
	}
	idx := 0
	var interval *time.Ticker
	if qps > 0 {
		interval = time.NewTicker(time.Second / time.Duration(qps))
		defer interval.Stop()
	}
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		d := domains[idx%len(domains)]
		idx++
		rcode := sendQuery(target, makeQuery(d, dns.TypeA))
		stats.Record("rebinding", rcode)
		rateControl(ctx, qps, interval)
	}
}

func runC2(ctx context.Context, target string, stats *Stats) {
	// C2 fast-flux: query same domain rapidly to observe IP diversity / TTL volatility
	domains := []string{
		"fastflux.botnet.com", "c2-beacon.malware.net",
		"flux-c2.evil.org", "dga-c2.bad.ru",
	}
	idx := 0
	var interval *time.Ticker
	if qps > 0 {
		interval = time.NewTicker(time.Second / time.Duration(qps))
		defer interval.Stop()
	}
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		d := domains[idx%len(domains)]
		idx++
		// Query both A and AAAA to track IP diversity
		rcode := sendQuery(target, makeQuery(d, dns.TypeA))
		stats.Record("c2", rcode)
		rcode2 := sendQuery(target, makeQuery(d, dns.TypeAAAA))
		stats.Record("c2", rcode2)
		rateControl(ctx, qps, interval)
	}
}

// --- Helpers ---

func randInt(max int) int {
	if max <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0
	}
	return int(n.Int64())
}

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func randomDGA(length int) string {
	consonants := "bcdfghjklmnpqrstvwxyz"
	vowels := "aeiou"
	result := make([]byte, length)
	for i := 0; i < length; i++ {
		if i%3 == 1 {
			result[i] = vowels[randInt(len(vowels))]
		} else {
			result[i] = consonants[randInt(len(consonants))]
		}
		// Occasionally insert digits (DGA families often do)
		if i > 4 && randInt(10) == 0 {
			result[i] = byte('0' + randInt(10))
		}
	}
	return string(result)
}

// Ensure net import is used
var _ = net.ParseIP
