package detectors

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

// ApplePinningConfig configures the Apple ASN/IP pinning detector.
type ApplePinningConfig struct {
	Enabled       bool   `yaml:"enabled"`
	PinFile       string `yaml:"pin_file"`       // path to pin data file (CIDR ranges)
	WatchlistFile string `yaml:"watchlist_file"` // path to Apple domain watchlist
}

// ApplePinningDetector verifies that responses for known Apple/critical
// domains resolve to IPs within expected ASN ranges. This catches DNS
// poisoning that returns attacker-controlled public IPs (not just private).
type ApplePinningDetector struct {
	cfg        ApplePinningConfig
	networks   []*net.IPNet        // allowed CIDR ranges for pinned domains
	watchlist  map[string]bool     // set of domains subject to pinning
	mu         sync.RWMutex
}

// ApplePinningFinding represents a detected violation.
type ApplePinningFinding struct {
	Domain    string
	IP        string
	Reason    string
	Detail    string
}

func NewApplePinningDetector(cfg ApplePinningConfig) *ApplePinningDetector {
	d := &ApplePinningDetector{
		cfg:       cfg,
		watchlist: make(map[string]bool),
	}

	if !cfg.Enabled {
		return d
	}

	// Load pinned IP ranges
	if cfg.PinFile != "" {
		nets, err := loadCIDRFile(cfg.PinFile)
		if err != nil {
			log.Printf("Apple pinning: failed to load pin file %s: %v", cfg.PinFile, err)
		} else {
			d.networks = nets
			log.Printf("Apple pinning: loaded %d CIDR ranges from %s", len(nets), cfg.PinFile)
		}
	}

	// Load Apple domain watchlist
	if cfg.WatchlistFile != "" {
		wl, err := loadWatchlistFile(cfg.WatchlistFile)
		if err != nil {
			log.Printf("Apple pinning: failed to load watchlist %s: %v", cfg.WatchlistFile, err)
		} else {
			d.watchlist = wl
			log.Printf("Apple pinning: loaded %d watched domains from %s", len(wl), cfg.WatchlistFile)
		}
	}

	// If no files loaded, use embedded defaults
	if len(d.networks) == 0 {
		d.networks = defaultAppleNetworks()
		log.Printf("Apple pinning: using %d embedded default CIDR ranges", len(d.networks))
	}
	if len(d.watchlist) == 0 {
		d.watchlist = defaultAppleWatchlist()
		log.Printf("Apple pinning: using %d embedded default watched domains", len(d.watchlist))
	}

	return d
}

// CheckResponse examines a DNS response for pinned domains and verifies
// resolved IPs fall within expected ranges. Returns nil if clean.
func (d *ApplePinningDetector) CheckResponse(resp *dns.Msg) *ApplePinningFinding {
	if !d.cfg.Enabled || resp == nil || len(resp.Question) == 0 {
		return nil
	}

	queryDomain := strings.TrimSuffix(strings.ToLower(resp.Question[0].Name), ".")

	// Check if this domain is in our watchlist (exact or suffix match)
	if !d.isDomainWatched(queryDomain) {
		return nil
	}

	// Check all A/AAAA records against pinned ranges
	for _, rr := range resp.Answer {
		var ipStr string
		switch v := rr.(type) {
		case *dns.A:
			ipStr = v.A.String()
		case *dns.AAAA:
			ipStr = v.AAAA.String()
		default:
			continue
		}

		// Skip private IPs — those are caught by rebinding detector
		if IsPrivateIP(ipStr) {
			continue
		}

		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}

		if !d.isIPAllowed(ip) {
			return &ApplePinningFinding{
				Domain: queryDomain,
				IP:     ipStr,
				Reason: "asn_pin_violation",
				Detail: fmt.Sprintf(
					"Apple domain %s resolved to %s which is outside known Apple/CDN IP ranges — possible DNS poisoning with attacker-controlled public IP",
					queryDomain, ipStr,
				),
			}
		}
	}

	return nil
}

// isDomainWatched checks if a domain matches the watchlist (exact or suffix).
func (d *ApplePinningDetector) isDomainWatched(domain string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()

	// Exact match
	if d.watchlist[domain] {
		return true
	}

	// Suffix match (e.g., "anything.apple.com" matches "apple.com" entry)
	parts := strings.Split(domain, ".")
	for i := 1; i < len(parts); i++ {
		parent := strings.Join(parts[i:], ".")
		if d.watchlist[parent] {
			return true
		}
	}

	return false
}

// isIPAllowed checks if an IP is within any of the pinned CIDR ranges.
func (d *ApplePinningDetector) isIPAllowed(ip net.IP) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()

	for _, network := range d.networks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// ReloadPins reloads pin data from files (for hot-reload).
func (d *ApplePinningDetector) ReloadPins() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.cfg.PinFile != "" {
		nets, err := loadCIDRFile(d.cfg.PinFile)
		if err != nil {
			return fmt.Errorf("reload pin file: %w", err)
		}
		d.networks = nets
	}

	if d.cfg.WatchlistFile != "" {
		wl, err := loadWatchlistFile(d.cfg.WatchlistFile)
		if err != nil {
			return fmt.Errorf("reload watchlist: %w", err)
		}
		d.watchlist = wl
	}

	return nil
}

// --- File loaders ---

func loadCIDRFile(path string) ([]*net.IPNet, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var nets []*net.IPNet
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Handle bare IPs (add /32 or /128)
		if !strings.Contains(line, "/") {
			ip := net.ParseIP(line)
			if ip == nil {
				continue
			}
			if ip.To4() != nil {
				line += "/32"
			} else {
				line += "/128"
			}
		}
		_, network, err := net.ParseCIDR(line)
		if err != nil {
			continue
		}
		nets = append(nets, network)
	}
	return nets, scanner.Err()
}

func loadWatchlistFile(path string) (map[string]bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	wl := make(map[string]bool)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Strip trailing dot if present
		line = strings.TrimSuffix(line, ".")
		wl[strings.ToLower(line)] = true
	}
	return wl, scanner.Err()
}

// --- Embedded defaults ---
// These are used if no external files are configured.

func defaultAppleNetworks() []*net.IPNet {
	cidrs := []string{
		// Apple Inc (AS714) - primary ranges
		"17.0.0.0/8",
		// Apple IPv6
		"2620:149::/32",
		"2a01:b740::/32",
		// Akamai (Apple CDN partner) - major ranges
		"23.0.0.0/12",
		"23.32.0.0/11",
		"23.64.0.0/14",
		"23.192.0.0/11",
		"104.64.0.0/10",
		"184.24.0.0/13",
		"184.50.0.0/15",
		"184.84.0.0/14",
		// Cloudflare (sometimes used by Apple)
		"104.16.0.0/13",
		"104.24.0.0/14",
		"172.64.0.0/13",
		"173.245.48.0/20",
		"188.114.96.0/20",
		"190.93.240.0/20",
		"197.234.240.0/22",
		"198.41.128.0/17",
		// Fastly (Apple CDN partner)
		"151.101.0.0/16",
		"199.232.0.0/16",
		// Amazon CloudFront (Apple uses for some services)
		"13.32.0.0/15",
		"13.224.0.0/14",
		"18.64.0.0/14",
		"52.84.0.0/15",
		"54.182.0.0/16",
		"54.192.0.0/16",
		"54.230.0.0/16",
		"54.239.128.0/18",
		"99.84.0.0/16",
		"143.204.0.0/16",
		"205.251.192.0/19",
		// Google (Apple Maps/some services)
		"142.250.0.0/15",
		"172.217.0.0/16",
		"216.58.192.0/19",
	}

	var nets []*net.IPNet
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		nets = append(nets, network)
	}
	return nets
}

func defaultAppleWatchlist() map[string]bool {
	domains := []string{
		// Certificate & Trust
		"ocsp.apple.com",
		"crl.apple.com",
		"valid.apple.com",
		// Software Updates
		"mesu.apple.com",
		"swscan.apple.com",
		"swdist.apple.com",
		"updates-http.cdn-apple.com",
		"updates.cdn-apple.com",
		"osrecovery.apple.com",
		"oscdn.apple.com",
		// Activation & Identity
		"albert.apple.com",
		"gs.apple.com",
		"identity.apple.com",
		"gsa.apple.com",
		"setup.icloud.com",
		// Push Notifications
		"courier.push.apple.com",
		"init-p01st.push.apple.com",
		// iCloud & Data
		"gateway.icloud.com",
		"keyvalueservice.icloud.com",
		"ckdatabase.icloud.com",
		// Telemetry
		"xp.apple.com",
		"metrics.apple.com",
		// Developer & App Store
		"ppq.apple.com",
		"buy.itunes.apple.com",
		"apps.apple.com",
		"itunes.apple.com",
		// Network & Configuration
		"configuration.apple.com",
		"captive.apple.com",
		"lcdn-registration.apple.com",
		// Gatekeeper / Notarization
		"api.apple-cloudkit.com",
		// Wildcard parent domains (suffix matching catches subdomains)
		"apple.com",
		"icloud.com",
		"icloud-content.com",
		"apple-cloudkit.com",
		"cdn-apple.com",
		"push.apple.com",
		"mzstatic.com",
	}

	wl := make(map[string]bool, len(domains))
	for _, d := range domains {
		wl[d] = true
	}
	return wl
}
