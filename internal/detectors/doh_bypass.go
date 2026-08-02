package detectors

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// DoHBypassDetector monitors for DNS traffic that bypasses Castiel by
// going directly to known DoH/DoT resolver IPs over HTTPS/TLS.
// On macOS, this works alongside PF firewall rules to detect and block
// unauthorized DoH clients.
//
// Known DoH resolver IPs are checked against outbound connections.
// When traffic to these IPs is detected (and Castiel isn't the one making it),
// an alert is generated.
type DoHBypassDetector struct {
	mu             sync.Mutex
	knownDoHIPs    map[string]string // IP -> resolver name
	alertCooldown  time.Duration
	alertHistory   map[string]time.Time // IP -> last alert time
}

// NewDoHBypassDetector creates a detector with known public DoH resolver IPs.
func NewDoHBypassDetector() *DoHBypassDetector {
	d := &DoHBypassDetector{
		knownDoHIPs:   make(map[string]string),
		alertCooldown: 5 * time.Minute,
		alertHistory:  make(map[string]time.Time),
	}
	// Populate known DoH/DoT resolver IPs
	d.populateKnownResolvers()
	return d
}

// CheckDestinationIP returns a finding if the destination IP is a known DoH/DoT resolver
// that should only be accessed by Castiel itself.
func (d *DoHBypassDetector) CheckDestinationIP(ip string) *DoHBypassFinding {
	d.mu.Lock()
	defer d.mu.Unlock()

	resolver, isKnown := d.knownDoHIPs[ip]
	if !isKnown {
		return nil
	}

	// Check cooldown
	if lastAlert, exists := d.alertHistory[ip]; exists {
		if time.Since(lastAlert) < d.alertCooldown {
			return nil
		}
	}
	d.alertHistory[ip] = time.Now()

	return &DoHBypassFinding{
		ResolverIP:   ip,
		ResolverName: resolver,
		Detail:       fmt.Sprintf("DNS traffic to known DoH resolver %s (%s) bypassing Castiel proxy", ip, resolver),
	}
}

// IsKnownDoHResolver returns true if the IP is a known DoH/DoT resolver.
func (d *DoHBypassDetector) IsKnownDoHResolver(ip string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, exists := d.knownDoHIPs[ip]
	return exists
}

// AddResolver allows adding custom DoH resolver IPs to watch for.
func (d *DoHBypassDetector) AddResolver(ip, name string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.knownDoHIPs[ip] = name
}

// DoHBypassFinding represents a detected DoH bypass attempt.
type DoHBypassFinding struct {
	ResolverIP   string
	ResolverName string
	Detail       string
}

func (d *DoHBypassDetector) populateKnownResolvers() {
	// Google Public DNS (DoH: dns.google.com, 8.8.8.8:443, 8.8.4.4:443)
	d.knownDoHIPs["8.8.8.8"] = "Google Public DNS"
	d.knownDoHIPs["8.8.4.4"] = "Google Public DNS"
	// Google DoH dedicated IPs
	d.knownDoHIPs["8.8.8.8"] = "Google DoH"

	// Cloudflare (DoH: cloudflare-dns.com, 1.1.1.1:443, 1.0.0.1:443)
	d.knownDoHIPs["1.1.1.1"] = "Cloudflare DoH"
	d.knownDoHIPs["1.0.0.1"] = "Cloudflare DoH"

	// Quad9 (DoH: dns.quad9.net, 9.9.9.9:443)
	d.knownDoHIPs["9.9.9.9"] = "Quad9 DoH"
	d.knownDoHIPs["149.112.112.112"] = "Quad9 DoH"

	// AdGuard (DoH: dns.adguard-dns.com)
	d.knownDoHIPs["94.140.14.14"] = "AdGuard DoH"
	d.knownDoHIPs["94.140.15.15"] = "AdGuard DoH"

	// OpenDNS / Cisco Umbrella
	d.knownDoHIPs["208.67.222.222"] = "OpenDNS DoH"
	d.knownDoHIPs["208.67.220.220"] = "OpenDNS DoH"

	// NextDNS
	d.knownDoHIPs["45.90.28.0"] = "NextDNS DoH"
	d.knownDoHIPs["45.90.30.0"] = "NextDNS DoH"

	// Control D
	d.knownDoHIPs["76.76.2.0"] = "ControlD DoH"
	d.knownDoHIPs["76.76.10.0"] = "ControlD DoH"

	// Mullvad
	d.knownDoHIPs["194.242.2.2"] = "Mullvad DoH"
	d.knownDoHIPs["194.242.2.3"] = "Mullvad DoH"

	// DNS.SB
	d.knownDoHIPs["185.222.222.222"] = "DNS.SB DoH"
	d.knownDoHIPs["45.11.45.11"] = "DNS.SB DoH"
}

// CheckIPInCIDR checks if an IP is within a given CIDR range.
func CheckIPInCIDR(ipStr, cidr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	return network.Contains(ip)
}
