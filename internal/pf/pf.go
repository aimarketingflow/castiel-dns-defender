//go:build darwin

package pf

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/castiel/dns/internal/config"
)

// Manager handles macOS PF (Packet Filter) firewall integration.
// PF is used to redirect DNS traffic from port 53 to the local
// Castiel proxy port, enabling transparent interception.
// It also blocks direct DoH/DoT connections to known public resolvers
// to prevent DNS traffic from bypassing Castiel.
type Manager struct {
	cfg        config.PFConfig
	anchorName string
	dohIPs     []string // known DoH resolver IPs to block
}

func NewManager(cfg config.PFConfig) (*Manager, error) {
	// Check if pfctl is available
	if _, err := exec.LookPath("pfctl"); err != nil {
		return nil, fmt.Errorf("pfctl not found: %w (PF requires root on macOS)", err)
	}

	return &Manager{
		cfg:        cfg,
		anchorName: cfg.AnchorName,
		dohIPs:     defaultDoHResolverIPs(),
	}, nil
}

// InstallRedirect sets up a PF anchor that redirects DNS traffic
// from port 53 to the proxy port.
func (m *Manager) InstallRedirect() error {
	// Create the anchor rules
	rules := m.generateRules()

	// Load rules into the anchor
	cmd := exec.Command("pfctl", "-a", m.anchorName, "-f", "-")
	cmd.Stdin = strings.NewReader(rules)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("loading PF anchor rules: %w", err)
	}

	// Enable PF if not already enabled
	enableCmd := exec.Command("pfctl", "-e")
	enableCmd.Run() // Ignore error if already enabled

	return nil
}

func (m *Manager) generateRules() string {
	var sb strings.Builder

	// RDR rule: redirect incoming DNS (port 53) to proxy port
	sb.WriteString(fmt.Sprintf(
		"rdr pass on %s inet proto udp from any to any port 53 -> 127.0.0.1 port %d\n",
		m.cfg.Interface, m.cfg.RedirectPort,
	))
	sb.WriteString(fmt.Sprintf(
		"rdr pass on %s inet proto tcp from any to any port 53 -> 127.0.0.1 port %d\n",
		m.cfg.Interface, m.cfg.RedirectPort,
	))

	// For IPv6
	sb.WriteString(fmt.Sprintf(
		"rdr pass on %s inet6 proto udp from any to any port 53 -> ::1 port %d\n",
		m.cfg.Interface, m.cfg.RedirectPort,
	))
	sb.WriteString(fmt.Sprintf(
		"rdr pass on %s inet6 proto tcp from any to any port 53 -> ::1 port %d\n",
		m.cfg.Interface, m.cfg.RedirectPort,
	))

	// Block direct DoH (port 443) and DoT (port 853) to known public resolvers
	// This prevents applications from bypassing Castiel via encrypted DNS
	for _, ip := range m.dohIPs {
		sb.WriteString(fmt.Sprintf(
			"block out quick on %s inet proto tcp from any to %s port { 443, 853 }\n",
			m.cfg.Interface, ip,
		))
	}

	return sb.String()
}

// defaultDoHResolverIPs returns the list of known public DoH/DoT resolver IPs
// that should be blocked to prevent DNS traffic from bypassing Castiel.
func defaultDoHResolverIPs() []string {
	return []string{
		"8.8.8.8",       // Google Public DNS
		"8.8.4.4",       // Google Public DNS
		"1.1.1.1",       // Cloudflare
		"1.0.0.1",       // Cloudflare
		"9.9.9.9",       // Quad9
		"149.112.112.112", // Quad9
		"94.140.14.14",  // AdGuard
		"94.140.15.15",  // AdGuard
		"208.67.222.222", // OpenDNS
		"208.67.220.220", // OpenDNS
		"45.90.28.0",    // NextDNS
		"45.90.30.0",    // NextDNS
		"76.76.2.0",     // ControlD
		"76.76.10.0",    // ControlD
		"194.242.2.2",   // Mullvad
		"194.242.2.3",   // Mullvad
		"185.222.222.222", // DNS.SB
		"45.11.45.11",   // DNS.SB
	}
}

// AddDoHBlockIP adds an additional DoH resolver IP to the block list.
func (m *Manager) AddDoHBlockIP(ip string) {
	m.dohIPs = append(m.dohIPs, ip)
}

// Cleanup removes the PF anchor and all associated rules.
// This flushes both filter rules and NAT/rdr rules, then removes the anchor
// entirely. Called on graceful shutdown, crash, and panic — ensures the
// system never gets stuck with orphaned DNS redirect rules.
func (m *Manager) Cleanup() {
	// Flush NAT/rdr rules in the anchor
	exec.Command("pfctl", "-a", m.anchorName, "-s", "nat", "-F", "all").Run()
	// Flush filter rules in the anchor
	exec.Command("pfctl", "-a", m.anchorName, "-s", "rules", "-F", "all").Run()
	// Remove the anchor entirely
	exec.Command("pfctl", "-a", m.anchorName, "-r").Run()
}
