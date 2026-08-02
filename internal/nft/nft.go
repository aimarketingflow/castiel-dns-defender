//go:build linux

package nft

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/castiel/dns/internal/config"
)

// Manager handles Linux nftables firewall integration.
// nftables is used to redirect DNS traffic from port 53 to the local
// Castiel proxy port, enabling transparent interception.
// Falls back to iptables if nftables is not available.
type Manager struct {
	cfg         config.NftConfig
	tableName   string
	useIptables bool
	dohIPs      []string // known DoH resolver IPs to block
}

// NewManager creates a new nftables (or iptables fallback) manager.
func NewManager(cfg config.NftConfig) (*Manager, error) {
	m := &Manager{
		cfg:       cfg,
		tableName: "castiel",
		dohIPs:    defaultDoHResolverIPs(),
	}

	// Determine backend: try nftables first, fall back to iptables
	if cfg.Backend == "iptables" {
		if _, err := exec.LookPath("iptables"); err != nil {
			return nil, fmt.Errorf("iptables not found: %w (install iptables or nftables)", err)
		}
		m.useIptables = true
	} else {
		// Default: try nftables
		if _, err := exec.LookPath("nft"); err != nil {
			// Fall back to iptables
			if _, err2 := exec.LookPath("iptables"); err2 != nil {
				return nil, fmt.Errorf("neither nft nor iptables found: %w (install nftables or iptables)", err)
			}
			m.useIptables = true
		}
	}

	return m, nil
}

// InstallRedirect sets up nftables NAT rules to redirect DNS traffic
// from port 53 to the Castiel proxy port.
func (m *Manager) InstallRedirect() error {
	if m.useIptables {
		return m.installIptables()
	}
	return m.installNftables()
}

func (m *Manager) installNftables() error {
	rules := m.generateNftRules()

	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(rules)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("loading nftables rules: %w", err)
	}

	return nil
}

func (m *Manager) generateNftRules() string {
	var sb strings.Builder
	port := m.cfg.RedirectPort

	// IPv4 table with NAT prerouting + output chains
	sb.WriteString(fmt.Sprintf("table ip %s {\n", m.tableName))
	sb.WriteString("    chain prerouting {\n")
	sb.WriteString("        type nat hook prerouting priority -100; policy accept;\n")
	if m.cfg.Interface != "" {
		sb.WriteString(fmt.Sprintf("        iifname \"%s\" udp dport 53 redirect to :%d\n", m.cfg.Interface, port))
		sb.WriteString(fmt.Sprintf("        iifname \"%s\" tcp dport 53 redirect to :%d\n", m.cfg.Interface, port))
	} else {
		sb.WriteString(fmt.Sprintf("        udp dport 53 redirect to :%d\n", port))
		sb.WriteString(fmt.Sprintf("        tcp dport 53 redirect to :%d\n", port))
	}
	sb.WriteString("    }\n")
	sb.WriteString("    chain output {\n")
	sb.WriteString("        type nat hook output priority -100; policy accept;\n")
	sb.WriteString(fmt.Sprintf("        udp dport 53 redirect to :%d\n", port))
	sb.WriteString(fmt.Sprintf("        tcp dport 53 redirect to :%d\n", port))
	sb.WriteString("    }\n")
	// DoH/DoT bypass blocking
	for _, ip := range m.dohIPs {
		sb.WriteString(fmt.Sprintf("    ip daddr %s tcp dport { 443, 853 } drop\n", ip))
	}
	sb.WriteString("}\n")

	// IPv6 table
	sb.WriteString(fmt.Sprintf("table ip6 %s {\n", m.tableName))
	sb.WriteString("    chain prerouting {\n")
	sb.WriteString("        type nat hook prerouting priority -100; policy accept;\n")
	if m.cfg.Interface != "" {
		sb.WriteString(fmt.Sprintf("        iifname \"%s\" udp dport 53 redirect to :%d\n", m.cfg.Interface, port))
		sb.WriteString(fmt.Sprintf("        iifname \"%s\" tcp dport 53 redirect to :%d\n", m.cfg.Interface, port))
	} else {
		sb.WriteString(fmt.Sprintf("        udp dport 53 redirect to :%d\n", port))
		sb.WriteString(fmt.Sprintf("        tcp dport 53 redirect to :%d\n", port))
	}
	sb.WriteString("    }\n")
	sb.WriteString("}\n")

	return sb.String()
}

func (m *Manager) installIptables() error {
	port := fmt.Sprintf("%d", m.cfg.RedirectPort)

	// IPv4 UDP redirect
	udpCheck := exec.Command("iptables", "-t", "nat", "-C", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-port", port)
	if udpCheck.Run() != nil {
		udpArgs := []string{"-t", "nat", "-A", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-port", port}
		if m.cfg.Interface != "" {
			udpArgs = append([]string{"-i", m.cfg.Interface}, udpArgs...)
		}
		if err := exec.Command("iptables", udpArgs...).Run(); err != nil {
			return fmt.Errorf("iptables UDP redirect: %w", err)
		}
	}

	// IPv4 TCP redirect
	tcpCheck := exec.Command("iptables", "-t", "nat", "-C", "OUTPUT", "-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-port", port)
	if tcpCheck.Run() != nil {
		tcpArgs := []string{"-t", "nat", "-A", "OUTPUT", "-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-port", port}
			if m.cfg.Interface != "" {
			tcpArgs = append([]string{"-i", m.cfg.Interface}, tcpArgs...)
		}
		if err := exec.Command("iptables", tcpArgs...).Run(); err != nil {
			return fmt.Errorf("iptables TCP redirect: %w", err)
		}
	}

	// DoH/DoT bypass blocking (iptables)
	for _, ip := range m.dohIPs {
		for _, dport := range []string{"443", "853"} {
			check := exec.Command("iptables", "-C", "OUTPUT", "-d", ip, "-p", "tcp", "--dport", dport, "-j", "DROP")
			if check.Run() != nil {
				exec.Command("iptables", "-A", "OUTPUT", "-d", ip, "-p", "tcp", "--dport", dport, "-j", "DROP").Run()
			}
		}
	}

	// IPv6 rules (ip6tables)
	if _, err := exec.LookPath("ip6tables"); err == nil {
		udp6Check := exec.Command("ip6tables", "-t", "nat", "-C", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-port", port)
		if udp6Check.Run() != nil {
			udp6Args := []string{"-t", "nat", "-A", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-port", port}
			if m.cfg.Interface != "" {
				udp6Args = append([]string{"-i", m.cfg.Interface}, udp6Args...)
			}
			exec.Command("ip6tables", udp6Args...).Run()
		}

		tcp6Check := exec.Command("ip6tables", "-t", "nat", "-C", "OUTPUT", "-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-port", port)
		if tcp6Check.Run() != nil {
			tcp6Args := []string{"-t", "nat", "-A", "OUTPUT", "-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-port", port}
			if m.cfg.Interface != "" {
				tcp6Args = append([]string{"-i", m.cfg.Interface}, tcp6Args...)
			}
			exec.Command("ip6tables", tcp6Args...).Run()
		}
	}

	return nil
}

// Cleanup removes the nftables tables or iptables rules.
func (m *Manager) Cleanup() {
	if m.useIptables {
		m.cleanupIptables()
		return
	}

	// Delete nftables tables (ignore errors if they don't exist)
	exec.Command("nft", "delete", "table", "ip", m.tableName).Run()
	exec.Command("nft", "delete", "table", "ip6", m.tableName).Run()
}

func (m *Manager) cleanupIptables() {
	port := fmt.Sprintf("%d", m.cfg.RedirectPort)

	// Remove iptables redirect rules (best-effort)
	exec.Command("iptables", "-t", "nat", "-D", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-port", port).Run()
	exec.Command("iptables", "-t", "nat", "-D", "OUTPUT", "-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-port", port).Run()

	// Remove DoH/DoT block rules
	for _, ip := range m.dohIPs {
		for _, dport := range []string{"443", "853"} {
			exec.Command("iptables", "-D", "OUTPUT", "-d", ip, "-p", "tcp", "--dport", dport, "-j", "DROP").Run()
		}
	}

	// IPv6
	if _, err := exec.LookPath("ip6tables"); err == nil {
		exec.Command("ip6tables", "-t", "nat", "-D", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-port", port).Run()
		exec.Command("ip6tables", "-t", "nat", "-D", "OUTPUT", "-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-port", port).Run()
	}
}

// defaultDoHResolverIPs returns the list of known public DoH/DoT resolver IPs
// that should be blocked to prevent DNS traffic from bypassing Castiel.
func defaultDoHResolverIPs() []string {
	return []string{
		"8.8.8.8",         // Google Public DNS
		"8.8.4.4",         // Google Public DNS
		"1.1.1.1",         // Cloudflare
		"1.0.0.1",         // Cloudflare
		"9.9.9.9",         // Quad9
		"149.112.112.112", // Quad9
		"94.140.14.14",    // AdGuard
		"94.140.15.15",    // AdGuard
		"208.67.222.222",  // OpenDNS
		"208.67.220.220",  // OpenDNS
		"45.90.28.0",      // NextDNS
		"45.90.30.0",      // NextDNS
		"76.76.2.0",       // ControlD
		"76.76.10.0",      // ControlD
		"194.242.2.2",     // Mullvad
		"194.242.2.3",     // Mullvad
		"185.222.222.222", // DNS.SB
		"45.11.45.11",     // DNS.SB
	}
}

// AddDoHBlockIP adds an additional DoH resolver IP to the block list.
func (m *Manager) AddDoHBlockIP(ip string) {
	m.dohIPs = append(m.dohIPs, ip)
}

// Backend returns the active firewall backend name ("nftables" or "iptables").
func (m *Manager) Backend() string {
	if m.useIptables {
		return "iptables"
	}
	return "nftables"
}
