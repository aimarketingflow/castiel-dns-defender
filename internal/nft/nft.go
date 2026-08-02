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
	cfg        config.NftConfig
	tableName  string
	useIptables bool
}

// NewManager creates a new nftables (or iptables fallback) manager.
func NewManager(cfg config.NftConfig) (*Manager, error) {
	m := &Manager{
		cfg:       cfg,
		tableName: "castiel",
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

	// IPv4 table
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
	ifaceFlag := ""
	if m.cfg.Interface != "" {
		ifaceFlag = fmt.Sprintf("-i %s", m.cfg.Interface)
	}

	// IPv4 rules
	rules := [][]string{
		{"iptables", "-t", "nat", "-C", "OUTPUT", ifaceFlag, "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-port", port},
	}
	// Check if rule exists, if not add it
	for _, check := range rules {
		checkCmd := exec.Command(check[0], check[1:]...)
		if checkCmd.Run() != nil {
			// Rule doesn't exist, add it
			addArgs := []string{"-t", "nat", "-A", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-port", port}
			if m.cfg.Interface != "" {
				addArgs = append([]string{"-i", m.cfg.Interface}, addArgs...)
			}
			if err := exec.Command("iptables", addArgs...).Run(); err != nil {
				return fmt.Errorf("iptables UDP redirect: %w", err)
			}
		}
	}

	// TCP
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

	// Remove iptables rules (best-effort)
	exec.Command("iptables", "-t", "nat", "-D", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-port", port).Run()
	exec.Command("iptables", "-t", "nat", "-D", "OUTPUT", "-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-port", port).Run()

	// IPv6
	if _, err := exec.LookPath("ip6tables"); err == nil {
		exec.Command("ip6tables", "-t", "nat", "-D", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-port", port).Run()
		exec.Command("ip6tables", "-t", "nat", "-D", "OUTPUT", "-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-port", port).Run()
	}
}

// Backend returns the active firewall backend name ("nftables" or "iptables").
func (m *Manager) Backend() string {
	if m.useIptables {
		return "iptables"
	}
	return "nftables"
}
