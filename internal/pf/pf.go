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
type Manager struct {
	cfg        config.PFConfig
	anchorName string
}

func NewManager(cfg config.PFConfig) (*Manager, error) {
	// Check if pfctl is available
	if _, err := exec.LookPath("pfctl"); err != nil {
		return nil, fmt.Errorf("pfctl not found: %w (PF requires root on macOS)", err)
	}

	return &Manager{
		cfg:        cfg,
		anchorName: cfg.AnchorName,
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

	return sb.String()
}

// Cleanup removes the PF anchor and rules.
func (m *Manager) Cleanup() {
	// Remove the anchor
	cmd := exec.Command("pfctl", "-a", m.anchorName, "-r")
	cmd.Run()
}
