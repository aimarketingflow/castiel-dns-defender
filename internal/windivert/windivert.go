//go:build windows

package windivert

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/castiel/dns/internal/config"
)

// Manager handles Windows DNS traffic redirection.
//
// On Windows, there is no built-in user-space NAT like PF (macOS) or
// nftables (Linux). Castiel uses two methods:
//
//  1. "system_dns" (default): Sets the system DNS to 127.0.0.1 so all
//     DNS queries go through Castiel directly on port 53.
//
//  2. "portproxy": Uses `netsh interface portproxy` to redirect TCP
//     port 53 to the Castiel proxy port. UDP is handled by system_dns.
//
//  3. "windivert": Uses WinDivert for full packet interception (requires
//     bundling WinDivert64.sys driver). Not implemented in this initial
//     version — falls back to system_dns.
type Manager struct {
	cfg          config.DnsRedirectConfig
	originalDNS  map[string][]string // interface -> DNS servers (for restore)
}

// NewManager creates a new Windows DNS redirect manager.
func NewManager(cfg config.DnsRedirectConfig) (*Manager, error) {
	return &Manager{
		cfg:         cfg,
		originalDNS: make(map[string][]string),
	}, nil
}

// InstallRedirect configures DNS redirection based on the configured method.
func (m *Manager) InstallRedirect() error {
	switch m.cfg.Method {
	case "portproxy":
		return m.installPortProxy()
	case "windivert":
		// WinDivert not yet implemented — fall back to system_dns
		return m.installSystemDNS()
	default:
		return m.installSystemDNS()
	}
}

// installSystemDNS sets the system DNS server to 127.0.0.1 on all
// active network interfaces. Castiel should bind to port 53 directly.
func (m *Manager) installSystemDNS() error {
	// Get all active network interfaces
	interfaces, err := m.getActiveInterfaces()
	if err != nil {
		return fmt.Errorf("getting network interfaces: %w", err)
	}

	for _, iface := range interfaces {
		// Save current DNS servers for restoration
		currentDNS := m.getDNSServers(iface)
		if len(currentDNS) > 0 {
			m.originalDNS[iface] = currentDNS
		}

		// Set DNS to 127.0.0.1
		cmd := exec.Command("netsh", "interface", "ip", "set", "dns",
			iface, "static", "127.0.0.1")
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("setting DNS on %s: %w", iface, err)
		}
	}

	// Also set up TCP portproxy as fallback (TCP DNS is less common but used by some apps)
	if m.cfg.RedirectPort != 53 {
		return m.installPortProxy()
	}

	return nil
}

// installPortProxy uses `netsh interface portproxy` to redirect
// TCP port 53 to the Castiel proxy port.
func (m *Manager) installPortProxy() error {
	port := fmt.Sprintf("%d", m.cfg.RedirectPort)

	// IPv4 TCP
	cmd := exec.Command("netsh", "interface", "portproxy", "add", "v4tov4",
		"listenport=53", "connectaddress=127.0.0.1",
		fmt.Sprintf("connectport=%s", port), "protocol=tcp")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("netsh portproxy v4tov4 TCP: %w", err)
	}

	// IPv4 UDP (netsh portproxy supports UDP on Windows 10+)
	cmd = exec.Command("netsh", "interface", "portproxy", "add", "v4tov4",
		"listenport=53", "connectaddress=127.0.0.1",
		fmt.Sprintf("connectport=%s", port), "protocol=udp")
	cmd.Run() // Best-effort — UDP portproxy may not be supported on all versions

	return nil
}

// Cleanup restores the original DNS settings and removes portproxy rules.
func (m *Manager) Cleanup() {
	m.cleanupSystemDNS()
	m.cleanupPortProxy()
}

func (m *Manager) cleanupSystemDNS() {
	// Restore original DNS or reset to DHCP
	for iface := range m.originalDNS {
		// Reset to DHCP (automatic DNS)
		exec.Command("netsh", "interface", "ip", "set", "dns", iface, "dhcp").Run()
	}

	// Also try resetting via PowerShell (more reliable on Windows 10+)
	exec.Command("powershell", "-NoProfile", "-Command",
		"Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Set-DnsClientServerAddress -ResetServerAddresses").Run()
}

func (m *Manager) cleanupPortProxy() {
	exec.Command("netsh", "interface", "portproxy", "delete", "v4tov4",
		"listenport=53", "protocol=tcp").Run()
	exec.Command("netsh", "interface", "portproxy", "delete", "v4tov4",
		"listenport=53", "protocol=udp").Run()
}

// getActiveInterfaces returns names of active (Up) network interfaces.
func (m *Manager) getActiveInterfaces() ([]string, error) {
	cmd := exec.Command("powershell", "-NoProfile", "-Command",
		"Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object -ExpandProperty Name")
	output, err := cmd.Output()
	if err != nil {
		// Fallback: use netsh
		return m.getInterfacesNetsh()
	}

	var interfaces []string
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		name := strings.TrimSpace(line)
		if name != "" {
			interfaces = append(interfaces, name)
		}
	}

	if len(interfaces) == 0 {
		return m.getInterfacesNetsh()
	}

	return interfaces, nil
}

func (m *Manager) getInterfacesNetsh() ([]string, error) {
	cmd := exec.Command("netsh", "interface", "show", "interface")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("netsh interface show: %w", err)
	}

	var interfaces []string
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		// Parse netsh output: look for "Connected" state lines
		fields := strings.Fields(line)
		if len(fields) >= 4 && fields[1] == "Connected" {
			// Interface name is the last field(s)
			name := strings.TrimSpace(strings.TrimPrefix(line, fields[0]+" "+fields[1]+" "+fields[2]+" "+fields[3]+" "))
			if name == "" {
				name = fields[len(fields)-1]
			}
			if name != "" {
				interfaces = append(interfaces, name)
			}
		}
	}

	return interfaces, nil
}

// getDNSServers retrieves current DNS servers for an interface.
func (m *Manager) getDNSServers(iface string) []string {
	cmd := exec.Command("netsh", "interface", "ip", "show", "dns", iface)
	output, err := cmd.Output()
	if err != nil {
		return nil
	}

	var servers []string
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		// Look for IP addresses in the output
		if strings.Contains(line, ".") && !strings.Contains(line, "Configuration") {
			parts := strings.Fields(line)
			for _, part := range parts {
				if isValidIPv4(part) {
					servers = append(servers, part)
				}
			}
		}
	}

	return servers
}

func isValidIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if len(p) == 0 || len(p) > 3 {
			return false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}

// Backend returns the active redirect method name.
func (m *Manager) Backend() string {
	return m.cfg.Method
}
