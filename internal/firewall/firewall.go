package firewall

// Manager is the cross-platform interface for DNS traffic redirection.
// Each platform implements this with its native firewall:
//   - macOS:   PF (Packet Filter) via pfctl — internal/pf/
//   - Linux:   nftables or iptables — internal/nft/
//   - Windows: WinDivert or netsh portproxy — internal/windivert/
type Manager interface {
	// InstallRedirect sets up rules to redirect DNS traffic (port 53)
	// to the local Castiel proxy port.
	InstallRedirect() error

	// Cleanup removes all redirect rules and restores normal DNS routing.
	Cleanup()
}
