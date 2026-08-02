# Castiel — Linux Build Specification

## Overview

Castiel on Linux replaces three macOS-specific subsystems with Linux equivalents:

| Component             | macOS (current)              | Linux (proposed)                        |
|-----------------------|------------------------------|-----------------------------------------|
| DNS traffic redirect  | PF firewall (`pfctl`)        | nftables / iptables NAT redirect        |
| System service        | LaunchDaemon (`launchctl`)   | systemd unit file                       |
| Desktop GUI app       | SwiftUI (macOS only)         | GTK4 + libadwaita (Go bindings) or CLI  |
| Desktop notifications | `osascript` (Notification Center) | `notify-send` (libnotify)         |
| DNS settings restore  | `networksetup`               | `/etc/resolv.conf` restore + `resolvectl`|
| App bundle            | `.app` bundle + `Info.plist` | `/opt/castiel/` + `.desktop` file       |
| Kill switch           | `doh-killswitch.sh` (bash)   | `doh-killswitch.sh` (bash, Linux paths) |

## Architecture

```
linux_build/
├── README.md                    # This file
├── install.sh                   # Linux install script
├── uninstall.sh                 # Linux uninstall script
├── castiel.service              # systemd unit file
├── castiel-tmpfiles.conf        # tmpfiles.d config for /run/castiel
├── doh-killswitch.sh            # Linux kill switch (nftables/iptables)
├── config.yaml                  # Linux-specific config (nftables instead of PF)
├── castiel.desktop              # Freedesktop.org .desktop entry
├── nftables/
│   └── castiel.nft              # nftables ruleset for DNS redirect
├── icons/
│   ├── castiel-16.png           # App icons (various sizes)
│   ├── castiel-32.png
│   ├── castiel-48.png
│   ├── castiel-128.png
│   ├── castiel-256.png
│   └── castiel-512.png
└── gui/                         # GTK4 GUI app (optional)
    ├── main.go                  # GTK4 entry point using gotk4
    ├── go.mod                   # GUI module
    └── README.md                # GUI build instructions
```

## 1. DNS Traffic Interception — nftables

### Approach

Use nftables NAT to redirect outbound DNS (port 53) to the local Castiel proxy:

```nft
# /etc/nftables.d/castiel.nft
table ip castiel {
    chain prerouting {
        type nat hook prerouting priority -100; policy accept;
        udp dport 53 redirect to :5300
        tcp dport 53 redirect to :5300
    }
}

table ip6 castiel {
    chain prerouting {
        type nat hook prerouting priority -100; policy accept;
        udp dport 53 redirect to :5300
        tcp dport 53 redirect to :5300
    }
}
```

### Go Implementation: `internal/nft/nft.go`

```go
package nft

type Manager struct {
    cfg        config.NftConfig
    tableName  string
}

func NewManager(cfg config.NftConfig) (*Manager, error) {
    // Check if `nft` binary exists
    // Fallback to iptables if nftables not available
}

func (m *Manager) InstallRedirect() error {
    // Load nftables ruleset via `nft -f -`
    // Or iptables equivalent: `iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-port 5300`
}

func (m *Manager) Cleanup() {
    // `nft delete table ip castiel`
    // `nft delete table ip6 castiel`
}
```

### Config Addition

```yaml
# Linux-specific config (replaces pf: section)
nft:
  enabled: true
  backend: "nftables"  # or "iptables" for legacy systems
  redirect_port: 5300
  interface: ""        # empty = all interfaces
```

### Build Constraint

```go
//go:build linux
package nft
```

The `main.go` will use build tags to select the right firewall manager:
- `//go:build darwin` → `internal/pf/`
- `//go:build linux` → `internal/nft/`
- `//go:build windows` → `internal/wfp/`

## 2. System Service — systemd

### Unit File: `castiel.service`

```ini
[Unit]
Description=Castiel DNS Defense Daemon
After=network-online.target
Wants=network-online.target
After=systemd-resolved.service

[Service]
Type=simple
ExecStart=/usr/local/bin/castiel -config /usr/local/etc/castiel/config.yaml
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=3
LimitNOFILE=4096

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/usr/local/etc/castiel /usr/local/var/log/castiel /run/castiel
PrivateTmp=true
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_ADMIN CAP_NET_RAW
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN CAP_NET_RAW

[Install]
WantedBy=multi-user.target
```

### Installation

```bash
sudo cp castiel.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now castiel
```

### Signal Handling

systemd maps `SIGUSR1`/`SIGUSR2` via `ExecReload` or custom commands:
```bash
sudo systemctl kill -s USR1 castiel   # Emergency DoH disable
sudo systemctl kill -s USR2 castiel   # Re-enable DoH
```

## 3. Desktop GUI — GTK4 (Optional)

### Approach

Use [gotk4](https://github.com/diamondburned/gotk4) (Go bindings for GTK4) to build a Linux equivalent of the macOS SwiftUI app.

```go
//go:build linux
package main

import (
    "github.com/diamondburned/gotk4/pkg/gtk/v4"
    "github.com/diamondburned/gotk4/pkg/adwaita"
)

func main() {
    app := adwaita.NewApplication("com.castiel.app", 0)
    app.ConnectActivate(func() {
        // Build dashboard window:
        // - Status indicator (running/stopped)
        // - Total queries / blocked queries counters
        // - Recent alerts list
        // - DoH toggle button
        // - Kill switch button
    })
    app.Run()
}
```

### Fallback: CLI Dashboard

If GTK4 is not available, provide a TUI (terminal UI) using [bubbletea](https://github.com/charmbracelet/bubbletea):

```
┌─────────────────────────────────────┐
│  Castiel DNS Defense  v0.1.0       │
│  Status: ● Running (PID 12345)     │
│                                     │
│  Queries:    1,234,567             │
│  Blocked:    45,678 (3.7%)         │
│  DoH:        ● Enabled             │
│                                     │
│  Recent Alerts:                     │
│  [critical] DGA: xkjhsdf8923.com   │
│  [warn]     Rate limit: 10.0.0.5   │
│  [critical] Tunneling: a3f8b.evil  │
│                                     │
│  [T] Toggle DoH  [K] Kill Switch   │
│  [Q] Quit                           │
└─────────────────────────────────────┘
```

## 4. Desktop Notifications — libnotify

### Alert Manager Change

Replace `osascript` with `notify-send`:

```go
//go:build linux
func (m *Manager) sendDesktopNotification(a Alert) {
    title := fmt.Sprintf("Castiel — %s", a.Severity)
    body := a.Message
    if a.Domain != "" {
        body = fmt.Sprintf("%s — Domain: %s", a.Message, a.Domain)
    }
    urgency := "normal"
    if a.Severity == "critical" {
        urgency = "critical"
    }
    exec.Command("notify-send", "-u", urgency, title, body).Run()
}
```

## 5. Kill Switch — `doh-killswitch.sh` (Linux)

Key differences from macOS version:
- Replace `networksetup` with `resolvectl` or `/etc/resolv.conf` manipulation
- Replace `pfctl -a castiel -r` with `nft delete table ip castiel`
- Replace `nslookup` with `dig` or `drill`

```bash
#!/bin/bash
# Linux-specific DNS restore
restore_dns() {
    # Restore systemd-resolved if it was disabled
    if systemctl is-active systemd-resolved >/dev/null 2>&1; then
        resolvectl dns-default   # Reset to DHCP defaults
    fi
    # Or restore resolv.conf from backup
    if [ -f /etc/resolv.conf.castiel-backup ]; then
        cp /etc/resolv.conf.castiel-backup /etc/resolv.conf
    fi
    # Remove nftables rules
    nft delete table ip castiel 2>/dev/null || true
    nft delete table ip6 castiel 2>/dev/null || true
}
```

## 6. Install Script — `install.sh`

```bash
#!/bin/bash
# Linux install script for Castiel
# Supports: Ubuntu/Debian, RHEL/Fedora, Arch

set -e

PREFIX="/usr/local"
BIN_DIR="${PREFIX}/bin"
ETC_DIR="${PREFIX}/etc/castiel"
VAR_DIR="${PREFIX}/var/log/castiel"
DATA_DIR="${ETC_DIR}/data"
SYSTEMD_DIR="/etc/systemd/system"

# Detect distro
if command -v apt-get >/dev/null; then
    DISTRO="debian"
elif command -v dnf >/dev/null; then
    DISTRO="fedora"
elif command -v pacman >/dev/null; then
    DISTRO="arch"
else
    DISTRO="unknown"
fi

# Install dependencies
case $DISTRO in
    debian) apt-get install -y nftables libnotify4 ;;
    fedora) dnf install -y nftables libnotify ;;
    arch)   pacman -S --noconfirm nftables libnotify ;;
esac

# Build Go daemon
go build -ldflags="-s -w" -o castiel .

# Install binary
install -Dm755 castiel "$BIN_DIR/castiel"

# Install config + data
mkdir -p "$ETC_DIR" "$DATA_DIR" "$VAR_DIR"
cp config.yaml "$ETC_DIR/config.yaml"
cp data/* "$DATA_DIR/"

# Patch config paths
sed -i "s|data/|$DATA_DIR/|g" "$ETC_DIR/config.yaml"

# Install systemd service
install -Dm644 castiel.service "$SYSTEMD_DIR/castiel.service"
systemctl daemon-reload
systemctl enable --now castiel

# Install kill switch
install -Dm755 doh-killswitch.sh "$BIN_DIR/doh-killswitch.sh"

# Install .desktop file (for GUI app launcher)
install -Dm644 castiel.desktop /usr/share/applications/castiel.desktop

# Install icons
for size in 16 32 48 128 256 512; do
    install -Dm644 icons/castiel-${size}.png \
        /usr/share/icons/hicolor/${size}x${size}/apps/castiel.png
done

echo "Installation complete."
echo "  sudo systemctl status castiel   # Check status"
echo "  sudo journalctl -u castiel -f   # View logs"
```

## 7. Config Changes

### `config.yaml` (Linux)

```yaml
# Replace pf: section with:
nft:
  enabled: true
  backend: "nftables"  # or "iptables"
  redirect_port: 5300
  interface: ""        # empty = all interfaces

# Alerts: use notify-send instead of osascript
alerts:
  enabled: true
  log_file: "/usr/local/var/log/castiel/castiel_alerts.jsonl"
  syslog_enabled: true
  desktop_notification: true   # uses notify-send on Linux
  min_severity: "warn"
```

## 8. Build Tags Strategy

```
internal/
├── pf/           # //go:build darwin
│   └── pf.go
├── nft/          # //go:build linux
│   └── nft.go
├── wfp/          # //go:build windows
│   └── wfp.go
├── alerts/
│   ├── manager.go         # shared logic
│   ├── notify_darwin.go   # //go:build darwin
│   ├── notify_linux.go    # //go:build linux
│   └── notify_windows.go  # //go:build windows
├── config/
│   └── config.go          # add NftConfig, WfpConfig structs
```

## 9. Cross-Platform main.go

```go
// main.go
//go:build darwin
import _ "github.com/castiel/dns/internal/pf"

// main_linux.go
//go:build linux
import _ "github.com/castiel/dns/internal/nft"

// main_windows.go
//go:build windows
import _ "github.com/castiel/dns/internal/wfp"
```

Or use a firewall interface:

```go
type FirewallManager interface {
    InstallRedirect() error
    Cleanup()
}

// main.go selects based on runtime.GOOS
func newFirewallManager(cfg *config.Config) (FirewallManager, error) {
    switch runtime.GOOS {
    case "darwin":
        return pf.NewManager(cfg.PF)
    case "linux":
        return nft.NewManager(cfg.Nft)
    case "windows":
        return wfp.NewManager(cfg.Wfp)
    }
}
```

## 10. Dependencies

### Build Dependencies
- Go 1.21+
- (Optional) GTK4 + gotk4 for GUI app
- (Optional) bubbletea for TUI dashboard

### Runtime Dependencies
- nftables (kernel 3.13+) or iptables (legacy)
- systemd (or run manually with `-config`)
- libnotify / `notify-send` (for desktop notifications)
- CAP_NET_ADMIN + CAP_NET_RAW capabilities (or root)

## 11. Testing

### Unit Tests
- `internal/nft/nft_test.go` — test rule generation (no root needed)
- Build-tag gated: `//go:build linux`

### Integration Tests
- `test-castiel.sh` works as-is on Linux (uses `pgrep`, `curl`, `awk`)
- Replace `pfctl` status check with `nft list table ip castiel`
- Replace `networksetup` with `resolvectl status`

## 12. Package Management

### Debian/Ubuntu (.deb)
```
castiel/
├── DEBIAN/
│   ├── control
│   ├── postinst        # systemctl enable --now castiel
│   ├── prerm           # systemctl stop castiel
│   └── postrm          # nft delete table ip castiel
├── usr/local/bin/castiel
├── usr/local/etc/castiel/config.yaml
├── etc/systemd/system/castiel.service
└── usr/share/applications/castiel.desktop
```

### RHEL/Fedora (.rpm)
Use `fpm` to convert from deb, or write spec file directly.

### Arch Linux (AUR)
```bash
# PKGBUILD
pkgname=castiel
pkgver=0.1.0
pkgrel=1
depends=(nftables libnotify)
```
