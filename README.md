# Castiel

Real-time DNS attack detection, prevention, and alerting for **macOS, Linux, and Windows**.
Named after the archangel Cassiel — guardian of the threshold, watcher of the gate.

## Quick Start

### macOS

```bash
# Build
go build -o castiel .

# Run (requires root for PF redirect)
sudo ./castiel -config config.yaml

# Or install as a system service
sudo make install
```

### Linux

```bash
# Cross-compile from any platform
make build-linux

# Install on Linux target
sudo ./linux_build/install.sh
```

### Windows

```bash
# Cross-compile from any platform
make build-windows

# Install on Windows target (run as Admin in PowerShell)
.\windows_build\install.ps1
```

## Architecture

Castiel acts as a local DNS proxy that intercepts all DNS traffic via platform-native firewall redirect. Every query passes through a detection pipeline before being forwarded upstream.

### Platform-Specific DNS Interception

| Platform | Firewall | Service Manager | Notifications |
|---|---|---|---|
| **macOS** | PF (Packet Filter) via `pfctl` | LaunchDaemon (`launchctl`) | Notification Center (`osascript`) |
| **Linux** | nftables (or iptables fallback) | systemd | `notify-send` (libnotify) |
| **Windows** | System DNS + `netsh portproxy` | Windows Service (SCM) | Windows Toast (WinRT) |

### Detection Pipeline (in order)

1. **Rate Limiting** — Per-IP token bucket + global QPS ceiling (DDoS/amplification)
2. **Zone Transfer Block** — AXFR/IXFR request blocking
3. **Blocklist Check** — Threat intel feeds (URLhaus, OpenPhish, PhishTank)
4. **Tunneling Detection** — Shannon entropy on subdomain labels
5. **DGA Detection** — Entropy + consonant ratio + digit ratio heuristics + n-gram model
6. **C2/Fast-Flux Detection** — TTL volatility + IP diversity tracking
7. **Cache Lookup** — TTL-aware LRU cache
8. **Upstream Forward** — Plain DNS or DoH (encrypted)
9. **DNSSEC Validation** — Reject bogus responses (cache poisoning prevention)
10. **Rebinding Protection** — Block public FQDNs resolving to RFC1918 IPs

### Blocking Coverage

| Attack Type | Blocked? |
|---|---|
| DNS Amplification DDoS | Yes |
| Water Torture / NXDOMAIN Flood | Yes |
| DNS Cache Poisoning | Yes (DNSSEC) |
| DNS Tunneling / Exfiltration | Yes (entropy) |
| DGA Domains | Yes (heuristic + n-gram ML) |
| DNS Rebinding | Yes (RFC1918 check) |
| Zone Transfer (AXFR) | Yes (ACL) |
| C2 Beaconing | Yes (threat feeds) |
| On-Path DNS (MITM) | Yes (DoH/DoT) |
| Fast Flux | Partial (detection → feed) |
| DNS Hijacking | Partial (DNSSEC at resolver) |
| Subdomain Takeover | No (zone-level remediation) |

## Configuration

See `config.yaml` for all options. Platform-specific sections:

- **macOS**: `pf:` — PF firewall redirect (anchor, port, interface)
- **Linux**: `nft:` — nftables/iptables redirect (backend, port, interface)
- **Windows**: `dns_redirect:` — System DNS or portproxy (method, port, interface)

Shared sections (all platforms):
- `server` — Listen address, upstream resolvers, DoH
- `rate_limit` — Token bucket per-IP and global QPS limits
- `tunneling_detection` — Shannon entropy threshold, CDN whitelist
- `dga_detection` — Entropy, consonant ratio, n-gram model
- `rebinding_protection` — RFC1918 range blocking
- `blocklists` — Threat intel feed URLs and refresh interval
- `alerts` — JSONL logging, desktop notifications, webhooks
- `metrics` — Prometheus endpoint

## Cross-Platform Build

```bash
# Native build (current platform)
make build

# Cross-compile
make build-linux     # Linux amd64 + arm64 → linux_build/
make build-windows   # Windows amd64 + arm64 → windows_build/
make build-cross     # All platforms

# Release builds (stripped, optimized)
make release         # macOS daemon + SwiftUI app
```

## Platform Installation

### macOS
```bash
sudo make install                    # Installs daemon, app, LaunchDaemon
launchctl list | grep castiel        # Check status
```

### Linux
```bash
sudo ./linux_build/install.sh        # Installs binary, systemd service, config
systemctl status castiel             # Check status
```

### Windows
```powershell
.\windows_build\install.ps1          # Installs binary, Windows Service, config
sc.exe query Castiel                 # Check status
```

## DoH Kill Switch

Each platform has a kill switch for emergency DoH control:

- **macOS/Linux**: `doh-killswitch.sh {toggle|off|on|status|stop|restore}`
- **Windows**: `.\doh-killswitch.ps1 {toggle|off|on|status|stop|restore}`

## Project Structure

```
Castiel/
├── main.go                          # Entry point, daemon setup
├── main_darwin.go                  # macOS: PF firewall init
├── main_linux.go                   # Linux: nftables firewall init
├── main_windows.go                 # Windows: DNS redirect firewall init
├── signals_unix.go                 # Unix signal handling (SIGHUP/USR1/USR2)
├── signals_windows.go              # Windows service signal handling
├── service_windows.go              # Windows Service (SCM) wrapper
├── config.yaml                      # macOS configuration
├── go.mod                           # Go module definition
├── data/
│   ├── legitimate-domains.txt       # N-gram model training corpus (1000+ domains)
│   ├── root-trust-anchor.txt        # DNSSEC trust anchor
│   ├── custom_block.txt             # Custom blocklist
│   └── custom_allow.txt             # Custom allowlist
├── internal/
│   ├── config/config.go             # Config struct + validation
│   ├── firewall/firewall.go         # Cross-platform firewall interface
│   ├── dnsproxy/proxy.go            # DNS proxy server + pipeline
│   ├── detectors/
│   │   ├── entropy.go               # Shannon entropy tunneling detection
│   │   ├── dga.go                   # DGA domain detection (heuristics + n-gram)
│   │   ├── ngram.go                 # N-gram statistical model
│   │   ├── ratelimit.go             # Token bucket rate limiter
│   │   └── rebinding_c2.go          # Rebinding + C2/fast-flux detection
│   ├── blocklists/manager.go        # Threat intel feed manager
│   ├── cache/cache.go               # TTL-aware LRU DNS cache
│   ├── alerts/
│   │   ├── manager.go               # Alert routing (log/notify/webhook)
│   │   ├── notify_darwin.go         # macOS Notification Center
│   │   ├── notify_linux.go          # Linux notify-send
│   │   └── notify_windows.go        # Windows Toast notifications
│   ├── metrics/metrics.go           # Prometheus metrics
│   ├── pf/pf.go                     # macOS PF firewall (//go:build darwin)
│   ├── nft/nft.go                   # Linux nftables/iptables (//go:build linux)
│   └── windivert/windivert.go       # Windows DNS redirect (//go:build windows)
├── deploy/                          # macOS deployment (install.sh, LaunchDaemon, .app)
├── linux_build/                     # Linux deployment (install.sh, systemd, config)
├── windows_build/                   # Windows deployment (install.ps1, NSIS, config)
├── macos-app/                       # macOS SwiftUI menu bar app
├── cmd/attack-sim/                  # DNS attack simulation tool
└── Makefile                         # Build targets for all platforms
```

## License

MIT
