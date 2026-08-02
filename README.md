<div align="center">

# Castiel

**Real-time DNS attack detection, prevention, and alerting**

Guardian of the threshold, watcher of the gate.

[![CI](https://github.com/aimarketingflow/castiel-dns-defender/actions/workflows/ci.yml/badge.svg)](https://github.com/aimarketingflow/castiel-dns-defender/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/castiel/dns)](https://goreportcard.com/report/github.com/castiel/dns)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Go Version](https://img.shields.io/badge/Go-1.23+-00ADD8.svg)](https://go.dev/)

macOS · Linux · Windows · Raspberry Pi

</div>

---

## Overview

Castiel is a cross-platform DNS defense proxy that intercepts all DNS traffic via platform-native firewall redirection and passes every query through a 25+ detector pipeline before being forwarded upstream. It detects and blocks DNS-based attacks in real-time, including DGA domains, DNS tunneling, fast-flux C2, water torture, cache poisoning, DNS rebinding, lookalike domains, and more.

> **Status:** v1.0.0-beta — macOS is fully tested and released. Linux (Raspberry Pi) and Windows builds compile and cross-compile cleanly but are not yet fully tested. Please report issues via [GitHub Issues](https://github.com/aimarketingflow/castiel-dns-defender/issues). See [Contributing](#contributing) if you'd like to help test those platforms.

### Why Castiel?

- **25+ attack detectors** across two tiers — from basic rate limiting to APT12 DNS calculation detection
- **True cross-platform** — PF on macOS, nftables/iptables on Linux, Windows Firewall on Windows
- **Single static binary** — no runtime dependencies, no Python, no Node.js
- **DoH bypass prevention** — blocks direct encrypted DNS to 18+ known public resolvers
- **Prometheus metrics** — built-in observability with Grafana dashboards
- **Desktop alerts** — native notifications on all three platforms
- **Attack simulator** — bundled `attack-sim` tool for testing all detection mechanisms

## Quick Start

### Install from source

```bash
go install github.com/castiel/dns@latest
```

### Install via Homebrew

```bash
brew tap aimarketingflow/tap
brew install --cask castiel
```

### Build from source

```bash
git clone https://github.com/aimarketingflow/castiel-dns-defender.git
cd castiel-dns-defender
go build -o castiel .
sudo ./castiel -config config.yaml
```

### macOS

```bash
sudo make install                    # Installs daemon, app, LaunchDaemon
launchctl list | grep castiel        # Check status
```

### Linux / Raspberry Pi (coming soon)

```bash
make build-linux                     # Cross-compile (amd64 + arm64)
sudo ./linux_build/install.sh        # Install on target
systemctl status castiel             # Check status
```

### Windows (coming soon)

```powershell
make build-windows                   # Cross-compile
.\windows_build\install.ps1          # Run as Admin
sc.exe query Castiel                 # Check status
```

## Platform-Specific DNS Interception

| Platform | Firewall | Service Manager | Notifications |
|---|---|---|---|
| **macOS** | PF (Packet Filter) via `pfctl` | LaunchDaemon (`launchctl`) | Notification Center |
| **Linux** | nftables (or iptables fallback) | systemd | `notify-send` (libnotify) |
| **Windows** | System DNS + `netsh portproxy` + Windows Firewall | Windows Service (SCM) | Windows Toast |

All platforms also block direct DoH/DoT connections to 18+ known public DNS resolvers (Google, Cloudflare, Quad9, AdGuard, OpenDNS, NextDNS, ControlD, Mullvad, DNS.SB) to prevent DNS traffic from bypassing Castiel via encrypted DNS.

## Detection Pipeline

### Tier 1 — Core Defenses

| # | Detector | Attack | Description |
|---|----------|--------|-------------|
| 1 | **Rate Limiting** | DDoS / Amplification | Per-IP token bucket + global QPS ceiling |
| 2 | **Zone Transfer Block** | Data exfiltration | AXFR/IXFR request blocking |
| 3 | **Blocklist Check** | Malware / Phishing | Threat intel feeds (URLhaus, OpenPhish, PhishTank) |
| 4 | **Tunneling Detection** | DNS tunneling | Shannon entropy on subdomain labels |
| 5 | **DGA Detection** | DGA domains | Entropy + consonant ratio + n-gram model |
| 6 | **C2/Fast-Flux** | C2 beaconing | TTL volatility + IP diversity tracking |
| 7 | **NXDOMAIN Tracking** | Water torture | Per-domain NXDOMAIN rate limiting with block mode |
| 8 | **EDNS0 Inspection** | SiphonDNS | ECS spoofing, cookie validation, unknown option detection |
| 9 | **Cache Lookup** | — | TTL-aware LRU cache |
| 10 | **Upstream Forward** | — | Plain DNS or DoH (encrypted) |
| 11 | **Response Validation** | TUDOOR | Bailiwick check, ID/question match, RCODE validation |
| 12 | **Fragmentation Defense** | IP fragmentation | UDP payload size capped at 1232 bytes |
| 13 | **DNSSEC Validation** | Cache poisoning | Reject bogus responses, downgrade detection |
| 14 | **Rebinding Protection** | DNS rebinding | Block public FQDNs resolving to RFC1918 IPs |
| 15 | **DoH Bypass Detection** | DoH bypass | Detect direct DoH/DoT connections to known resolvers |

### Tier 2 — Advanced Defenses

| # | Detector | Attack | Description |
|---|----------|--------|-------------|
| 16 | **Fast-Flux Enhanced** | Fast-flux C2 | IP rotation rate, ASN diversity, double-flux NS rotation |
| 17 | **Dictionary DGA** | Matsnu/Suppobox | Dynamic programming word-splitting with 150+ word dictionary |
| 18 | **Sparse DGA** | Ramdo/Ramnit/Virut | 24h rolling NXDOMAIN ratio per client IP |
| 19 | **CNAME Chain Validation** | CNAME abuse | Loop detection, dangling CNAMEs, excessive depth, cross-bailiwick |
| 20 | **DNS Calculation** | APT12 | IP-encoded command detection (sequential octets, encoded data) |
| 21 | **Low-and-Slow Exfil** | FrameworkPOS | 24h+ beaconing analysis, subdomain diversity, volume patterns |
| 22 | **Lookalike Domains** | Typosquatting | Levenshtein distance, homoglyph substitution, hyphen insertion, TLD swap |

### Blocking Coverage

| Attack Type | Status |
|---|---|
| DNS Amplification DDoS | **Blocked** |
| Water Torture / NXDOMAIN Flood | **Blocked** |
| DNS Cache Poisoning | **Blocked** (DNSSEC) |
| DNS Tunneling / Exfiltration | **Blocked** (entropy + low-slow) |
| DGA Domains (all types) | **Blocked** (heuristic + n-gram + dictionary + sparse) |
| DNS Rebinding | **Blocked** (RFC1918 check) |
| Zone Transfer (AXFR) | **Blocked** (ACL) |
| C2 Beaconing / Fast-Flux | **Blocked** (TTL + IP rotation + ASN) |
| On-Path DNS (MITM) | **Blocked** (DoH/DoT) |
| DoH Bypass | **Blocked** (firewall rules on all platforms) |
| Lookalike / Typosquatting | **Blocked** (Levenshtein + homoglyph) |
| CNAME Loops / Dangling | **Blocked** (chain validation) |
| DNS Calculation (APT12) | **Blocked** (IP pattern analysis) |
| EDNS0 Exploitation | **Blocked** (option inspection + stripping) |
| IP Fragmentation | **Blocked** (payload size cap) |
| DNSSEC Downgrade | **Detected** (previously-valid → failing alert) |

## Configuration

See `config.yaml` for all options. Key sections:

```yaml
# Platform-specific
pf:              # macOS PF firewall redirect
nft:             # Linux nftables/iptables redirect
dns_redirect:    # Windows DNS redirect method

# Detection (all platforms)
rate_limit:           # Token bucket per-IP and global QPS
tunneling_detection:  # Shannon entropy threshold
dga_detection:        # Entropy + consonant ratio + n-gram
dictionary_dga:       # Dictionary word-splitting DGA
sparse_dga:           # 24h NXDOMAIN ratio per client
cname_validation:     # CNAME chain depth, loops, dangling
dns_calculation:      # APT12 IP encoding detection
low_slow_exfil:       # Beaconing + subdomain diversity
lookalike_detection:  # Levenshtein + homoglyph + TLD swap
edns_inspection:      # EDNS0 option inspection
nxdomain_tracking:    # Per-domain water torture defense
dnssec_downgrade:     # DNSSEC downgrade detection
doh_bypass:           # DoH bypass blocking
response_validation:  # Response packet validation

# Infrastructure
blocklists:     # Threat intel feed URLs
alerts:         # JSONL logging, notifications, webhooks
metrics:        # Prometheus endpoint
cache:          # TTL-aware LRU cache
```

## Metrics

Castiel exposes Prometheus metrics at the configured endpoint:

```
castiel_total_queries_total
castiel_blocked_queries_total{reason}
castiel_cache_hits_total / cache_misses_total
castiel_rate_limited_queries_total
castiel_dga_alerts_total
castiel_fastflux_alerts_total{reason}
castiel_dictionary_dga_alerts_total{domain}
castiel_sparse_dga_alerts_total{client_ip}
castiel_cname_chain_alerts_total{type}
castiel_dns_calculation_alerts_total{reason}
castiel_low_slow_exfil_alerts_total{reason}
castiel_lookalike_alerts_total{reason}
castiel_edns_suspicious_total{type}
castiel_nxdomain_water_torture_total{domain}
castiel_dnssec_downgrade_alerts_total{domain}
castiel_doh_bypass_alerts_total{resolver}
castiel_response_validation_failures_total{field}
```

A pre-configured Grafana dashboard is included in `deploy/grafana/`.

## Attack Simulation

The bundled `attack-sim` tool tests all detection mechanisms:

```bash
go run ./cmd/attack-sim/ --help
```

Simulates: DGA domains, DNS tunneling, fast-flux, water torture, rebinding, lookalike domains, CNAME loops, DNS calculation, and more.

## DoH Kill Switch

Emergency DoH control on each platform:

- **macOS/Linux**: `doh-killswitch.sh {toggle|off|on|status|stop|restore}`
- **Windows**: `.\doh-killswitch.ps1 {toggle|off|on|status|stop|restore}`

## Project Structure

```
Castiel/
├── main.go                          # Entry point, daemon setup
├── main_darwin.go                   # macOS: PF firewall init
├── main_linux.go                    # Linux: nftables firewall init
├── main_windows.go                  # Windows: DNS redirect firewall init
├── config.yaml                      # Default configuration
├── go.mod                           # Go module (github.com/castiel/dns)
├── data/
│   ├── legitimate-domains.txt       # N-gram model training corpus
│   ├── root-trust-anchor.txt        # DNSSEC trust anchor
│   ├── custom_block.txt             # Custom blocklist
│   └── custom_allow.txt             # Custom allowlist
├── internal/
│   ├── config/config.go             # Config structs + validation
│   ├── firewall/firewall.go         # Cross-platform firewall interface
│   ├── dnsproxy/proxy.go            # DNS proxy server + detection pipeline
│   ├── detectors/
│   │   ├── entropy.go               # Shannon entropy tunneling detection
│   │   ├── dga.go                   # DGA (heuristics + n-gram)
│   │   ├── ngram.go                 # N-gram statistical model
│   │   ├── ratelimit.go             # Token bucket rate limiter
│   │   ├── rebinding_c2.go          # Rebinding + C2/fast-flux
│   │   ├── edns.go                  # EDNS0 option inspection
│   │   ├── nxndomain.go             # Per-domain NXDOMAIN tracking
│   │   ├── dnssec_downgrade.go      # DNSSEC downgrade detection
│   │   ├── response_validator.go    # Response packet validation
│   │   ├── doh_bypass.go            # DoH bypass detection
│   │   ├── fastflux.go              # Enhanced fast-flux (rotation, ASN)
│   │   ├── dictionary_dga.go        # Dictionary DGA (word splitting)
│   │   ├── sparse_dga.go            # Sparse DGA (NXDOMAIN ratio)
│   │   ├── cname_chain.go           # CNAME chain validation
│   │   ├── dns_calculation.go       # DNS calculation (APT12)
│   │   ├── lowslow_exfil.go         # Low-and-slow exfiltration
│   │   └── lookalike.go             # Lookalike/typosquatting
│   ├── blocklists/manager.go        # Threat intel feed manager
│   ├── cache/cache.go               # TTL-aware LRU DNS cache
│   ├── alerts/                      # Alert routing + notifications
│   ├── metrics/metrics.go           # Prometheus metrics
│   ├── pf/pf.go                     # macOS PF (//go:build darwin)
│   ├── nft/nft.go                   # Linux nftables/iptables (//go:build linux)
│   └── windivert/windivert.go       # Windows DNS redirect (//go:build windows)
├── deploy/                          # macOS deployment + Grafana
├── linux_build/                     # Linux deployment (systemd)
├── windows_build/                   # Windows deployment
├── macos-app/                       # macOS SwiftUI menu bar app
├── cmd/attack-sim/                  # DNS attack simulation tool
├── .github/workflows/ci.yml         # CI/CD pipeline (macOS)
├── .goreleaser.yml                  # macOS release builds (Homebrew + GitHub Releases)
└── Makefile                         # Build targets for all platforms
```

## Building

```bash
# Native build (current platform)
make build

# Cross-compile
make build-linux     # Linux amd64 + arm64 → linux_build/
make build-windows   # Windows amd64 + arm64 → windows_build/
make build-cross     # All platforms

# Release builds (stripped, optimized)
make release         # macOS daemon + SwiftUI app

# Run tests
go test ./...
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, code style, and pull request guidelines.

## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.

## Acknowledgments

- [miekg/dns](https://github.com/miekg/dns) — Go DNS library
- [Prometheus](https://prometheus.io/) — Metrics and monitoring
- Research references: SiphonDNS, TUDOOR, APT12 DNS Calculation, FrameworkPOS, Matsnu/Suppobox DGA, Ramdo/Ramnit DGA
