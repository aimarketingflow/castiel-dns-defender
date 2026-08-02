# Castiel — macOS App

Native SwiftUI macOS app for managing the Castiel Go daemon.

## Building

### Option 1: Swift Package Manager (CLI)
```bash
cd macos-app
swift build
swift run Castiel
```

### Option 2: Xcode
```bash
cd macos-app
open Package.swift
```
This opens the project in Xcode. Press ⌘R to build and run.

## Features

- **Dashboard** — Real-time metrics (queries, blocked, cache hits, rate limited, DoH status)
- **DoH Control** — Kill switch panel with toggle, emergency disable, signal reference
- **Alerts** — Live alert feed with severity filtering
- **Logs** — Live daemon log output
- **Settings** — Configure server, DoH, DNSSEC, rate limiting, blocklists, cache, PF

## Architecture

```
macos-app/
├── Package.swift                          # SPM package manifest
└── Sources/Castiel/
    ├── CastielApp.swift               # App entry point + menu commands
    ├── ContentView.swift                  # Main window + sidebar navigation
    ├── DaemonManager.swift                # Go binary process lifecycle + signals
    ├── MetricsPoller.swift                # Prometheus endpoint polling
    ├── AlertFeed.swift                    # Alert log file tailing
    ├── DashboardView.swift                # Metrics dashboard with charts
    ├── DoHControlView.swift               # DoH kill switch control panel
    ├── AlertsView.swift                   # Alert feed view
    ├── LogsView.swift                      # Live log viewer
    └── SettingsView.swift                 # Configuration editor
```

## Integration

The app manages the Go `castiel` binary:
- **Start/Stop** — Launches/terminates the daemon process
- **DoH Toggle** — Sends SIGHUP/SIGUSR1/SIGUSR2 signals to the running daemon
- **Metrics** — Polls `http://127.0.0.1:9090/metrics` (Prometheus format)
- **Alerts** — Tails `data/alerts.log`
- **Kill Switch** — Runs `doh-killswitch.sh` with various actions

## Environment Variables

- `CASTIEL_ROOT` — Path to the project root (default: current directory)
- `CASTIEL_CONFIG` — Path to config.yaml (default: `$CASTIEL_ROOT/config.yaml`)
