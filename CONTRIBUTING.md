# Contributing to Castiel

Thank you for your interest in contributing to Castiel! This document covers the development setup, code style, and pull request process.

## Development Setup

### Prerequisites

- **Go 1.23+** — [go.dev/dl](https://go.dev/dl/)
- **make** — for build targets
- **Root/sudo** — only needed for runtime testing (PF/nftables/Windows Firewall)

### Getting Started

```bash
git clone https://github.com/aimarketingflow/castiel-dns-defender.git
cd castiel-dns-defender
go build ./...
go test ./...
```

### Cross-Platform Compilation

Castiel uses build tags for platform-specific code:

- `//go:build darwin` — macOS PF firewall (`internal/pf/`)
- `//go:build linux` — Linux nftables/iptables (`internal/nft/`)
- `//go:build windows` — Windows DNS redirect (`internal/windivert/`)

To verify cross-compilation from any platform:

```bash
GOOS=linux GOARCH=arm64 go build ./...
GOOS=linux GOARCH=amd64 go build ./...
GOOS=windows GOARCH=amd64 go build ./...
```

## Code Style

- Follow standard Go conventions (`gofmt`, `go vet`)
- Use meaningful variable names — avoid abbreviations except for well-known ones (IP, DNS, TTL, DGA)
- All detector files go in `internal/detectors/`
- Each detector should have:
  - A struct with clearly-named fields
  - A `New*Detector()` constructor
  - Detection methods that return a finding struct or `nil`
  - A `Cleanup()` method if stateful
- Configuration structs go in `internal/config/config.go`
- Prometheus metrics go in `internal/metrics/metrics.go`
- Wire detectors into the pipeline in `internal/dnsproxy/proxy.go`

## Adding a New Detector

1. **Create the detector file** in `internal/detectors/your_detector.go`
2. **Add config struct** in `internal/config/config.go`
3. **Add Prometheus metrics** in `internal/metrics/metrics.go`
4. **Wire into Proxy struct** in `internal/dnsproxy/proxy.go`:
   - Add field to `Proxy` struct
   - Initialize in `New()` constructor
   - Add detection logic in `handleDNS()` (query or response phase)
   - Start cleanup goroutine if stateful
5. **Add config section** in `config.yaml`
6. **Write unit tests** in `internal/detectors/your_detector_test.go`
7. **Update README** detection pipeline table

### Detector Template

```go
package detectors

type YourDetector struct {
    // state fields
}

type YourFinding struct {
    Reason string
    Detail string
}

func NewYourDetector(cfg config.YourConfig) *YourDetector {
    return &YourDetector{}
}

func (d *YourDetector) Check(domain string) *YourFinding {
    // detection logic
    return nil
}

func (d *YourDetector) Cleanup() {
    // prune stale state
}
```

## Testing

```bash
# Run all tests
go test ./...

# Run with verbose output
go test -v ./internal/detectors/

# Run a specific test
go test -run TestLookalike ./internal/detectors/

# Benchmark
go test -bench=. ./internal/detectors/
```

### Test Guidelines

- Every detector must have unit tests
- Test both positive (detection triggers) and negative (no false positives) cases
- Test edge cases (empty input, nil responses, boundary conditions)
- Use table-driven tests where appropriate

## Pull Request Process

1. **Fork** the repository and create your branch from `main`
2. **Write tests** for new detectors or bug fixes
3. **Ensure all tests pass**: `go test ./...`
4. **Ensure cross-platform builds pass**: `GOOS=linux go build ./...` and `GOOS=windows go build ./...`
5. **Run `go vet`**: `go vet ./...`
6. **Update the README** if adding new detectors or changing the pipeline
7. **Keep PRs focused** — one detector or feature per PR

## Architecture Notes

### Detection Pipeline Flow

```
Query arrives
  → Rate limiting
  → Zone transfer block
  → Blocklist check
  → Tunneling detection (entropy)
  → DGA detection (heuristic + n-gram)
  → Dictionary DGA detection
  → Lookalike domain detection
  → Sparse DGA tracking
  → Low-and-slow exfil tracking
  → C2/fast-flux detection
  → Enhanced fast-flux analysis
  → NXDOMAIN tracking (block check)
  → EDNS0 inspection
  → Cache lookup
  → Forward upstream
  → Response validation
  → NXDOMAIN tracking (record)
  → Sparse DGA NXDOMAIN update
  → Fast-flux response tracking
  → CNAME chain validation
  → DNS calculation detection
  → DNSSEC validation + downgrade detection
  → Rebinding protection
  → Cache response
  → Send to client
```

### Platform Firewall Integration

Each platform implements the `firewall.Manager` interface:

```go
type Manager interface {
    InstallRedirect() error
    AddDoHBlockIP(ip string)
    Cleanup()
}
```

Platform-specific code is isolated in `internal/pf/`, `internal/nft/`, and `internal/windivert/` with build tags.

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
