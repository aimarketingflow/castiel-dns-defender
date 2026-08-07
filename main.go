package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/castiel/dns/internal/alerts"
	"github.com/castiel/dns/internal/blocklists"
	"github.com/castiel/dns/internal/config"
	"github.com/castiel/dns/internal/dnsproxy"
	"github.com/castiel/dns/internal/endpointmonitor"
	"github.com/castiel/dns/internal/metrics"
	"github.com/castiel/dns/internal/pfguard"
	"gopkg.in/yaml.v3"
)

var (
	version = "0.1.0"
)

func main() {
	configPath := flag.String("config", "config.yaml", "Path to configuration file")
	versionFlag := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *versionFlag {
		fmt.Printf("Castiel v%s\n", version)
		os.Exit(0)
	}

	// On Windows, check if running as a service and delegate to SCM.
	// On other platforms, this is a no-op.
	maybeRunAsService(*configPath)
}

// runDaemon is the main daemon loop, shared across all platforms.
// It can be called from main() (foreground) or from the Windows Service wrapper.
func runDaemon(ctx context.Context, configPath string) {
	// Load configuration
	cfg, err := loadConfig(configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	log.Printf("Castiel v%s starting...", version)

	// Initialize alert system
	alertMgr := alerts.NewManager(cfg.Alerts)
	go alertMgr.Start()

	// Initialize blocklist manager
	blocklistMgr := blocklists.NewManager(cfg.Blocklists)
	go blocklistMgr.StartRefreshLoop()

	// Initialize metrics server
	if cfg.Metrics.Enabled {
		metricsSrv := metrics.NewServer(cfg.Metrics)
		go metricsSrv.Start()
		log.Printf("Metrics server listening on %s%s", cfg.Metrics.BindAddr, cfg.Metrics.Path)
	}

	// Initialize firewall redirect (platform-specific: PF on macOS, nftables on Linux, DNS redirect on Windows)
	fwMgr := initFirewall(cfg)
	if fwMgr != nil {
		defer fwMgr.Cleanup()
	}

	// Initialize DNS proxy server
	proxy, err := dnsproxy.New(cfg, blocklistMgr, alertMgr)
	if err != nil {
		log.Printf("Failed to create DNS proxy: %v", err)
		if fwMgr != nil {
			fwMgr.Cleanup()
		}
		os.Exit(1)
	}

	// Start the proxy — on error, clean up PF rules before exiting
	// (log.Fatalf calls os.Exit which skips deferred functions)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("DNS proxy panic: %v", r)
				if fwMgr != nil {
					fwMgr.Cleanup()
				}
				os.Exit(1)
			}
		}()
		if err := proxy.Start(ctx); err != nil {
			log.Printf("DNS proxy error: %v", err)
			if fwMgr != nil {
				fwMgr.Cleanup()
			}
			os.Exit(1)
		}
	}()

	// Start DoH health checker (auto-disables DoH on failure, auto-re-enables when healthy)
	proxy.StartDoHHealthChecker(ctx)

	// Start Apple endpoint health monitor (detects Phase 3: IP-level OCSP blocking)
	if cfg.EndpointMonitor.Enabled {
		endpointMon := endpointmonitor.NewMonitor(cfg.EndpointMonitor, alertMgr)
		go endpointMon.Start(ctx)
	}

	// Start PF rules integrity guard (detects unauthorized PF rules blocking Apple endpoints)
	if cfg.PFGuard.Enabled {
		pfGuard := pfguard.NewGuard(cfg.PFGuard, alertMgr)
		go pfGuard.Start(ctx)
	}

	log.Printf("DNS proxy listening on %s:%d", cfg.Server.ListenAddr, cfg.Server.ListenPort)
	log.Printf("Upstream: %v (DoH: %v)", cfg.Server.Upstream, cfg.Server.UseDoH)
	if cfg.Server.UseDoH && cfg.Server.DoHUpstream != "" {
		log.Printf("DoH endpoint: %s", cfg.Server.DoHUpstream)
	}

	// Signal handlers (Unix signals; on Windows these are handled via service controls)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	handleSignals(ctx, cancel, proxy, fwMgr)
}

func loadConfig(path string) (*config.Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	var cfg config.Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config validation: %w", err)
	}

	return &cfg, nil
}
