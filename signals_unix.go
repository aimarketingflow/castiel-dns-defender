//go:build !windows

package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/castiel/dns/internal/dnsproxy"
	"github.com/castiel/dns/internal/firewall"
)

// maybeRunAsService is a no-op on non-Windows platforms.
func maybeRunAsService(configPath string) {
	runDaemon(context.Background(), configPath)
}

// handleSignals manages Unix signals for DoH toggle and graceful shutdown.
// fwMgr is passed so PF rules can be cleaned up immediately on SIGTERM/SIGINT,
// before any sleep — this prevents orphaned PF redirects if launchd sends
// SIGKILL during the shutdown grace period.
func handleSignals(ctx context.Context, cancel context.CancelFunc, proxy *dnsproxy.Proxy, fwMgr firewall.Manager) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGUSR1, syscall.SIGUSR2)

	for {
		sig := <-sigChan
		switch sig {
		case syscall.SIGHUP:
			if proxy.DoHEnabled() {
				log.Printf("SIGHUP received — disabling DoH (kill switch activated)")
				proxy.DisableDoH()
			} else {
				log.Printf("SIGHUP received — re-enabling DoH")
				proxy.EnableDoH()
			}
		case syscall.SIGUSR1:
			log.Printf("SIGUSR1 received — emergency DoH disable")
			proxy.DisableDoH()
		case syscall.SIGUSR2:
			log.Printf("SIGUSR2 received — re-enabling DoH")
			proxy.EnableDoH()
		case syscall.SIGINT, syscall.SIGTERM:
			log.Printf("Received signal %v, shutting down...", sig)
			// Clean up PF rules FIRST, before anything else, so the system
			// doesn't lose DNS even if the process is killed mid-shutdown.
			if fwMgr != nil {
				fwMgr.Cleanup()
				log.Printf("Firewall rules cleaned up.")
			}
			cancel()
			log.Printf("Shutdown complete.")
			return
		}
	}
}
