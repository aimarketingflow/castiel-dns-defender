//go:build windows

package main

import (
	"context"
	"log"
	"time"

	"github.com/castiel/dns/internal/dnsproxy"
	"github.com/castiel/dns/internal/firewall"
)

// maybeRunAsService checks if the process is running as a Windows Service.
// If so, it delegates to the SCM service handler. Otherwise, it runs
// the daemon in the foreground (console mode).
func maybeRunAsService(configPath string) {
	if isWindowsService() {
		log.Printf("Running as Windows Service — delegating to SCM")
		if err := runAsService(func(ctx context.Context) {
			runDaemon(ctx, configPath)
		}); err != nil {
			log.Fatalf("Windows Service error: %v", err)
		}
		return
	}

	// Running in console — start daemon directly
	runDaemon(context.Background(), configPath)
}

// handleSignals is a no-op on Windows. Signal handling is done via
// Windows Service controls (see service_windows.go).
func handleSignals(ctx context.Context, cancel context.CancelFunc, proxy *dnsproxy.Proxy, fwMgr firewall.Manager) {
	// On Windows, we don't use Unix signals. The service wrapper handles
	// stop/shutdown via SCM. For console mode, Ctrl+C is handled by the
	// Go runtime default behavior (SIGINT → exit).
	//
	// DoH toggle is handled via named pipe commands (doh-killswitch.ps1).
	// TODO: implement named pipe IPC for DoH toggle on Windows.

	// Block forever — the daemon runs until the service is stopped
	// or the process is killed.
	<-ctx.Done()
	time.Sleep(2 * time.Second)
	log.Printf("Shutdown complete.")
}
