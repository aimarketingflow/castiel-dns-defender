//go:build !windows

package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/castiel/dns/internal/dnsproxy"
)

// maybeRunAsService is a no-op on non-Windows platforms.
func maybeRunAsService(configPath string) {
	runDaemon(context.Background(), configPath)
}

// handleSignals manages Unix signals for DoH toggle and graceful shutdown.
func handleSignals(ctx context.Context, cancel context.CancelFunc, proxy *dnsproxy.Proxy) {
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
			cancel()
			time.Sleep(2 * time.Second)
			log.Printf("Shutdown complete.")
			return
		}
	}
}
