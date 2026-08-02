//go:build windows

package main

import (
	"log"

	"github.com/castiel/dns/internal/config"
	"github.com/castiel/dns/internal/firewall"
	"github.com/castiel/dns/internal/windivert"
)

func initFirewall(cfg *config.Config) firewall.Manager {
	if !cfg.DnsRedirect.Enabled {
		return nil
	}

	mgr, err := windivert.NewManager(cfg.DnsRedirect)
	if err != nil {
		log.Printf("WARNING: Windows DNS redirect setup failed: %v", err)
		return nil
	}

	// Add custom DoH bypass IPs from config
	if cfg.DoHBypass.Enabled {
		for _, ip := range cfg.DoHBypass.BlockIPs {
			mgr.AddDoHBlockIP(ip)
		}
	}

	if err := mgr.InstallRedirect(); err != nil {
		log.Printf("WARNING: DNS redirect install failed: %v", err)
		return nil
	}

	log.Printf("DNS redirect: method=%s port=%d", cfg.DnsRedirect.Method, cfg.DnsRedirect.RedirectPort)
	if cfg.DoHBypass.Enabled {
		log.Printf("DoH bypass: blocking direct DoH/DoT to known public resolvers via Windows Firewall")
	}
	return mgr
}
