//go:build darwin

package main

import (
	"log"

	"github.com/castiel/dns/internal/config"
	"github.com/castiel/dns/internal/firewall"
	"github.com/castiel/dns/internal/pf"
)

func initFirewall(cfg *config.Config) firewall.Manager {
	if !cfg.PF.Enabled {
		return nil
	}

	mgr, err := pf.NewManager(cfg.PF)
	if err != nil {
		log.Printf("WARNING: PF setup failed: %v", err)
		return nil
	}

	// Add custom DoH bypass IPs from config
	if cfg.DoHBypass.Enabled {
		for _, ip := range cfg.DoHBypass.BlockIPs {
			mgr.AddDoHBlockIP(ip)
		}
	}

	if err := mgr.InstallRedirect(); err != nil {
		log.Printf("WARNING: PF redirect install failed: %v", err)
		return nil
	}

	log.Printf("PF redirect: DNS :53 -> :%d on %s", cfg.PF.RedirectPort, cfg.PF.Interface)
	if cfg.DoHBypass.Enabled {
		log.Printf("PF DoH bypass: blocking direct DoH/DoT to known public resolvers")
	}
	return mgr
}
