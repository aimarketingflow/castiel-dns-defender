//go:build linux

package main

import (
	"log"

	"github.com/castiel/dns/internal/config"
	"github.com/castiel/dns/internal/firewall"
	"github.com/castiel/dns/internal/nft"
)

func initFirewall(cfg *config.Config) firewall.Manager {
	if !cfg.Nft.Enabled {
		return nil
	}

	mgr, err := nft.NewManager(cfg.Nft)
	if err != nil {
		log.Printf("WARNING: nftables/iptables setup failed: %v", err)
		return nil
	}

	// Add custom DoH bypass IPs from config
	if cfg.DoHBypass.Enabled {
		for _, ip := range cfg.DoHBypass.BlockIPs {
			mgr.AddDoHBlockIP(ip)
		}
	}

	if err := mgr.InstallRedirect(); err != nil {
		log.Printf("WARNING: %s redirect install failed: %v", mgr.Backend(), err)
		return nil
	}

	iface := cfg.Nft.Interface
	if iface == "" {
		iface = "all interfaces"
	}
	log.Printf("%s redirect: DNS :53 -> :%d on %s", mgr.Backend(), cfg.Nft.RedirectPort, iface)
	if cfg.DoHBypass.Enabled {
		log.Printf("%s DoH bypass: blocking direct DoH/DoT to known public resolvers", mgr.Backend())
	}
	return mgr
}
