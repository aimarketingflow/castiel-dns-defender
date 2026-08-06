//go:build !darwin

package pfguard

import (
	"context"
	"log"

	"github.com/castiel/dns/internal/alerts"
	"github.com/castiel/dns/internal/config"
)

type Guard struct{}

func NewGuard(cfg config.PFGuardConfig, alertMgr *alerts.Manager) *Guard {
	return &Guard{}
}

func (g *Guard) Start(ctx context.Context) {
	if cfg := config.PFGuardConfig{}; cfg.Enabled {
		log.Printf("PF guard is only available on macOS")
	}
}
