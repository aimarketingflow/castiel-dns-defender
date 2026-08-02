//go:build linux

package nft

import (
	"strings"
	"testing"

	"github.com/castiel/dns/internal/config"
)

func TestGenerateNftRules(t *testing.T) {
	cfg := config.NftConfig{
		Enabled:      true,
		RedirectPort: 5300,
		Interface:    "eth0",
	}

	m := &Manager{cfg: cfg, tableName: "castiel"}
	rules := m.generateNftRules()

	// Should contain IPv4 table
	if !strings.Contains(rules, "table ip castiel") {
		t.Error("Missing IPv4 nftables table")
	}

	// Should contain IPv6 table
	if !strings.Contains(rules, "table ip6 castiel") {
		t.Error("Missing IPv6 nftables table")
	}

	// Should contain UDP redirect on eth0
	if !strings.Contains(rules, `iifname "eth0" udp dport 53 redirect to :5300`) {
		t.Error("Missing IPv4 UDP redirect rule with interface")
	}

	// Should contain TCP redirect
	if !strings.Contains(rules, `iifname "eth0" tcp dport 53 redirect to :5300`) {
		t.Error("Missing IPv4 TCP redirect rule with interface")
	}

	// Should contain NAT hook
	if !strings.Contains(rules, "type nat hook prerouting priority -100") {
		t.Error("Missing NAT prerouting hook")
	}
}

func TestGenerateNftRulesNoInterface(t *testing.T) {
	cfg := config.NftConfig{
		Enabled:      true,
		RedirectPort: 5300,
		Interface:    "",
	}

	m := &Manager{cfg: cfg, tableName: "castiel"}
	rules := m.generateNftRules()

	// Without interface, should not have iifname filter
	if strings.Contains(rules, "iifname") {
		t.Error("Rules should not contain iifname when interface is empty")
	}

	// Should still have redirect rules
	if !strings.Contains(rules, "udp dport 53 redirect to :5300") {
		t.Error("Missing UDP redirect rule without interface filter")
	}
}

func TestGenerateNftRulesDifferentPort(t *testing.T) {
	cfg := config.NftConfig{
		Enabled:      true,
		RedirectPort: 5353,
		Interface:    "",
	}

	m := &Manager{cfg: cfg, tableName: "castiel"}
	rules := m.generateNftRules()

	if !strings.Contains(rules, "redirect to :5353") {
		t.Error("Rules should reference redirect port 5353")
	}
}

func TestBackend(t *testing.T) {
	m := &Manager{useIptables: false}
	if m.Backend() != "nftables" {
		t.Errorf("Backend() = %q, want %q", m.Backend(), "nftables")
	}

	m2 := &Manager{useIptables: true}
	if m2.Backend() != "iptables" {
		t.Errorf("Backend() = %q, want %q", m2.Backend(), "iptables")
	}
}
