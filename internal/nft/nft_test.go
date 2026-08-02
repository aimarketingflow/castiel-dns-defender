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

	m := &Manager{cfg: cfg, tableName: "castiel", dohIPs: defaultDoHResolverIPs()}
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

	// Should contain output chain
	if !strings.Contains(rules, "type nat hook output priority -100") {
		t.Error("Missing NAT output hook")
	}

	// Should contain DoH block rules
	if !strings.Contains(rules, "tcp dport { 443, 853 } drop") {
		t.Error("Missing DoH/DoT block rules")
	}
}

func TestGenerateNftRulesNoInterface(t *testing.T) {
	cfg := config.NftConfig{
		Enabled:      true,
		RedirectPort: 5300,
		Interface:    "",
	}

	m := &Manager{cfg: cfg, tableName: "castiel", dohIPs: defaultDoHResolverIPs()}
	rules := m.generateNftRules()

	// Without interface, should not have iifname filter
	if strings.Contains(rules, "iifname") {
		t.Error("Rules should not contain iifname when interface is empty")
	}

	// Should still have redirect rules
	if !strings.Contains(rules, "udp dport 53 redirect to :5300") {
		t.Error("Missing UDP redirect rule without interface filter")
	}

	// Should contain DoH block rules
	if !strings.Contains(rules, "tcp dport { 443, 853 } drop") {
		t.Error("Missing DoH/DoT block rules")
	}
}

func TestGenerateNftRulesDifferentPort(t *testing.T) {
	cfg := config.NftConfig{
		Enabled:      true,
		RedirectPort: 5353,
		Interface:    "",
	}

	m := &Manager{cfg: cfg, tableName: "castiel", dohIPs: defaultDoHResolverIPs()}
	rules := m.generateNftRules()

	if !strings.Contains(rules, "redirect to :5353") {
		t.Error("Rules should reference redirect port 5353")
	}
}

func TestAddDoHBlockIP(t *testing.T) {
	m := &Manager{cfg: config.NftConfig{}, tableName: "castiel", dohIPs: defaultDoHResolverIPs()}
	initialCount := len(m.dohIPs)
	m.AddDoHBlockIP("203.0.113.1")
	if len(m.dohIPs) != initialCount+1 {
		t.Errorf("Expected %d DoH IPs after add, got %d", initialCount+1, len(m.dohIPs))
	}
	if m.dohIPs[len(m.dohIPs)-1] != "203.0.113.1" {
		t.Error("Added IP should be last in slice")
	}
}

func TestDefaultDoHResolverIPs(t *testing.T) {
	ips := defaultDoHResolverIPs()
	if len(ips) < 10 {
		t.Errorf("Expected at least 10 default DoH resolver IPs, got %d", len(ips))
	}
	// Check for some known resolvers
	found := false
	for _, ip := range ips {
		if ip == "8.8.8.8" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Default DoH IPs should include 8.8.8.8")
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

func TestGenerateNftRulesDoHBlock(t *testing.T) {
	cfg := config.NftConfig{
		Enabled:      true,
		RedirectPort: 5300,
		Interface:    "",
	}
	m := &Manager{cfg: cfg, tableName: "castiel", dohIPs: []string{"8.8.8.8", "1.1.1.1"}}
	rules := m.generateNftRules()

	// Should contain block rule for each DoH IP
	if !strings.Contains(rules, "ip daddr 8.8.8.8 tcp dport { 443, 853 } drop") {
		t.Error("Missing DoH block rule for 8.8.8.8")
	}
	if !strings.Contains(rules, "ip daddr 1.1.1.1 tcp dport { 443, 853 } drop") {
		t.Error("Missing DoH block rule for 1.1.1.1")
	}
}
