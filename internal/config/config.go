package config

import (
	"fmt"
	"time"
)

type Config struct {
	Server              ServerConfig              `yaml:"server"`
	DNSSEC              DNSSECConfig              `yaml:"dnssec"`
	RateLimit           RateLimitConfig           `yaml:"rate_limit"`
	TunnelingDetection  TunnelingDetectionConfig  `yaml:"tunneling_detection"`
	DGADetection        DGADetectionConfig        `yaml:"dga_detection"`
	RebindingProtection RebindingProtectionConfig `yaml:"rebinding_protection"`
	Blocklists          BlocklistsConfig          `yaml:"blocklists"`
	ZoneTransfer        ZoneTransferConfig        `yaml:"zone_transfer"`
	C2Detection         C2DetectionConfig         `yaml:"c2_detection"`
	Alerts              AlertsConfig              `yaml:"alerts"`
	Metrics             MetricsConfig             `yaml:"metrics"`
	PF                  PFConfig                  `yaml:"pf"`
	Nft                 NftConfig                 `yaml:"nft"`
	DnsRedirect         DnsRedirectConfig         `yaml:"dns_redirect"`
	Cache               CacheConfig               `yaml:"cache"`
}

type ServerConfig struct {
	ListenAddr      string   `yaml:"listen_addr"`
	ListenPort      int      `yaml:"listen_port"`
	Upstream        []string `yaml:"upstream"`
	UpstreamTimeout string   `yaml:"upstream_timeout"`
	DoHUpstream     string   `yaml:"doh_upstream"`
	UseDoH          bool     `yaml:"use_doh"`
}

func (s *ServerConfig) TimeoutDuration() time.Duration {
	d, err := time.ParseDuration(s.UpstreamTimeout)
	if err != nil {
		return 5 * time.Second
	}
	return d
}

type DNSSECConfig struct {
	Enabled         bool   `yaml:"enabled"`
	TrustAnchorFile string `yaml:"trust_anchor_file"`
	RejectBogus     bool   `yaml:"reject_bogus"`
}

type RateLimitConfig struct {
	Enabled           bool   `yaml:"enabled"`
	PerIPQPS          int    `yaml:"per_ip_qps"`
	GlobalQPS         int    `yaml:"global_qps"`
	NXDomainPerIPQPS  int    `yaml:"nxdomain_per_ip_qps"`
	WindowSeconds     int    `yaml:"window_seconds"`
	Action            string `yaml:"action"`
	DelayMs           int    `yaml:"delay_ms"`
}

type TunnelingDetectionConfig struct {
	Enabled          bool     `yaml:"enabled"`
	EntropyThreshold float64  `yaml:"entropy_threshold"`
	MinLabelLength   int      `yaml:"min_label_length"`
	MaxSubdomainDepth int     `yaml:"max_subdomain_depth"`
	TXTRecordAlert   bool     `yaml:"txt_record_alert"`
	CDNWhitelist     []string `yaml:"cdn_whitelist"`
}

type DGADetectionConfig struct {
	Enabled                bool    `yaml:"enabled"`
	EntropyThreshold       float64 `yaml:"entropy_threshold"`
	ConsonantRatioThreshold float64 `yaml:"consonant_ratio_threshold"`
	MinDomainLength        int     `yaml:"min_domain_length"`
	NgramModel             string  `yaml:"ngram_model"`
	NewlyRegisteredDays    int     `yaml:"newly_registered_days"`
}

type RebindingProtectionConfig struct {
	Enabled              bool     `yaml:"enabled"`
	BlockPublicToPrivate bool     `yaml:"block_public_to_private"`
	PrivateRanges        []string `yaml:"private_ranges"`
}

type BlocklistsConfig struct {
	Enabled         bool         `yaml:"enabled"`
	RefreshInterval int          `yaml:"refresh_interval"`
	Feeds           []FeedConfig `yaml:"feeds"`
	CustomBlockFile string       `yaml:"custom_block_file"`
	CustomAllowFile string       `yaml:"custom_allow_file"`
}

type FeedConfig struct {
	Name    string `yaml:"name"`
	URL     string `yaml:"url"`
	Format  string `yaml:"format"`
	Enabled bool   `yaml:"enabled"`
}

type ZoneTransferConfig struct {
	BlockAXFR  bool `yaml:"block_axfr"`
	BlockIXFR  bool `yaml:"block_ixfr"`
	AlertOnly  bool `yaml:"alert_only"`
}

type C2DetectionConfig struct {
	Enabled              bool `yaml:"enabled"`
	TTLVolatilityThreshold int  `yaml:"ttl_volatility_threshold"`
	MinIPCount           int  `yaml:"min_ip_count"`
	CheckInterval        int  `yaml:"check_interval"`
}

type AlertsConfig struct {
	Enabled             bool   `yaml:"enabled"`
	LogFile             string `yaml:"log_file"`
	WebhookURL          string `yaml:"webhook_url"`
	WebhookEnabled      bool   `yaml:"webhook_enabled"`
	SyslogEnabled       bool   `yaml:"syslog_enabled"`
	MinSeverity         string `yaml:"min_severity"`
	RateLimitAlerts     bool   `yaml:"rate_limit_alerts"`
	DesktopNotification bool   `yaml:"desktop_notification"`
}

type MetricsConfig struct {
	Enabled  bool   `yaml:"enabled"`
	BindAddr string `yaml:"bind_addr"`
	Path     string `yaml:"path"`
}

type PFConfig struct {
	Enabled      bool   `yaml:"enabled"`
	AnchorName   string `yaml:"anchor_name"`
	RedirectPort int    `yaml:"redirect_port"`
	Interface    string `yaml:"interface"`
}

// NftConfig configures Linux nftables/iptables DNS redirect.
// Used on Linux as the equivalent of PFConfig on macOS.
type NftConfig struct {
	Enabled      bool   `yaml:"enabled"`
	Backend      string `yaml:"backend"`       // "nftables" (default) or "iptables"
	RedirectPort int    `yaml:"redirect_port"`
	Interface    string `yaml:"interface"`    // empty = all interfaces
}

// DnsRedirectConfig configures Windows DNS traffic redirection.
// Used on Windows as the equivalent of PFConfig on macOS.
type DnsRedirectConfig struct {
	Enabled      bool   `yaml:"enabled"`
	Method       string `yaml:"method"`        // "system_dns" (default), "portproxy", or "windivert"
	RedirectPort int    `yaml:"redirect_port"`
	Interface    string `yaml:"interface"`    // empty = all interfaces
	BindPort53   bool   `yaml:"bind_port_53"` // Castiel binds directly to :53
}

type CacheConfig struct {
	Enabled     bool `yaml:"enabled"`
	MaxEntries  int  `yaml:"max_entries"`
	DefaultTTL  int  `yaml:"default_ttl"`
	NegativeTTL int  `yaml:"negative_ttl"`
}

func (c *Config) Validate() error {
	if c.Server.ListenPort < 1 || c.Server.ListenPort > 65535 {
		return fmt.Errorf("invalid listen port: %d", c.Server.ListenPort)
	}
	if len(c.Server.Upstream) == 0 && !c.Server.UseDoH {
		return fmt.Errorf("no upstream servers configured")
	}
	if c.RateLimit.Enabled && c.RateLimit.PerIPQPS < 1 {
		return fmt.Errorf("rate_limit.per_ip_qps must be >= 1")
	}
	return nil
}
