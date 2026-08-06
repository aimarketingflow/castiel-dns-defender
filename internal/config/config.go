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
	EDNSInspection      EDNSInspectionConfig      `yaml:"edns_inspection"`
	NXDomainTracking    NXDomainTrackingConfig    `yaml:"nxdomain_tracking"`
	DNSSECDowngrade     DNSSECDowngradeConfig     `yaml:"dnssec_downgrade"`
	DoHBypass           DoHBypassConfig           `yaml:"doh_bypass"`
	ResponseValidation  ResponseValidationConfig  `yaml:"response_validation"`
	DictionaryDGA      DictionaryDGAConfig      `yaml:"dictionary_dga"`
	SparseDGA          SparseDGAConfig          `yaml:"sparse_dga"`
	CNAMEValidation    CNAMEValidationConfig    `yaml:"cname_validation"`
	DNSCalculation     DNSCalculationConfig     `yaml:"dns_calculation"`
	LowSlowExfil       LowSlowExfilConfig       `yaml:"low_slow_exfil"`
	LookalikeDetection LookalikeConfig          `yaml:"lookalike_detection"`
	EndpointMonitor    EndpointMonitorConfig    `yaml:"endpoint_monitor"`
	PFGuard            PFGuardConfig            `yaml:"pf_guard"`
	ShadowQuery        ShadowQueryConfig        `yaml:"shadow_query"`
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

// ShadowQueryConfig enables an out-of-band comparison query sent directly
// to the local network's resolver (e.g. DHCP-provided gateway) in parallel
// with the primary DoH-resolved query. This lets Castiel detect and alert
// on active DNS poisoning attempts on the network even when DoH resolution
// already protected the client from the poisoned response.
type ShadowQueryConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Resolver  string `yaml:"resolver"`   // e.g. "192.168.2.1:53" — network resolver to shadow-query
	TimeoutMs int    `yaml:"timeout_ms"` // shadow query timeout in milliseconds
}

func (s *ShadowQueryConfig) TimeoutDuration() time.Duration {
	if s.TimeoutMs <= 0 {
		return 2 * time.Second
	}
	return time.Duration(s.TimeoutMs) * time.Millisecond
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

// EDNSInspectionConfig configures EDNS0 option inspection for covert
// data exfiltration detection (SiphonDNS-style attacks).
type EDNSInspectionConfig struct {
	Enabled          bool `yaml:"enabled"`
	StripSuspicious  bool `yaml:"strip_suspicious"` // strip suspicious EDNS0 options before forwarding
	MaxCookieLen     int  `yaml:"max_cookie_len"`  // max allowed DNS cookie length (default 8)
	AlertOnUnknown   bool `yaml:"alert_on_unknown"` // alert on unknown EDNS0 option codes
}

// NXDomainTrackingConfig configures per-domain NXDOMAIN rate limiting
// to detect distributed DNS water torture attacks.
type NXDomainTrackingConfig struct {
	Enabled    bool `yaml:"enabled"`
	Threshold  int  `yaml:"threshold"`   // max NXDOMAINs per domain per window before alerting
	WindowSecs int  `yaml:"window_secs"` // rolling window in seconds
	BlockMode  bool `yaml:"block_mode"`  // block all queries to domain when threshold exceeded
}

// DNSSECDowngradeConfig configures DNSSEC downgrade attack detection.
type DNSSECDowngradeConfig struct {
	Enabled bool `yaml:"enabled"`
}

// DoHBypassConfig configures detection of DNS traffic bypassing Castiel
// via direct DoH/DoT connections to public resolvers.
type DoHBypassConfig struct {
	Enabled  bool     `yaml:"enabled"`
	BlockIPs []string `yaml:"block_ips"` // additional DoH resolver IPs to block beyond the built-in list
}

// ResponseValidationConfig configures strict DNS response packet validation
// to detect malformed packets (TUDOOR-style attacks).
type ResponseValidationConfig struct {
	Enabled          bool `yaml:"enabled"`
	DropMalformed    bool `yaml:"drop_malformed"`    // drop responses that fail validation
	BailiwickCheck   bool `yaml:"bailiwick_check"`   // enforce bailiwick checking on answer records
	MaxEDNS0UDPSize  int  `yaml:"max_edns0_udp_size"` // max EDNS0 UDP payload size (default 1232, prevents fragmentation)
}

// DictionaryDGAConfig configures dictionary-based DGA detection.
type DictionaryDGAConfig struct {
	Enabled  bool     `yaml:"enabled"`
	WordList string   `yaml:"word_list"` // path to word list file (optional, uses built-in if empty)
}

// SparseDGAConfig configures sparse/low-frequency DGA detection.
type SparseDGAConfig struct {
	Enabled          bool    `yaml:"enabled"`
	NXDomainRatio    float64 `yaml:"nxdomain_ratio"`    // e.g., 0.6 = 60% NXDOMAIN threshold
	MinQueries       int     `yaml:"min_queries"`      // minimum queries in 24h to trigger
	MinUniqueDomains int     `yaml:"min_unique_domains"` // minimum unique domains to trigger
	WindowHours      int     `yaml:"window_hours"`     // rolling window (default 24)
}

// CNAMEValidationConfig configures CNAME chain validation.
type CNAMEValidationConfig struct {
	Enabled     bool `yaml:"enabled"`
	MaxDepth    int  `yaml:"max_depth"`     // max CNAME chain depth (default 10)
	BlockLoops  bool `yaml:"block_loops"`   // block CNAME loops
	BlockDangling bool `yaml:"block_dangling"` // block dangling CNAMEs
}

// DNSCalculationConfig configures DNS calculation attack detection (APT12-style).
type DNSCalculationConfig struct {
	Enabled bool `yaml:"enabled"`
}

// LowSlowExfilConfig configures low-and-slow exfiltration detection.
type LowSlowExfilConfig struct {
	Enabled         bool `yaml:"enabled"`
	MaxSubdomains   int   `yaml:"max_subdomains"`    // unique subdomain threshold (default 50)
	BeaconThreshold float64 `yaml:"beacon_threshold"` // regularity score threshold (default 0.7)
}

// LookalikeConfig configures lookalike/typosquatting domain detection.
type LookalikeConfig struct {
	Enabled          bool     `yaml:"enabled"`
	ProtectedDomains []string `yaml:"protected_domains"` // additional domains to protect beyond defaults
	MaxLevenshtein   int      `yaml:"max_levenshtein"`   // max edit distance (default 2)
}

// EndpointMonitorConfig configures Apple endpoint health monitoring.
// Periodically TCP-probes Apple's OCSP/CRL/notarization endpoints to detect
// IP-level blocking (Phase 3 attack: PF rules blocking 17.0.0.0/8 on ports 80/443
// to make trustd fail-open and bypass Gatekeeper revocation).
type EndpointMonitorConfig struct {
	Enabled        bool `yaml:"enabled"`
	CheckInterval  int  `yaml:"check_interval"`   // seconds between checks (default 30)
	ConnectTimeout int  `yaml:"connect_timeout"`  // TCP connect timeout in seconds (default 3)
}

// PFGuardConfig configures PF rules integrity monitoring.
// Scans PF rules for unauthorized block rules targeting Apple's IP ranges
// or certificate validation ports (80/443).
type PFGuardConfig struct {
	Enabled       bool   `yaml:"enabled"`
	CheckInterval int    `yaml:"check_interval"` // seconds between checks (default 30)
	CastielAnchor string `yaml:"castiel_anchor"` // Castiel's own anchor name to exclude from scans
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
