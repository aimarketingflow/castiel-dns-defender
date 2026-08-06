package metrics

import (
	"log"
	"net/http"

	"github.com/castiel/dns/internal/config"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	TotalQueries = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "castiel_total_queries_total",
		Help: "Total DNS queries received",
	})

	CacheHits = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "castiel_cache_hits_total",
		Help: "DNS cache hits",
	})

	CacheMisses = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "castiel_cache_misses_total",
		Help: "DNS cache misses",
	})

	RateLimitedQueries = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "castiel_rate_limited_queries_total",
		Help: "Queries dropped or truncated by rate limiter",
	})

	BlockedQueries = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "castiel_blocked_queries_total",
		Help: "Queries blocked by detection engine",
	}, []string{"reason"})

	QueryDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "castiel_query_duration_seconds",
		Help:    "DNS query processing duration",
		Buckets: prometheus.DefBuckets,
	})

	DoHQueries = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "castiel_doh_queries_total",
		Help: "Total queries forwarded over DoH",
	})

	DoHFailures = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "castiel_doh_failures_total",
		Help: "DoH query failures (fallback to plain DNS)",
	})

	DoHEnabled = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "castiel_doh_enabled",
		Help: "1 if DoH is enabled, 0 if disabled",
	})

	DNSSECValidations = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "castiel_dnssec_validations_total",
		Help: "DNSSEC validation results",
	}, []string{"result"}) // result: valid, bogus, insecure, indeterminate

	UpstreamFailures = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "castiel_upstream_failures_total",
		Help: "Upstream DNS query failures",
	}, []string{"upstream"})

	ActiveConnections = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "castiel_active_connections",
		Help: "Currently active DNS client connections",
	})

	EDNSSuspicious = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "castiel_edns_suspicious_total",
		Help: "Suspicious EDNS0 options detected",
	}, []string{"type"})

	NXDomainPerDomain = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "castiel_nxdomain_per_domain_total",
		Help: "NXDOMAIN responses tracked per apex domain",
	}, []string{"domain"})

	NXDomainWaterTorture = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "castiel_nxdomain_water_torture_total",
		Help: "DNS water torture attacks detected per domain",
	}, []string{"domain"})

	DNSSECDowngradeAlerts = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "castiel_dnssec_downgrade_alerts_total",
		Help: "DNSSEC downgrade attempts detected",
	}, []string{"domain"})

	DoHBypassAlerts = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "castiel_doh_bypass_alerts_total",
		Help: "DoH bypass attempts detected",
	}, []string{"resolver"})

	ResponseValidationFailures = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "castiel_response_validation_failures_total",
		Help: "DNS response packets that failed validation",
	}, []string{"field"})

	FastFluxAlerts = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "castiel_fastflux_alerts_total",
		Help: "Fast-flux/C2 detection alerts",
	}, []string{"reason"})

	DictionaryDGAAlerts = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "castiel_dictionary_dga_alerts_total",
		Help: "Dictionary-based DGA domains detected",
	}, []string{"domain"})

	SparseDGAAlerts = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "castiel_sparse_dga_alerts_total",
		Help: "Sparse DGA detection alerts",
	}, []string{"client_ip"})

	CNAMEChainAlerts = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "castiel_cname_chain_alerts_total",
		Help: "CNAME chain validation alerts",
	}, []string{"type"})

	DNSCalculationAlerts = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "castiel_dns_calculation_alerts_total",
		Help: "DNS calculation attack detections",
	}, []string{"reason"})

	LowSlowExfilAlerts = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "castiel_low_slow_exfil_alerts_total",
		Help: "Low-and-slow exfiltration detections",
	}, []string{"reason"})

	LookalikeAlerts = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "castiel_lookalike_alerts_total",
		Help: "Lookalike/typosquatting domain detections",
	}, []string{"reason"})

	AppleEndpointUnreachable = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "castiel_apple_endpoint_unreachable_total",
		Help: "Apple certificate validation endpoints that are unreachable (possible IP-level blocking)",
	}, []string{"endpoint"})

	AppleEndpointStatus = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "castiel_apple_endpoint_status",
		Help: "1 if Apple endpoint is reachable, 0 if unreachable",
	}, []string{"endpoint"})

	UnauthorizedPFAlerts = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "castiel_unauthorized_pf_alerts_total",
		Help: "Unauthorized PF rules detected blocking Apple endpoints",
	}, []string{"rule_type"})
)

func init() {
	prometheus.MustRegister(TotalQueries, CacheHits, CacheMisses,
		RateLimitedQueries, BlockedQueries, QueryDuration,
		DoHQueries, DoHFailures, DoHEnabled,
		DNSSECValidations, UpstreamFailures, ActiveConnections,
		EDNSSuspicious, NXDomainPerDomain, NXDomainWaterTorture,
		DNSSECDowngradeAlerts, DoHBypassAlerts, ResponseValidationFailures,
		FastFluxAlerts, DictionaryDGAAlerts, SparseDGAAlerts,
		CNAMEChainAlerts, DNSCalculationAlerts, LowSlowExfilAlerts, LookalikeAlerts,
		AppleEndpointUnreachable, AppleEndpointStatus, UnauthorizedPFAlerts)
}

type Server struct {
	cfg config.MetricsConfig
}

func NewServer(cfg config.MetricsConfig) *Server {
	return &Server{cfg: cfg}
}

func (s *Server) Start() {
	mux := http.NewServeMux()
	mux.Handle(s.cfg.Path, promhttp.Handler())
	log.Printf("Prometheus metrics available at %s%s", s.cfg.BindAddr, s.cfg.Path)
	log.Fatal(http.ListenAndServe(s.cfg.BindAddr, mux))
}
