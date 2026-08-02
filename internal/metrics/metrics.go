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
		Name: "dad_total_queries",
		Help: "Total DNS queries received",
	})

	CacheHits = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "dad_cache_hits",
		Help: "DNS cache hits",
	})

	CacheMisses = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "dad_cache_misses",
		Help: "DNS cache misses",
	})

	RateLimitedQueries = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "dad_rate_limited_queries",
		Help: "Queries dropped or truncated by rate limiter",
	})

	BlockedQueries = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "dad_blocked_queries",
		Help: "Queries blocked by detection engine",
	}, []string{"reason"})

	QueryDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "dad_query_duration_seconds",
		Help:    "DNS query processing duration",
		Buckets: prometheus.DefBuckets,
	})

	DoHQueries = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "dad_doh_queries_total",
		Help: "Total queries forwarded over DoH",
	})

	DoHFailures = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "dad_doh_failures_total",
		Help: "DoH query failures (fallback to plain DNS)",
	})

	DoHEnabled = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "dad_doh_enabled",
		Help: "1 if DoH is enabled, 0 if disabled",
	})

	DNSSECValidations = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "dad_dnssec_validations_total",
		Help: "DNSSEC validation results",
	}, []string{"result"}) // result: valid, bogus, insecure, indeterminate

	UpstreamFailures = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "dad_upstream_failures_total",
		Help: "Upstream DNS query failures",
	}, []string{"upstream"})

	ActiveConnections = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "dad_active_connections",
		Help: "Currently active DNS client connections",
	})
)

func init() {
	prometheus.MustRegister(TotalQueries, CacheHits, CacheMisses,
		RateLimitedQueries, BlockedQueries, QueryDuration,
		DoHQueries, DoHFailures, DoHEnabled,
		DNSSECValidations, UpstreamFailures, ActiveConnections)
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
