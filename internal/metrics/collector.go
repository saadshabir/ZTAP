package metrics

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Collector manages all ZTAP metrics
type Collector struct {
	flowsAllowed   prometheus.Counter
	flowsBlocked   prometheus.Counter
	anomalyScore   prometheus.Gauge
	policyLoadTime prometheus.Histogram
	flowsTotal     *prometheus.CounterVec
	mu             sync.Mutex
}

var (
	globalCollector *Collector
	once            sync.Once
)

func newCollector(registerer prometheus.Registerer) *Collector {
	collector := &Collector{
		flowsAllowed: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "ztap_flows_allowed_total",
			Help: "Total number of flows allowed",
		}),
		flowsBlocked: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "ztap_flows_blocked_total",
			Help: "Total number of flows blocked",
		}),
		anomalyScore: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ztap_anomaly_score",
			Help: "Current anomaly score (0-100)",
		}),
		policyLoadTime: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "ztap_policy_load_duration_seconds",
			Help:    "Time taken to load policies",
			Buckets: prometheus.DefBuckets,
		}),
		flowsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ztap_flows_total",
			Help: "Total number of network flows by action, protocol, and direction",
		}, []string{"action", "protocol", "direction"}),
	}

	registerer.MustRegister(collector.flowsAllowed)
	registerer.MustRegister(collector.flowsBlocked)
	registerer.MustRegister(collector.anomalyScore)
	registerer.MustRegister(collector.policyLoadTime)
	registerer.MustRegister(collector.flowsTotal)
	return collector
}

// GetCollector returns the singleton metrics collector
func GetCollector() *Collector {
	once.Do(func() {
		globalCollector = newCollector(prometheus.DefaultRegisterer)
	})

	return globalCollector
}

// NewRegistry creates an isolated registry and collector for an embedded
// process such as the native Linux agent. The caller owns the returned
// registry and may create more than one without global metric collisions.
func NewRegistry() (*prometheus.Registry, *Collector) {
	registry := prometheus.NewRegistry()
	registry.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	registry.MustRegister(collectors.NewGoCollector())
	return registry, newCollector(registry)
}

// IncFlowsAllowed increments the flows allowed counter
func (c *Collector) IncFlowsAllowed() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.flowsAllowed.Inc()
}

// IncFlowsBlocked increments the flows blocked counter
func (c *Collector) IncFlowsBlocked() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.flowsBlocked.Inc()
}

// SetAnomalyScore sets the current anomaly score
func (c *Collector) SetAnomalyScore(score float64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.anomalyScore.Set(score)
}

// ObservePolicyLoadTime records a policy load duration
func (c *Collector) ObservePolicyLoadTime(seconds float64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.policyLoadTime.Observe(seconds)
}

// RecordFlow records a flow event with labels for action, protocol, and direction.
func (c *Collector) RecordFlow(action, protocol, direction string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.flowsTotal.WithLabelValues(action, protocol, direction).Inc()

	// Also update legacy counters for backward compatibility
	if action == "allowed" {
		c.flowsAllowed.Inc()
	} else {
		c.flowsBlocked.Inc()
	}
}

// ValidatePath checks that path is a valid net/http ServeMux pattern for the
// metrics endpoint. It prevents user-provided configuration from reaching the
// panic-based ServeMux.Handle API unchecked.
func ValidatePath(path string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		path = "/metrics"
	}
	if !strings.HasPrefix(path, "/") {
		return fmt.Errorf("metrics path %q must start with '/'", path)
	}

	mux := http.NewServeMux()
	return registerMetricsHandler(mux, path, http.NotFoundHandler())
}

// NewServer builds a Prometheus metrics HTTP server on the given listen
// address (host:port) and path. The collector is initialized here so callers
// embedding the server in agent/enforcement processes expose the same metrics
// as the standalone `ztap metrics` command.
func NewServer(listen, path string) (*http.Server, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		path = "/metrics"
	}
	if err := ValidatePath(path); err != nil {
		return nil, err
	}
	GetCollector()

	mux := http.NewServeMux()
	if err := registerMetricsHandler(mux, path, promhttp.Handler()); err != nil {
		return nil, err
	}

	return &http.Server{
		Addr:              listen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}, nil
}

// StartServer starts the Prometheus metrics HTTP server on the given listen
// address (host:port) and path.
func StartServer(listen, path string) error {
	srv, err := NewServer(listen, path)
	if err != nil {
		return err
	}

	path = strings.TrimSpace(path)
	if path == "" {
		path = "/metrics"
	}
	fmt.Printf("Starting metrics server on http://%s%s\n", listen, path)
	return srv.ListenAndServe()
}

// registerMetricsHandler converts ServeMux's panic-based registration API into
// an error for configuration supplied by users. Besides the leading-slash
// check above, this protects against future ServeMux pattern restrictions.
func registerMetricsHandler(mux *http.ServeMux, path string, handler http.Handler) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("invalid metrics path %q: %v", path, recovered)
		}
	}()
	mux.Handle(path, handler)
	return nil
}
