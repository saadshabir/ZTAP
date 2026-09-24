//go:build linux

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/saadshabir/ZTAP/internal/enforcer"
	"github.com/saadshabir/ZTAP/internal/policy"
)

type nativeAgentHTTP struct {
	server              *http.Server
	listener            net.Listener
	errors              chan error
	stateMu             sync.RWMutex
	ready               bool
	enforcing           bool
	reason              string
	readyMetric         prometheus.Gauge
	enforcingMetric     prometheus.Gauge
	networkPolicies     *prometheus.GaugeVec
	reconciliations     *prometheus.CounterVec
	reconcileDuration   prometheus.Histogram
	compiledRules       prometheus.Gauge
	enforcedCgroups     prometheus.Gauge
	quarantinedCgroups  prometheus.Gauge
	unresolvedRunning   prometheus.Gauge
	classificationDelay prometheus.Histogram
	activePolicyEpoch   prometheus.Gauge
	packetDecisions     *prometheus.CounterVec
	flowDrops           *prometheus.CounterVec
	slotCleanupFailures prometheus.Counter
	engineMetricsMu     sync.RWMutex
	engineMetrics       enforcer.MetricsProvider
	lastDecisions       map[string]uint64
	lastDrops           map[string]uint64
	lastCleanupFailures uint64
	classifiedCgroups   map[uint64]struct{}
}

type nativeAgentHealthResponse struct {
	Status    string `json:"status"`
	Version   string `json:"version,omitempty"`
	Ready     bool   `json:"ready,omitempty"`
	Enforcing bool   `json:"enforcing,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

func startNativeAgentHTTP(listen string) (*nativeAgentHTTP, error) {
	return startNativeAgentHTTPWithListener(listen, nil)
}

func startNativeAgentHTTPWithListener(listen string, supplied net.Listener) (*nativeAgentHTTP, error) {
	if strings.TrimSpace(listen) == "" {
		listen = ":9090"
	}
	listener := supplied
	if listener == nil {
		var err error
		listener, err = net.Listen("tcp", listen)
		if err != nil {
			return nil, fmt.Errorf("listen for native agent status on %q: %w", listen, err)
		}
	}
	registry := prometheus.NewRegistry()
	registry.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	registry.MustRegister(collectors.NewGoCollector())
	agent := &nativeAgentHTTP{
		listener:            listener,
		errors:              make(chan error, 1),
		reason:              "starting",
		readyMetric:         prometheus.NewGauge(prometheus.GaugeOpts{Name: "ztap_agent_ready", Help: "Whether the native agent is ready to serve policy state"}),
		enforcingMetric:     prometheus.NewGauge(prometheus.GaugeOpts{Name: "ztap_agent_enforcing", Help: "Whether the native agent has active eBPF enforcement"}),
		networkPolicies:     prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "ztap_network_policies", Help: "Observed native NetworkPolicies by bounded reconciliation state"}, []string{"state"}),
		reconciliations:     prometheus.NewCounterVec(prometheus.CounterOpts{Name: "ztap_policy_reconciliations_total", Help: "Native policy reconciliation attempts by result"}, []string{"result"}),
		reconcileDuration:   prometheus.NewHistogram(prometheus.HistogramOpts{Name: "ztap_policy_reconcile_duration_seconds", Help: "Time spent compiling and applying a native policy snapshot", Buckets: prometheus.DefBuckets}),
		compiledRules:       prometheus.NewGauge(prometheus.GaugeOpts{Name: "ztap_compiled_rules", Help: "Number of compiled policy rules in the last applied snapshot"}),
		enforcedCgroups:     prometheus.NewGauge(prometheus.GaugeOpts{Name: "ztap_enforced_cgroups", Help: "Number of subject cgroups in the last applied snapshot"}),
		quarantinedCgroups:  prometheus.NewGauge(prometheus.GaugeOpts{Name: "ztap_quarantined_cgroups", Help: "Number of subject cgroups with a quarantined direction"}),
		unresolvedRunning:   prometheus.NewGauge(prometheus.GaugeOpts{Name: "ztap_unresolved_running_containers", Help: "Running local containers with an identity that could not be resolved to a cgroup"}),
		classificationDelay: prometheus.NewHistogram(prometheus.HistogramOpts{Name: "ztap_pod_start_classification_delay_seconds", Help: "Time from observing a running container to installing its cgroup classification", Buckets: prometheus.DefBuckets}),
		activePolicyEpoch:   prometheus.NewGauge(prometheus.GaugeOpts{Name: "ztap_active_policy_epoch", Help: "Active instance-owned policy epoch"}),
		packetDecisions:     prometheus.NewCounterVec(prometheus.CounterOpts{Name: "ztap_packet_decisions_total", Help: "Packet decisions reported by the persistent engine counters"}, []string{"action", "direction", "reason"}),
		flowDrops:           prometheus.NewCounterVec(prometheus.CounterOpts{Name: "ztap_flow_events_dropped_total", Help: "Flow events suppressed or rejected by the engine"}, []string{"reason"}),
		slotCleanupFailures: prometheus.NewCounter(prometheus.CounterOpts{Name: "ztap_policy_slot_cleanup_failures_total", Help: "Policy slot cleanup failures observed by the engine"}),
		lastDecisions:       make(map[string]uint64),
		lastDrops:           make(map[string]uint64),
		classifiedCgroups:   make(map[uint64]struct{}),
	}
	registry.MustRegister(agent.readyMetric)
	registry.MustRegister(agent.enforcingMetric)
	registry.MustRegister(agent.networkPolicies)
	registry.MustRegister(agent.reconciliations)
	registry.MustRegister(agent.reconcileDuration)
	registry.MustRegister(agent.compiledRules)
	registry.MustRegister(agent.enforcedCgroups)
	registry.MustRegister(agent.quarantinedCgroups)
	registry.MustRegister(agent.unresolvedRunning)
	registry.MustRegister(agent.classificationDelay)
	registry.MustRegister(agent.activePolicyEpoch)
	registry.MustRegister(agent.packetDecisions)
	registry.MustRegister(agent.flowDrops)
	registry.MustRegister(agent.slotCleanupFailures)
	for _, state := range []string{"observed", "accepted", "rejected"} {
		agent.networkPolicies.WithLabelValues(state).Set(0)
	}
	for _, result := range []string{"success", "rejected", "error"} {
		agent.reconciliations.WithLabelValues(result).Add(0)
	}
	agent.unresolvedRunning.Set(0)
	for _, metric := range enforcer.EngineDecisionMetricLabels() {
		agent.packetDecisions.WithLabelValues(metric.Action, metric.Direction, metric.Reason).Add(0)
	}
	for _, metric := range enforcer.EngineEventDropMetricLabels() {
		agent.flowDrops.WithLabelValues(metric.Reason).Add(0)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", getOnly(agent.handleHealth))
	mux.HandleFunc("/readyz", getOnly(agent.handleReady))
	mux.Handle("/metrics", getOnlyHandler(promhttp.HandlerFor(registry, promhttp.HandlerOpts{})))
	agent.server = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	go func() {
		if err := agent.server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			agent.errors <- err
		}
		close(agent.errors)
	}()
	return agent, nil
}

func (a *nativeAgentHTTP) markApplied(result policy.CompileResult, dryRun bool) {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	a.enforcing = !dryRun
	if a.enforcingMetric != nil {
		a.enforcingMetric.Set(boolGauge(a.enforcing))
	}
	if dryRun {
		a.ready = false
		a.reason = "dry_run"
		if a.readyMetric != nil {
			a.readyMetric.Set(0)
		}
		return
	}
	for _, subject := range result.PolicySet.Subjects {
		if subject.Quarantined != 0 {
			a.ready = false
			a.reason = "quarantined"
			if a.readyMetric != nil {
				a.readyMetric.Set(0)
			}
			return
		}
	}
	a.ready = true
	a.reason = "ok"
	if a.readyMetric != nil {
		a.readyMetric.Set(1)
	}
}

// recordReconciliation publishes bounded snapshot-level metrics. A failed
// attempt leaves the last applied gauges intact while incrementing its result
// counter, so a transient Kubernetes or kernel error is observable without
// erasing the state that remains active in the engine.
func (a *nativeAgentHTTP) recordReconciliation(observed int, result policy.CompileResult, reconcileErr error, duration time.Duration, dryRun bool) {
	if a == nil {
		return
	}
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	if a.reconcileDuration != nil {
		if duration < 0 {
			duration = 0
		}
		a.reconcileDuration.Observe(duration.Seconds())
	}
	if reconcileErr != nil {
		if a.reconciliations != nil {
			a.reconciliations.WithLabelValues("error").Inc()
		}
		return
	}
	resultLabel := "success"
	if len(result.Rejected) != 0 {
		resultLabel = "rejected"
	}
	if a.reconciliations != nil {
		a.reconciliations.WithLabelValues(resultLabel).Inc()
	}
	if a.networkPolicies != nil && observed >= 0 {
		accepted := observed - len(result.Rejected)
		if accepted < 0 {
			accepted = 0
		}
		a.networkPolicies.WithLabelValues("observed").Set(float64(observed))
		a.networkPolicies.WithLabelValues("accepted").Set(float64(accepted))
		a.networkPolicies.WithLabelValues("rejected").Set(float64(len(result.Rejected)))
	}
	if a.compiledRules != nil {
		a.compiledRules.Set(float64(len(result.PolicySet.Rules)))
	}
	if a.enforcedCgroups != nil {
		enforced := len(result.PolicySet.Subjects)
		if dryRun {
			enforced = 0
		}
		a.enforcedCgroups.Set(float64(enforced))
	}
	if a.quarantinedCgroups != nil {
		quarantined := 0
		for _, subject := range result.PolicySet.Subjects {
			if subject.Quarantined != 0 {
				quarantined++
			}
		}
		a.quarantinedCgroups.Set(float64(quarantined))
	}
}

func (a *nativeAgentHTTP) recordResolutionTelemetry(unresolved int) {
	if a == nil {
		return
	}
	if unresolved < 0 {
		unresolved = 0
	}
	a.stateMu.Lock()
	if a.unresolvedRunning != nil {
		a.unresolvedRunning.Set(float64(unresolved))
	}
	a.stateMu.Unlock()
}

// recordClassification observes the watcher gap for newly classified
// cgroups. The applied subject set is tracked so policy updates do not count
// an already classified container repeatedly; removing a subject retires its
// state, allowing a later pod recreation to produce a new interval.
func (a *nativeAgentHTTP) recordClassification(observedAt map[uint64]time.Time, set policy.PolicySet, installedAt time.Time, dryRun bool) nativeClassificationReport {
	if a == nil || dryRun {
		return nativeClassificationReport{}
	}
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	if a.classifiedCgroups == nil {
		a.classifiedCgroups = make(map[uint64]struct{})
	}
	desired := make(map[uint64]struct{}, len(set.Subjects))
	report := nativeClassificationReport{}
	for _, subject := range set.Subjects {
		if subject.CgroupID == 0 {
			continue
		}
		desired[subject.CgroupID] = struct{}{}
		if _, exists := a.classifiedCgroups[subject.CgroupID]; exists {
			continue
		}
		firstObserved, ok := observedAt[subject.CgroupID]
		if !ok || firstObserved.IsZero() {
			// Keep the subject eligible for a later sample. A complete
			// reconciliation normally supplies this timestamp, but retaining
			// the pending state avoids silently losing the delay if resolution
			// and classification become observable on different iterations.
			continue
		}
		a.classifiedCgroups[subject.CgroupID] = struct{}{}
		delay := installedAt.Sub(firstObserved)
		if delay < 0 {
			delay = 0
		}
		if a.classificationDelay != nil {
			a.classificationDelay.Observe(delay.Seconds())
		}
		report.count++
		if delay > report.maxDelay {
			report.maxDelay = delay
		}
	}
	for cgroupID := range a.classifiedCgroups {
		if _, keep := desired[cgroupID]; !keep {
			delete(a.classifiedCgroups, cgroupID)
		}
	}
	return report
}

func (a *nativeAgentHTTP) setEngineMetricsProvider(provider enforcer.MetricsProvider) {
	if a == nil {
		return
	}
	a.engineMetricsMu.Lock()
	a.engineMetrics = provider
	a.engineMetricsMu.Unlock()
	if provider == nil {
		a.stateMu.Lock()
		a.lastDecisions = make(map[string]uint64)
		a.lastDrops = make(map[string]uint64)
		a.lastCleanupFailures = 0
		a.stateMu.Unlock()
	}
}

func (a *nativeAgentHTTP) refreshEngineMetrics() {
	if a == nil {
		return
	}
	a.engineMetricsMu.RLock()
	provider := a.engineMetrics
	a.engineMetricsMu.RUnlock()
	if provider == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	snapshot, err := provider.MetricsSnapshot(ctx)
	cancel()
	if err != nil {
		return
	}
	a.stateMu.Lock()
	if a.lastDecisions == nil {
		a.lastDecisions = make(map[string]uint64)
	}
	if a.lastDrops == nil {
		a.lastDrops = make(map[string]uint64)
	}
	if a.activePolicyEpoch != nil {
		a.activePolicyEpoch.Set(float64(snapshot.ActivePolicyEpoch))
	}
	for _, decision := range snapshot.Decisions {
		key := decision.Action + "\x00" + decision.Direction + "\x00" + decision.Reason
		previous := a.lastDecisions[key]
		delta := counterDelta(previous, decision.Count)
		if delta != 0 && a.packetDecisions != nil {
			a.packetDecisions.WithLabelValues(decision.Action, decision.Direction, decision.Reason).Add(float64(delta))
		}
		a.lastDecisions[key] = decision.Count
	}
	for _, drop := range snapshot.EventDrops {
		previous := a.lastDrops[drop.Reason]
		delta := counterDelta(previous, drop.Count)
		if delta != 0 && a.flowDrops != nil {
			a.flowDrops.WithLabelValues(drop.Reason).Add(float64(delta))
		}
		a.lastDrops[drop.Reason] = drop.Count
	}
	delta := counterDelta(a.lastCleanupFailures, snapshot.SlotCleanupFailures)
	if delta != 0 && a.slotCleanupFailures != nil {
		a.slotCleanupFailures.Add(float64(delta))
	}
	a.lastCleanupFailures = snapshot.SlotCleanupFailures
	a.stateMu.Unlock()
}

func counterDelta(previous, current uint64) uint64 {
	if current >= previous {
		return current - previous
	}
	// A kernel map can be recreated after a process restart. Treat the new
	// value as the delta rather than allowing a wrapped subtraction to create
	// an enormous Prometheus increment.
	return current
}

func (a *nativeAgentHTTP) startEngineMetricsPolling(ctx context.Context) func() {
	if a == nil || ctx == nil {
		return nil
	}
	pollCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		a.refreshEngineMetrics()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-pollCtx.Done():
				return
			case <-ticker.C:
				a.refreshEngineMetrics()
			}
		}
	}()
	var once sync.Once
	return func() {
		once.Do(func() {
			cancel()
			<-done
		})
	}
}

func (a *nativeAgentHTTP) markApplyFailure() {
	a.stateMu.Lock()
	a.ready = false
	a.reason = "apply_error"
	if a.readyMetric != nil {
		a.readyMetric.Set(0)
	}
	a.stateMu.Unlock()
}

func (a *nativeAgentHTTP) markStopping() {
	a.stateMu.Lock()
	a.ready = false
	a.enforcing = false
	a.reason = "stopping"
	if a.readyMetric != nil {
		a.readyMetric.Set(0)
	}
	if a.enforcingMetric != nil {
		a.enforcingMetric.Set(0)
	}
	a.stateMu.Unlock()
}

func boolGauge(value bool) float64 {
	if value {
		return 1
	}
	return 0
}

func (a *nativeAgentHTTP) handleHealth(w http.ResponseWriter, _ *http.Request) {
	a.writeJSON(w, http.StatusOK, nativeAgentHealthResponse{Status: "ok", Version: agentVersion()})
}

func (a *nativeAgentHTTP) handleReady(w http.ResponseWriter, _ *http.Request) {
	a.stateMu.RLock()
	response := nativeAgentHealthResponse{
		Status:    "not_ready",
		Ready:     a.ready,
		Enforcing: a.enforcing,
		Reason:    a.reason,
	}
	status := http.StatusServiceUnavailable
	if a.ready {
		response.Status = "ready"
		status = http.StatusOK
	}
	a.stateMu.RUnlock()
	a.writeJSON(w, status, response)
}

func (a *nativeAgentHTTP) writeJSON(w http.ResponseWriter, status int, response nativeAgentHealthResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(response)
}

func getOnly(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}
		handler(w, r)
	}
}

func getOnlyHandler(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}
		handler.ServeHTTP(w, r)
	})
}

func (a *nativeAgentHTTP) errorsCh() <-chan error { return a.errors }

func (a *nativeAgentHTTP) close(ctx context.Context) error {
	if a == nil || a.server == nil {
		return nil
	}
	if ctx == nil {
		return errors.New("native agent HTTP shutdown context is nil")
	}
	a.markStopping()
	return a.server.Shutdown(ctx)
}

func agentVersion() string {
	if strings.TrimSpace(Version) == "" {
		return "dev"
	}
	return Version
}
