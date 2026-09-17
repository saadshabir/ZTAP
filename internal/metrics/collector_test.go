package metrics

import (
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
)

// resetCollector clears the global collector so each test gets a clean registry.
func resetCollector(t *testing.T) {
	t.Helper()
	if globalCollector != nil {
		prometheus.Unregister(globalCollector.flowsAllowed)
		prometheus.Unregister(globalCollector.flowsBlocked)
		prometheus.Unregister(globalCollector.anomalyScore)
		prometheus.Unregister(globalCollector.policyLoadTime)
		prometheus.Unregister(globalCollector.flowsTotal)
	}
	globalCollector = nil
	once = sync.Once{}
}

func TestStartServerRejectsInvalidPath(t *testing.T) {
	if err := StartServer("127.0.0.1:0", "metrics"); err == nil {
		t.Fatal("expected invalid metrics path to return an error")
	}
}

func TestNewServer(t *testing.T) {
	resetCollector(t)
	srv, err := NewServer("127.0.0.1:0", "/metrics")
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if srv == nil || srv.Handler == nil {
		t.Fatalf("expected configured HTTP server, got %+v", srv)
	}
	if err := srv.Close(); err != nil {
		t.Fatalf("close server: %v", err)
	}
}

func TestGetCollectorSingleton(t *testing.T) {
	resetCollector(t)

	c1 := GetCollector()
	c2 := GetCollector()

	if c1 == nil {
		t.Fatal("expected collector instance, got nil")
	}
	if c1 != c2 {
		t.Fatal("expected singleton collector")
	}
}

func TestNewRegistryIsPrivate(t *testing.T) {
	firstRegistry, firstCollector := NewRegistry()
	secondRegistry, secondCollector := NewRegistry()
	if firstRegistry == secondRegistry {
		t.Fatal("private registry constructor returned the same registry")
	}

	firstCollector.IncFlowsAllowed()
	if got := testutil.ToFloat64(firstCollector.flowsAllowed); got != 1 {
		t.Fatalf("first private collector value = %v, want 1", got)
	}
	if got := testutil.ToFloat64(secondCollector.flowsAllowed); got != 0 {
		t.Fatalf("second private collector value = %v, want 0", got)
	}
	if _, err := firstRegistry.Gather(); err != nil {
		t.Fatalf("gather first private registry: %v", err)
	}
	if _, err := secondRegistry.Gather(); err != nil {
		t.Fatalf("gather second private registry: %v", err)
	}
}

func TestCollectorCounters(t *testing.T) {
	resetCollector(t)
	collector := GetCollector()

	collector.IncFlowsAllowed()
	collector.IncFlowsBlocked()
	collector.IncFlowsBlocked()
	if got := testutil.ToFloat64(collector.flowsAllowed); got != 1 {
		t.Fatalf("expected flowsAllowed=1, got %v", got)
	}
	if got := testutil.ToFloat64(collector.flowsBlocked); got != 2 {
		t.Fatalf("expected flowsBlocked=2, got %v", got)
	}
}

func TestCollectorGaugeAndHistogram(t *testing.T) {
	resetCollector(t)
	collector := GetCollector()

	collector.SetAnomalyScore(42.5)
	collector.ObservePolicyLoadTime(0.5)
	collector.ObservePolicyLoadTime(1.5)

	if got := testutil.ToFloat64(collector.anomalyScore); got != 42.5 {
		t.Fatalf("expected anomalyScore=42.5, got %v", got)
	}

	metric := &dto.Metric{}
	if err := collector.policyLoadTime.Write(metric); err != nil {
		t.Fatalf("failed to read histogram metric: %v", err)
	}

	hist := metric.GetHistogram()
	if hist.GetSampleSum() != 2.0 {
		t.Fatalf("expected histogram sum=2.0, got %v", hist.GetSampleSum())
	}
	if hist.GetSampleCount() != 2 {
		t.Fatalf("expected histogram count=2, got %v", hist.GetSampleCount())
	}

	if count := testutil.CollectAndCount(collector.policyLoadTime); count != 1 {
		t.Fatalf("expected histogram to collect once, got %d", count)
	}
}
