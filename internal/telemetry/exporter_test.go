package telemetry

import (
	"context"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/saadshabir/ZTAP/internal/flow"
	collectorpb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	"google.golang.org/protobuf/proto"
)

func TestDecisionRecordSchema(t *testing.T) {
	event := flow.FlowEvent{
		Timestamp: time.Unix(1000, 7), ObservedAt: time.Unix(1002, 9), PolicyEpoch: math.MaxUint64,
		CgroupID: math.MaxUint64 - 1, AddressFamily: 4, SourceIP: net.ParseIP("10.0.0.1"),
		DestIP: net.ParseIP("10.1.0.2"), SourcePort: 55271, DestPort: 8080, Protocol: "TCP",
		Direction: "ingress", Action: "blocked", Reason: "default_deny", SchemaVersion: 1,
	}
	record := decisionRecord(event, PodIdentity{UID: "pod-1", Namespace: "workloads", Name: "receiver"})
	if record.GetEventName() != "ztap.policy.decision" || record.GetBody().GetStringValue() != record.GetEventName() ||
		record.GetTimeUnixNano() != 1000000000007 || record.GetObservedTimeUnixNano() != 1002000000009 {
		t.Fatalf("unexpected event header: %v", record)
	}
	wantStrings := map[string]string{
		"ztap.decision.action": "blocked", "ztap.decision.direction": "ingress", "ztap.decision.reason": "default_deny",
		"ztap.policy.epoch": "18446744073709551615", "ztap.subject.cgroup.id": "18446744073709551614",
		"ztap.subject.identity.status": "resolved", "ztap.subject.k8s.pod.uid": "pod-1",
		"ztap.subject.k8s.namespace.name": "workloads", "ztap.subject.k8s.pod.name": "receiver",
		"source.address": "10.0.0.1", "destination.address": "10.1.0.2", "network.transport": "tcp",
	}
	wantInts := map[string]int64{"source.port": 55271, "destination.port": 8080, "ztap.flow.schema.version": 1}
	if len(record.GetAttributes()) != len(wantStrings)+len(wantInts) {
		t.Fatalf("unexpected attributes: %v", record.GetAttributes())
	}
	for _, attr := range record.GetAttributes() {
		key, value := attr.GetKey(), attr.GetValue()
		if want, ok := wantStrings[key]; ok {
			if value.GetStringValue() != want {
				t.Errorf("%s = %v, want %q", key, value, want)
			}
			delete(wantStrings, key)
		} else if want, ok := wantInts[key]; ok && value.GetIntValue() == want {
			delete(wantInts, key)
		} else {
			t.Errorf("unexpected attribute %v", attr)
		}
	}
	if len(wantStrings)+len(wantInts) != 0 {
		t.Fatalf("missing attributes: %v %v", wantStrings, wantInts)
	}
	malformed := decisionRecord(flow.FlowEvent{Reason: "malformed", SourceIP: net.IPv4zero, DestIP: net.IPv4zero}, PodIdentity{})
	for _, attr := range malformed.GetAttributes() {
		switch attr.GetKey() {
		case "ztap.subject.identity.status":
			if attr.GetValue().GetStringValue() != "unresolved" {
				t.Fatal(attr)
			}
		case "source.address", "destination.address", "source.port", "destination.port", "network.transport", "ztap.subject.k8s.pod.uid":
			t.Fatalf("invented a field absent from the raw record: %v", attr)
		}
	}
}

func TestExporterRetriesThrottledBatchAndStopsAtPartialSuccess(t *testing.T) {
	var calls atomic.Int32
	arrivals := make(chan time.Time, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempt := calls.Add(1)
		body, err := io.ReadAll(r.Body)
		var request collectorpb.ExportLogsServiceRequest
		if err != nil || proto.Unmarshal(body, &request) != nil || r.URL.Path != "/v1/logs" ||
			r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/x-protobuf" {
			t.Error("invalid log export request")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		logs := request.GetResourceLogs()
		if len(logs) != 1 || len(logs[0].GetScopeLogs()) != 1 || len(logs[0].GetScopeLogs()[0].GetLogRecords()) != 2 ||
			logs[0].GetResource().GetAttributes()[0].GetValue().GetStringValue() != "ztap-agent" {
			t.Errorf("unexpected protobuf request: %v", &request)
		}
		if attempt <= 2 {
			arrivals <- time.Now()
		}
		if attempt == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		body, err = proto.Marshal(&collectorpb.ExportLogsServiceResponse{
			PartialSuccess: &collectorpb.ExportLogsPartialSuccess{RejectedLogRecords: 1, ErrorMessage: "one rejected"},
		})
		if err != nil {
			t.Error(err)
		}
		w.Header().Set("Content-Type", protobufMediaType)
		_, _ = w.Write(body)
	}))
	defer server.Close()

	exporter, metrics := testExporter(server, 2)
	exporter.Enqueue(flow.FlowEvent{}, PodIdentity{})
	exporter.Enqueue(flow.FlowEvent{}, PodIdentity{})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	exporter.Close(ctx)
	if got := calls.Load(); got != 2 {
		t.Fatalf("attempts = %d, want two", got)
	}
	a, b := <-arrivals, <-arrivals
	if b.Sub(a) < time.Second {
		t.Fatalf("retried before Retry-After: %s", b.Sub(a))
	}
	requireCounter(t, metrics, "acknowledged", 1)
	requireCounter(t, metrics, "rejected", 1)
	requireCounter(t, metrics, "unknown", 0)
}

func TestExporterBoundsQueueAndShutdown(t *testing.T) {
	firstRequest := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			return
		}
		close(firstRequest)
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer server.Close()
	defer close(release)
	exporter, metrics := testExporter(server, 1)
	exporter.Enqueue(flow.FlowEvent{}, PodIdentity{})
	select {
	case <-firstRequest:
	case <-time.After(3 * time.Second):
		t.Fatal("exporter never started request")
	}
	exporter.Enqueue(flow.FlowEvent{}, PodIdentity{})
	exporter.Enqueue(flow.FlowEvent{}, PodIdentity{})
	flush, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	exporter.Close(flush)
	requireCounter(t, metrics, "unknown", 1)
	if got := metricValue(t, metrics.Losses.WithLabelValues("export_queue_full")); got != 1 {
		t.Errorf("queue losses = %v, want 1", got)
	}
	if got := metricValue(t, metrics.Losses.WithLabelValues("shutdown")); got != 1 {
		t.Errorf("shutdown losses = %v, want 1", got)
	}
}

func TestExporterDoesNotReplayMalformedSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", protobufMediaType)
		_, _ = w.Write([]byte{0xff})
	}))
	defer server.Close()
	exporter, metrics := testExporter(server, 1)
	exporter.Enqueue(flow.FlowEvent{}, PodIdentity{})
	exporter.Close(t.Context())
	requireCounter(t, metrics, "unknown", 1)
	requireCounter(t, metrics, "acknowledged", 0)
	if got := metricValue(t, metrics.retries); got != 0 {
		t.Errorf("unexpected retries: %v", got)
	}
}

func TestExporterDoesNotAcknowledgeHeaderlessOK(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	exporter, metrics := testExporter(server, 1)
	exporter.Enqueue(flow.FlowEvent{}, PodIdentity{})
	exporter.Close(t.Context())
	requireCounter(t, metrics, "unknown", 1)
	requireCounter(t, metrics, "acknowledged", 0)
	if got := metricValue(t, metrics.lastAck); got != 0 {
		t.Fatalf("last acknowledgement advanced to %v", got)
	}
}

func TestExporterHonorsRetryAfterAcrossBatches(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		arrivals := make(chan time.Time, 4)
		client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			response := &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}
			response.Header.Set("Content-Type", protobufMediaType)
			if len(arrivals) == 0 {
				response.StatusCode = http.StatusTooManyRequests
				response.Header.Set("Retry-After", "60")
			}
			arrivals <- time.Now()
			return response, nil
		})}
		reg := prometheus.NewRegistry()
		metrics := RegisterMetrics(reg)
		exporter := StartExporter(Config{endpoint: "http://collector/v1/logs", headers: make(http.Header), client: client, capacity: 1}, AgentResource{}, metrics, reg)
		exporter.Enqueue(flow.FlowEvent{}, PodIdentity{})
		synctest.Wait()
		exporter.Enqueue(flow.FlowEvent{}, PodIdentity{})
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
		defer cancel()
		exporter.Close(ctx)
		if len(arrivals) != 2 {
			t.Fatalf("requests = %d, want 2", len(arrivals))
		}
		first, second := <-arrivals, <-arrivals
		if delay := second.Sub(first); delay < time.Minute {
			t.Fatalf("next batch sent after %s, want at least a minute", delay)
		}
		requireCounter(t, metrics, "retry_exhausted", 1)
		requireCounter(t, metrics, "acknowledged", 1)
	})
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func requireCounter(t *testing.T, metrics *Metrics, label string, want float64) {
	t.Helper()
	if got := metricValue(t, metrics.outcomes.WithLabelValues(label)); got != want {
		t.Errorf("%s = %v, want %v", label, got, want)
	}
}

func metricValue(t *testing.T, metric prometheus.Metric) float64 {
	t.Helper()
	var sample dto.Metric
	if err := metric.Write(&sample); err != nil {
		t.Fatal(err)
	}
	if counter := sample.GetCounter(); counter != nil {
		return counter.GetValue()
	}
	if gauge := sample.GetGauge(); gauge != nil {
		return gauge.GetValue()
	}
	t.Fatal("expected a counter or gauge")
	return 0
}

func testExporter(server *httptest.Server, capacity int) (*Exporter, *Metrics) {
	registry := prometheus.NewRegistry()
	metrics := RegisterMetrics(registry)
	exporter := StartExporter(Config{endpoint: server.URL + "/v1/logs", headers: make(http.Header), client: server.Client(), capacity: capacity},
		AgentResource{NodeName: "test-node"}, metrics, registry)
	return exporter, metrics
}

func TestCertificateFailurePrecedesDelivery(t *testing.T) {
	receiver := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("unexpected HTTP request after certificate verification failure")
	}))
	defer receiver.Close()
	exporter := &Exporter{config: Config{endpoint: receiver.URL, client: &http.Client{}, headers: make(http.Header)}}
	result := exporter.send(t.Context(), nil, 1)
	if result.acknowledged || result.uncertain || !result.retry {
		t.Fatalf("unexpected certificate failure outcome: %+v", result)
	}
}
