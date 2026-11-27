package telemetry

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"math/rand/v2"
	"mime"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/saadshabir/ZTAP/internal/flow"
	collectorpb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/protobuf/proto"
)

const (
	exportBatchSize   = 256
	exportInterval    = time.Second
	exportMaxRetry    = 15 * time.Second
	protobufMediaType = "application/x-protobuf"
)

// Exporter has a single asynchronous OTLP worker. Its producer must stop
// calling Enqueue before calling Close.
type Exporter struct {
	config       Config
	metrics      *Metrics
	resource     *resourcepb.Resource
	queue        chan *logspb.LogRecord
	done         chan struct{}
	cancel       context.CancelFunc
	highWater    atomic.Int64
	queueDropped prometheus.Counter
}

func StartExporter(config Config, agent AgentResource, metrics *Metrics, reg prometheus.Registerer) *Exporter {
	e := &Exporter{
		config: config, metrics: metrics, resource: agent.resource(),
		queue: make(chan *logspb.LogRecord, config.capacity), done: make(chan struct{}),
		queueDropped: metrics.Losses.WithLabelValues("export_queue_full"),
	}
	reg.MustRegister(
		prometheus.NewGaugeFunc(
			prometheus.GaugeOpts{Name: "ztap_flow_export_queue_depth", Help: "Flow records waiting in the OTLP export queue."},
			func() float64 { return float64(len(e.queue)) }),
		prometheus.NewGaugeFunc(
			prometheus.GaugeOpts{Name: "ztap_flow_export_queue_capacity", Help: "Capacity of the OTLP export queue in records."},
			func() float64 { return float64(cap(e.queue)) }),
		prometheus.NewGaugeFunc(
			prometheus.GaugeOpts{Name: "ztap_flow_export_queue_high_water", Help: "Highest queue depth observed at ingestion."},
			func() float64 { return float64(e.highWater.Load()) }),
	)
	ctx, cancel := context.WithCancel(context.Background())
	e.cancel = cancel
	go e.run(ctx)
	return e
}

func (e *Exporter) Enqueue(event flow.FlowEvent, subject PodIdentity) {
	if len(e.queue) == cap(e.queue) {
		e.queueDropped.Inc()
		e.noteQueueDepth(int64(cap(e.queue)))
		return
	}
	// With a single producer, a slot cannot disappear after the capacity check.
	e.queue <- decisionRecord(event, subject)
	e.noteQueueDepth(int64(len(e.queue)))
}

func (e *Exporter) noteQueueDepth(depth int64) {
	for high := e.highWater.Load(); depth > high; high = e.highWater.Load() {
		if e.highWater.CompareAndSwap(high, depth) {
			return
		}
	}
}

func (e *Exporter) Close(ctx context.Context) {
	close(e.queue)
	select {
	case <-e.done:
	case <-ctx.Done():
		e.cancel()
		<-e.done
	}
	e.cancel()
	e.config.client.CloseIdleConnections()
}

func (e *Exporter) run(ctx context.Context) {
	defer close(e.done)
	batchSize := min(exportBatchSize, cap(e.queue))
	var receiverRetryAt time.Time
	for {
		var first *logspb.LogRecord
		select {
		case <-ctx.Done():
			e.metrics.Losses.WithLabelValues("shutdown").Add(float64(len(e.queue)))
			return
		case record, ok := <-e.queue:
			if !ok {
				return
			}
			first = record
		}
		records, closed := e.collectBatch(ctx, first, batchSize)
		e.export(ctx, records, &receiverRetryAt)
		if closed {
			return
		}
	}
}

func (e *Exporter) collectBatch(ctx context.Context, first *logspb.LogRecord, limit int) ([]*logspb.LogRecord, bool) {
	batch := make([]*logspb.LogRecord, 1, limit)
	batch[0] = first
	if limit == 1 {
		return batch, false
	}
	timer := time.NewTimer(exportInterval)
	defer timer.Stop()
	for len(batch) < limit {
		select {
		case <-timer.C:
			return batch, false
		case <-ctx.Done():
			return batch, false
		case record, ok := <-e.queue:
			if !ok {
				return batch, true
			}
			batch = append(batch, record)
		}
	}
	return batch, false
}

func (e *Exporter) export(workerCtx context.Context, records []*logspb.LogRecord, receiverRetryAt *time.Time) {
	// Receiver throttling applies to every request, including subsequent
	// batches. Start this batch's retry budget once it can actually try.
	if !waitUntil(workerCtx, *receiverRetryAt) {
		e.metrics.Losses.WithLabelValues("shutdown").Add(float64(len(records)))
		return
	}
	request := &collectorpb.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{{
		Resource: e.resource,
		ScopeLogs: []*logspb.ScopeLogs{{
			Scope:      &commonpb.InstrumentationScope{Name: "github.com/saadshabir/ZTAP/flow", Version: "1"},
			LogRecords: records,
		}},
	}}}
	body, err := proto.Marshal(request)
	if err != nil {
		e.metrics.outcomes.WithLabelValues("rejected").Add(float64(len(records)))
		return
	}

	ctx, cancel := context.WithTimeout(workerCtx, exportMaxRetry)
	defer cancel()
	var uncertain bool
	for backoff := 200 * time.Millisecond; ; backoff = min(2*backoff, 3*time.Second) {
		result := e.send(ctx, body, int64(len(records)))
		if result.acknowledged {
			accepted := int64(len(records)) - result.rejected
			e.metrics.outcomes.WithLabelValues("acknowledged").Add(float64(accepted))
			outcome := "rejected"
			if uncertain {
				// This receiver could have accepted the rejected records on
				// an earlier attempt whose acknowledgement was lost.
				outcome = "unknown"
			}
			e.metrics.outcomes.WithLabelValues(outcome).Add(float64(result.rejected))
			if accepted != 0 {
				e.metrics.lastAck.SetToCurrentTime()
			}
			return
		}
		uncertain = uncertain || result.uncertain
		if !result.retry {
			outcome := "rejected"
			if uncertain {
				outcome = "unknown"
			}
			e.metrics.outcomes.WithLabelValues(outcome).Add(float64(len(records)))
			return
		}

		if result.retryAt.After(*receiverRetryAt) {
			*receiverRetryAt = result.retryAt
		}
		// Jitter clients independently, while respecting receiver throttling.
		nextAttempt := time.Now().Add(backoff + rand.N(backoff/2)) // #nosec G404 -- jitter is not security-sensitive
		if receiverRetryAt.After(nextAttempt) {
			nextAttempt = *receiverRetryAt
		}
		if !waitUntil(ctx, nextAttempt) {
			outcome := "retry_exhausted"
			if uncertain {
				outcome = "unknown"
			}
			e.metrics.outcomes.WithLabelValues(outcome).Add(float64(len(records)))
			return
		}
		e.metrics.retries.Inc()
	}
}

func waitUntil(ctx context.Context, until time.Time) bool {
	if delay := time.Until(until); delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return false
		case <-timer.C:
		}
	}
	return ctx.Err() == nil
}

type exportResult struct {
	acknowledged bool
	rejected     int64
	retry        bool
	uncertain    bool
	retryAt      time.Time
}

func (e *Exporter) send(ctx context.Context, body []byte, count int64) exportResult {
	if ctx.Err() != nil {
		return exportResult{retry: true}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, e.config.endpoint, bytes.NewReader(body))
	if err != nil {
		return exportResult{}
	}
	request.Header = e.config.headers.Clone()
	request.Header.Set("Content-Type", protobufMediaType)
	response, err := e.config.client.Do(request) // #nosec G704 -- destination is operator-configured
	if err != nil {
		// Dial and server certificate verification failures precede the POST.
		netErr, isNetOp := errors.AsType[*net.OpError](err)
		_, certificateFailure := errors.AsType[*tls.CertificateVerificationError](err)
		beforeRequest := certificateFailure || (isNetOp && netErr.Op == "dial")
		return exportResult{retry: true, uncertain: !beforeRequest}
	}
	defer func() { _ = response.Body.Close() }()
	const maxReply = 64 << 10
	if response.StatusCode == http.StatusOK {
		mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
		if err != nil || mediaType != protobufMediaType {
			return exportResult{uncertain: true}
		}
		body, err := io.ReadAll(io.LimitReader(response.Body, maxReply+1))
		var reply collectorpb.ExportLogsServiceResponse
		if err != nil || len(body) > maxReply || proto.Unmarshal(body, &reply) != nil {
			return exportResult{uncertain: true}
		}
		rejected := reply.GetPartialSuccess().GetRejectedLogRecords()
		if rejected < 0 || rejected > count {
			return exportResult{uncertain: true}
		}
		return exportResult{acknowledged: true, rejected: rejected}
	}
	// Bounded draining lets the transport reuse connections after failure.
	receivedAt := time.Now()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxReply))
	switch response.StatusCode {
	case http.StatusTooManyRequests, http.StatusServiceUnavailable:
		return exportResult{retry: true, retryAt: retryAfter(response.Header.Get("Retry-After"), receivedAt)}
	case http.StatusBadGateway, http.StatusGatewayTimeout:
		return exportResult{retry: true, uncertain: true}
	default:
		return exportResult{}
	}
}

func retryAfter(header string, now time.Time) time.Time {
	header = strings.TrimSpace(header)
	if seconds, err := strconv.ParseUint(header, 10, 64); err == nil {
		const maxSeconds = uint64((1<<63 - 1) / time.Second)
		return now.Add(time.Duration(min(seconds, maxSeconds)) * time.Second) // #nosec G115 -- bounded above
	}
	if until, err := http.ParseTime(header); err == nil {
		return until
	}
	return time.Time{}
}
