//go:build linux

package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/saadshabir/ZTAP/internal/flow"
	"github.com/saadshabir/ZTAP/internal/telemetry"
	"golang.org/x/sys/unix"
)

func startNativeFlowTelemetry(parent context.Context, ready <-chan struct{}, options NativeAgentOptions, reg *prometheus.Registry, history *flowDecisionHistory) func() {
	metrics := telemetry.RegisterMetrics(reg)
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	go func() {
		defer close(done)
		config, err := telemetry.ConfigFromEnv(options.FlowQueueSize)
		if err != nil {
			slog.Default().Error("flow log export configuration is invalid", "error", err)
			return
		}
		metrics.ConfigValid.Set(1)
		select {
		case <-ctx.Done():
			return
		case <-ready:
		}
		exporter := telemetry.StartExporter(config, telemetry.AgentResource{
			Version: agentVersion(), InstanceID: options.PodUID, NodeName: options.NodeName, ClusterName: os.Getenv("ZTAP_CLUSTER_NAME"),
		}, metrics, reg)
		defer func() {
			flush, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			exporter.Close(flush)
		}()

		var lastError string
		for ctx.Err() == nil {
			err := readNativeFlowTelemetry(ctx, options, history, metrics, exporter)
			if ctx.Err() != nil {
				return
			}
			if err != nil && err.Error() != lastError {
				lastError = err.Error()
				slog.Default().Warn("flow log reader unavailable; retrying", "error", err)
			}
			timer := time.NewTimer(time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
			case <-timer.C:
			}
		}
	}()
	return func() {
		cancel()
		<-done
	}
}

func readNativeFlowTelemetry(ctx context.Context, options NativeAgentOptions, history *flowDecisionHistory, metrics *telemetry.Metrics, exporter *telemetry.Exporter) (resultErr error) {
	unlock, err := acquireFlowReaderLock(options.RunDir)
	if errors.Is(err, unix.EWOULDBLOCK) {
		metrics.ReaderLockBusy.Set(1)
	} else {
		metrics.ReaderLockBusy.Set(0)
	}
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, unlock()) }()
	listener, err := listenAgentFlows(options.RunDir)
	if err != nil {
		return fmt.Errorf("listen for local flow subscriptions: %w", err)
	}
	defer func() { _ = listener.Close() }()

	decodeLosses := metrics.Losses.WithLabelValues("decode")
	readerLosses := metrics.Losses.WithLabelValues("reader_full")
	reader, err := openObservedPinnedFlowReader(options.BPFFSRoot, func(stage string) {
		if stage == "decode" {
			decodeLosses.Inc()
		} else {
			readerLosses.Inc()
		}
	})
	if err != nil {
		return err
	}

	readCtx, stopRead := context.WithCancel(ctx)
	defer stopRead()
	monitor := flow.NewMonitor(reader)
	shutdownDrops := metrics.Losses.WithLabelValues("shutdown")
	monitor.SetDiscardObserver(func(records int) { shutdownDrops.Add(float64(records)) })
	exportDrops := metrics.Losses.WithLabelValues("export_subscription_full")
	// Let the monitor close this subscription so already queued records can
	// reach the exporter even after the agent starts shutting down.
	events := monitor.SubscribeWithDrops(context.WithoutCancel(readCtx), true, exportDrops.Inc)
	defer func() { resultErr = errors.Join(resultErr, monitor.Stop(), reader.Stop()) }()
	if err := monitor.Start(readCtx); err != nil {
		return err
	}
	metrics.ReaderActive.Set(1)
	defer metrics.ReaderActive.Set(0)
	cliDrops := metrics.Losses.WithLabelValues("cli_slow")
	socketDone := make(chan error, 1)
	go func() {
		socketDone <- serveAgentFlows(readCtx, listener, monitor, cliDrops.Inc)
		// Reopen the reader and listener together after a terminal accept error.
		stopRead()
	}()
	defer func() {
		stopRead()
		resultErr = errors.Join(resultErr, <-socketDone)
	}()

	for event := range events {
		subject := history.subject(event)
		if excludeFlowSubject(subject, options.FlowExcludeNamespaces) {
			metrics.Filtered.Inc()
			continue
		}
		exporter.Enqueue(event, subject)
	}
	return monitor.Err()
}

func excludeFlowSubject(subject telemetry.PodIdentity, namespaces []string) bool {
	return len(namespaces) > 0 && (subject.UID == "" || subject.Namespace == "" || slices.Contains(namespaces, subject.Namespace))
}
