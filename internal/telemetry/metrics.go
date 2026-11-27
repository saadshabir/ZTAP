package telemetry

import "github.com/prometheus/client_golang/prometheus"

type Metrics struct {
	Losses         *prometheus.CounterVec
	ReaderActive   prometheus.Gauge
	ReaderLockBusy prometheus.Gauge
	ConfigValid    prometheus.Gauge
	Filtered       prometheus.Counter
	outcomes       *prometheus.CounterVec
	retries        prometheus.Counter
	lastAck        prometheus.Gauge
}

func RegisterMetrics(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		Losses: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ztap_flow_userspace_dropped_total",
			Help: "Node-local flow records discarded in userspace by stage. CLI losses are independent of export losses.",
		}, []string{"stage"}),
		ReaderActive: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ztap_flow_reader_active", Help: "Whether the agent owns an active flow reader.",
		}),
		ReaderLockBusy: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ztap_flow_reader_lock_busy", Help: "Whether another process holds the flow-reader lock.",
		}),
		ConfigValid: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ztap_flow_export_config_valid", Help: "Whether the enabled flow exporter has a valid configuration.",
		}),
		Filtered: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "ztap_flow_export_filtered_total", Help: "Flow records intentionally excluded from export by subject namespace.",
		}),
		outcomes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ztap_flow_export_records_total", Help: "Terminal OTLP export outcomes by record (acknowledgements cover the immediate receiver).",
		}, []string{"outcome"}),
		retries: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "ztap_flow_export_retries_total", Help: "OTLP retries attempted after the first request for a batch.",
		}),
		lastAck: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ztap_flow_export_last_ack_timestamp_seconds", Help: "Unix timestamp of the last positive OTLP acknowledgement.",
		}),
	}
	for _, stage := range []string{"decode", "reader_full", "export_subscription_full", "export_queue_full", "cli_slow", "shutdown"} {
		m.Losses.WithLabelValues(stage)
	}
	for _, outcome := range []string{"acknowledged", "rejected", "retry_exhausted", "unknown"} {
		m.outcomes.WithLabelValues(outcome)
	}
	reg.MustRegister(m.Losses, m.ReaderActive, m.ReaderLockBusy, m.ConfigValid, m.Filtered, m.outcomes, m.retries, m.lastAck)
	return m
}
