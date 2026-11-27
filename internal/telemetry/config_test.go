package telemetry

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestLogsConfigPrefersSignalSettingsAndCustomCA(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/logs" || r.Header.Get("Authorization") != "Bearer token" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", protobufMediaType)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://other.invalid/base")
	t.Setenv("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", server.URL+"/logs")
	t.Setenv("OTEL_EXPORTER_OTLP_LOGS_CERTIFICATE", ca)
	t.Setenv("OTEL_EXPORTER_OTLP_LOGS_HEADERS", "Authorization=Bearer%20token")
	t.Setenv("OTEL_EXPORTER_OTLP_LOGS_PROTOCOL", "http/protobuf")

	config, err := ConfigFromEnv(DefaultQueueCapacity)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(config.client.CloseIdleConnections)
	if result := (&Exporter{config: config}).send(t.Context(), nil, 1); !result.acknowledged {
		t.Fatalf("custom CA request did not succeed: %+v", result)
	}
	t.Setenv("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", "")
	config, err = ConfigFromEnv(DefaultQueueCapacity)
	if err != nil || config.endpoint != "http://other.invalid/base/v1/logs" {
		t.Fatalf("generic endpoint = %q, err=%v", config.endpoint, err)
	}
}

func TestFlowConfigRejectsBrokenHeaderAndIncompleteClientPair(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_LOGS_HEADERS", "Authorization=bad%0aheader")
	if _, err := ConfigFromEnv(DefaultQueueCapacity); err == nil {
		t.Fatal("accepted malformed header")
	}
	t.Setenv("OTEL_EXPORTER_OTLP_LOGS_HEADERS", "Authorization=ok")
	t.Setenv("OTEL_EXPORTER_OTLP_LOGS_CLIENT_CERTIFICATE", "client.pem")
	t.Setenv("OTEL_EXPORTER_OTLP_LOGS_CLIENT_KEY", "")
	t.Setenv("OTEL_EXPORTER_OTLP_CLIENT_KEY", "")
	if _, err := ConfigFromEnv(DefaultQueueCapacity); err == nil {
		t.Fatal("accepted a client certificate without key")
	}
}
