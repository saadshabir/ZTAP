package telemetry

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/http/httpguts"
)

const DefaultQueueCapacity = 2048
const MaxQueueCapacity = 65536

type Config struct {
	endpoint string
	headers  http.Header
	client   *http.Client
	capacity int
}

// ConfigFromEnv reads the standard OTLP HTTP endpoint, headers, timeout and
// TLS file settings. Signal-specific settings take precedence.
func ConfigFromEnv(queueCapacity int) (Config, error) {
	if queueCapacity < 1 || queueCapacity > MaxQueueCapacity {
		return Config{}, fmt.Errorf("OTLP queue capacity must be between 1 and %d", MaxQueueCapacity)
	}
	protocol := otlpEnv("PROTOCOL")
	if protocol != "" && protocol != "http/protobuf" {
		return Config{}, errors.New("OTLP flow logs require the http/protobuf protocol")
	}
	endpoint := os.Getenv("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT")
	appendPath := endpoint == ""
	if appendPath {
		endpoint = os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
		if endpoint == "" {
			endpoint = "http://localhost:4318"
		}
	}
	address, err := url.Parse(endpoint)
	if err != nil || address.Hostname() == "" || (address.Scheme != "http" && address.Scheme != "https") ||
		address.User != nil || address.Fragment != "" {
		return Config{}, errors.New("OTLP endpoint must be an absolute HTTP(S) URL without credentials or a fragment")
	}
	if appendPath {
		address = address.JoinPath("v1/logs")
	} else if address.Path == "" {
		address.Path = "/"
	}

	timeout := 3 * time.Second
	if value := otlpEnv("TIMEOUT"); value != "" {
		ms, err := strconv.ParseInt(value, 10, 64)
		if err != nil || ms <= 0 || ms > int64((1<<63-1)/time.Millisecond) {
			return Config{}, errors.New("OTLP timeout must be a positive number of milliseconds")
		}
		timeout = time.Duration(ms) * time.Millisecond
	}

	headers, err := parseHeaders(otlpEnv("HEADERS"))
	if err != nil {
		return Config{}, err
	}
	tlsConfig, err := exporterTLS()
	if err != nil {
		return Config{}, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig
	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return Config{endpoint: address.String(), headers: headers, client: client, capacity: queueCapacity}, nil
}

func otlpEnv(suffix string) string {
	if value := os.Getenv("OTEL_EXPORTER_OTLP_LOGS_" + suffix); value != "" {
		return value
	}
	return os.Getenv("OTEL_EXPORTER_OTLP_" + suffix)
}

func parseHeaders(value string) (http.Header, error) {
	headers := make(http.Header)
	if value == "" {
		return headers, nil
	}
	for pair := range strings.SplitSeq(value, ",") {
		key, encoded, found := strings.Cut(pair, "=")
		key = strings.TrimSpace(key)
		decoded, err := url.PathUnescape(strings.TrimSpace(encoded))
		if !found || err != nil || !httpguts.ValidHeaderFieldName(key) || !httpguts.ValidHeaderFieldValue(decoded) {
			return nil, errors.New("invalid OTLP headers; use comma-separated key=value pairs")
		}
		headers.Add(key, decoded)
	}
	return headers, nil
}

func exporterTLS() (*tls.Config, error) {
	config := &tls.Config{MinVersion: tls.VersionTLS12}
	if filename := otlpEnv("CERTIFICATE"); filename != "" {
		certs, err := os.ReadFile(filename) // #nosec G304 -- operator-configured CA file
		if err != nil {
			return nil, fmt.Errorf("read OTLP CA certificate: %w", err)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(certs) {
			return nil, errors.New("OTLP CA file contains no PEM certificates")
		}
		config.RootCAs = roots
	}
	certFile, keyFile := otlpEnv("CLIENT_CERTIFICATE"), otlpEnv("CLIENT_KEY")
	if certFile != "" || keyFile != "" {
		if certFile == "" || keyFile == "" {
			return nil, errors.New("OTLP client certificate and key must both be configured")
		}
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("load OTLP client certificate: %w", err)
		}
		config.Certificates = []tls.Certificate{cert}
	}
	return config, nil
}
