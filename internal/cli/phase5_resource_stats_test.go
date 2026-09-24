package cli

import (
	"errors"
	"fmt"
	"io"
	"math/bits"
	"net/http"
	"strings"
	"testing"
)

type phase5ProcessStats struct {
	cpuTicks uint64
	rssBytes uint64
}

func readPhase5MetricsResponse(response *http.Response) (string, bool, error) {
	if response == nil || response.Body == nil {
		return "", false, errors.New("metrics response has no body")
	}
	if response.StatusCode != http.StatusOK {
		if err := response.Body.Close(); err != nil {
			return "", false, fmt.Errorf("close non-success metrics response: %w", err)
		}
		return "", false, nil
	}
	body, err := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	if err != nil {
		return "", false, fmt.Errorf("read metrics response: %w", err)
	}
	if closeErr != nil {
		return "", false, fmt.Errorf("close metrics response: %w", closeErr)
	}
	return string(body), true, nil
}

func phase5MaxRSSBytes(samples ...uint64) uint64 {
	var max uint64
	for _, sample := range samples {
		if sample > max {
			max = sample
		}
	}
	return max
}

func phase5ProcessStatsFromCounters(userTicks, systemTicks, residentPages uint64, pageSize int) (phase5ProcessStats, error) {
	if pageSize <= 0 {
		return phase5ProcessStats{}, fmt.Errorf("process page size must be positive, got %d", pageSize)
	}
	cpuTicks, carry := bits.Add64(userTicks, systemTicks, 0)
	if carry != 0 {
		return phase5ProcessStats{}, errors.New("process CPU tick total overflows uint64")
	}
	rssHigh, rssBytes := bits.Mul64(residentPages, uint64(pageSize))
	if rssHigh != 0 {
		return phase5ProcessStats{}, errors.New("process RSS byte total overflows uint64")
	}
	return phase5ProcessStats{cpuTicks: cpuTicks, rssBytes: rssBytes}, nil
}

func TestPhase5ProcessStatsFromCounters(t *testing.T) {
	stats, err := phase5ProcessStatsFromCounters(10, 20, 3, 4096)
	if err != nil {
		t.Fatalf("calculate process counters: %v", err)
	}
	if stats.cpuTicks != 30 || stats.rssBytes != 12288 {
		t.Fatalf("process counters = %+v, want 30 ticks/12288 bytes", stats)
	}
	for _, test := range []struct {
		name          string
		userTicks     uint64
		systemTicks   uint64
		residentPages uint64
		pageSize      int
	}{
		{name: "CPU tick overflow", userTicks: ^uint64(0), systemTicks: 1, residentPages: 1, pageSize: 4096},
		{name: "RSS byte overflow", residentPages: ^uint64(0)/4096 + 1, pageSize: 4096},
		{name: "zero page size", residentPages: 1, pageSize: 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := phase5ProcessStatsFromCounters(test.userTicks, test.systemTicks, test.residentPages, test.pageSize); err == nil {
				t.Fatal("phase5ProcessStatsFromCounters accepted overflowing or invalid counters")
			}
		})
	}
}

func TestPhase5MaxRSSBytesRetainsMiddleSamplePeak(t *testing.T) {
	got := phase5MaxRSSBytes(32, 96, 48)
	if got != 96 {
		t.Fatalf("maximum RSS sample = %d, want middle-sample peak 96", got)
	}
	if got := phase5MaxRSSBytes(); got != 0 {
		t.Fatalf("empty RSS sample set = %d, want 0", got)
	}
}

func TestReadPhase5MetricsResponseRequiresOK(t *testing.T) {
	const metrics = "ztap_agent_enforcing 1\n"
	for _, status := range []int{http.StatusBadGateway, http.StatusServiceUnavailable} {
		t.Run(fmt.Sprintf("status_%d", status), func(t *testing.T) {
			body, ok, err := readPhase5MetricsResponse(&http.Response{
				StatusCode: status,
				Body:       io.NopCloser(strings.NewReader(metrics)),
			})
			if err != nil {
				t.Fatalf("read non-success metrics response: %v", err)
			}
			if ok || body != "" {
				t.Fatalf("non-success metrics response = %q, ok=%t; want empty and false", body, ok)
			}
		})
	}
	body, ok, err := readPhase5MetricsResponse(&http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(metrics)),
	})
	if err != nil {
		t.Fatalf("read success metrics response: %v", err)
	}
	if !ok || body != metrics {
		t.Fatalf("success metrics response = %q, ok=%t; want %q and true", body, ok, metrics)
	}
}
