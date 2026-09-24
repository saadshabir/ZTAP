package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"
)

func main() {
	urlFlag := flag.String("url", "", "HTTP URL that returns status 200 and the exact body ok")
	interval := flag.Duration("interval", 10*time.Millisecond, "delay between fresh HTTP probes")
	requestTimeout := flag.Duration("request-timeout", 250*time.Millisecond, "per-probe request timeout")
	maxDuration := flag.Duration("max-duration", 5*time.Minute, "maximum time to observe a complete fail-open interval")
	stopFile := flag.String("stop-file", "", "optional file whose presence stops the probe")
	flag.Parse()

	if err := runProbe(*urlFlag, *interval, *requestTimeout, *maxDuration, *stopFile, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "phase5 rollout probe: %v\n", err)
		os.Exit(1)
	}
}

type failOpenTracker struct {
	startNS             int64
	blockedAfterAllowed int
}

func (tracker *failOpenTracker) observe(allowed bool, observedAt time.Time) (startNS, endNS int64) {
	if allowed {
		if tracker.startNS == 0 {
			tracker.startNS = observedAt.UnixNano()
			return tracker.startNS, 0
		}
		tracker.blockedAfterAllowed = 0
		return 0, 0
	}

	if tracker.startNS == 0 {
		return 0, 0
	}
	tracker.blockedAfterAllowed++
	if tracker.blockedAfterAllowed == 2 {
		return 0, observedAt.UnixNano()
	}
	return 0, 0
}

func runProbe(target string, interval, requestTimeout, maxDuration time.Duration, stopFile string, output io.Writer) error {
	parsedTarget, err := url.ParseRequestURI(target)
	if err != nil || parsedTarget.Scheme != "http" || parsedTarget.Host == "" {
		return errors.New("target must be an absolute HTTP URL")
	}
	if interval <= 0 || requestTimeout <= 0 || maxDuration <= 0 {
		return errors.New("probe intervals and duration must be positive")
	}
	if output == nil {
		return errors.New("probe output writer is nil")
	}

	transport := &http.Transport{DisableKeepAlives: true}
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	defer transport.CloseIdleConnections()

	tracker := failOpenTracker{}
	deadline := time.Now().Add(maxDuration)
	for time.Now().Before(deadline) {
		if stopFile != "" {
			if _, err := os.Stat(stopFile); err == nil {
				return errors.New("stop file appeared before a complete fail-open interval")
			} else if !os.IsNotExist(err) {
				return fmt.Errorf("check stop file: %w", err)
			}
		}

		requestContext, cancel := context.WithTimeout(context.Background(), requestTimeout)
		request, err := http.NewRequestWithContext(requestContext, http.MethodGet, parsedTarget.String(), nil)
		if err != nil {
			cancel()
			return fmt.Errorf("create probe request: %w", err)
		}
		request.Close = true
		response, requestErr := client.Do(request)
		allowed := false
		if requestErr == nil {
			body, readErr := io.ReadAll(io.LimitReader(response.Body, 16))
			closeErr := response.Body.Close()
			allowed = readErr == nil && closeErr == nil && response.StatusCode == http.StatusOK && string(body) == "ok\n"
		}
		cancel()

		startNS, endNS := tracker.observe(allowed, time.Now())
		if startNS != 0 {
			if _, err := fmt.Fprintf(output, "fail_open_start_ns=%d\n", startNS); err != nil {
				return fmt.Errorf("write fail-open start: %w", err)
			}
		}
		if endNS != 0 {
			if _, err := fmt.Fprintf(output, "fail_open_end_ns=%d\n", endNS); err != nil {
				return fmt.Errorf("write fail-open end: %w", err)
			}
			return nil
		}
		time.Sleep(interval)
	}

	if tracker.startNS == 0 {
		return fmt.Errorf("no successful HTTP probe observed within %s", maxDuration)
	}
	return fmt.Errorf("recovery was not observed within %s after the first successful HTTP probe", maxDuration)
}
