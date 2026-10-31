// churnprobe supplies sequenced TCP traffic for the disposable multi-node gate.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

func main() {
	mode := flag.String("mode", "check", "serve, check, stream, or reply-state")
	address := flag.String("address", "", "TCP target (serve listens on 8080 and 8081)")
	denied := flag.String("denied-address", "", "stream: address that must never accept TCP")
	deny := flag.Bool("deny", false, "check: require a failed TCP handshake")
	stop := flag.String("stop-file", "", "stream: finish after this marker appears")
	revoke := flag.String("revoke-file", "", "stream: marker written after policy revocation converges")
	revoking := flag.String("revoking-file", "", "stream: end availability measurement before deliberate revocation")
	changed := flag.String("changed-file", "", "reply-state: marker written after both nodes publish a changed snapshot")
	duration := flag.Duration("duration", 10*time.Minute, "stream deadline")
	gap := flag.Duration("max-gap", 5*time.Second, "maximum permitted gap between echoes before revocation")
	flag.Parse()
	var err error
	switch *mode {
	case "serve":
		err = serve()
	case "check":
		err = check(*address, *deny)
	case "stream":
		err = stream(context.Background(), streamOptions{
			address: *address, denied: *denied, stopFile: *stop, revokeFile: *revoke, revokingFile: *revoking,
			duration: *duration, maxGap: *gap, interval: 100 * time.Millisecond,
		}, os.Stdout)
	case "reply-state":
		err = replyState(context.Background(), *address, *changed, *gap, *duration, os.Stdout)
	default:
		err = errors.New("unknown mode")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func serve() error {
	errorsCh := make(chan error, 2)
	for _, port := range []string{":8080", ":8081"} {
		listener, err := net.Listen("tcp4", port)
		if err != nil {
			return err
		}
		defer func() { _ = listener.Close() }()
		go func() {
			for {
				conn, err := listener.Accept()
				if err != nil {
					errorsCh <- err
					return
				}
				go echo(conn)
			}
		}()
	}
	return <-errorsCh
}

func echo(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		if scanner.Text() == "push" {
			push(conn)
			return
		}
		if _, err := fmt.Fprintln(conn, scanner.Text()); err != nil {
			return
		}
	}
}

func push(conn net.Conn) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for sequence := uint64(1); ; sequence++ {
		<-ticker.C
		if _, err := fmt.Fprintln(conn, sequence); err != nil {
			return
		}
	}
}

func check(address string, deny bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp4", address)
	if err != nil {
		// Refusals and routing/DNS errors are broken controls, not proof of
		// enforcement. A policy drop must time out the handshake.
		if deny && isTimeout(err) {
			return nil
		}
		return err
	}
	defer func() { _ = conn.Close() }()
	if deny {
		return errors.New("prohibited TCP handshake succeeded")
	}
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		return err
	}
	if _, err := io.WriteString(conn, "probe\n"); err != nil {
		return err
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return err
	}
	if line != "probe\n" {
		return fmt.Errorf("unexpected echo %q", line)
	}
	return nil
}

type streamOptions struct {
	dial                                                func(context.Context, string) (net.Conn, error)
	address, denied, stopFile, revokeFile, revokingFile string
	duration, maxGap, interval                          time.Duration
}

type streamReport struct {
	SchemaVersion         int     `json:"schema_version"`
	StartedNS             int64   `json:"started_ns"`
	TimestampNS           int64   `json:"timestamp_ns"`
	Connections           int     `json:"connections"`
	Sent                  uint64  `json:"sent"`
	Received              uint64  `json:"received"`
	DeniedAttempts        uint64  `json:"denied_attempts"`
	ProhibitedConnections uint64  `json:"prohibited_connections"`
	MaxGapMS              float64 `json:"max_gap_ms"`
	AvailabilityEndedNS   int64   `json:"availability_ended_ns"`
	RevokedNS             int64   `json:"revoked_ns"`
	SentAfterRevocation   uint64  `json:"sent_after_revocation"`
	PostRevocationReplies uint64  `json:"post_revocation_replies"`
	Finished              bool    `json:"finished"`
}

// stream opens exactly one allowed socket. A lost or stalled socket fails the
// gate; there is no HTTP transport retry or replacement connection to hide it.
// The writer continues during revocation so a quiet socket cannot pass vacuously.
func stream(parent context.Context, opts streamOptions, output io.Writer) (result error) {
	if opts.interval <= 0 || opts.maxGap <= 0 || opts.duration <= 0 || opts.denied == "" || output == nil {
		return errors.New("invalid stream options")
	}
	ctx, cancel := context.WithTimeout(parent, opts.duration)
	defer cancel()
	dial := opts.dial
	if dial == nil {
		dial = func(ctx context.Context, address string) (net.Conn, error) {
			return (&net.Dialer{Timeout: opts.maxGap}).DialContext(ctx, "tcp4", address)
		}
	}
	conn, err := dial(ctx, opts.address)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	started := time.Now()
	report := streamReport{SchemaVersion: 1, StartedNS: started.UnixNano(), Connections: 1}
	lastReply := started
	var lastSequence, revokeSequence uint64
	var mu sync.Mutex
	var wg sync.WaitGroup
	failures := make(chan error, 3)
	fail := func(err error) {
		select {
		case failures <- err:
		default:
		}
	}
	wg.Add(2)
	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(conn)
		for scanner.Scan() {
			seq, err := strconv.ParseUint(strings.TrimSpace(scanner.Text()), 10, 64)
			mu.Lock()
			if err != nil || seq == 0 || seq <= lastSequence || seq > report.Sent {
				mu.Unlock()
				fail(errors.New("invalid or out-of-order stream echo"))
				return
			}
			now := time.Now()
			if report.AvailabilityEndedNS == 0 {
				report.MaxGapMS = max(report.MaxGapMS, now.Sub(lastReply).Seconds()*1000)
			}
			if report.RevokedNS > 0 && seq > revokeSequence {
				report.PostRevocationReplies++
			}
			lastReply, lastSequence = now, seq
			report.Received++
			mu.Unlock()
		}
		if ctx.Err() == nil {
			fail(fmt.Errorf("original TCP connection closed: %v", scanner.Err()))
		}
	}()
	go func() {
		defer wg.Done()
		for ctx.Err() == nil {
			mu.Lock()
			report.DeniedAttempts++
			mu.Unlock()
			probeCtx, stop := context.WithTimeout(ctx, 250*time.Millisecond)
			blocked, err := dial(probeCtx, opts.denied)
			stop()
			if err == nil {
				_ = blocked.Close()
				mu.Lock()
				report.ProhibitedConnections++
				mu.Unlock()
				fail(errors.New("prohibited TCP handshake succeeded during churn"))
				return
			}
			if ctx.Err() == nil && !isTimeout(err) {
				fail(fmt.Errorf("denied control did not time out: %w", err))
				return
			}
		}
	}()
	encoder := json.NewEncoder(output)
	emit := func() error {
		mu.Lock()
		snapshot := report
		mu.Unlock()
		snapshot.TimestampNS = time.Now().UnixNano()
		return encoder.Encode(snapshot)
	}
	defer func() {
		cancel()
		_ = conn.Close()
		wg.Wait()
		if result == nil {
			select {
			case result = <-failures:
			default:
			}
		}
		if result != nil || report.ProhibitedConnections > 0 || report.PostRevocationReplies > 0 {
			report.Finished = false
			if result == nil {
				result = errors.New("prohibited traffic observed at shutdown")
			}
		}
		if err := emit(); result == nil {
			result = err
		}
	}()
	ticker := time.NewTicker(opts.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("stream deadline before stop marker: %w", ctx.Err())
		case err := <-failures:
			return err
		case <-ticker.C:
			mu.Lock()
			if report.AvailabilityEndedNS == 0 && (markerExists(opts.revokingFile) || markerExists(opts.revokeFile)) {
				report.MaxGapMS = max(report.MaxGapMS, time.Since(lastReply).Seconds()*1000)
				report.AvailabilityEndedNS = time.Now().UnixNano()
			}
			if report.RevokedNS == 0 && markerExists(opts.revokeFile) {
				report.RevokedNS = time.Now().UnixNano()
				revokeSequence = report.Sent
			}
			if report.PostRevocationReplies > 0 {
				mu.Unlock()
				return errors.New("original connection delivered data after revocation")
			}
			if report.AvailabilityEndedNS == 0 {
				report.MaxGapMS = max(report.MaxGapMS, time.Since(lastReply).Seconds()*1000)
			}
			if report.MaxGapMS > opts.maxGap.Seconds()*1000 {
				mu.Unlock()
				return errors.New("original connection exceeded availability gap")
			}
			if markerExists(opts.stopFile) {
				valid := report.Received >= 10 && report.DeniedAttempts >= 10 && report.ProhibitedConnections == 0
				if opts.revokeFile != "" {
					valid = valid && report.RevokedNS > 0 && report.SentAfterRevocation >= 10 && time.Since(time.Unix(0, report.RevokedNS)) >= 3*time.Second
				}
				report.Finished = valid
				mu.Unlock()
				if !valid {
					return errors.New("insufficient stream, denial, or revocation evidence")
				}
				return nil
			}
			report.Sent++
			seq := report.Sent
			if report.RevokedNS > 0 {
				report.SentAfterRevocation++
			}
			mu.Unlock()
			if err := conn.SetWriteDeadline(time.Now().Add(opts.maxGap)); err != nil {
				return err
			}
			if _, err := fmt.Fprintln(conn, seq); err != nil {
				return err
			}
			if err := emit(); err != nil {
				return err
			}
		}
	}
}

func markerExists(path string) bool {
	if path == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

func isTimeout(err error) bool {
	var networkError net.Error
	return errors.As(err, &networkError) && networkError.Timeout()
}
