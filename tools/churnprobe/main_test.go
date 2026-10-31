package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testServer(t *testing.T, handle func(net.Conn)) string {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			wg.Go(func() { handle(conn) })
		}
	})
	t.Cleanup(func() { _ = listener.Close(); wg.Wait() })
	return listener.Addr().String()
}

func TestCheckRequiresLiveEchoAndTimeoutDenial(t *testing.T) {
	address := testServer(t, echo)
	if err := check(address, false); err != nil {
		t.Fatal(err)
	}
	if err := check(address, true); err == nil {
		t.Fatal("accepted a prohibited handshake")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := listener.Addr().String()
	_ = listener.Close()
	if err := check(closed, true); err == nil {
		t.Fatal("connection refusal was mistaken for an enforced drop")
	}
	wrong := testServer(t, func(conn net.Conn) { defer func() { _ = conn.Close() }(); _, _ = fmt.Fprintln(conn, "wrong") })
	if err := check(wrong, false); err == nil {
		t.Fatal("accepted the wrong echo")
	}
}

type reportWriter struct {
	reports []streamReport
	onWrite func(streamReport) error
}

func (w *reportWriter) Write(data []byte) (int, error) {
	var report streamReport
	if err := json.Unmarshal(data, &report); err != nil {
		return 0, err
	}
	w.reports = append(w.reports, report)
	if w.onWrite != nil {
		if err := w.onWrite(report); err != nil {
			return 0, err
		}
	}
	return len(data), nil
}

func testOptions(t *testing.T, address string) streamOptions {
	t.Helper()
	return streamOptions{
		address: address, denied: "denied", stopFile: filepath.Join(t.TempDir(), "stop"),
		duration: 6 * time.Second, maxGap: time.Second, interval: 10 * time.Millisecond,
		dial: func(ctx context.Context, target string) (net.Conn, error) {
			if target == "denied" {
				select {
				case <-ctx.Done():
				case <-time.After(10 * time.Millisecond):
				}
				// Linux can report the socket deadline rather than wrapping the
				// context's DeadlineExceeded; both represent an enforced drop.
				return nil, &net.OpError{Op: "dial", Net: "tcp4", Err: os.ErrDeadlineExceeded}
			}
			return (&net.Dialer{}).DialContext(ctx, "tcp4", target)
		},
	}
}

func TestStreamKeepsOneConnection(t *testing.T) {
	t.Parallel()
	var connections atomic.Int32
	address := testServer(t, func(conn net.Conn) { connections.Add(1); echo(conn) })
	opts := testOptions(t, address)
	output := &reportWriter{onWrite: func(r streamReport) error {
		if r.Received >= 10 && r.DeniedAttempts >= 10 {
			return os.WriteFile(opts.stopFile, nil, 0o600)
		}
		return nil
	}}
	if err := stream(context.Background(), opts, output); err != nil {
		t.Fatal(err)
	}
	last := output.reports[len(output.reports)-1]
	if !last.Finished || connections.Load() != 1 || last.Connections != 1 || last.MaxGapMS > 1000 {
		t.Fatalf("connections=%d final=%+v", connections.Load(), last)
	}
}

func TestStreamRejectsHiddenReconnectStallAndMalformedEcho(t *testing.T) {
	for _, scenario := range []string{"close", "stall", "malformed", "denied-leak", "deadline"} {
		t.Run(scenario, func(t *testing.T) {
			t.Parallel()
			var connections atomic.Int32
			address := testServer(t, func(conn net.Conn) {
				connections.Add(1)
				defer func() { _ = conn.Close() }()
				switch scenario {
				case "close":
					return
				case "stall":
					scanner := bufio.NewScanner(conn)
					for scanner.Scan() { /* consume without echo */
					}
				case "malformed":
					_, _ = fmt.Fprintln(conn, "bad-sequence")
				default:
					echo(conn)
				}
			})
			opts := testOptions(t, address)
			opts.maxGap = 100 * time.Millisecond
			if scenario == "denied-leak" {
				opts.denied = address
			}
			if scenario == "deadline" {
				opts.duration = 200 * time.Millisecond
			}
			output := &reportWriter{}
			if err := stream(context.Background(), opts, output); err == nil {
				t.Fatal("accepted a broken stream")
			}
			last := output.reports[len(output.reports)-1]
			if last.Finished || (scenario != "denied-leak" && connections.Load() != 1) {
				t.Fatalf("connections=%d final=%+v", connections.Load(), last)
			}
			if scenario == "denied-leak" && last.ProhibitedConnections == 0 {
				t.Fatal("missing prohibited handshake evidence")
			}
		})
	}
}

func TestStreamRevocationOnOriginalSocket(t *testing.T) {
	for _, leak := range []bool{false, true} {
		t.Run(fmt.Sprintf("leak=%v", leak), func(t *testing.T) {
			t.Parallel()
			var revoked atomic.Bool
			address := testServer(t, func(conn net.Conn) {
				defer func() { _ = conn.Close() }()
				scanner := bufio.NewScanner(conn)
				for scanner.Scan() {
					if !revoked.Load() || leak {
						if _, err := fmt.Fprintln(conn, scanner.Text()); err != nil {
							return
						}
					}
				}
			})
			opts := testOptions(t, address)
			opts.revokeFile = filepath.Join(t.TempDir(), "revoke")
			opts.revokingFile = filepath.Join(t.TempDir(), "revoking")
			output := &reportWriter{onWrite: func(r streamReport) error {
				if r.Received >= 10 && !revoked.Load() {
					revoked.Store(true)
					if err := os.WriteFile(opts.revokingFile, nil, 0o600); err != nil {
						return err
					}
					return os.WriteFile(opts.revokeFile, nil, 0o600)
				}
				if r.RevokedNS > 0 && time.Since(time.Unix(0, r.RevokedNS)) > 3100*time.Millisecond {
					return os.WriteFile(opts.stopFile, nil, 0o600)
				}
				return nil
			}}
			err := stream(context.Background(), opts, output)
			last := output.reports[len(output.reports)-1]
			if leak {
				if err == nil || !strings.Contains(err.Error(), "after revocation") || last.PostRevocationReplies == 0 {
					t.Fatalf("revocation leak was missed: %v %+v", err, last)
				}
			} else if err != nil || !last.Finished || last.SentAfterRevocation < 10 || last.AvailabilityEndedNS == 0 {
				t.Fatalf("revocation evidence: %v %+v", err, last)
			}
		})
	}
}
