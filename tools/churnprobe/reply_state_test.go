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
	"sync/atomic"
	"testing"
	"time"
)

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(data []byte) (int, error) { return f(data) }

func TestReplyStateDistinguishesInterruptionAndOriginalSocketRecovery(t *testing.T) {
	for _, scenario := range []string{"uninterrupted", "interrupted", "unrecoverable"} {
		t.Run(scenario, func(t *testing.T) {
			t.Parallel()
			var blocked atomic.Bool
			var connections atomic.Int32
			address := testServer(t, func(conn net.Conn) {
				connections.Add(1)
				defer func() { _ = conn.Close() }()
				scanner := bufio.NewScanner(conn)
				if !scanner.Scan() || scanner.Text() != "push" {
					return
				}
				stop, done := make(chan struct{}), make(chan struct{})
				go func() {
					defer close(done)
					ticker := time.NewTicker(50 * time.Millisecond)
					defer ticker.Stop()
					sequence := 0
					for {
						select {
						case <-stop:
							return
						case <-ticker.C:
							if !blocked.Load() {
								sequence++
								if _, err := fmt.Fprintln(conn, sequence); err != nil {
									return
								}
							}
						}
					}
				}()
				for scanner.Scan() {
					if scanner.Text() == "resume" && scenario != "unrecoverable" {
						blocked.Store(false)
					}
				}
				close(stop)
				<-done
			})
			changed := filepath.Join(t.TempDir(), "changed")
			var last replyStateReport
			marked := false
			output := writerFunc(func(data []byte) (int, error) {
				if err := json.Unmarshal(data, &last); err != nil {
					return 0, err
				}
				if last.Received >= 10 && !marked {
					marked = true
					blocked.Store(scenario != "uninterrupted")
					if err := os.WriteFile(changed, nil, 0o600); err != nil {
						return 0, err
					}
				}
				return len(data), nil
			})
			err := replyState(context.Background(), address, changed, time.Second, 8*time.Second, output)
			if connections.Load() != 1 || last.Connections != 1 || last.BaselineReceived < 10 {
				t.Fatalf("invalid baseline/socket count: connections=%d %+v", connections.Load(), last)
			}
			switch scenario {
			case "uninterrupted":
				if err != nil || !last.Finished || last.Interrupted || last.ResumeNS != 0 {
					t.Fatalf("uninterrupted stream: %v %+v", err, last)
				}
			case "interrupted":
				if err != nil || !last.Finished || !last.Interrupted || !last.Recovered || last.MaxGapMS < 1900 {
					t.Fatalf("recovered stream: %v %+v", err, last)
				}
			case "unrecoverable":
				if err == nil || !strings.Contains(err.Error(), "did not recover") || last.Finished || !last.Interrupted || last.Recovered {
					t.Fatalf("unrecoverable stream was hidden: %v %+v", err, last)
				}
			}
		})
	}
}
