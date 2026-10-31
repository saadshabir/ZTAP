package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

type replyStateReport struct {
	SchemaVersion    int     `json:"schema_version"`
	TimestampNS      int64   `json:"timestamp_ns"`
	Connections      int     `json:"connections"`
	Received         uint64  `json:"received"`
	BaselineReceived uint64  `json:"baseline_received"`
	ChangedNS        int64   `json:"changed_ns"`
	ResumeNS         int64   `json:"resume_ns"`
	Interrupted      bool    `json:"interrupted"`
	Recovered        bool    `json:"recovered"`
	MaxGapMS         float64 `json:"max_gap_ms"`
	Finished         bool    `json:"finished"`
}

// Observe a server-push stream without client payloads after its initial
// handshake. Changed global epochs can strand replies until new initiating
// traffic recreates state. Report that interruption, then require recovery on
// the original socket after ONE client payload. Future uninterrupted behavior
// also passes; this is a characterization of the documented epoch contract.
func replyState(parent context.Context, address, changedFile string, maxGap, duration time.Duration, output io.Writer) (result error) {
	if changedFile == "" || maxGap <= 0 || duration <= 0 || output == nil {
		return errors.New("invalid reply-state options")
	}
	ctx, cancel := context.WithTimeout(parent, duration)
	defer cancel()
	conn, err := (&net.Dialer{Timeout: maxGap}).DialContext(ctx, "tcp4", address)
	if err != nil {
		return err
	}
	frames := make(chan uint64, 64)
	failures := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		scanner := bufio.NewScanner(conn)
		var previous uint64
		for scanner.Scan() {
			sequence, err := strconv.ParseUint(scanner.Text(), 10, 64)
			if err != nil || sequence <= previous {
				failures <- errors.New("invalid server-push sequence")
				return
			}
			previous = sequence
			select {
			case frames <- sequence:
			case <-ctx.Done():
				return
			}
		}
		failures <- fmt.Errorf("server-push socket closed: %v", scanner.Err())
	}()
	report := replyStateReport{SchemaVersion: 1, Connections: 1}
	encoder := json.NewEncoder(output)
	emit := func() error { report.TimestampNS = time.Now().UnixNano(); return encoder.Encode(report) }
	defer func() {
		cancel()
		_ = conn.Close()
		<-done
		if result != nil {
			report.Finished = false
		}
		if err := emit(); result == nil {
			result = err
		}
	}()
	send := func(payload string) error {
		if err := conn.SetWriteDeadline(time.Now().Add(maxGap)); err != nil {
			return err
		}
		_, err := io.WriteString(conn, payload)
		return err
	}
	if err := send("push\n"); err != nil {
		return err
	}
	lastReply := time.Now()
	var resumedReceived uint64
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("reply-state deadline: %w", ctx.Err())
		case err := <-failures:
			return err
		case <-frames:
			report.Received++
			report.MaxGapMS = max(report.MaxGapMS, time.Since(lastReply).Seconds()*1000)
			lastReply = time.Now()
			if report.ResumeNS > 0 && report.Received >= resumedReceived+10 {
				report.Recovered, report.Finished = true, true
				return nil
			}
		case <-ticker.C:
			report.MaxGapMS = max(report.MaxGapMS, time.Since(lastReply).Seconds()*1000)
			switch {
			case report.ChangedNS == 0:
				if time.Since(lastReply) > maxGap {
					return errors.New("server-push baseline stalled before snapshot change")
				}
				if markerExists(changedFile) {
					if report.Received < 10 {
						return errors.New("snapshot changed without a server-push baseline")
					}
					report.ChangedNS = time.Now().UnixNano()
					report.BaselineReceived = report.Received
				}
			case report.ResumeNS == 0:
				if time.Since(lastReply) >= 2*time.Second {
					report.Interrupted = true
					report.ResumeNS = time.Now().UnixNano()
					resumedReceived = report.Received
					if err := send("resume\n"); err != nil {
						return err
					}
				} else if time.Since(time.Unix(0, report.ChangedNS)) >= 3*time.Second && report.Received >= report.BaselineReceived+10 {
					report.Finished = true
					return nil
				}
			case time.Since(time.Unix(0, report.ResumeNS)) > maxGap:
				return errors.New("server-push stream did not recover on its original socket")
			}
			if err := emit(); err != nil {
				return err
			}
		}
	}
}
