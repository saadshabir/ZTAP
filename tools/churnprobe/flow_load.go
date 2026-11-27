package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"time"
)

func echoUDP(conn net.PacketConn) error {
	var packet [256]byte
	for {
		n, addr, err := conn.ReadFrom(packet[:])
		if err != nil {
			return err
		}
		if _, err := conn.WriteTo(packet[:n], addr); err != nil {
			return err
		}
	}
}

func bulk(conn net.Conn) {
	payload := make([]byte, 128*1024)
	for {
		if _, err := conn.Write(payload); err != nil {
			return
		}
	}
}

func measureFlow(address string, duration time.Duration, output io.Writer) error {
	if duration <= 0 || duration > time.Minute {
		return errors.New("measure-flow duration must be positive and at most one minute")
	}
	tcpBytes, err := measureTCP(address, duration)
	if err != nil {
		return fmt.Errorf("measure TCP: %w", err)
	}
	const roundTrips = 1500
	p99, err := measureUDP(address, roundTrips)
	if err != nil {
		return fmt.Errorf("measure UDP: %w", err)
	}
	return json.NewEncoder(output).Encode(struct {
		TCPBytes          int64   `json:"tcp_bytes"`
		TCPSampleSeconds  float64 `json:"tcp_sample_seconds"`
		TCPBytesPerSecond float64 `json:"tcp_bytes_per_second"`
		UDPRoundTrips     int     `json:"udp_round_trips"`
		UDPP99NS          int64   `json:"udp_p99_ns"`
	}{tcpBytes, duration.Seconds(), float64(tcpBytes) / duration.Seconds(), roundTrips, p99.Nanoseconds()})
}

func measureTCP(address string, duration time.Duration) (int64, error) {
	conn, err := net.DialTimeout("tcp4", address, time.Second)
	if err != nil {
		return 0, err
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(duration)); err != nil {
		return 0, err
	}
	if _, err := io.WriteString(conn, "bulk\n"); err != nil {
		return 0, err
	}
	buf := make([]byte, 128*1024)
	var total int64
	for {
		n, err := conn.Read(buf)
		total += int64(n)
		if isTimeout(err) && total > 0 {
			return total, nil
		}
		if err != nil {
			return 0, err
		}
	}
}

func measureUDP(address string, count int) (time.Duration, error) {
	conn, err := net.DialTimeout("udp4", address, time.Second)
	if err != nil {
		return 0, err
	}
	defer func() { _ = conn.Close() }()
	var sent, received [32]byte
	durations := make([]time.Duration, 0, count)
	for seq := range count {
		binary.BigEndian.PutUint32(sent[:], uint32(seq)) // #nosec G115 -- fixed number of small samples
		if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
			return 0, err
		}
		start := time.Now()
		if _, err := conn.Write(sent[:]); err != nil {
			return 0, err
		}
		n, err := conn.Read(received[:])
		elapsed := time.Since(start)
		if err != nil {
			return 0, err
		}
		if n != len(sent) || !bytes.Equal(sent[:], received[:]) {
			return 0, errors.New("UDP echo differed from probe")
		}
		durations = append(durations, elapsed)
	}
	slices.Sort(durations)
	return durations[(99*count+99)/100-1], nil
}
