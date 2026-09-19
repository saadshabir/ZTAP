//go:build linux && integration
// +build linux,integration

package enforcer

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/saadshabir/ZTAP/internal/flow"

	"github.com/cilium/ebpf/ringbuf"
)

func TestCgroupUDPSendHelper(t *testing.T) {
	if os.Getenv("ZTAP_CGROUP_HELPER") != "1" {
		t.Skip("helper")
	}
	addr := os.Getenv("ZTAP_UDP_ADDR")
	if addr == "" {
		t.Fatal("ZTAP_UDP_ADDR not set")
	}
	if os.Getenv("ZTAP_START_FD") != "3" {
		t.Fatalf("unexpected ZTAP_START_FD=%q", os.Getenv("ZTAP_START_FD"))
	}
	startFile := os.NewFile(3, "start")
	if startFile == nil {
		t.Fatal("failed to open start fd")
	}
	_, _ = startFile.Read(make([]byte, 1))
	_ = startFile.Close()

	conn, err := net.DialTimeout("udp4", addr, 500*time.Millisecond)
	if err != nil {
		t.Fatalf("dial udp: %v", err)
	}
	_, _ = conn.Write([]byte("x"))
	_ = conn.Close()
}

func TestCgroupUDPReceiveHelper(t *testing.T) {
	if os.Getenv("ZTAP_CGROUP_RECEIVE_HELPER") != "1" {
		t.Skip("helper")
	}
	addr := os.Getenv("ZTAP_UDP_ADDR")
	if addr == "" {
		t.Fatal("ZTAP_UDP_ADDR not set")
	}
	startFile := os.NewFile(3, "start")
	statusFile := os.NewFile(4, "status")
	if startFile == nil || statusFile == nil {
		t.Fatal("failed to open helper pipes")
	}
	defer startFile.Close()
	defer statusFile.Close()
	if _, err := io.ReadFull(startFile, make([]byte, 1)); err != nil {
		t.Fatalf("start signal: %v", err)
	}

	conn, err := net.ListenPacket("udp4", addr)
	if err != nil {
		_, _ = statusFile.Write([]byte{'e'})
		t.Fatalf("listen: %v", err)
	}
	defer conn.Close()
	if _, err := statusFile.Write([]byte{'r'}); err != nil {
		t.Fatalf("ready signal: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(1200 * time.Millisecond))
	_, _, err = conn.ReadFrom(make([]byte, 1))
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			_, _ = statusFile.Write([]byte{'0'})
			return
		}
		_, _ = statusFile.Write([]byte{'e'})
		t.Fatalf("receive: %v", err)
	}
	_, _ = statusFile.Write([]byte{'1'})
}

func TestCgroupUDP6SendHelper(t *testing.T) {
	if os.Getenv("ZTAP_CGROUP_IPV6_HELPER") != "1" {
		t.Skip("helper")
	}
	addr := os.Getenv("ZTAP_UDP_ADDR")
	if addr == "" {
		t.Fatal("ZTAP_UDP_ADDR not set")
	}
	startFile := os.NewFile(3, "start")
	if startFile == nil {
		t.Fatal("failed to open start fd")
	}
	if _, err := startFile.Read(make([]byte, 1)); err != nil {
		t.Fatalf("start signal: %v", err)
	}
	_ = startFile.Close()

	conn, err := net.DialTimeout("udp6", addr, 500*time.Millisecond)
	if err != nil {
		t.Fatalf("dial udp6: %v", err)
	}
	_, _ = conn.Write([]byte("x"))
	_ = conn.Close()
}

func mustCgroupID(t *testing.T, cgroupPath string) uint64 {
	t.Helper()
	id, err := cgroupInodeID(cgroupPath)
	if err != nil {
		t.Fatalf("stat cgroup: %v", err)
	}
	return id
}

func createTestCgroup(t *testing.T) string {
	t.Helper()
	path := filepath.Join("/sys/fs/cgroup", fmt.Sprintf("ztap-test-%d", time.Now().UnixNano()))
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatalf("create test cgroup %s: %v", path, err)
	}
	t.Cleanup(func() {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			t.Errorf("remove test cgroup %s: %v", path, err)
		}
	})
	return path
}

func createSubCgroup(t *testing.T, parent, name string) string {
	t.Helper()
	path := filepath.Join(parent, name)
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatalf("create child cgroup %s: %v", path, err)
	}
	t.Cleanup(func() { _ = os.Remove(path) })
	return path
}

func runUDPSendHelperInCgroup(t *testing.T, cgroupPath, addr string) {
	t.Helper()
	startReader, startWriter, err := os.Pipe()
	if err != nil {
		t.Fatalf("create start pipe: %v", err)
	}
	t.Cleanup(func() {
		_ = startReader.Close()
		_ = startWriter.Close()
	})

	cmd := exec.Command(os.Args[0], "-test.run", "^TestCgroupUDPSendHelper$", "-test.v")
	cmd.Env = append(os.Environ(), "ZTAP_CGROUP_HELPER=1", "ZTAP_UDP_ADDR="+addr, "ZTAP_START_FD=3")
	cmd.ExtraFiles = []*os.File{startReader}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start UDP helper: %v", err)
	}

	moveProcessToCgroup(t, cmd, cgroupPath)
	if _, err := startWriter.Write([]byte{'1'}); err != nil {
		_ = cmd.Process.Kill()
		t.Fatalf("release UDP helper: %v", err)
	}
	_ = startWriter.Close()
	if err := cmd.Wait(); err != nil {
		t.Fatalf("UDP helper failed: %v", err)
	}
}

func runUDPReceiveHelperInCgroup(t *testing.T, cgroupPath string, port int) bool {
	t.Helper()
	startReader, startWriter, err := os.Pipe()
	if err != nil {
		t.Fatalf("create start pipe: %v", err)
	}
	statusReader, statusWriter, err := os.Pipe()
	if err != nil {
		_ = startReader.Close()
		_ = startWriter.Close()
		t.Fatalf("create status pipe: %v", err)
	}
	t.Cleanup(func() {
		_ = startReader.Close()
		_ = startWriter.Close()
		_ = statusReader.Close()
		_ = statusWriter.Close()
	})

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	cmd := exec.Command(os.Args[0], "-test.run", "^TestCgroupUDPReceiveHelper$", "-test.v")
	cmd.Env = append(os.Environ(), "ZTAP_CGROUP_RECEIVE_HELPER=1", "ZTAP_UDP_ADDR="+addr)
	cmd.ExtraFiles = []*os.File{startReader, statusWriter}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start receive helper: %v", err)
	}
	_ = startReader.Close()
	_ = statusWriter.Close()

	moveProcessToCgroup(t, cmd, cgroupPath)
	if _, err := startWriter.Write([]byte{'1'}); err != nil {
		_ = cmd.Process.Kill()
		t.Fatalf("release receive helper: %v", err)
	}
	_ = startWriter.Close()

	status := make([]byte, 2)
	if _, err := io.ReadFull(statusReader, status[:1]); err != nil {
		_ = cmd.Process.Kill()
		t.Fatalf("receive helper readiness: %v", err)
	}
	if status[0] != 'r' {
		_ = cmd.Process.Kill()
		t.Fatalf("receive helper failed before readiness: %q", status[0])
	}
	conn, err := net.DialTimeout("udp4", addr, 500*time.Millisecond)
	if err != nil {
		_ = cmd.Process.Kill()
		t.Fatalf("dial receive helper: %v", err)
	}
	_, writeErr := conn.Write([]byte{'x'})
	_ = conn.Close()
	if writeErr != nil {
		_ = cmd.Process.Kill()
		t.Fatalf("send receive helper datagram: %v", writeErr)
	}
	if _, err := io.ReadFull(statusReader, status[1:]); err != nil {
		_ = cmd.Process.Kill()
		t.Fatalf("receive helper result: %v", err)
	}
	if err := cmd.Wait(); err != nil && status[1] != '0' {
		t.Fatalf("receive helper failed: %v", err)
	}
	return status[1] == '1'
}

func runUDP6SendHelperInCgroup(t *testing.T, cgroupPath, addr string) {
	t.Helper()
	startReader, startWriter, err := os.Pipe()
	if err != nil {
		t.Fatalf("create IPv6 start pipe: %v", err)
	}
	t.Cleanup(func() {
		_ = startReader.Close()
		_ = startWriter.Close()
	})
	cmd := exec.Command(os.Args[0], "-test.run", "^TestCgroupUDP6SendHelper$", "-test.v")
	cmd.Env = append(os.Environ(), "ZTAP_CGROUP_IPV6_HELPER=1", "ZTAP_UDP_ADDR="+addr)
	cmd.ExtraFiles = []*os.File{startReader}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start IPv6 helper: %v", err)
	}
	moveProcessToCgroup(t, cmd, cgroupPath)
	if _, err := startWriter.Write([]byte{'1'}); err != nil {
		_ = cmd.Process.Kill()
		t.Fatalf("release IPv6 helper: %v", err)
	}
	_ = startWriter.Close()
	if err := cmd.Wait(); err != nil {
		t.Fatalf("IPv6 helper failed: %v", err)
	}
}

func reserveUDPPort(t *testing.T) int {
	t.Helper()
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatalf("reserve UDP port: %v", err)
	}
	port := listener.LocalAddr().(*net.UDPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatalf("release UDP port: %v", err)
	}
	return port
}

func readFlowEvent(t *testing.T, reader *ringbuf.Reader, destPort uint16, protocol, direction uint8, timeout time.Duration) flow.RawFlowEvent {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			t.Fatalf("timeout waiting for flow event destPort=%d protocol=%d direction=%d", destPort, protocol, direction)
		}
		records := make(chan ringbuf.Record, 1)
		errors := make(chan error, 1)
		go func() {
			record, err := reader.Read()
			if err != nil {
				errors <- err
				return
			}
			records <- record
		}()
		select {
		case err := <-errors:
			t.Fatalf("ringbuf read error: %v", err)
		case record := <-records:
			if len(record.RawSample) != 72 {
				t.Fatalf("unexpected raw event size %d", len(record.RawSample))
			}
			var raw flow.RawFlowEvent
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &raw); err != nil {
				t.Fatalf("parse versioned raw event: %v", err)
			}
			if raw.DestPort != destPort || raw.Protocol != protocol || raw.Direction != direction {
				continue
			}
			return raw
		case <-time.After(remaining):
		}
	}
}
