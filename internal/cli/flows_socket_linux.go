//go:build linux

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/saadshabir/ZTAP/internal/flow"
	"golang.org/x/sys/unix"
)

const (
	flowSocketName    = "flows.sock"
	maxFlowSocketPath = len(unix.RawSockaddrUnix{}.Path) - 1
	maxFlowClients    = 16
)

func agentFlowSocketPath(runDir string) (string, error) {
	if runDir = strings.TrimSpace(runDir); runDir == "" {
		runDir = "/run/ztap"
	}
	return filepath.Abs(filepath.Join(runDir, flowSocketName))
}

func openAgentFlowSocket(ctx context.Context, runDir string) (io.ReadCloser, error) {
	path, err := agentFlowSocketPath(runDir)
	if err != nil {
		return nil, err
	}
	if len(path) > maxFlowSocketPath {
		return nil, nil
	}
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "unix", path)
	if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ECONNREFUSED) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("connect to agent flow socket: %w", err)
	}
	if err := requireRootFlowPeer(conn.(*net.UnixConn)); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func requireRootFlowPeer(conn *net.UnixConn) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var credentials *unix.Ucred
	var credentialErr error
	if err := raw.Control(func(fd uintptr) {
		credentials, credentialErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return err
	}
	if credentialErr != nil {
		return credentialErr
	}
	if credentials.Uid != 0 {
		return errors.New("agent flow socket requires a root peer")
	}
	return nil
}

// listenAgentFlows is called while the agent holds the node's flow-reader lock.
func listenAgentFlows(runDir string) (*net.UnixListener, error) {
	path, err := agentFlowSocketPath(runDir)
	if err != nil {
		return nil, err
	}
	if len(path) > maxFlowSocketPath {
		return nil, fmt.Errorf("flow socket path is longer than %d bytes; use a shorter --run-dir", maxFlowSocketPath)
	}
	dir, err := openLockDirectory(filepath.Dir(path), "flow socket")
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(dir) }()
	var stat unix.Stat_t
	switch err := unix.Fstatat(dir, flowSocketName, &stat, unix.AT_SYMLINK_NOFOLLOW); {
	case err == nil:
		if stat.Mode&unix.S_IFMT != unix.S_IFSOCK || stat.Uid != 0 {
			return nil, errors.New("refusing to replace an untrusted flow socket path")
		}
		if err := unix.Unlinkat(dir, flowSocketName, 0); err != nil {
			return nil, err
		}
	case !errors.Is(err, unix.ENOENT):
		return nil, err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = listener.Close()
		return nil, err
	}
	return listener, nil
}

func serveAgentFlows(ctx context.Context, listener *net.UnixListener, monitor *flow.Monitor, onDrop func()) {
	ctx, cancel := context.WithCancel(ctx)
	var clients sync.WaitGroup
	defer func() {
		cancel()
		clients.Wait()
	}()
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stop()
	defer func() { _ = listener.Close() }()

	slots := make(chan struct{}, maxFlowClients)
	for {
		conn, err := listener.AcceptUnix()
		if err != nil {
			return
		}
		if err := requireRootFlowPeer(conn); err != nil {
			_ = conn.Close()
			continue
		}
		select {
		case slots <- struct{}{}:
			clients.Go(func() {
				defer func() { <-slots }()
				serveAgentFlowClient(ctx, conn, monitor, onDrop)
			})
		default:
			_ = writeAgentFlow(conn, json.NewEncoder(conn), agentFlowMessage{Error: "all live flow subscriptions are in use"})
			_ = conn.Close()
		}
	}
}

func serveAgentFlowClient(ctx context.Context, conn *net.UnixConn, monitor *flow.Monitor, onDrop func()) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer func() { _ = conn.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	// The protocol is server-to-client. Read once to detect an idle
	// subscriber disconnect even when the kernel has no events to send.
	go func() {
		var unused [1]byte
		_, _ = conn.Read(unused[:])
		cancel()
	}()
	encoder := json.NewEncoder(conn)
	events := monitor.SubscribeWithDrops(ctx, false, onDrop)
	if err := writeAgentFlow(conn, encoder, agentFlowMessage{Ready: true}); err != nil {
		return
	}
	for event := range events {
		if err := writeAgentFlow(conn, encoder, agentFlowMessage{Event: &event}); err != nil {
			if netErr, ok := errors.AsType[net.Error](err); ok && netErr.Timeout() && onDrop != nil {
				onDrop()
			}
			return
		}
	}
	if err := monitor.Err(); err != nil {
		_ = writeAgentFlow(conn, encoder, agentFlowMessage{Error: err.Error()})
	}
}

func writeAgentFlow(conn *net.UnixConn, encoder *json.Encoder, message agentFlowMessage) error {
	if err := conn.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return err
	}
	return encoder.Encode(message)
}
