package alert

import (
	"context"
	"sync"
	"testing"
)

type recordingSink struct {
	mu     sync.Mutex
	alerts []Alert
}

func (r *recordingSink) Send(ctx context.Context, a Alert) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.alerts = append(r.alerts, a)
	return nil
}

func TestDispatcherEmitDropsWhenFull(t *testing.T) {
	t.Parallel()

	sink := &recordingSink{}
	d, err := NewDispatcher(DispatcherOptions{Sinks: []Sink{sink}, QueueSize: 1})
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}
	t.Cleanup(d.Close)

	ok1 := d.Emit(Alert{Source: "test", Severity: SeverityInfo, Title: "a", Message: "b"})
	ok2 := d.Emit(Alert{Source: "test", Severity: SeverityInfo, Title: "a", Message: "b"})
	if !ok1 {
		t.Fatalf("expected first emit ok")
	}
	if ok2 {
		t.Fatalf("expected second emit to drop")
	}
	if d.Dropped() == 0 {
		t.Fatalf("expected dropped > 0")
	}
}
