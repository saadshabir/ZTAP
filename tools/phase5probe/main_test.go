package main

import (
	"testing"
	"time"
)

func TestFailOpenTrackerRequiresTwoConsecutiveBlockedProbes(t *testing.T) {
	tracker := failOpenTracker{}
	base := time.Unix(100, 0)

	if start, end := tracker.observe(false, base); start != 0 || end != 0 {
		t.Fatalf("blocked probe before rollout opened the interval: start=%d end=%d", start, end)
	}
	start, end := tracker.observe(true, base.Add(time.Second))
	if start != base.Add(time.Second).UnixNano() || end != 0 {
		t.Fatalf("first allowed probe did not open the interval: start=%d end=%d", start, end)
	}
	if start, end := tracker.observe(false, base.Add(2*time.Second)); start != 0 || end != 0 {
		t.Fatalf("one blocked probe closed the interval: start=%d end=%d", start, end)
	}
	if start, end := tracker.observe(true, base.Add(3*time.Second)); start != 0 || end != 0 {
		t.Fatalf("allowed probe did not reset consecutive blocked probes: start=%d end=%d", start, end)
	}
	if start, end := tracker.observe(false, base.Add(4*time.Second)); start != 0 || end != 0 {
		t.Fatalf("first blocked probe after reset closed the interval: start=%d end=%d", start, end)
	}
	start, end = tracker.observe(false, base.Add(5*time.Second))
	if start != 0 || end != base.Add(5*time.Second).UnixNano() {
		t.Fatalf("second consecutive blocked probe did not close the interval: start=%d end=%d", start, end)
	}
}
