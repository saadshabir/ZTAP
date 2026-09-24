package cli

import (
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/saadshabir/ZTAP/internal/flow"
)

func TestFormatFlowJSONIncludesEngineMetadata(t *testing.T) {
	event := flow.FlowEvent{
		Timestamp:     time.Unix(123, 456).UTC(),
		PolicyEpoch:   19,
		CgroupID:      200,
		SourceIP:      net.IPv4(192, 0, 2, 1),
		DestIP:        net.IPv4(198, 51, 100, 2),
		SourcePort:    45678,
		DestPort:      443,
		Protocol:      "TCP",
		Direction:     "egress",
		Action:        "allowed",
		Reason:        "rule",
		SchemaVersion: 1,
	}

	var got map[string]any
	if err := json.Unmarshal([]byte(formatFlowJSON(event)), &got); err != nil {
		t.Fatalf("formatFlowJSON produced invalid JSON: %v", err)
	}
	for key, want := range map[string]any{
		"policy_epoch":   float64(19),
		"cgroup_id":      float64(200),
		"schema_version": float64(1),
		"reason":         "rule",
	} {
		if got[key] != want {
			t.Fatalf("JSON field %q = %#v, want %#v", key, got[key], want)
		}
	}
}

func TestFormatFlowJSONEscapesStringFields(t *testing.T) {
	event := flow.FlowEvent{
		Timestamp: time.Unix(0, 0).UTC(),
		Protocol:  "TCP\"\\\n",
		Reason:    "reason\"\\\n",
	}

	var got struct {
		Protocol string `json:"protocol"`
		Reason   string `json:"reason"`
	}
	if err := json.Unmarshal([]byte(formatFlowJSON(event)), &got); err != nil {
		t.Fatalf("formatFlowJSON escaped output is invalid JSON: %v", err)
	}
	if got.Protocol != event.Protocol || got.Reason != event.Reason {
		t.Fatalf("escaped fields = %#v, want protocol=%q reason=%q", got, event.Protocol, event.Reason)
	}
}
