package flow

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
	"unsafe"
)

func TestParseEngineFlowEvent(t *testing.T) {
	data := make([]byte, engineRawEventSize)
	binary.LittleEndian.PutUint64(data[0:8], 123)
	binary.LittleEndian.PutUint64(data[8:16], 19)
	binary.LittleEndian.PutUint64(data[16:24], 200)
	binary.LittleEndian.PutUint32(data[24:28], 0xc0000201)
	binary.LittleEndian.PutUint32(data[40:44], 0xc6336402)
	binary.LittleEndian.PutUint16(data[56:58], 45678)
	binary.LittleEndian.PutUint16(data[58:60], 443)
	data[60] = ProtocolTCP
	data[61] = DirectionEgress
	data[62] = ActionAllowed
	data[63] = ReasonRule
	data[64] = 4
	data[65] = engineEventSchema

	got, err := parseRawEvent(data)
	if err != nil {
		t.Fatalf("parse engine event: %v", err)
	}
	if got.PolicyEpoch != 19 || got.CgroupID != 200 || got.SchemaVersion != engineEventSchema || got.Reason != ReasonRule {
		t.Fatalf("engine metadata decode = %+v", got)
	}
	flow := got.ToFlowEvent(time.Unix(0, 0))
	if flow.SourceIP.String() != "192.0.2.1" || flow.DestIP.String() != "198.51.100.2" {
		t.Fatalf("engine address decode = %s -> %s", flow.SourceIP, flow.DestIP)
	}
	if flow.PolicyEpoch != 19 || flow.CgroupID != 200 || flow.Reason != "rule" || flow.SchemaVersion != engineEventSchema {
		t.Fatalf("engine FlowEvent metadata = %+v", flow)
	}
	if !flow.SourceIP.Equal(net.IPv4(192, 0, 2, 1)) || !flow.DestIP.Equal(net.IPv4(198, 51, 100, 2)) {
		t.Fatalf("engine FlowEvent addresses = %s -> %s", flow.SourceIP, flow.DestIP)
	}
}

func TestParseFlowEventRejectsUnknownSizeAndSchema(t *testing.T) {
	if _, err := parseRawEvent(make([]byte, engineRawEventSize+1)); err == nil {
		t.Fatal("expected an unknown event size to be rejected")
	}
	data := make([]byte, engineRawEventSize)
	data[65] = 2
	if _, err := parseRawEvent(data); err == nil {
		t.Fatal("expected an unknown engine schema to be rejected")
	}
}

func TestRawFlowEventV1LayoutIs72Bytes(t *testing.T) {
	if got := unsafe.Sizeof(RawFlowEvent{}); got != engineRawEventSize {
		t.Fatalf("RawFlowEvent size = %d, want %d", got, engineRawEventSize)
	}
}
