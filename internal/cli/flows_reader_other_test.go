//go:build !linux && !windows

package cli

import "testing"

func TestOpenStreamingFlowReader_OtherPlatform(t *testing.T) {
	reader, err := openStreamingFlowReader()
	if err == nil || reader != nil {
		t.Fatalf("openStreamingFlowReader() = (%T, %v), want unsupported-platform error", reader, err)
	}
}

func TestCreateAnomalyFlowReader_OtherPlatform(t *testing.T) {
	reader, err := createAnomalyFlowReader()
	if err == nil {
		t.Fatalf("expected anomaly reader setup to fail on unsupported platform, got %v", reader)
	}
	if reader != nil {
		t.Fatalf("expected no reader on unsupported platform, got %T", reader)
	}
}
