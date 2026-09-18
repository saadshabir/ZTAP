//go:build windows

package cli

import "testing"

func TestOpenStreamingFlowReader_Windows(t *testing.T) {
	reader, err := openStreamingFlowReader()
	if err == nil || reader != nil {
		t.Fatalf("openStreamingFlowReader() = (%T, %v), want unsupported-platform error", reader, err)
	}
}
