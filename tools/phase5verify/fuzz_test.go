package main

import "testing"

func FuzzHostedFixtureYAMLNeverPanics(f *testing.F) {
	f.Add([]byte("apiVersion: v1\nkind: Namespace\nmetadata:\n  name: ztap-performance\n"))
	f.Add([]byte("---\napiVersion: v1\nkind: Pod\nmetadata:\n  name: reference-pod-000\n"))
	f.Add([]byte("metadata:\n  labels:\n    phase5-bucket: \"00\"\n"))
	f.Add([]byte("a: &value\n  b: *value\n---\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Keep ordinary seed execution bounded. The release verifier already
		// applies a 4 MiB input limit; fuzzing does not need to duplicate a
		// large-input stress test in every package test run.
		if len(data) > 64<<10 {
			t.Skip()
		}
		documents, err := hostedFixtureDocuments("fuzz-fixture.yaml", string(data))
		if err != nil {
			return
		}
		for _, document := range documents {
			_, _ = decodeHostedYAMLDocument("fuzz-fixture.yaml", document)
		}
	})
}
