// Command phase5verify records and validates the environment and raw evidence
// emitted by the Linux Phase 5 performance harness. It checks the documented
// fixture shape, provenance, sample counts, measurement validity, budgets, and
// accounting invariants; it does not manufacture or reinterpret measurements.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "record-environment" {
		if err := recordEnvironmentCommand(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "phase5verify: record environment: %v\n", err)
			os.Exit(1)
		}
		return
	}

	directory := flag.String("dir", "dist", "directory containing Phase 5 JSON evidence")
	expectedRunID := flag.String("run-id", "", "expected run ID shared by the Phase 5 artifacts")
	environmentPath := flag.String("environment", "", "optional phase5-environment.txt path to validate")
	expectedMigrationRunID := flag.String("migration-ci-run-id", "", "expected trusted Migration CI workflow run ID")
	expectedCommit := flag.String("commit", "", "expected source commit recorded in the environment file")
	expectedRef := flag.String("ref", "", "expected workflow ref recorded in the environment file")
	expectedWorkflowRunID := flag.String("workflow-run-id", "", "expected workflow run ID recorded in the environment file")
	expectedWorkflowEvent := flag.String("workflow-event", "", "expected workflow event recorded in the environment file")
	expectedWorkflowPath := flag.String("workflow-path", "", "expected workflow path recorded in the environment file")
	expectedMigrationBranch := flag.String("migration-ci-branch", "", "expected trusted Migration CI branch recorded in the environment file")
	expectedEnvironmentArch := flag.String("environment-arch", "", "expected environment GOARCH")
	hostedEBPFDirectory := flag.String("hosted-ebpf-dir", "", "optional directory containing trusted hosted eBPF evidence")
	hostedCapabilityDirectory := flag.String("hosted-capability-dir", "", "optional directory containing trusted hosted capability-agent evidence")
	restartDirectory := flag.String("restart-dir", "", "verify only a version-2 deployed restart, guard, and uninstall evidence bundle")
	flag.Parse()
	if *restartDirectory != "" {
		path := filepath.Join(*restartDirectory, "rolling-fail-open-evidence.txt")
		values, err := hostedKeyValues(path)
		if err == nil {
			err = requireHostedValue(values, path, "schema_version", "2")
		}
		if err == nil {
			err = validateHostedContinuityRolling(values, path)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "phase5verify: restart evidence: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("validated restart evidence in %s\n", *restartDirectory)
		return
	}
	if err := verifyDirectory(*directory, *expectedRunID); err != nil {
		fmt.Fprintf(os.Stderr, "phase5verify: %v\n", err)
		os.Exit(1)
	}
	if strings.TrimSpace(*environmentPath) != "" {
		if err := verifyEnvironmentFileForContext(*environmentPath, environmentContext{
			RunID: *expectedRunID, MigrationRunID: *expectedMigrationRunID,
			Commit: *expectedCommit, Ref: *expectedRef, WorkflowRunID: *expectedWorkflowRunID,
			WorkflowEvent: *expectedWorkflowEvent, WorkflowPath: *expectedWorkflowPath,
			MigrationBranch: *expectedMigrationBranch, Arch: *expectedEnvironmentArch,
		}); err != nil {
			fmt.Fprintf(os.Stderr, "phase5verify: environment: %v\n", err)
			os.Exit(1)
		}
		if err := verifyEnvironmentMatchesEvidence(*environmentPath, *directory); err != nil {
			fmt.Fprintf(os.Stderr, "phase5verify: environment provenance: %v\n", err)
			os.Exit(1)
		}
	}
	if strings.TrimSpace(*hostedEBPFDirectory) != "" || strings.TrimSpace(*hostedCapabilityDirectory) != "" {
		if strings.TrimSpace(*hostedEBPFDirectory) == "" || strings.TrimSpace(*hostedCapabilityDirectory) == "" {
			fmt.Fprintln(os.Stderr, "phase5verify: hosted eBPF and capability-agent directories must be supplied together")
			os.Exit(1)
		}
		if err := verifyHostedEvidence(*hostedEBPFDirectory, *hostedCapabilityDirectory); err != nil {
			fmt.Fprintf(os.Stderr, "phase5verify: hosted evidence: %v\n", err)
			os.Exit(1)
		}
	}
	fmt.Printf("validated Phase 5 evidence in %s\n", *directory)
}

func verifyDirectory(directory, expectedRunID string) error {
	if err := validatePhase5JSONDirectory(directory); err != nil {
		return err
	}
	type evidenceCheck struct {
		name string
		out  any
	}
	checks := make([]evidenceCheck, 0, len(phase5JSONArtifactSpecs))
	for _, spec := range phase5JSONArtifactSpecs {
		checks = append(checks, evidenceCheck{name: spec.name, out: spec.newOutput()})
	}
	for _, check := range checks {
		if err := readEvidence(filepath.Join(directory, check.name), check.out); err != nil {
			return err
		}
	}

	if err := validateReference(*checks[0].out.(*referenceEvidence)); err != nil {
		return fmt.Errorf("phase5-performance.json: %w", err)
	}
	if err := validateFlow(*checks[1].out.(*flowEvidence)); err != nil {
		return fmt.Errorf("phase5-flow.json: %w", err)
	}
	if err := validatePacket(*checks[2].out.(*packetEvidence)); err != nil {
		return fmt.Errorf("phase5-packet.json: %w", err)
	}
	if err := validateActivation(*checks[3].out.(*activationEvidence)); err != nil {
		return fmt.Errorf("phase5-agent.json: %w", err)
	}
	if err := validateReconciliation(*checks[4].out.(*reconciliationEvidence)); err != nil {
		return fmt.Errorf("phase5-agent-reconcile.json: %w", err)
	}
	if err := validateEvent(*checks[5].out.(*eventEvidence)); err != nil {
		return fmt.Errorf("phase5-agent-event.json: %w", err)
	}
	if err := validatePodStart(*checks[6].out.(*podStartEvidence)); err != nil {
		return fmt.Errorf("phase5-agent-pod-start.json: %w", err)
	}
	if err := validateRestart(*checks[7].out.(*restartEvidence)); err != nil {
		return fmt.Errorf("phase5-agent-restart.json: %w", err)
	}
	if err := validateCrash(*checks[8].out.(*crashEvidence)); err != nil {
		return fmt.Errorf("phase5-agent-crash.json: %w", err)
	}
	if err := validateResource(*checks[9].out.(*resourceEvidence)); err != nil {
		return fmt.Errorf("phase5-agent-resource.json: %w", err)
	}
	if err := validateEvidenceSetEnvironment(
		phase5EvidenceEnvironmentFromReference("phase5-performance.json", *checks[0].out.(*referenceEvidence)),
		phase5EvidenceEnvironmentFromFlow("phase5-flow.json", *checks[1].out.(*flowEvidence)),
		phase5EvidenceEnvironmentFromPacket("phase5-packet.json", *checks[2].out.(*packetEvidence)),
		phase5EvidenceEnvironmentFromActivation("phase5-agent.json", *checks[3].out.(*activationEvidence)),
		phase5EvidenceEnvironmentFromReconciliation("phase5-agent-reconcile.json", *checks[4].out.(*reconciliationEvidence)),
		phase5EvidenceEnvironmentFromEvent("phase5-agent-event.json", *checks[5].out.(*eventEvidence)),
		phase5EvidenceEnvironmentFromPodStart("phase5-agent-pod-start.json", *checks[6].out.(*podStartEvidence)),
		phase5EvidenceEnvironmentFromRestart("phase5-agent-restart.json", *checks[7].out.(*restartEvidence)),
		phase5EvidenceEnvironmentFromCrash("phase5-agent-crash.json", *checks[8].out.(*crashEvidence)),
		phase5EvidenceEnvironmentFromResource("phase5-agent-resource.json", *checks[9].out.(*resourceEvidence)),
	); err != nil {
		return fmt.Errorf("evidence environment: %w", err)
	}
	actualRunID := checks[0].out.(*referenceEvidence).RunID
	if strings.TrimSpace(expectedRunID) != "" && actualRunID != expectedRunID {
		return fmt.Errorf("evidence run ID %q does not match expected run ID %q", actualRunID, expectedRunID)
	}
	if err := validateAgentKernelReleases(
		phase5AgentProvenance{Artifact: "phase5-agent.json", KernelRelease: checks[3].out.(*activationEvidence).KernelRelease},
		phase5AgentProvenance{Artifact: "phase5-agent-reconcile.json", KernelRelease: checks[4].out.(*reconciliationEvidence).KernelRelease},
		phase5AgentProvenance{Artifact: "phase5-agent-event.json", KernelRelease: checks[5].out.(*eventEvidence).KernelRelease},
		phase5AgentProvenance{Artifact: "phase5-agent-pod-start.json", KernelRelease: checks[6].out.(*podStartEvidence).KernelRelease},
		phase5AgentProvenance{Artifact: "phase5-agent-restart.json", KernelRelease: checks[7].out.(*restartEvidence).KernelRelease},
		phase5AgentProvenance{Artifact: "phase5-agent-crash.json", KernelRelease: checks[8].out.(*crashEvidence).KernelRelease},
		phase5AgentProvenance{Artifact: "phase5-agent-resource.json", KernelRelease: checks[9].out.(*resourceEvidence).KernelRelease},
	); err != nil {
		return fmt.Errorf("agent provenance: %w", err)
	}
	return nil
}

func validatePhase5JSONDirectory(directory string) error {
	info, err := os.Lstat(directory)
	if err != nil {
		return fmt.Errorf("inspect Phase 5 evidence directory %q: %w", directory, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("phase 5 evidence directory %q is a symlink", directory)
	}
	if !info.IsDir() {
		return fmt.Errorf("phase 5 evidence path %q is not a directory", directory)
	}
	expected := make(map[string]struct{}, len(phase5JSONArtifactSpecs))
	for _, spec := range phase5JSONArtifactSpecs {
		expected[spec.name] = struct{}{}
	}
	seen := make(map[string]int, len(expected))
	if err := filepath.WalkDir(directory, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		name := entry.Name()
		lowerName := strings.ToLower(name)
		isPhase5JSON := strings.HasPrefix(lowerName, "phase5-") && strings.HasSuffix(lowerName, ".json")
		if entry.Type()&os.ModeSymlink != 0 {
			if isPhase5JSON {
				return fmt.Errorf("phase 5 JSON artifact %q is a symlink", path)
			}
			return fmt.Errorf("phase 5 evidence tree contains symlink %q", path)
		}
		if entry.IsDir() {
			if isPhase5JSON {
				return fmt.Errorf("phase 5 JSON artifact %q is not a regular file", path)
			}
			return nil
		}
		entryInfo, err := entry.Info()
		if err != nil {
			return fmt.Errorf("inspect Phase 5 evidence entry %q: %w", path, err)
		}
		if !entryInfo.Mode().IsRegular() {
			return fmt.Errorf("phase 5 evidence entry %q is not a regular file", path)
		}
		if !isPhase5JSON {
			return nil
		}
		if _, ok := expected[name]; !ok {
			return fmt.Errorf("unexpected Phase 5 JSON artifact %q", path)
		}
		seen[name]++
		if seen[name] > 1 {
			return fmt.Errorf("phase 5 JSON artifact %q occurs more than once", name)
		}
		return nil
	}); err != nil {
		return fmt.Errorf("walk Phase 5 evidence directory %q: %w", directory, err)
	}
	for _, spec := range phase5JSONArtifactSpecs {
		if seen[spec.name] != 1 {
			return fmt.Errorf("phase 5 JSON artifact %q occurs %d times", spec.name, seen[spec.name])
		}
	}
	return nil
}

func phase5EvidenceEnvironmentFromReference(artifact string, evidence referenceEvidence) phase5EvidenceEnvironment {
	return phase5EvidenceEnvironment{Artifact: artifact, RunID: evidence.RunID, GoVersion: evidence.GoVersion, GOOS: evidence.GOOS, GOARCH: evidence.GOARCH, CPUs: evidence.CPUs}
}

func phase5EvidenceEnvironmentFromFlow(artifact string, evidence flowEvidence) phase5EvidenceEnvironment {
	return phase5EvidenceEnvironment{Artifact: artifact, RunID: evidence.RunID, GoVersion: evidence.GoVersion, GOOS: evidence.GOOS, GOARCH: evidence.GOARCH, CPUs: evidence.CPUs}
}

func phase5EvidenceEnvironmentFromPacket(artifact string, evidence packetEvidence) phase5EvidenceEnvironment {
	return phase5EvidenceEnvironment{Artifact: artifact, RunID: evidence.RunID, GoVersion: evidence.GoVersion, GOOS: evidence.GOOS, GOARCH: evidence.GOARCH, CPUs: evidence.CPUs}
}

func phase5EvidenceEnvironmentFromActivation(artifact string, evidence activationEvidence) phase5EvidenceEnvironment {
	return phase5EvidenceEnvironment{Artifact: artifact, RunID: evidence.RunID, GoVersion: evidence.GoVersion, GOOS: evidence.GOOS, GOARCH: evidence.GOARCH, CPUs: evidence.CPUs}
}

func phase5EvidenceEnvironmentFromReconciliation(artifact string, evidence reconciliationEvidence) phase5EvidenceEnvironment {
	return phase5EvidenceEnvironment{Artifact: artifact, RunID: evidence.RunID, GoVersion: evidence.GoVersion, GOOS: evidence.GOOS, GOARCH: evidence.GOARCH, CPUs: evidence.CPUs}
}

func phase5EvidenceEnvironmentFromEvent(artifact string, evidence eventEvidence) phase5EvidenceEnvironment {
	return phase5EvidenceEnvironment{Artifact: artifact, RunID: evidence.RunID, GoVersion: evidence.GoVersion, GOOS: evidence.GOOS, GOARCH: evidence.GOARCH, CPUs: evidence.CPUs}
}

func phase5EvidenceEnvironmentFromPodStart(artifact string, evidence podStartEvidence) phase5EvidenceEnvironment {
	return phase5EvidenceEnvironment{Artifact: artifact, RunID: evidence.RunID, GoVersion: evidence.GoVersion, GOOS: evidence.GOOS, GOARCH: evidence.GOARCH, CPUs: evidence.CPUs}
}

func phase5EvidenceEnvironmentFromRestart(artifact string, evidence restartEvidence) phase5EvidenceEnvironment {
	return phase5EvidenceEnvironment{Artifact: artifact, RunID: evidence.RunID, GoVersion: evidence.GoVersion, GOOS: evidence.GOOS, GOARCH: evidence.GOARCH, CPUs: evidence.CPUs}
}

func phase5EvidenceEnvironmentFromCrash(artifact string, evidence crashEvidence) phase5EvidenceEnvironment {
	return phase5EvidenceEnvironment{Artifact: artifact, RunID: evidence.RunID, GoVersion: evidence.GoVersion, GOOS: evidence.GOOS, GOARCH: evidence.GOARCH, CPUs: evidence.CPUs}
}

func phase5EvidenceEnvironmentFromResource(artifact string, evidence resourceEvidence) phase5EvidenceEnvironment {
	return phase5EvidenceEnvironment{Artifact: artifact, RunID: evidence.RunID, GoVersion: evidence.GoVersion, GOOS: evidence.GOOS, GOARCH: evidence.GOARCH, CPUs: evidence.CPUs}
}

func validateEvidenceSetEnvironment(entries ...phase5EvidenceEnvironment) error {
	if len(entries) == 0 {
		return errors.New("evidence environment set is empty")
	}
	baseline := entries[0]
	if strings.TrimSpace(baseline.RunID) == "" {
		return fmt.Errorf("%s has empty run ID", baseline.Artifact)
	}
	for _, entry := range entries[1:] {
		if strings.TrimSpace(entry.RunID) == "" {
			return fmt.Errorf("%s has empty run ID", entry.Artifact)
		}
		if entry.RunID != baseline.RunID || entry.GoVersion != baseline.GoVersion || entry.GOOS != baseline.GOOS || entry.GOARCH != baseline.GOARCH || entry.CPUs != baseline.CPUs {
			return fmt.Errorf("%s provenance differs from %s: run_id=%q/%q Go=%q/%q GOOS=%q/%q GOARCH=%q/%q CPUs=%d/%d",
				entry.Artifact, baseline.Artifact, entry.RunID, baseline.RunID, entry.GoVersion, baseline.GoVersion, entry.GOOS, baseline.GOOS,
				entry.GOARCH, baseline.GOARCH, entry.CPUs, baseline.CPUs)
		}
	}
	return nil
}

func validateAgentKernelReleases(entries ...phase5AgentProvenance) error {
	if len(entries) == 0 {
		return errors.New("agent provenance set is empty")
	}
	baseline := entries[0]
	for _, entry := range entries[1:] {
		if entry.KernelRelease != baseline.KernelRelease {
			return fmt.Errorf("%s kernel release %q differs from %s kernel release %q", entry.Artifact, entry.KernelRelease, baseline.Artifact, baseline.KernelRelease)
		}
	}
	return nil
}
