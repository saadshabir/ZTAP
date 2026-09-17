# ZTAP Testing Documentation

How to run the test suite, interpret coverage, and maintain test quality.

## Overview

ZTAP includes comprehensive test coverage across all critical components with unit tests, integration tests, and validation scenarios.

## Test Coverage

### Unit Tests

#### Policy Package (`internal/policy/policy_test.go`)

- **TestLoadFromFile**: Validates YAML policy file loading
- **TestValidate**: Tests policy validation rules
  - Valid policy structure
  - Missing apiVersion
  - Invalid CIDR notation
  - Invalid port numbers
  - Invalid protocol types
- **TestPolicyResolver**: Tests label resolution with service discovery

**Run**: `go test ./internal/policy/... -v`

#### Compliance Package (`internal/compliance`)

- Mapping extraction from policy annotations and mapping files
- Audit evidence evaluation (integrity + `policy.enforced` event presence)
- JSON/CSV exporters and Markdown report rendering

**Run**: `go test ./internal/compliance/... -v`

#### Audit Package (`internal/audit`)

- **TestNewAuditLogger**: Logger creation and initialization
- **TestAuditLogger_Log**: Event logging
- **TestAuditLogger_LogFailure**: Failure event logging
- **TestAuditLogger_HashChaining**: SHA-256 hash chain correctness
- **TestAuditLogger_VerifyIntegrity**: Full integrity verification pass
- **TestAuditLogger_VerifyIntegrityDetectsTampering**: Tamper detection
- **TestAuditLogger_Ed25519Signing**: Ed25519 signature verification
- **TestAuditLogger_TruncationDetection**: Checkpoint-based truncation detection
- **TestAuditLogger_TamperAndRecompute**: Tamper and re-hash detection
- **TestVerifyIntegrity_DetectsCorruption**: Corruption detection
- **TestFullWorkflow**: End-to-end audit workflow
- **TestAuditLogger_Query** / **TestAuditLogger_QueryByResource**: Query filtering
- **TestAuditLogger_GetStats**: Statistics reporting
- **TestAuditLogger_Persistence**: Log persistence across reopens
- **TestAuditLogger_ConcurrentWrites**: Thread-safety under concurrent writes
- **TestVerifyFileIntegrityAndQueryFile** / **TestVerifyFileIntegrityDetectsTamper**: File-level integrity
- **TestVerifyIntegrityDetailed_EntryCount**: Verifies entry count accuracy in detailed verification
- **TestLoadLastHash_ResetsCounterOnReopen**: Verifies entryCount resets correctly when log is reopened
- **TestVerifyIntegrityDetailed_EmptyLog**: Empty log edge case
- **TestEntryHash_NilEntry**: Nil entry hash behavior
- **TestEntryHash_ValidEntry**: Valid entry hash computation
- **TestEntryHash_NonSerializableDetails**: Verifies error return when Details cannot be JSON-serialized

**Run**: `go test ./internal/audit/... -v`

#### Flow Package (`internal/flow`)

- **TestMonitor_SubscriberLifecycle_NoPanic**: Subscribe/unsubscribe without panics or races
- **TestMonitor_SubscribeAfterStop**: Subscribing after monitor stop returns nil channel
- **TestMonitor_ConcurrentSubscribeUnsubscribe**: Concurrent subscribe/unsubscribe safety

**Run**: `go test ./internal/flow/... -v`

#### Discovery Package (`internal/discovery/discovery_test.go`)

- **TestInMemoryDiscovery_RegisterAndResolve**: Service registration and label-based resolution
- **TestInMemoryDiscovery_NoMatch**: Handling non-existent services
- **TestInMemoryDiscovery_InvalidIP**: IP address validation
- **TestInMemoryDiscovery_Deregister**: Service removal
- **TestInMemoryDiscovery_ListServices**: Listing all registered services
- **TestInMemoryDiscovery_Watch**: Dynamic service change notifications
- **TestDNSDiscovery**: DNS-based discovery validation
- **TestCacheDiscovery**: Caching layer functionality
  - Cache hits and misses
  - TTL expiration
  - Cache clearing
- **TestMatchLabels**: Label selector matching logic
- **TestK8sDiscovery_WatchNoMatchInitialState**: Validates that K8s watcher treats `NoMatchesError` as empty initial state while propagating real errors

**Run**: `go test ./internal/discovery/... -v`

#### Cloud Package (`internal/cloud/aws_test.go`)

- **TestMatchResourcesByLabels**: Ensures label selectors align with AWS tags
- **TestDiscoverResources**: Discovers running EC2 instances and captures metadata
- **TestDiscoverResourcesError**: Propagates DescribeInstances failures
- **TestSyncPolicyWithIPBlock**: Syncs multi-port Security Group egress rules
- **TestSyncPolicyAuthorizeError**: Handles authorization API failures
- **TestSyncPolicyWithSelectorResolution**: Resolves podSelector targets via EC2 tags and syncs host CIDRs
- **TestSyncPolicyWithSelectorExpressions**: Resolves matchExpressions selector targets via EC2 tags
- **TestAuthorizeEgressDuplicate**: Suppresses duplicate rule errors
- **TestSyncPolicyReplaceEgressReauthorizesExistingDesiredRule**: Takeover mode re-adds desired rules after clearing egress
- **TestRevokeAllEgress**: Revokes existing egress rules for cleanup
- **TestRevokeAllEgressNoRules**: No-op when no rules exist

#### Cloud Package (Azure/GCP inventory)

- **TestAzureDiscoverResources**: Discovers NIC inventory and resolves public IPs
- **TestAzureClientCountManagedRules**: Counts managed NSG rules by prefix
- **TestGCPDiscoverResources**: Discovers GCE instance inventory within a network
- **TestGCPClientCountManagedFirewalls**: Counts managed firewall rules by prefix

### Integration Tests

#### Enforcer Package (`internal/enforcer/ebpf_linux_integration_test.go`)

> **Note**: These tests require Linux, root privileges, and a kernel supporting eBPF (5.7+).

- **TestEBPFIntegrationLoadAndAttach**: Verifies eBPF program compilation, map population, and cgroup attachment
- **TestEBPFIntegrationCgroupScopedMapKey**: Verifies non-zero cgroup key programming and selected-only config
- **TestEBPFIntegrationCgroupIsolationBetweenCgroups**: Verifies a rule programmed for cgroup A does not match cgroup B
- **TestEBPFIntegrationSelectedOnlySemantics**: Verifies non-enforced cgroups default-allow and enforced cgroups default-deny on miss
- **TestEBPFGracefulReload**: Verifies that policy updates are applied using atomic `bpf_link` updates without detaching the program (ensuring zero downtime)

Run prerequisites (Linux only, for the parked compatibility tests):

- root (or sufficient capabilities to load/attach cgroup BPF)
- kernel 5.7+
- `make`, `clang`, and `llvm-strip` available (the migration tests recompile `bpf/filter.o`)

**Run**: `sudo go test -tags=integration ./internal/enforcer -run TestEBPFIntegration -v`

The supported native agent suite is run with:
`sudo go test -race -tags=integration -timeout=10m ./internal/enforcer -run '^(TestEBPFIntegrationPhase0KernelPreflight|TestLinuxEngine)' -v`.
The required Linux CI job runs this command with the race detector and uploads
the verbose output as the `ebpf-engine-evidence` artifact for review.
The `Capability-only Agent (Kubernetes)` CI job additionally runs the shipped
DaemonSet in a disposable kind cluster. It checks the pod security context and
exact effective capability set, then requires the `ztap_enforced_cgroups`
gauge to report the selected client, proves an unselected control can reach the
server while that client is denied, and checks the engine's default-deny counter.
Its logs and cluster diagnostics are uploaded as `capability-agent-evidence`.

- **TestRevokeAllEgressNotFound**: Detects missing Security Groups

**Run**: `go test ./internal/cloud/... -v`

#### Metrics Package (`internal/metrics/collector_test.go`)

- **TestGetCollectorSingleton**: Verifies singleton initialization semantics
- **TestCollectorCounters**: Confirms counter increments for flows
- **TestCollectorGaugeAndHistogram**: Validates gauge state and histogram buckets

**Run**: `go test ./internal/metrics/... -v`

#### Enforcer Package (`internal/enforcer/policy_enforcer_test.go`)

- **TestPolicyEnforcerDryRun**: Verifies that dry-run mode correctly tracks policy versions without applying system changes
- **TestPolicyEnforcerStartStop**: Validates lifecycle management
- **TestPolicyEnforcerAppliesUpdates**: End-to-end enforcement logic check

**Run**: `go test ./internal/enforcer/... -v`

## Running Tests

### All Tests

```bash
go test ./... -v
```

This includes the Kubernetes operator/agent packages. Dedicated unit tests for the operator reconcile loop are included in `internal/operator/controllers/ztapnetworkpolicy_controller_test.go`.

### Specific Package

```bash
go test ./internal/policy/... -v
go test ./internal/cloud/... -v
go test ./internal/discovery/... -v
go test ./internal/metrics/... -v
```

### With Coverage

```bash
go test ./... -cover
go test ./... -coverprofile=coverage.out
go tool cover -html=coverage.out
```

### Race Detection

```bash
go test ./... -race
```

### Security Audit

Run the built-in security audit script:

```bash
bash scripts/security_check.sh
```

The script runs:

- `go test ./...`
- `go vet ./...`
- `govulncheck ./...`
- `gosec -exclude=G304,G602 -exclude-generated ./...`

Optional dedicated secret scanning:

```bash
gitleaks detect --source . --redact --no-banner
```

### Windows Notes (WFP)

- Windows support uses Windows Filtering Platform (WFP) and requires an elevated terminal (Administrator) to actually apply/tear down filters.
- Unit tests for policy translation run on any OS; WFP runtime behavior is best validated on Windows.
- Windows WFP integration tests exist behind a build tag and are not part of the default test suite.

Run the Windows WFP flow integration tests (on Windows, elevated terminal):

```bash
go test ./internal/flow -tags=integration -run TestWFPFlowIntegration -v
```

Compile-check WFP codepaths from non-Windows hosts:

```bash
GOOS=windows GOARCH=amd64 go test ./... -c
```

CI note: `.github/workflows/ci.yml` runs Go unit tests on `windows-latest` (in the matrix) and includes Windows in the cross-build matrix.

## Test Results Summary

Test counts and coverage are expected to change as the project evolves.

```bash
# Quick pass/fail
go test ./...

# Coverage (project-wide)
go test ./... -cover
```

## Test Data

### Sample Policy (tests/fixtures/test-policy.yaml)

```yaml
apiVersion: ztap/v1
kind: NetworkPolicy
metadata:
  name: web-to-db
spec:
  podSelector:
    matchLabels:
      app: web
  egress:
    - to:
        ipBlock:
          cidr: 10.0.2.0/24
      ports:
        - protocol: TCP
          port: 5432
```

### Service Discovery Test Data

```go
services := []Service{
    {Name: "web-1", IP: "10.0.1.1", Labels: {"app": "web", "tier": "frontend"}},
    {Name: "web-2", IP: "10.0.1.2", Labels: {"app": "web", "tier": "frontend"}},
    {Name: "db-1", IP: "10.0.2.1", Labels: {"app": "database", "tier": "backend"}},
}
```

## Continuous Integration

The repository ships with `.github/workflows/ci.yml`, which runs `golangci-lint` plus Go tests on `ubuntu-24.04`, `macos-latest`, and `windows-latest`. The CI runs on every PR and weekly on Monday at 02:00 UTC.

Coverage notes:

- Each matrix job writes `coverage-${{ matrix.os }}.out` with `-coverpkg=./internal/...,./cmd/...`.
- The `cmd/covergate` step is a hard gate: it fails the job when any `internal/` or `cmd/` file drops below its baseline in `.covergate-baseline.json` (ratchet — improvements allowed, regressions are not). See "Coverage gate (ratchet)" in `CONTRIBUTING.md` for local usage and how to regenerate the baseline.
- Shared matrix `run:` commands must be shell-compatible across bash and PowerShell.
- CI artifacts (coverage) have a 14-day retention policy.

Docker builds are parallelized via a matrix strategy (ztap, ztap-anomaly, ztap-operator) with GHA layer caching. A separate Docker Compose test job validates the full stack on non-PR events.

### GitHub Actions (Recommended)

```yaml
name: Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version-file: go.mod
      - run: go test ./... -v -race -coverprofile=coverage.out
      - run: go tool cover -func=coverage.out
```

## Testing Best Practices

1. **Isolation**: Each test uses `t.TempDir()` for isolated file operations
2. **Cleanup**: Automatic cleanup of test resources via `defer` and temp directories
3. **Parallelism**: Tests can run in parallel (add `t.Parallel()` where appropriate)
4. **Table-Driven**: Complex scenarios use table-driven tests for clarity
5. **Error Checking**: Both success and failure paths are validated

## Troubleshooting

### Test Failures

**"no services found matching labels"**

- Check label selector syntax
- Verify services are registered before resolution

**"invalid CIDR"**

- Ensure CIDR notation includes subnet mask (e.g., `10.0.0.0/8`)

**"session expired"**

- Tests manipulate time; ensure timing expectations are reasonable

### Running Individual Tests

```bash
go test ./internal/policy -run TestLoadFromFile -v
go test ./internal/discovery -run TestInMemoryDiscovery_Watch -v
```

## Test Maintenance

- Update tests when adding new policy validation rules
- Add integration tests for new service discovery backends (Consul, K8s)
- Keep test data synchronized with documentation examples
- Run `go test ./... -race` regularly to detect concurrency issues
- Run `bash scripts/security_check.sh` before merging changes
