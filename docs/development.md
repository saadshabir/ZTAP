# Development

## Prerequisites

Go `1.26.6` or a compatible newer toolchain is required. Linux is required
for privileged eBPF and Kubernetes acceptance tests; a non-Linux checkout is
suitable for the non-privileged unit tests.

The privileged Linux integration gate vet-checks and executes both the
enforcer and CLI integration-tagged package trees, including the Phase 5
agent, flow-reader, cgroup-path, and evidence-writer support tests. The
Kubernetes acceptance gate runs separately in a disposable kind cluster.

### Tested kernel record

- Current Phase 5 CI validation: pending for the uncommitted Phase 5 diff.
- Current Phase 5 manual validation: no kernel release recorded.

No exact kernel version is claimed until the hosted gates pass for the reviewed
commit. The release workflow records `uname` in `phase5-environment.txt` and
requires all native-agent artifacts to report the same kernel release. Release
preparation must replace the pending entries above with those exact CI and
manual-validation kernel releases; missing kernel records remain a release
blocker.

For the complete local workflow, install `make`, clang/LLVM with the
configured `clang-18` binary, Docker, `kubectl`, and kind. `golangci-lint`,
actionlint, and govulncheck are pinned by the Makefile and installed into
repository-local tool/cache paths; Trivy is pinned and run by CI.

## Repository map

```text
cmd/ztap/                 process entry point
internal/cli/             Cobra commands and user-facing I/O
internal/policy/          native NetworkPolicy validation and compilation
internal/enforcer/        Linux eBPF engine and generated bindings
internal/flow/            pinned flow-map decoding and output
deployments/kubernetes/   capability-only DaemonSet and manifest tests
examples/native/          validator fixtures
bpf/                      retained eBPF C source
tools/bpfgen/             source-only binding generator
tools/phase5verify/       retained performance and hosted-evidence verifier
```

The dependency direction is intentional: Kubernetes resolution feeds the
kernel-neutral policy compiler, and the agent composes the compiler with the
Linux engine. The compiler and engine do not depend on Cobra or each other's
runtime concerns.

## Common targets

```sh
make build            # bin/ztap
make test             # race-enabled unit tests
make vet              # go vet
make fmt-check        # gofmt check
make lint             # golangci-lint and actionlint
make vulncheck        # pinned Go vulnerability scan
make check            # non-privileged merge gate
make check-generated  # regenerate and compare eBPF bindings
make integration      # privileged Linux engine and agent tests
make performance      # real-cgroup performance and agent evidence (Linux only)
make verify-performance # validate retained Phase 5 JSON evidence
make docker           # scratch runtime image
make clean            # remove local build and tool artifacts
```

The build writes executables below `bin/`; it does not create generated
executables in the repository root. `make check-generated` requires the
configured clang binary (`BPF2GO_CC`, default `clang-18`). It snapshots the
working-tree bindings before and after regeneration, so synchronized source
and generated-binding changes can be checked before they are committed while
stale bindings still fail the gate.

## Test layers

The default Go suite covers the policy compiler, native engine, flow monitor,
CLI, and Kubernetes agent helpers. The Linux eBPF gate runs the instance-owned
engine with the `integration` build tag and requires host bpffs and the
appropriate privileges. The privileged suite includes the policy-deletion
boundary: deleting the last selecting policy must clear both slots, detach all
owned cgroup links, and allow traffic from the formerly selected cgroup again.
CI also builds the scratch image, runs the offline validator through that image
over stdin, and exercises the capability-only DaemonSet in kind.

The fixed-size binary flow-event decoder has a fuzz target that rejects
unknown sizes and schemas before decoding and exercises conversion of valid
72-byte events without unbounded input-derived allocation. Run it locally with
a bounded time budget when changing the event layout:

```sh
GOCACHE="$PWD/.cache/go-build" GOFLAGS=-buildvcs=false \
  go test ./internal/flow -run '^$' -fuzz '^FuzzParseRawEventNeverPanics$' -fuzztime=10s
```

Phase 5 also fuzzes hosted fixture YAML splitting/strict decoding and IPv4
`ipBlock` exclusion expansion. Both targets have bounded inputs and checked-in
regression seeds, so the normal suite runs the seeds without starting an
unbounded fuzz job:

```sh
GOCACHE="$PWD/.cache/go-build" GOFLAGS=-buildvcs=false \
  go test ./tools/phase5verify -run '^$' -fuzz '^FuzzHostedFixtureYAMLNeverPanics$' -fuzztime=10s
GOCACHE="$PWD/.cache/go-build" GOFLAGS=-buildvcs=false \
  go test ./internal/policy -run '^$' -fuzz '^FuzzExpandNativeIPBlockNeverPanics$' -fuzztime=10s
```

The `flows` command reads the agent's pinned flow events and is therefore a
Linux runtime check, not a portable unit-test fixture:

```sh
ztap flows --output json
ztap flows --action blocked --direction egress
```

`ztap flows` reads `/sys/fs/bpf` by default. When it runs inside the shipped
DaemonSet container, use `--bpffs-root=/host/sys/fs/bpf` because the manifest
mounts the host bpffs hierarchy at that path.

On Linux, the flow reader traverses the bpffs root and `ztap` pin directory
through descriptor-relative no-follow handles and loads each stable pin through
the retained handle. Symlink substitutions fail closed; missing pins are
reported by the kernel loader as the actionable runtime error.

Engine startup uses the same descriptor-relative, no-follow traversal for
configured bpffs and cgroup roots before creating the pin directory, cleaning
stale pins, or validating a subject cgroup. This keeps a replaced parent path
from redirecting startup or cleanup into another directory.

## Generated code and review

The only generated Go bindings retained by the product are the engine eBPF
bindings under `internal/enforcer`. Review generated diffs together with the
source change. The Makefile prefers an installed `clang-18`, then resolves the
pinned Homebrew LLVM 18 locations on macOS; CI supplies the explicit
`clang-18` binary. Before submitting a change, run:

```sh
make fmt-check
make test
make check-generated
git diff --check
```

The merge workflow also reruns `go mod tidy` and fails if it changes
`go.mod` or `go.sum`.

The repository also contains a supporting compiler-shape benchmark for the
documented 250-Pod/25-policy/2,500-rule fixture (10 selected Pods and 10 peer
addresses per policy):

```sh
GOCACHE="$PWD/.cache/go-build" GOFLAGS=-buildvcs=false \
  go test -bench '^BenchmarkCompileReferenceFixture$' -benchmem -count=3 ./internal/policy
```

This measures policy compilation only. It cannot satisfy the release gate's
real-cgroup packet-path, resource, fail-open-interval, or flow-loss claims;
those measurements must run on the documented Linux reference environment.

On the documented 2-vCPU Linux reference environment, the release workflow
pins the performance process to CPUs 0 and 1, and the `make performance`
target first removes only its ten named Phase 5 JSON outputs and enforces
`GOMAXPROCS=2`. It then creates 250 real cgroups, applies 2,500 kernel
rules after a warm-up, runs three timed samples, enforces the direct
engine-apply 2-second p95 budget, and writes raw
JSON evidence to the ten `dist/phase5-*.json` artifacts consumed by the
release verifier, including the reference, flow, packet, and native-agent
activation/reconciliation/event/Pod-start/restart/crash/resource results.
Native-agent performance polls evaluate metrics only after an HTTP `200 OK`
response; non-success responses are retried and cannot satisfy a measurement
with a success-shaped body.
The reference, flow, packet, Pod-start, restart, crash, and resource artifacts
each retain the complete 250-subject/25-policy/2,500-rule fixture shape; the
verifier rejects a reduced policy projection even when subject and rule totals
look consistent.
The native-agent activation and SIGKILL fixture constructors also validate that
shape before starting their fake-informer processes: they require one default
Namespace, one node, the complete zero-padded Pod and policy name sets, unique
Pod UIDs, Running Pods with one container status, 25 bucket-matched policies,
and the projected 2,500 subject-to-peer rules. Fixture drift therefore fails
before it can produce success-shaped performance evidence.
The activation predicates also require exact `ztap_enforced_cgroups` and
`ztap_compiled_rules` values for initial and post-policy-event activation,
including exactly 251 enforced cgroups and 2,510 compiled rules after the
Pod-start addition; an at-least threshold cannot hide stale or incomplete
kernel state. The predicate also rejects duplicate samples for any of these
unlabelled gauges rather than accepting the first matching line.
The reference, flow, packet, agent activation/reconciliation/event, and
resource producers write only after their final fixture, accounting, budget,
or resource assertions pass, so a failed measurement cannot leave a stale
success-shaped JSON artifact for a later verification run.
Each Linux harness creates its JSON output through no-follow descriptor
traversal for both parent directories and the final file, with exclusive file
creation after the target is removed by `make performance`; an existing or
redirected output path therefore fails closed instead of overwriting unrelated
content. Missing parents are created one component at a time. The `dist`
evidence root must also be a real directory; the target rejects a symlinked or
non-directory root before cleanup.
The agent harness creates a supplied run directory one component at a time
with the same Linux no-follow directory opener used by the runtime locks.
Its privileged cgroup fixture directories use the same descriptor-relative
creation and cleanup discipline, rejecting symlinked parent or final paths.
The native resolver and engine also require every resolved cgroup target to be
an in-root directory whose inode still matches the selected cgroup ID before
the linker queries or attaches it; regular-file substitutions fail closed.
The linker retains that validated cgroup descriptor for attachment rather than
reopening the path, and the legacy attach fallback retains its own descriptor
and cloned program until cleanup succeeds.
All real-cgroup integration helpers, including the packet and crash
performance helpers, open each `cgroup.procs` control file relative to a
validated cgroup descriptor, so a redirected control-file path cannot receive
the helper PID.
The engine evidence reports calculated bounded-map payload capacity and
kernel-reported memlock where available, retains every warm-up/apply map
snapshot, and fails if map structure or available memlock grows across
repeated applies after warm-up. The cgroup-storage map is recorded explicitly
as an unbounded per-cgroup map with zero configured capacity; bounded maps
must carry a positive capacity, a recognized kernel type, and a unique sorted
name in every snapshot.
Before publication, `make verify-performance PHASE5_EVIDENCE_DIR=dist`
independently checks the ten JSON artifacts for the documented fixture shape,
sample counts, Linux/two-CPU environment metadata, positive elapsed/packet
measurements, fixed documented budgets, and flow-accounting invariants. The
verifier requires exactly the documented two-CPU profile, not merely a host
with at least two CPUs. It can also validate the retained
`phase5-environment.txt` record, including its timestamp, semantic release ref
(which the verifier compares with the current release tag), release
workflow/event, trusted Migration CI run ID, tagged commit, migration
workflow/event/branch provenance, cgroup-v2 and bpffs
markers, positive clock-tick rate, and the complete recorded Go, host CPU, and
kernel metadata when the release job supplies the expected values. Duplicate
or unknown environment keys are rejected. It
also recomputes reported p95/max and packet aggregate values so a manually
edited summary field cannot bypass the release gate.
Hosted resource transcripts must also retain the exact reference-fixture scope,
the transition into the quiet interval, the observed agent Pod/container/cgroup
identity, and three ordered sample records with at least the documented
five-second elapsed intervals, raw CPU-usec and `memory.current` byte counters,
100-ms peak-memory polling, and the derived values; a summary line alone is
insufficient. Resource and rolling transcripts use closed key/value schemas:
malformed lines, unknown keys, and duplicate non-sample keys are rejected. The
verifier rejects CPU counter resets, requires each recorded memory peak to cover
both endpoint readings, recomputes each sample's CPU and memory values from the
raw counters, and recomputes the reported CPU and `memory.current` maxima from
those samples before applying the fixed budgets. The retained cgroup path must
be under the supported systemd containerd hierarchies beneath
`/sys/fs/cgroup/kubepods.slice/` or
`/sys/fs/cgroup/kubelet.slice/kubelet-kubepods.slice/` and canonical; both the
workflow and release verifier require a full 64-hex container ID and require
the measured cgroup basename to match that ID. The workflow passes the
resulting cgroup name as an argument to `docker exec` without a nested shell,
searches only the two supported hierarchy roots, rejects an ambiguous match,
and checks the returned path before sampling it.
Rolling transcripts must bind the old and replacement agent Pods to the
measured `smoke-client` node, record the baseline old Pod only when it is
Running and Kubernetes Ready (`old_ready=true`), enumerate the replacement
there only after it is Running and Kubernetes Ready, retain
`replacement_ready=true`, identify distinct old and replacement Pods and
Kubernetes UIDs, retain the replacement creation timestamp and first
observation time, and bound both to the rollout-to-fail-open interval together
with a positive fail-open interval.
The environment verifier additionally checks that the recorded Go target and
`uname` are Linux-compatible and that `cpu_max` has a valid cgroup quota form.
Its `release_commit` record must be a full 40- or 64-character hexadecimal
commit ID even when verification is run without an externally supplied
expected SHA; release publication additionally compares it with the tagged
commit.
The release job passes `PHASE5_EXPECTED_RUN_ID` from its retained environment
record so the artifact set cannot be substituted with a different same-host
run.
The verifier also cross-checks the environment's Phase 5 run ID, recorded Go
version, OS, architecture, and reference CPU count against the producer
metadata in `phase5-performance.json`, so those records cannot be mixed
independently.
The hosted 250-Pod fixture is parsed as strict, depth-bounded YAML before its
exact document, object-name, bucket, selector, Egress/TCP:10000 policy, and
peer-shape checks; duplicate mapping keys and malformed or excessively nested
documents are rejected even when their line counts match.
Names and namespaces must come from `metadata`, policy buckets from the
structured selector mappings, and peers from `spec.egress[].to[].ipBlock.cidr`;
matching text in an unrelated YAML field is not accepted.
Evidence discovery and the direct JSON, environment, and hosted-evidence
readers reject symlink roots/files and non-regular paths before reading release
evidence. On the Linux release runner, the readers traverse parent components
through no-follow directory descriptors and validate the opened descriptor,
closing parent-path replacement races; the Darwin development fallback keeps
the same final-file protection while allowing normal `/var` paths.
The tag workflow also rejects a symlinked or non-directory `dist` root and
evidence subdirectory before downloading hosted artifacts, and validates the
immutable manifest output path is absent and safe before rendering it.
The GoReleaser re-verification job applies the same guard before downloading
the retained raw evidence bundle.
The recorded `go version` token in both the environment record and every JSON
artifact must contain a dotted numeric Go release; arbitrary tokens such as
`goevil` or `go1evil` cannot satisfy the provenance check.
Evidence is decoded against the checked-in producer schema with unknown fields,
duplicate JSON object keys, multiple JSON values, and excessive nesting
rejected, and every artifact timestamp must be valid RFC3339. This keeps schema
drift and malformed retained files fail-closed.
Map capacity bytes, map shape, adjacent-snapshot memlock stability, and the
final summary's exact memlock readings are also recomputed from the retained
map history rather than accepted from the producer's summary fields. It rejects
unknown, duplicate, or reordered map entries, requires the exact generated
engine map inventory and dimensions, and preserves the explicit unbounded
cgroup-storage representation.
The verifier also requires all ten JSON artifacts to share one run ID, Go
version, Linux architecture, and recorded CPU profile, and requires all
native-agent artifacts to report one kernel release. `make performance` creates
one run ID and passes it to both integration-test processes; CI supplies the
workflow run and commit. This prevents a release from combining measurements
from different hosts or runs. Each artifact validator rejects a missing run ID
before the cross-artifact comparison is reached.
The verifier requires exact producer provenance for each artifact, including
the checked-in kernel-path or traffic scope literal, kernel release for
native-agent runs, and absolute cgroup/bpffs roots for activation evidence;
caller-reworded non-empty scopes are rejected.
The history must contain the ordered pre-warm-up, post-warm-up, and three
post-apply snapshots.
Available kernel-memlock readings must be positive before their adjacent
stability is compared; an unavailable reading must carry zero observed bytes
so stale kernel metadata cannot be reused.
It also compares three real-loopback UDP/TCP samples from one selected subject
with the cgroup eBPF program detached and attached while the full
250-subject/2,500-rule engine state is resident, enforcing the 10-microsecond
UDP p99 delta and 10-percent TCP throughput regression budgets in
`dist/phase5-packet.json`; one complete detached/attached pass warms the
loopback and cgroup paths before those three samples are retained. It then
starts the native agent against the same 250-Pod/25-policy/2,500-rule
shape, measures three initial activation samples, enforces a 3-second p95
budget, and writes `dist/phase5-agent.json`. It separately reads the actual
compile-and-apply reconciliation histogram after cache synchronization for
three samples, enforces the 2-second p95 budget, and writes
`dist/phase5-agent-reconcile.json`. It then updates one policy on the
synchronized fake informer cache three times, measures the next active policy
epoch, enforces the same 3-second p95 budget, and writes
`dist/phase5-agent-event.json`. The flow run applies the full
250-subject/25-policy/2,500-rule real-cgroup policy set, selects one subject, warms its
real UDP path, then emits one alternating allowed or blocked UDP decision per
millisecond and
reconciles delivered events with the explicit rate-limited and ring-full
counters at the 1,000-decisions/second target; delivery is filtered to the
post-warm-up policy epoch so late warm-up records cannot inflate the result.
Within that epoch, delivery is further bound to the selected cgroup's
loopback-to-loopback IPv4 UDP egress tuple and the expected allowed/blocked
action, so unrelated ring records cannot inflate the delivered count; source
or destination mismatches and action mismatches fail the run. The evidence
producer also rejects counter resets and
uint64 addition overflow instead of allowing wrapped deltas into the accounting
result.
The resource run samples a dedicated helper process for three quiet
five-second intervals, retaining the maximum observed RSS from 100-ms
samples in each interval. It enforces the 0.10-core/200-MiB bound for that
fixture, derives CPU usage from the measured process tick delta and elapsed
interval, and writes `dist/phase5-agent-resource.json`; it excludes kernel-map
memory and a real API server, so it is supporting evidence rather than the full
quiet reference-cluster resource gate. These are supporting kernel-path and
reconciliation gates, not substitutes for the full Section 14.5 resource or
rolling-update/failure fail-open measurements. The packet comparison is the
Section 14.5 packet-latency/TCP-throughput gate, but its raw result still
requires hosted Linux execution. The restart run also writes
`dist/phase5-agent-restart.json` for the orderly process-owned shutdown and
replacement interval; it does not stand in for SIGKILL or DaemonSet rollout
evidence. The Pod-start run adds a newly running Pod to the synchronized fake
cache three times, waits for its exact cgroup to enter the next active policy,
and writes `dist/phase5-agent-pod-start.json`; its scope excludes API-server
and container-runtime startup latency and it has no availability claim.
The crash run applies the full 250-Pod/25-policy/2,500-rule native-agent
fixture, then SIGKILLs a child process that owns the engine links and records
the first allowed UDP packet after link detachment in three samples, writing
`dist/phase5-agent-crash.json`; Kubernetes restart scheduling and DaemonSet
rollout are excluded. The parent test process owns cleanup for every fixture
cgroup because the crash helper is intentionally terminated before its own
test cleanup handlers can run; it also supplies the helper's run directory and
removes only the engine's two stable pins after the child exits.
The kind capability-agent job constrains its control-plane node to a 2-vCPU
cgroup quota, validates the generated reference NetworkPolicies through the
shipped scratch image, requires exactly one Running/Ready `ztap-agent` Pod in
the shipped `ztap-system` namespace for its
smoke, resource, and flow probes, captures each retained transcript through an
explicit `set -euo pipefail` pipeline, and asserts that the selected smoke client is
denied, then
separately restarts the shipped DaemonSet,
probes the selected smoke client until it first succeeds and then until two
successive probes are blocked again, and uploads
`rolling-fail-open-evidence.txt` with the smoke-client node, the exact
`ztap-system` agent namespace, old and replacement Pod node, a uniquely
selected Running/Ready baseline old Pod, a Running/Ready replacement
(`old_ready=true` and `replacement_ready=true`), distinct old/replacement Pod
UIDs, and replacement creation and first-observation
timestamps bounded to the rollout interval. The verifier also requires the
first observation to follow replacement creation, so the transcript cannot
invert the Pod lifecycle. This hosted measurement is not reproduced by
the local `make performance` target. It also samples the shipped agent
container's cgroup CPU and `memory.current` counters for three quiet
five-second intervals after creating and classifying the real
250-Pod/25-policy/2,500-rule fixture, polling `memory.current` every 100 ms
and retaining each interval's peak. `memory.current` is a conservative
cgroup-memory upper bound and includes non-RSS charges. It enforces the
0.10-core/200-MiB budgets and uploads
`phase5-reference-fixture.yaml`,
`capability-agent-reference-fixture.txt`, and
`capability-agent-resource.txt`; the result is a fail-closed hosted resource
gate. The release performance evidence bundle also includes
`phase5-environment.txt`; the release gate checks its recorded Linux/amd64,
cgroup-v2, bpffs, `0,1` CPU set, `GOMAXPROCS=2`, positive clock-tick rate, and
two-CPU profile before publication. It also includes the
trusted same-commit eBPF and capability-agent artifacts from `Migration CI`;
the capability smoke also exercises `ztap flows` against the pinned map and
records the smoke client/server IPv4 tuple plus TCP/8080 destination. The
workflow and checked-in Phase 5 verifier require a blocked flow record for
that exact tuple before accepting the flow-streaming result. The smoke also
probes `/healthz`, `/readyz`, and `/metrics` after active enforcement, checks
the ready response's enforcing state, and verifies that POST requests receive
405; it retains `status_endpoints=passed` in the hosted transcript. The
verifier also checks the offline-validator result, exact fixture shape, resource-budget
values, exact `ztap-system` namespace and valid `ztap-agent-` resource and
rolling Pod-name markers, and rolling fail-open timestamps before attaching the complete bundle as
`ztap-<tag>-phase5-evidence.tar.gz`.
It also requires the evidence tree to contain exactly the ten named
`phase5-*.json` artifacts; an extra or duplicate Phase 5 JSON file is rejected
rather than silently omitted from verification, and symlinked or non-regular
evidence-tree entries are rejected. The release preflight and GoReleaser
staging steps also apply case-insensitive uniqueness with canonical basenames,
then repeat the exact-set and entry-type checks before creating the attached
raw evidence archive.
The GoReleaser job independently reruns the same verifier against the
downloaded artifact, rejects duplicate evidence filenames while staging it,
and binds verification to the tagged commit, release run ID, and trusted
Migration CI run ID before building or staging release artifacts. GoReleaser
creates a draft GitHub release; the workflow publishes that draft only after
the multi-architecture image and its aliases resolve to the verified digest
and the immutable install manifest has been attached.
The fixture transcript check also requires the expected kind-specific API
versions, the exact `ztap-performance` Namespace and object namespaces, Pod
and NetworkPolicy name prefixes, and the complete zero-padded Pod and
NetworkPolicy name sets plus per-object bucket markers; matching totals alone
are not sufficient. Policy selector labels are not counted as separate object
markers. Each NetworkPolicy document must also carry the matching selector
bucket, exactly one Egress policy type, TCP port 10000, and exactly ten
`198.18.x.x/32` peer entries, so a balanced aggregate cannot conceal a
malformed policy.

The tag release workflow also verifies the protected `main` branch directly.
Configure the repository secret `BRANCH_PROTECTION_TOKEN` with a fine-grained
PAT or GitHub App token that has repository `Administration: read` permission;
the release job fails closed when the secret is absent or cannot read the
required status-check contexts. Agent shutdown also treats caller cancellation
as a clean lifecycle transition even if the local status listener reports an
error at the same time. The release gate binds its privileged and required
checks to the successful `Migration CI` push run for the exact tagged commit,
not merely to same-SHA check names from another event. That trusted workflow
run ID is passed from the release gate job into the performance job, used to
download the hosted artifacts, and recorded in `phase5-environment.txt` beside
the release performance run ID. The same record includes the semantic release
ref, release workflow/event, tagged commit, and the `Migration CI` workflow,
`push`, and `main` provenance used to resolve that trusted run.

## Adding policy behavior

Start with the native Kubernetes API field and its documented semantics. Add
or update validator tests for both accepted and rejected forms, then add a
kernel-neutral compiler test before changing the eBPF representation. Keep
unsupported behavior as a typed validation error; do not add a permissive
fallback, compatibility flag, or dormant informer. Update `docs/policies.md`
and the relevant deployment or release note when the supported contract
changes.

## Contribution guidance

Keep changes focused on the retained Linux/Kubernetes product. New commands,
configuration layers, platform backends, or auxiliary services require an
explicit product-contract review. Include the exact local commands used for
verification, and identify Linux-only evidence that still needs hosted CI.
