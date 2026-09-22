# Changelog

## [0.1.0] - Unreleased

This release records the intentional product cutover to a focused Linux
Kubernetes eBPF enforcer.

### Breaking changes

- The primary command surface is now `agent`, `validate`, `flows`, and
  `version`. The removed commands and auxiliary services are not compatibility
  aliases.
- Runtime file configuration and environment-based configuration keys were
  removed. Use the explicit flags documented in `docs/deployment.md`.
- The module path is now `github.com/saadshabir/ZTAP`.
- The supported runtime is Linux with cgroup v2 and eBPF. Platform-specific
  enforcement backends and the former control-plane/deployment assets are not
  part of this release.
- Native Kubernetes `NetworkPolicy` is the policy input. The offline
  validator is the supported preflight path.

### Added

- GoReleaser now creates a draft GitHub release; the workflow publishes it only
  after the multi-architecture image is pushed and verified and the immutable
  install manifest is attached, so a late container failure cannot leave a
  public binary-only release.
- Engine map pinning now holds the validated bpffs directory descriptor through
  the final pin syscalls and descriptor-relative shutdown cleanup, preventing a
  replacement directory from redirecting pin creation or removal.
- Legacy cgroup attachment now recognizes the kernel errors used for an
  unsupported multi-attach flag and reaches the single-program fallback instead
  of returning before the fallback attempt.
- Monthly Dependabot schedules now rely on the documented first-of-month
  behavior instead of supplying the weekly-only `day` option.
- Maintained policy and deployment documentation now distinguishes cluster-wide
  selector peers from node-local subjects, describes the supported CNI profile
  as one without another NetworkPolicy enforcer, and keeps exact tested kernel
  versions as an explicit hosted release blocker until evidence exists.
- A scratch-based Linux runtime image.
- A single capability-only Kubernetes DaemonSet manifest.
- Manifest validation now requires explicit false values for host network, PID,
  and IPC namespace sharing and requires the host cgroup hierarchy to be
  mounted read-only; privileged
  runtime behavior remains a hosted Phase 5 gate, and the kind smoke job now
  verifies the same rendered Pod namespace, mount, and exact capability
  contract with fail-fast shell handling.
- Hosted eBPF and release performance transcript steps now use fail-fast
  shell options, so a failed piped test cannot be masked by a later marker
  write or successful transcript command.
- The hosted flow-reader smoke now parses its output as JSON and requires a
  blocked-egress record instead of accepting an unstructured text match.
- The Phase 5 release verifier independently parses the archived live-flow
  transcript and requires a complete schema-versioned blocked-egress record,
  so the success marker cannot stand in for flow evidence.
- Phase 5 JSON evidence validation now rejects omitted top-level or nested
  schema fields and JSON `null` values before Go zero-value decoding can make
  them appear valid.
- Archived Phase 5 live-flow JSON validation now applies the same required-field
  and non-null contract, including numeric fields whose typed zero is valid for
  ICMP records.
- The shared Linux no-follow directory opener now rejects relative paths before
  traversing from the filesystem root; lock, bpffs, and evidence-writer callers
  remain absolute-path-only.
- Phase 5 activation evidence now requires the documented `/sys/fs/cgroup` and
  `/sys/fs/bpf` roots instead of accepting arbitrary absolute paths.
- Native policy compilation now has regression coverage for full-snapshot policy
  deletion: one additive contribution is removed without losing the other, and
  deleting all policies leaves no stale subjects or rules.
- Flow monitoring now fails closed before startup when its reader reports
  unavailable; the pinned Linux reader also treats nil or closed state as
  unavailable.
- The Linux ring-buffer reader now treats nil or zero-value flow-map state as
  unavailable and rejects direct startup before opening a ring buffer.
- Native-agent startup now rejects an empty or nil informer cache-sync set
  before calling client-go, preventing an accidental empty cache from being
  treated as synchronized (and avoiding a nil callback panic).
- Archived flow evidence now rejects whitespace-only decision reasons instead
  of treating them as usable decision provenance.
- Hosted live-flow evidence now records the smoke client/server IPv4 tuple and
  TCP/8080 destination, and both the workflow and release verifier require a
  blocked record for that exact tuple instead of accepting incidental traffic.
- Hosted live-flow evidence now requires the exact `default_deny` decision reason
  in addition to the smoke client/server IPv4 TCP tuple, so quarantine or
  malformed records cannot satisfy the flow gate.
- The hosted live-flow smoke now validates the required schema metadata and
  numeric field shapes before retaining `flow_streaming=passed`, so Migration CI
  rejects malformed records at the runtime evidence boundary.
- Hosted live-flow validation now rejects a zero TCP source port, preventing a
  malformed transport identity from satisfying the blocked-flow gate.
- Rolling-update evidence now rejects a replacement Pod observation timestamp
  that precedes the recorded Pod creation timestamp.
- The hosted resource producer now searches only the supported containerd
  hierarchy roots and rejects an ambiguous container-ID match before sampling.
- The hosted resource producer now requires one exact active reference-fixture
  metric snapshot, including `ztap_agent_enforcing=1` and a non-zero policy
  epoch, before retaining the 250-cgroup/2,500-rule resource evidence.
- The hosted reference-fixture gate now validates the live applied Pod and
  NetworkPolicy object shape, including names, readiness, UID uniqueness,
  buckets, selectors, peers, and TCP/10000 ports, before retaining its marker.
- The hosted smoke classification probe now rejects duplicate or labeled gauge
  samples and requires exact one-cgroup active enforcement with a non-zero
  policy epoch before exercising packet behavior.
- The hosted packet smoke now requires exactly one positive blocked-default-deny
  counter sample, retains its value in the transcript, and rejects duplicate or
  malformed counter evidence before release publication.
- The hosted status smoke now verifies the `Allow: GET` header as well as the
  `405 Method Not Allowed` response for non-GET requests.
- Linux agent lifecycle coverage now queries the live dry-run status listener,
  confirming `/readyz` remains 503 with `dry_run` and `ztap_agent_enforcing`
  remains zero before shutdown.
- Native-agent Phase 5 metric predicates now reject NaN and infinite samples,
  including non-finite active policy epochs that could otherwise satisfy a
  lower-bound readiness check.
- Phase 5 metric predicates now reject labelled or duplicate samples from the
  same metric family instead of ignoring an extra series beside the canonical
  unlabelled sample; the hosted smoke parser applies the same rule.
- Linux Phase 5 helper status readers now close timed-out pipe readers so their
  blocked read goroutines can finish, and native-agent metric polling closes a
  response returned alongside a request error before retrying.
- The Linux flow reader now closes its ring reader when the caller context is
  canceled during a blocking read, so direct streaming shutdown does not wait
  for another event; a blocking-reader regression covers the wake-up path.
- The shared flow monitor now owns and cancels a derived reader context during
  `Stop`, including the reader-start handoff window, so shutdown cannot wait
  forever when a reader's own stop method has not taken effect yet.
- The `ztap flows` startup path now closes the pre-start subscription and
  already-opened pinned reader when monitor startup fails, preserving cleanup
  errors alongside the startup failure.
- The Linux flow reader now rechecks cancellation after waiting for its state
  lock, so a canceled startup cannot open a ring reader during the lock handoff.
- The pinned flow-reader wrapper now rechecks cancellation after waiting for
  its ownership lock, preventing canceled commands from starting reader or
  status-polling goroutines.
- Native-agent startup now rechecks cancellation after acquiring the node lock,
  preventing canceled commands from starting HTTP or informer state.
- The pinned `ztap flows` reader now rejects an already-canceled command
  context before entering map ownership or status polling.
- Pinned flow-reader shutdown now preserves terminal status, reader, and stop
  errors when those goroutines finish in either order, while suppressing only
  cancellation caused by coordinated shutdown.
- Pinned-agent status polling now gives caller cancellation precedence before
  its first or next map lookup, avoiding misleading status-map errors during
  flow-command shutdown.
- The public `flows` command now rejects an already-canceled context before
  acquiring its host lock or opening pinned maps, so canceled commands leave no
  lock-directory side effects.
- Native-agent startup now treats an already-canceled context as a clean exit
  before acquiring its lock or starting HTTP/informer state, while still
  releasing a caller-supplied listener.
- Native-agent reconciliation now suppresses success telemetry and readiness
  publication when cancellation wins while a snapshot is completing.
- Native-agent cache synchronization now rechecks caller cancellation after
  informer callbacks report success, preventing startup from creating engine
  and HTTP state during a shutdown race.
- Flow monitor startup now rejects an already-canceled context before entering
  the reader lifecycle, and its startup handoff avoids invoking a reader after
  cancellation wins ownership.
- The hosted rolling-update probe now requires the unselected control client to
  reach the smoke server before rollout and throughout sampling, preventing
  server or dataplane outages from being recorded as policy fail-open time.
- Release publication preflight now matches smoke, fixture, resource, and
  rolling success markers as exact lines, matching the standalone verifier.
- Release publication preflight now rejects duplicate or conflicting keyed
  hosted success markers instead of accepting a valid line alongside a failed
  or repeated result.
- Variable-valued hosted release markers now require exactly one matching,
  well-formed line, so malformed or duplicated Pod, timestamp, sample, and
  interval records fail before publication.
- The generated-code Makefile gate resolves the pinned Homebrew LLVM 18
  compiler on macOS while retaining the explicit `clang-18` CI toolchain.
- The pinned `govulncheck@v1.1.4` tool is now installed under `bin/tools` by
  `make vulncheck`; CI invokes the same local target as the merge gate.
- The live flow reader now opens bpffs directories and stable pins through
  descriptor-relative no-follow handles before loading the eBPF maps, closing
  the path-swap window left by a preflight-only symlink check.
- Flow-monitor subscriptions using a valid non-cancellable context no longer
  leak a cancellation watcher goroutine; monitor shutdown still closes them.
- `make check-generated` now compares the working-tree generated-binding
  snapshot before and after regeneration, so synchronized uncommitted Phase 5
  source/binding changes are accepted while stale bindings still fail closed.
- Phase 5 verification and GoReleaser evidence staging now reject extra direct
  or nested `phase5-*.json` artifacts and require the exact ten-file evidence
  set before release publication; symlinked and non-regular evidence-tree
  entries are rejected as well.
- Linux cgroup identity validation now rejects non-directory targets before
  cgroup attachment or resolver cache publication, with regression coverage for
  target type, root containment, and inode identity checks.
- Linux cgroup attachment now queries and attaches through the descriptor that
  passed root-containment and inode validation, including descriptor-retaining
  cleanup for the legacy attach fallback instead of reopening the path.
- The privileged engine suite now covers deletion of the last selecting policy:
  both policy slots are empty, owned cgroup links are detached without orphans,
  and traffic from the formerly selected cgroup is allowed again.
- Linux real-cgroup integration helpers now place child processes through
  `cgroup.procs` opened relative to a validated no-follow cgroup descriptor,
  covering packet and ordinary integration measurements as well as crash
  cleanup paths.
- Linux amd64 and arm64 integration-tag test binaries for the enforcer and CLI
  compile from the Phase 5 source tree; the ordinary policy, enforcer, flow,
  and evidence-verifier suites remain green while privileged execution stays
  a hosted gate.
- Build metadata in `ztap version` and standard-library `slog` logging.
- A standard-library Phase 5 evidence verifier with strict schemas, fixed
  budgets, independently recomputed map-capacity bytes, explicit
  unbounded cgroup-storage handling, map-type/order checks, and producer
  provenance checks, including duplicate-field rejection, per-artifact run
  identity, and exact cross-artifact run and environment consistency bound to
  the release record.
- Hosted kind resource evidence now retains raw cgroup CPU and
  `memory.current` counters; the release verifier recomputes each sample and
  rejects counter resets before applying the fixed budgets.
- Hosted resource and rolling-update transcripts now use closed structured
  key/value schemas, retain exact reference-fixture and agent cgroup
  provenance, and reject malformed, unknown, or duplicate records before
  release verification.
- Real-cgroup reference, flow, packet, agent-latency, and resource harnesses
  now write raw JSON only after their final assertions pass, preventing a
  failed measurement from leaving a stale success-shaped artifact behind.
- The privileged `make integration` target now covers both Linux enforcer and
  CLI package trees, including Phase 5 agent, flow-reader, cgroup-path, and
  evidence-writer integration coverage.
- Hosted privileged eBPF CI now executes the complete integration-tagged
  enforcer and CLI package trees instead of filtering runtime coverage to the
  engine test-name prefix.
- The Linux integration contract now runs tagged `go vet` over the enforcer
  and CLI package trees before the Phase 5 integration tests.
- Native-agent activation and SIGKILL Phase 5 fixture constructors now validate
  the complete 250-Pod/25-policy/2,500-rule object shape, exact names, unique
  UIDs, Running status, and bucket-matched Egress policies before starting
  measurements, preventing producer-side fixture drift from emitting
  success-shaped evidence.
- Phase 5 native-agent activation predicates now require exact enforced-cgroup
  and compiled-rule gauges for initial and post-policy-event activation,
  including the 251-cgroup/2,510-rule Pod-start state, so stale or incomplete
  kernel state cannot satisfy a fixed-shape measurement; duplicate unlabelled
  gauge samples are rejected instead of being accepted by first-match parsing.
- The hosted resource probe and release verifier validate full 64-hex
  container IDs before locating cgroups, bind the cgroup basename to that ID,
  require canonical in-root paths, and no longer evaluate runtime metadata
  through a nested shell command.
- The hosted-evidence regression now exercises that container-ID/cgroup-path
  binding through the complete bundle verifier, rejecting a mismatched but
  otherwise valid 64-hex identity at the release boundary.
- Hosted resource identity validation now rejects container scopes under an
  unrelated cgroup hierarchy and accepts only the two documented containerd
  systemd layouts used by the runtime resolver.
- Flow-loss evidence now applies the full 250-subject/25-policy/2,500-rule
  real-cgroup fixture and records its complete shape before accounting
  delivered, rate-limited, and ring-full decisions; every counter identity is
  checked for monotonicity before deltas are summed. The identity-keyed
  counter-delta helpers and reset/shape/overflow regressions also run in the
  ordinary package unit suite, and the recorded duration is bounded to the
  documented 60-second run plus a fixed five-second scheduling tolerance.
- Sustained flow delivery is now filtered to the measured epoch, selected
  cgroup, loopback-to-loopback IPv4 UDP egress tuple, and expected
  allowed/blocked action; source and destination mismatches plus action
  mismatches fail closed and the ordinary suite covers the event contract.
- Native-agent Phase 5 metric polling now requires `200 OK` before evaluating
  a response body; non-success responses are closed and retried instead of
  allowing a failure body to satisfy a performance predicate.
- Reference-apply, packet, and Pod-start evidence now records the complete
  250-subject/25-policy/2,500-rule shape, and the verifier rejects reduced
  policy projections.
- Crash fail-open evidence now applies the full native-agent reference fixture
  and records its shape before measuring the post-SIGKILL packet gap; the
  parent harness also owns the child run directory, stable engine pins, and
  cgroup cleanup after the samples.
- Rolling-update evidence now records and verifies the smoke-client node plus
  the old and replacement Pod node, distinct old/replacement Pod UIDs, the
  replacement creation timestamp, and its first observation after rollout
  start, all bounded by the measured fail-open interval rather than trusting
  list order alone.
- Rolling-update evidence now selects a same-node replacement only after it is
  Running and Ready, and retains and verifies an explicit readiness marker.
- The rolling-update producer now enforces that readiness at the Kubernetes
  candidate-selection step and retains the observed condition value, rather
  than unconditionally writing a successful readiness marker.
- The rolling-update producer now selects exactly one Running and Ready old
  agent on the smoke-client node before restart and retains `old_ready=true`;
  the release verifier requires that baseline marker.
- The tag release preflight now checks both rolling readiness markers before
  uploading hosted evidence, matching the publication-time verifier.
- Capability smoke, resource, and flow steps now require exactly one Running
  and Ready agent Pod instead of selecting a DaemonSet Pod by list order.
- Release provenance now explicitly selects the newest successful same-commit
  Migration CI push run when resolving trusted hosted evidence.
- Release evidence staging now rejects duplicate hosted filenames before raw
  evidence upload, not only during the later GoReleaser re-verification.
- Rolling evidence no longer selects the first matching replacement Pod during
  overlap; it waits for exactly one same-node Running/Ready candidate.
- The image publication gate now parses the raw multi-architecture registry
  index, requires exactly two runnable descriptors consisting of one Linux
  amd64 and one Linux arm64 manifest,
  verifies that both explicit release aliases resolve to the pushed digest, and
  requires an attestation descriptor from the enabled SBOM/provenance build.
- Phase 5 JSON verification now requires each of the ten retained artifacts to
  carry the exact kernel-path or measurement scope literal emitted by its
  checked-in producer harness; regressions reject non-empty caller-reworded
  scopes that could detach a budget from the real measurement path.
- Hosted Phase 5 evidence discovery and release-time staging now reject
  case-variant copies of required evidence filenames instead of silently
  ignoring a contradictory duplicate beside the canonical file.
- Release preflight and downloaded raw-evidence checks now apply the same
  case-insensitive uniqueness and canonical-basename guard before upload or
  archive staging.
- Release preflight now requires the exact `ztap-system` namespace and
  `ztap-agent-` Pod-name markers in hosted resource and rolling transcripts.
- Standalone hosted verification now rejects prefixed but malformed or
  overlong agent Pod names, matching the release preflight's identity shape.
- Capability-agent evidence steps now propagate both measurement and `tee`
  writer failures through explicit `pipefail` pipelines.
- Hosted resource and rolling transcripts now require recorded Pod identities
  to use the shipped `ztap-agent-` DaemonSet name prefix.
- Hosted resource and rolling transcripts now retain and verify the shipped
  `ztap-system` agent namespace alongside the Pod name prefix.
- Environment and JSON evidence provenance now requires a dotted numeric Go
  release token in the recorded Linux `go version` output.
- Native-agent shutdown now suppresses a simultaneous status-listener error
  when the caller has already canceled the agent context.
- A fuzz target for the fixed-size binary flow-event decoder, covering malformed
  sizes and schemas plus valid-event conversion without unbounded allocation.
- Strict, depth-bounded YAML parsing for hosted Phase 5 fixture documents,
  including duplicate and non-string mapping-key rejection, anchor/alias and
  merge-key rejection, plus structured metadata/spec path validation for the
  exact Egress/TCP:10000 fixture semantics before shape validation; the
  verifier also requires the exact Namespace, Pod workload, and
  NetworkPolicy field sets so changed images, commands, runtime fields, or
  policy shape cannot pass through aggregate fixture counts. Seed-only fuzz
  coverage also exercises YAML splitting/strict decoding and IPv4 `ipBlock`
  exclusion expansion invariants.
- Hosted evidence discovery now rejects symlink roots, symlink entries, and
  non-regular matched paths before reading release evidence.
- Direct JSON, environment, and hosted-evidence readers now reject symlink
  files and non-regular paths before reading evidence.
- Hosted-evidence reads are now bounded at the 4 MiB verifier limit before the
  artifact can be fully loaded.
- Release branch-protection verification now checks both GitHub required-status
  representations and requires exactly the `Required CI` context in each.
- Strict JSON evidence scanning now rejects case-variant fields and excessively
  nested artifacts before recursive duplicate-key validation can consume
  unbounded stack depth.
- Hosted resource evidence now requires its non-empty scope provenance in
  addition to raw counter and budget validation.
- The Phase 5 verifier now binds the final reference map-memory summary's
  memlock readings exactly to the retained final snapshot.
- Phase 5 environment verification now rejects a zero trusted Migration CI
  run ID and host CPU metadata smaller than the pinned two-CPU reference
  profile.
- Phase 5 live flow JSON output now uses standard-library serialization with
  escaping regression coverage.
- Phase 5 live flow readers now reject symlinked bpffs roots, pin directories,
  and stable map entries before opening pinned maps.
- Phase 5 Linux CLI tests now verify native-agent and flow-reader locks release
  after the owning process is killed while retaining the child lock owner for
  the full crash simulation.
- Phase 5 Linux node locks now reject symlinked run directories and lock files,
  create missing directory components without following indirection, and open
  only regular lock files with no-follow semantics.
- Phase 5 packet enforcement now denies unsupported IPv4 protocols before
  considering Node/self bypasses, with a privileged ICMP regression test.
- Phase 5 privileged packet coverage now injects raw IPv4 fragments and
  malformed-version packets and verifies their bounded deny reasons.
- Flow-monitor context cancellation now closes subscribers and leaves the
  reader restartable, with a regression covering cancellation followed by a
  fresh start.
- Flow-monitor subscriptions now reject nil contexts with an already-closed
  channel, preventing uncancellable subscribers and cancellation-goroutine
  panics.
- Linux Phase 5 agent performance helpers now pass an already-bound status
  listener into the agent, including across the resource and crash helper
  subprocesses, so evidence samples do not depend on a close-and-reopen port
  race; ownership is also released when agent startup fails before HTTP setup.
- Engine startup and shutdown pin cleanup now rejects owned-name directories
  and unlinks symlinks without following their targets.
- Release tag validation now rejects non-canonical leading-zero version
  components before publication evidence is accepted.
- Privileged packet coverage now verifies that an ingress ICMP packet cannot
  use Node or self bypasses to evade an isolated direction.
- Environment evidence verification now rejects abbreviated or non-hexadecimal
  release commit values even when standalone verification has no expected SHA.
- Linux node-lock acquisition now walks parent directories by descriptor and
  uses no-follow `openat` semantics to close parent-component redirection races.
- Engine metrics now reject per-CPU counter-total overflow instead of exposing
  a wrapped lower value.
- Engine startup now creates the bpffs pin directory with descriptor-relative
  no-follow semantics instead of path-recursive directory creation.
- Engine startup and cgroup validation now traverse canonical root paths with
  descriptor-relative no-follow handles, rejecting symlinked parent components
  before pin creation, stale-pin cleanup, or subject validation.
- Migration CI now runs both the pinned default and `--pedantic` zizmor
  workflow-security audits.
- Phase 5 evidence verification and release staging now reject case-variant
  `phase5-*.json` filenames instead of silently ignoring them beside the exact
  artifact set.
- Engine pin cleanup now uses descriptor-relative `unlinkat` semantics so a
  replaced parent or intermediate parent-component symlink cannot redirect
  removal to another directory.
- Phase 5 environment evidence is now bounded to 1 MiB before key/value
  parsing, matching the verifier's bounded JSON and hosted-evidence inputs.
- Startup stale-pin cleanup now holds one validated bpffs directory descriptor
  while removing both owned pins, closing the replacement-directory window
  between validation and per-pin cleanup.
- Hosted resource evidence now rejects CPU-usec counter resets between adjacent
  samples, preventing recreated cgroups from fabricating a low-CPU interval.
- Hosted resource evidence now requires exactly 250 enforced cgroups for the
  fixed 250-Pod reference fixture instead of accepting an over-count.
- Hosted resource evidence now polls `memory.current` every 100 ms during each
  five-second sample, retains the observed peak counter, and recomputes the
  memory budget from that peak instead of only the interval endpoints.
- The hosted capability smoke now probes health, readiness, metrics, and the
  GET-only method contract after active enforcement, retaining a required
  `status_endpoints=passed` marker.
- The native-agent resource sampler now rejects wrapped `/proc` CPU-tick and
  RSS-byte totals before writing supporting Phase 5 evidence.
- The native-agent resource sampler now polls RSS during each quiet interval
  and retains the maximum observed value, so a middle-interval peak cannot be
  hidden by endpoint-only sampling; hosted cgroup resource evidence remains
  the authoritative acceptance gate.
- The real-cgroup map-memory sampler now rejects wrapped capacity-byte totals
  before writing Phase 5 evidence.
- Release verification now binds native-agent resource CPU timing to the
  retained environment clock-tick rate.
- The standard-library release verifier now opens evidence files with Unix
  no-follow semantics and checks the opened descriptor, closing the final-file
  replacement window between path validation and reading.
- Linux release evidence reads now traverse parent directories through
  no-follow descriptors, closing parent-path redirection races; Linux
  symlinked-parent and cross-platform FIFO regressions cover the hardened
  opener while the Darwin fallback preserves normal `/var` paths.
- Linux Phase 5 harnesses now create each JSON artifact exclusively with
  no-follow semantics, failing closed on stale or redirected output paths.
- Their parent-directory traversal is also descriptor-relative and no-follow;
  missing output directories are created one component at a time, so a
  symlinked parent cannot redirect evidence outside the checkout.
- `make performance` now rejects a symlinked or non-directory `dist` evidence
  root before cleanup, preventing the release evidence directory from being
  redirected outside the checkout.
- The tag workflow now applies the same `dist` and evidence-subdirectory
  guards before hosted downloads and rejects a pre-existing or redirected
  immutable manifest output before rendering.
- GoReleaser raw-evidence download now rejects a redirected `dist` or bundle
  directory before extracting the retained performance artifact.
- The Linux agent performance harness now creates a supplied run directory
  component by component without following symlinks, matching runtime lock
  directory hardening.
- Its privileged cgroup fixture lifecycle now validates, creates, and removes
  directories relative to no-follow parent descriptors, rejecting redirected
  parent and final paths during hosted measurements.
- Crash-harness process placement now opens `cgroup.procs` relative to the
  validated cgroup directory with no-follow semantics.
- Native-agent status endpoints now reject non-GET methods with `405` and
  `Allow: GET`; status-server shutdown publishes readiness reason `stopping`
  before closing the listener.
- Standalone hosted-evidence verification now rejects unmatched non-regular
  entries as well as required-file symlinks, matching the release archive
  preflight guard.
- The release performance job now rejects pre-existing, symlinked, or special
  root-level environment and raw-log output paths before `tee` writes them.
- The release performance environment transcript now enables explicit
  `set -euo pipefail` and no longer masks required clock-tick or cgroup-quota
  read failures, so incomplete host metadata cannot be retained behind the
  final `tee`.
- Hosted `Migration CI` eBPF and capability-agent jobs now reject pre-existing,
  symlinked, or special evidence output paths before `tee`, append, copy, or
  diagnostic writes, including the later smoke-log append.
- The tag workflow now rejects a pre-existing, symlinked, or special
  `release-notes.md` path before GoReleaser note extraction or fallback output.
- Privileged engine integration coverage now verifies that deleting one rule
  contribution preserves the remaining selected rule while default-denying the
  deleted destination after the next policy epoch.

### Release process

- Pull requests and trusted branch pushes use one Linux-focused `Migration CI`
  workflow with a stable `Required CI` result, generated-code validation,
  image scanning, and hosted eBPF/kind evidence.
- Semantic-version tags publish only Linux amd64/arm64 artifacts and one
  multi-architecture image after the final checks and the real-cgroup
  engine-apply, flow-accounting, initial-agent-activation, native-agent
  reconciliation, synchronized policy-event, Pod-start, crash, packet/TCP,
  orderly restart-gap, and 250-Pod reference-fixture agent resource
  measurements are retained. The
  release attaches the raw performance bundle plus the trusted same-commit
  eBPF and capability-agent evidence; the attached install manifest pins the
  image by digest, and the published image uses versioned aliases rather than
  a mutable `:latest` tag. The release gate also verifies that the pushed
  multi-architecture manifest digest matches the digest in that install
  manifest. The release also checks content markers in the trusted hosted
  eBPF, capability-agent, resource, fixture, and rolling-update evidence before
  attaching the raw bundle. Rolling-update and crash fail-open measurements
  remain explicit acceptance gates, while hosted resource evidence is required.
  The release gate also checks that `main` branch
  protection is strict and requires the exact `Required CI` context and that the final
  checks came from the successful `Migration CI` push run for the tagged
  commit. The trusted Migration CI run ID is propagated to the performance
  gate and retained in the raw environment evidence used for publication.
- The release gate requires the retained performance log to contain exact pass
  markers exactly once for all ten Phase 5 harnesses before attaching raw
  evidence; raw evidence staging also rejects symlink/non-regular entries, and
  the GoReleaser recheck applies the same exact-name and exact-count rule.
- The retained performance environment records the semantic release ref, and
  both verification passes compare it with the current tag while validating
  the `release.yml`/`push` provenance alongside the tagged commit and trusted
  Migration CI run.
- The release performance and image-publication jobs disable mutable Go and
  BuildKit dependency caching; the pinned zizmor audit therefore cannot flag a
  cache-poisoning path into publication artifacts. The CI image job uses fixed
  checked-in inputs rather than interpolated matrix values, and workflow
  permissions document their release or review purpose. GoReleaser now
  downloads and verifies the checked-in module graph before its evidence
  re-verification, and the performance job rejects symlink or non-regular
  evidence entries before uploading the retained bundle. The rendered install
  manifest requires one valid 64-hex SHA-256 image digest and no mutable
  `:latest` reference.

[0.1.0]: https://github.com/saadshabir/ZTAP/releases/tag/v0.1.0
