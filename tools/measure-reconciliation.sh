#!/usr/bin/env bash
# Run sequentially on an idle, disposable Linux host with cgroup v2 and bpffs.
set -euo pipefail
output="${1:?usage: tools/measure-reconciliation.sh NEW_OUTPUT_DIRECTORY}"
test "$(go env GOOS)" = linux
test "$(id -u)" = 0
test ! -e "$output" && test ! -L "$output"
mkdir -p "$output"
output="$(cd "$output" && pwd)"
export GOMAXPROCS="${GOMAXPROCS:-2}"
export GOFLAGS="${GOFLAGS:--buildvcs=false}"
{
  go version
  uname -a
  printf 'gomaxprocs=%s\ngo_flags=%s\n' "$GOMAXPROCS" "$GOFLAGS"
  git rev-parse HEAD
  git status --porcelain
  go env GOARCH CGO_ENABLED
} > "$output/environment.txt"
git diff --binary HEAD > "$output/source.patch"
git ls-files --others --exclude-standard -z | tar --null -T - -cf "$output/untracked-source.tar"
go list -deps ./cmd/ztap > "$output/dependencies.txt"
go list -m all > "$output/modules.txt"
build_cache="$(mktemp -d)"
trap 'rm -rf "$build_cache"' EXIT
for sample in 1 2 3; do
  /usr/bin/time -f 'cold_build_seconds=%e max_rss_kib=%M' \
    env GOCACHE="$build_cache/$sample" CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' \
    -o "$output/ztap" ./cmd/ztap 2> "$output/build-$sample.txt"
done
wc -c < "$output/ztap" > "$output/binary-bytes.txt"
go test -c -tags=integration -o "$output/cli.test" ./internal/cli
"$output/cli.test" -test.run '^$' -test.bench '^BenchmarkNativeSnapshotReconciliation$' \
  -test.benchmem -test.count=5 -test.benchtime=1s > "$output/snapshot-bench.txt"
ZTAP_PHASE5_RUN_ID="$(basename "$output")"
export ZTAP_PHASE5_PERFORMANCE=1 ZTAP_PHASE5_RUN_ID
export ZTAP_PHASE5_AGENT_RECONCILE_OUTPUT="$output/phase5-agent-reconcile.json"
export ZTAP_PHASE5_AGENT_EVENT_OUTPUT="$output/phase5-agent-event.json"
export ZTAP_PHASE5_AGENT_RESOURCE_OUTPUT="$output/phase5-agent-resource.json"
"$output/cli.test" -test.run '^TestPhase5Agent(Reconciliation|EventActivation|ResourceUsage)$' \
  -test.v -test.timeout=5m > "$output/performance.log" 2>&1
if [ -n "${ZTAP_MEASUREMENT_IMAGE:-}" ]; then
  docker image inspect "$ZTAP_MEASUREMENT_IMAGE" > "$output/image.json"
fi
