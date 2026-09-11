#!/bin/sh

set -eu

fixture_version="v0.1.0"
namespace="ztap-phase0-fixture"
pod_count=250
policy_count=25
rules_per_policy=100
output=""
force=0

usage() {
  printf '%s\n' "usage: $0 --output DIRECTORY [--force]" >&2
  exit 2
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --output)
      [ "$#" -ge 2 ] || usage
      output=$2
      shift 2
      ;;
    --force)
      force=1
      shift
      ;;
    -h|--help)
      usage
      ;;
    *)
      usage
      ;;
  esac
done

[ -n "$output" ] || usage

mkdir -p "$output"
if [ "$force" -eq 0 ] && [ -n "$(find "$output" -mindepth 1 -maxdepth 1 -print -quit)" ]; then
  printf 'refusing to overwrite non-empty fixture directory: %s\n' "$output" >&2
  exit 1
fi

workloads="$output/workloads.yaml"
policies="$output/policies.yaml"
metadata="$output/metadata.env"
checksums="$output/manifest.sha256"

if [ "$force" -eq 1 ]; then
  rm -f -- "$workloads" "$policies" "$metadata" "$checksums"
fi

{
  printf '%s\n' 'apiVersion: v1'
  printf '%s\n' 'kind: Namespace'
  printf '%s\n' 'metadata:'
  printf '  name: %s\n' "$namespace"

  pod=0
  while [ "$pod" -lt "$pod_count" ]; do
    pod_name=$(printf 'fixture-worker-%03d' "$pod")
    policy_name=$(printf 'fixture-policy-%02d' "$((pod / 10))")
    printf '%s\n' '---'
    printf '%s\n' 'apiVersion: v1'
    printf '%s\n' 'kind: Pod'
    printf '%s\n' 'metadata:'
    printf '  name: %s\n' "$pod_name"
    printf '  namespace: %s\n' "$namespace"
    printf '%s\n' '  labels:'
    printf '%s\n' '    app: phase0-fixture'
    printf '    fixture-policy: %s\n' "$policy_name"
    printf '%s\n' 'spec:'
    printf '%s\n' '  automountServiceAccountToken: false'
    printf '%s\n' '  containers:'
    printf '%s\n' '    - name: worker'
    printf '%s\n' '      image: busybox:1.36.1'
    printf '%s\n' '      imagePullPolicy: IfNotPresent'
    printf '%s\n' '      command: ["/bin/sh", "-c", "exec sleep 3600"]'
    pod=$((pod + 1))
  done
} > "$workloads"

{
  policy=0
  while [ "$policy" -lt "$policy_count" ]; do
    policy_name=$(printf 'fixture-policy-%02d' "$policy")
    printf '%s\n' 'apiVersion: networking.k8s.io/v1'
    printf '%s\n' 'kind: NetworkPolicy'
    printf '%s\n' 'metadata:'
    printf '  name: %s\n' "$policy_name"
    printf '  namespace: %s\n' "$namespace"
    printf '%s\n' 'spec:'
    printf '%s\n' '  podSelector:'
    printf '    matchLabels:\n      fixture-policy: %s\n' "$policy_name"
    printf '%s\n' '  policyTypes:'
    printf '%s\n' '    - Egress'
    printf '%s\n' '  egress:'

    rule=0
    while [ "$rule" -lt "$rules_per_policy" ]; do
      destination_octet=$((rule + 1))
      destination_suffix=$((policy + 1))
      destination_port=$((10000 + rule))
      printf '%s\n' '    - to:'
      printf '%s\n' '        - ipBlock:'
      printf '            cidr: 198.18.%d.%d/32\n' "$destination_octet" "$destination_suffix"
      printf '%s\n' '      ports:'
      printf '%s\n' '        - protocol: TCP'
      printf '          port: %d\n' "$destination_port"
      rule=$((rule + 1))
    done
    if [ "$policy" -lt "$((policy_count - 1))" ]; then
      printf '%s\n' '---'
    fi
    policy=$((policy + 1))
  done
} > "$policies"

{
  printf 'fixture_version=%s\n' "$fixture_version"
  printf 'namespace=%s\n' "$namespace"
  printf 'pod_count=%d\n' "$pod_count"
  printf 'policy_count=%d\n' "$policy_count"
  printf 'rules_per_policy=%d\n' "$rules_per_policy"
  printf 'expected_compiled_local_rule_count=%d\n' "$((policy_count * rules_per_policy))"
  printf 'generator=scripts/phase0_reference_fixture.sh\n'
} > "$metadata"

if command -v sha256sum >/dev/null 2>&1; then
  (cd "$output" && sha256sum workloads.yaml policies.yaml) > "$checksums"
else
  (cd "$output" && shasum -a 256 workloads.yaml policies.yaml) > "$checksums"
fi

printf 'generated Phase 0 %s fixture: %s\n' "$fixture_version" "$output"
cat "$metadata"
