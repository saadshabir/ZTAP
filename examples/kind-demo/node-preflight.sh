#!/usr/bin/env bash
# Run the active kernel probe with the exact agent container security context.
set -euo pipefail
cd "$(dirname "$0")/../.."

pod=ztap-node-preflight
kubectl create --dry-run=client -f "${1:-deployments/kubernetes/ztap-agent.yaml}" -o json |
  jq '
    (if .kind == "List" then .items[] else . end)
    | select(.kind == "DaemonSet" and .metadata.name == "ztap-agent")
    | {apiVersion: "v1", kind: "Pod", metadata: {name: "ztap-node-preflight", namespace: "default"},
       spec: .spec.template.spec}
    | .spec |= (del(.serviceAccountName) | .automountServiceAccountToken = false | .restartPolicy = "Never"
        | .volumes |= map(select(.name != "run-dir")))
    | .spec.containers[0] |= (del(.livenessProbe, .readinessProbe, .ports)
        | .volumeMounts |= map(select(.name != "run-dir"))
        | .args = ["preflight", "node", "--cgroup-root=/host/sys/fs/cgroup", "--bpffs-root=/host/sys/fs/bpf"])
  ' | kubectl create -f -

trap 'kubectl -n default delete pod "$pod" --ignore-not-found --wait=false' EXIT
for ((attempt = 0; attempt < 60; attempt++)); do
  phase="$(kubectl -n default get pod "$pod" -o jsonpath='{.status.phase}')"
  case "$phase" in
    Succeeded) kubectl -n default logs "$pod"; exit 0 ;;
    Failed) kubectl -n default logs "$pod" >&2; exit 1 ;;
  esac
  sleep 2
done
kubectl -n default describe pod "$pod" >&2
exit 1
