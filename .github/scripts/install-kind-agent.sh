#!/usr/bin/env bash
# Bootstrap the shipped agent in a disposable kind cluster, after kindnet stops.
set -euo pipefail
test "${ZTAP_KINDNET_NETWORKPOLICY_DISABLED:-}" = 1
bash "$(dirname "$0")/harden-kind-system-pods.sh"
kubectl apply -f deployments/kubernetes/ztap-agent.yaml
kubectl -n ztap-system rollout status daemonset/ztap-node-init --timeout=180s
kubectl -n ztap-system rollout status daemonset/ztap-agent --timeout=180s
