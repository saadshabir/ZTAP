#!/usr/bin/env bash
# Bootstrap the shipped agent in a disposable kind cluster, after kindnet stops.
set -euo pipefail
test "${ZTAP_KINDNET_NETWORKPOLICY_DISABLED:-}" = 1
# Harden pre-existing system workloads before the packet-socket audit.
kubectl -n kube-system patch deployment coredns --type=strategic \
  -p '{"spec":{"template":{"spec":{"containers":[{"name":"coredns","securityContext":{"allowPrivilegeEscalation":false,"capabilities":{"drop":["NET_RAW"]}}}]}}}}'
kubectl -n kube-system rollout status deployment/coredns --timeout=180s
kubectl -n local-path-storage patch deployment local-path-provisioner --type=strategic \
  -p '{"spec":{"template":{"spec":{"containers":[{"name":"local-path-provisioner","securityContext":{"allowPrivilegeEscalation":false,"capabilities":{"drop":["NET_RAW"]}}}]}}}}'
kubectl -n local-path-storage rollout status deployment/local-path-provisioner --timeout=180s
kubectl apply -f deployments/kubernetes/ztap-agent.yaml
kubectl -n ztap-system rollout status daemonset/ztap-node-init --timeout=180s
kubectl -n ztap-system rollout status daemonset/ztap-agent --timeout=180s
