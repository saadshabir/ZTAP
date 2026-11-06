#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."

for tool in docker go jq kind kubectl make; do
  command -v "$tool" >/dev/null || { printf 'Required command missing: %s\n' "$tool" >&2; exit 1; }
done
docker info --format '{{.ServerVersion}}' >/dev/null

tmp="$(mktemp -d)"
export KUBECONFIG="$tmp/kubeconfig"
export KIND_CLUSTER_NAME="ztap-demo-$(basename "$tmp" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9')"
image="ztap-local/$KIND_CLUSTER_NAME"
built=false
created=false
cleanup() {
  status=$?
  if [ "$created" = true ]; then
    kind delete cluster --name "$KIND_CLUSTER_NAME" || status=1
  fi
  if [ "$built" = true ]; then
    docker image rm "$image:dev" >/dev/null || status=1
  fi
  rm -rf -- "$tmp"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Make the local image tag private to this run, including when running a tagged checkout.
make build
make docker IMAGE="$image" VERSION=dev
built=true
docker run --rm "$image:dev" version
created=true
kind create cluster --name "$KIND_CLUSTER_NAME" --wait 180s \
  --image kindest/node:v1.36.4@sha256:099e049362a1526b2db71494e1947aae99bd16290d7c895f2b7ea312e3cbfaed \
  --config examples/kind-demo/kind.yaml
# Use a private mount inside this kind node so its pins disappear with the node.
docker exec "$KIND_CLUSTER_NAME-control-plane" mount -t bpf bpffs /sys/fs/bpf
kind load docker-image "$image:dev" --name "$KIND_CLUSTER_NAME"
sed "s@image: ztap:dev@image: $image:dev@" \
  deployments/kubernetes/ztap-agent.yaml > "$tmp/ztap-agent.yaml"
bash .github/scripts/disable-kindnet-policy.sh
bash .github/scripts/harden-kind-system-pods.sh
./bin/ztap preflight cluster
bash examples/kind-demo/node-preflight.sh "$tmp/ztap-agent.yaml"
./bin/ztap validate --file examples/kind-demo/policies.yaml

kubectl apply -f "$tmp/ztap-agent.yaml"
kubectl -n ztap-system rollout status daemonset/ztap-node-init --timeout=180s
kubectl -n ztap-system rollout status daemonset/ztap-agent --timeout=180s
bash examples/kind-demo/traffic.sh
