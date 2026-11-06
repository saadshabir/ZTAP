# ZTAP traffic demo

Run from a ZTAP source checkout with Go, make, Docker with Buildx, kubectl, jq,
and kind v0.32.0 or later. The Docker host needs a Linux kernel with the
[ZTAP deployment prerequisites](../../docs/deployment.md#requirements).

```sh
bash examples/kind-demo/run.sh
```

The script uses a temporary kubeconfig and a single-node kind cluster with a
private bpffs mount. It disables kindnet's policy controller in that cluster
and hardens its stock Pods. It runs both preflight checks before applying the
ZTAP install manifest. The script deletes the cluster on exit.

The [workloads](workloads.yaml) are a BusyBox HTTP server listening on TCP
8080 and 8081 and a client Pod. [The policies](policies.yaml) isolate the
client's egress and allow TCP 8080 to the demo server. The test uses the
server Pod's IPv4 address so the requests need no DNS access.

A successful run prints these traffic results.

```text
Before policy: TCP 8080 allowed (demo-ok)
Before policy: TCP 8081 allowed (demo-ok)
After policy: TCP 8080 allowed (demo-ok)
After policy: TCP 8081 blocked (ZTAP egress default-deny counter 0 -> 2)
```

The counter delta varies with packet retransmissions. The demo requires it
to increase after the blocked request. The [traffic script](traffic.sh) can
also be run by itself in a disposable single-node cluster with the ZTAP agent
Ready, kindnet policy enforcement disabled, and the demo namespace unused.

```sh
bash examples/kind-demo/traffic.sh
kubectl delete namespace ztap-demo
```

The kind node image and BusyBox workload image are pinned by digest.
[kind v0.33.0 image list](https://github.com/kubernetes-sigs/kind/releases/tag/v0.33.0)
