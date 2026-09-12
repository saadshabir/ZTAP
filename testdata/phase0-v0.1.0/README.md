# Phase 0 `v0.1.0` reference fixture

This fixture is the small, reproducible reference environment for the first
release feasibility and performance gates. It is deliberately separate from
the later scale milestone.

The generator creates deterministic Kubernetes YAML with:

- 250 workload Pods grouped into 25 policy subjects;
- 25 `networking.k8s.io/v1` NetworkPolicies;
- 100 explicit IPv4 TCP `ipBlock` rules per policy;
- 2,500 explicit rule inputs, with an expected 2,500 compiled local rules;
- no timestamps, random IDs, or host-specific paths.

Generate it with:

```sh
sh scripts/phase0_reference_fixture.sh \
  --output dist/phase0-v0.1.0 \
  --force
```

The output contains `workloads.yaml`, `policies.yaml`, `metadata.env`, and
`manifest.sha256`. The reference environment for measured runs is one Linux
worker with 2 vCPUs. Each measured gate must run three times after warm-up and
retain the raw command output with the Phase 0 evidence artifact.

The 1,000-Pod/10,000-rule fixture is intentionally not part of `v0.1.0`.
