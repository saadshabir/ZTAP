# Changelog

## [0.1.0] - Unreleased

This release is the product cutover described by `STREAMLINING_PLAN.md`.

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

- A scratch-based Linux runtime image.
- A single capability-only Kubernetes DaemonSet manifest.
- Build metadata in `ztap version` and standard-library `slog` logging.

[0.1.0]: https://github.com/saadshabir/ZTAP/releases/tag/v0.1.0
