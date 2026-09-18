# Windows WFP Flow Reader - Integration Validation

The `ztap flows` command streams the Linux node agent's pinned eBPF ring buffer only. The Windows WFP NetEvents reader remains available to integration tests while the legacy code is retained for migration coverage. This runbook checks that reader directly.

## Prerequisites

- A Windows host with the Go toolchain.
- An elevated PowerShell terminal (Administrator).
- The Base Filtering Engine (BFE) service running. Check with `sc query bfe`.

## Run the integration tests

From the repository root in elevated PowerShell:

```powershell
go test ./internal/flow -tags=integration -run TestWFPFlowIntegration -v
```

Expected results:

- `TestWFPFlowIntegration_AllowedEgress` passes.
- `TestWFPFlowIntegration_BlockedEgress` passes.

The tests install ZTAP-owned WFP filters, generate traffic, and verify the corresponding NetEvents. They clean up their filters on completion.

## Troubleshooting

- For `access denied` or missing events, run PowerShell as Administrator and check that BFE is running.
- If only blocked events appear, check WFP allow-event auditing on the host. Some environments do not surface permit events without additional auditing.
