# eBPF Enforcement Setup

ZTAP uses eBPF (Extended Berkeley Packet Filter) for high-performance, kernel-level network policy enforcement on Linux systems.

## Overview

ZTAP employs a **pre-compiled binary** strategy. The eBPF bytecode is compiled at build-time and embedded directly into the Go binary using `bpf2go`. This eliminates the need for `clang`, `llvm`, or kernel headers on the target production systems.

## Prerequisites

### Runtime Requirements

- **Operating System**: Linux kernel 5.7+ (for cgroup v2 support)
- **Root/CAP_BPF**: Root privileges or `CAP_BPF` and `CAP_NET_ADMIN` capabilities
- **cgroup v2**: Must be mounted at `/sys/fs/cgroup`

No compiler toolchain is required at runtime.

### Dry-Run Mode

The Kubernetes agent can validate snapshot compilation without attaching to the kernel:

```bash
# Validates informer-snapshot compilation without kernel changes
ztap agent --node-name "$NODE_NAME" --dry-run
```

In dry-run mode:

- Kubernetes objects are read from the informer snapshot and validated
- The candidate policy set is compiled
- Kernel attachment and map pinning are skipped
- Reconciliation results are logged to stdout

### Graceful Policy Reload

The Kubernetes node agent uses the instance-owned engine for atomic policy
updates on Linux. It loads one eBPF collection for the process lifetime, fills
the inactive policy slot, and publishes the new slot and monotonically
increasing policy epoch with one configuration-map replacement. Existing
links remain attached; newly selected cgroups are attached before the flip and
removed cgroups are detached after it. The engine waits for in-flight packet
readers before reclaiming the old slot, so a failed candidate leaves the active
policy in place.

Links are process-owned in this release. A graceful shutdown or crash detaches
enforcement and traffic fails open until the replacement agent completes its
first policy apply. The retired Linux file-based `ztap enforce` surface does
not load or attach eBPF programs; use the node agent for Linux enforcement.

### Build/Development Dependencies

If you are building ZTAP from source or modifying the eBPF program, you will need:

- `clang` (LLVM compiler)
- `llvm`
- Go 1.25+

#### Install Build Dependencies (Ubuntu/Debian)

```bash
sudo apt-get update
sudo apt-get install -y clang llvm
```

## Compilation

### Standard Build (Go)

The eBPF bytecode is automatically generated and embedded during the build process if `go generate` is run.

Notes:

- `go generate ./internal/enforcer/...` requires a `clang` toolchain that supports the BPF backend.
- On macOS, Apple clang typically does not include the BPF backend; run generation on Linux (or in a Linux container/VM).

```bash
# Generate the Go wrappers for eBPF bytecode
go generate ./internal/enforcer/...

# Build the binary
go build -o ztap ./cmd/ztap
```

### Manual C Compilation (Optional)

If you wish to manually compile the C source without using the Go generator:

```bash
cd bpf
make
```

After a manual build, the instance-owned object file will be at `bpf/engine.o`.
The production agent uses the embedded engine bytecode; the retired loader does
not accept `ZTAP_BPF_OBJECT` for Linux enforcement.

```bash
sudo ./ztap agent --node-name "$NODE_NAME"
```

## Loader

The Kubernetes agent always loads the embedded `bpf/engine.c` bytecode. It does
not search the filesystem for an object file or honor `ZTAP_BPF_OBJECT`; this
keeps the production path tied to the generated, ABI-checked engine bindings.
The historical `bpf/filter.c` loader remains only for migration tests and is
not a supported Linux enforcement path.

## eBPF Program Variants

ZTAP provides two eBPF program variants:

### 1. Native engine (Kubernetes `ztap agent`)

- **Behavior**: Per-subject, direction-specific deny-by-default with node/self
  bypasses, quarantine precedence, and epoch-scoped reply state
- **Use Case**: Kubernetes node enforcement
- **Implementation**: `bpf/engine.c` with bounded IPv4 parsing and LPM rules

### 2. Retired compatibility sources

The historical `bpf/filter.c` object and its loader remain in the repository
only for migration and regression coverage. No production command or API route
can select this global/default path; Linux enforcement is owned by `ztap agent`.

## Architecture

### eBPF Map Structure

The native engine owns one collection for the process lifetime. Its policy
state is split into two slots and published through an `active_config`
array-of-maps entry containing the active slot and policy epoch. The maps that
carry policy state are:

```c
struct subject_key {
    __u64 cgroup_id;
    __u32 slot;
};

struct subject_value {
    __u8 isolated;    // DirectionEgress and/or DirectionIngress
    __u8 quarantined; // Direction mask
};

struct policy_rule_key {
    __u32 prefix_length; // 96 + IPv4 CIDR bits
    __u32 meta;          // slot, direction, protocol, destination port
    __u64 cgroup_id;
    __u8  peer[4];
};

struct active_config_value {
    __u32 active_slot;
    __u64 policy_epoch;
};
```

The collection also owns stable flow and decision maps, an epoch-scoped LRU
reply map, the cgroup-local attachment identity map, and the pinned
`agent_status` map. There is no global `cgroup_id = 0` fallback in this
engine.

Lookup behavior:

- The attachment-owned cgroup identity selects the subject state for the
  active slot. A missing subject is unselected traffic and is allowed.
- A selected direction first honors the node and self bypass sets, then
  quarantine, reply state, and the compiled IPv4 rule set. A rule miss is
  default deny.
- The engine parses bounded IPv4 TCP/UDP headers. Isolated IPv6, fragmented,
  malformed, and unsupported traffic is denied with a recorded reason.

### Flow Events Ring Buffer

Flow events are streamed to userspace via a ring buffer:

```c
struct flow_event {
    __u64 timestamp_ns;   // Kernel timestamp (nanoseconds since boot)
    __u64 policy_epoch;   // Policy generation that decided the packet
    __u64 cgroup_id;      // Subject cgroup identified by the attachment
    __u32 src_ip[4];      // Source IP address (v4 uses first word)
    __u32 dest_ip[4];     // Destination IP address (v4 uses first word)
    __u16 src_port;       // Source port
    __u16 dest_port;      // Destination port
    __u8  protocol;       // Protocol (TCP=6, UDP=17)
    __u8  direction;      // 0=egress, 1=ingress
    __u8  action;         // 0=blocked, 1=allowed
    __u8  reason;         // Bounded decision reason
    __u8  family;         // 4=IPv4, 6=IPv6
    __u8  schema_version; // Binary event schema (currently 1)
    __u8  _padding[6];
};
```

The 1 MiB ring buffer is intended to enable real-time flow monitoring. The
JSON output includes the epoch, cgroup ID, reason, and schema version so a
consumer can distinguish events from different policy generations.

On Linux, the native `ztap agent` pins the `flow_events` ring buffer map at:

`/sys/fs/bpf/ztap/flow_events`

`ztap flows --follow` opens this pinned map and the companion `agent_status`
map, then streams events in real time. It holds `/run/ztap/flows.lock` (or the
directory supplied with `--run-dir`) so only one reader consumes the node's
ring buffer. The reader stops with a clear error when the status schema is
incompatible, the agent stops enforcing, the heartbeat is older than five
seconds, or the agent epoch changes. If the native maps are unavailable, the
interactive command retains its compatibility simulated output.

### Attachment Points

The native programs attach to cgroups using both `BPF_CGROUP_INET_EGRESS` and
`BPF_CGROUP_INET_INGRESS`:

- **Scope**: Applies to all processes in the selected cgroup and descendants
- **Direction**: Independent egress and ingress direction masks
- **Performance**: Inline filtering with minimal latency

## Usage

### Basic Usage (with ZTAP)

The Kubernetes node agent loads and attaches the instance-owned eBPF engine:

```bash
# Start the node-local reconciler (requires the documented eBPF capabilities)
sudo ztap agent --node-name "$NODE_NAME"

# Check enforcement status
ztap status
```

Notes:

- `ztap agent` owns the cgroup links and detaches them on shutdown.
- Linux policy input is the Kubernetes informer snapshot; direct file-based
  enforcement through `ztap enforce` is retired.
- The engine supports IPv4 TCP/UDP rules and explicit node/self bypasses. IPv6,
  malformed, fragmented, and unsupported isolated traffic is denied.

### Manual Inspection (Advanced)

The supported Linux process owns attachment and map lifecycle. Inspect the
running agent with `bpftool`; direct `bpftool prog load` commands target the
retired compatibility source and are useful only when maintaining its
migration tests.

```bash
# View the native programs and maps owned by the agent
sudo bpftool prog show
sudo bpftool map show
```

## Troubleshooting

### "missing BTF" / "load BTF maps: missing BTF"

If you see an error like:

```
load BTF maps: missing BTF
```

Ensure the object was compiled with debug info so it embeds BTF:

```bash
cd bpf
make clean && make
```

The Makefile includes `-g` by default. If you removed it, add it back to `CLANG_FLAGS`.

The agent uses its embedded, generated object and reports the failing
prerequisite directly. Check cgroup v2 and bpffs mounts and run it with the
documented eBPF capabilities before investigating verifier output.

### "eBPF object load failed"

The production agent does not load an object from the filesystem. Re-run the
build-time generation check with `clang-18`, then verify the runtime cgroup v2,
bpffs, and capability prerequisites described above.

### "failed to remove memlock"

**Error**: `failed to remove memlock: operation not permitted`

**Solution**: Run with root privileges or add `CAP_BPF` capability:

```bash
sudo ztap agent --node-name "$NODE_NAME"
# OR
sudo setcap cap_bpf,cap_net_admin+ep ./ztap
```

### "failed to load eBPF objects"

**Possible Causes**:

1. Kernel version < 5.7
2. BPF not enabled in kernel
3. Invalid eBPF program

**Check Kernel Version**:

```bash
uname -r
```

**Verify BPF Support**:

```bash
zgrep BPF /proc/config.gz | grep -E 'BPF=|CGROUP'
```

Should show:

```
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_CGROUP_BPF=y
```

### "failed to attach to cgroup"

**Error**: `failed to attach to cgroup: no such file or directory`

**Solution**: Verify cgroup v2 is mounted:

```bash
mount | grep cgroup2
# Should show: cgroup2 on /sys/fs/cgroup type cgroup2 ...
```

If not mounted:

```bash
sudo mount -t cgroup2 none /sys/fs/cgroup
```

### Debugging eBPF Programs

#### View eBPF Logs

```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

#### List Loaded Maps

```bash
sudo bpftool map show
```

#### Dump Map Contents

```bash
# Find map ID
sudo bpftool map show | grep policy_map

# Dump map (replace <id> with actual map ID)
sudo bpftool map dump id <id>
```

## Performance Considerations

### Overhead

- **CPU**: < 5% overhead for typical workloads
- **Latency**: < 100ns per packet
- **Memory**: ~10MB for 10,000 policy entries

### Scalability

- **Map Capacity**: 10,000 policy entries (configurable)
- **LPM Trie Lookup**: longest-prefix match (fast; worst-case scales with prefix length)
- **No Context Switch**: Runs entirely in kernel space

### Optimization Tips

1. **Aggregate Policies**: Combine similar rules to reduce map entries
2. **CIDR Ranges**: Use broader CIDR blocks where appropriate
3. **Protocol-Specific**: Apply policies at protocol level (TCP/UDP)

## Security Considerations

### Kernel Verifier

All eBPF programs are verified by the kernel before loading:

- **Memory Safety**: No out-of-bounds access
- **Termination**: Guaranteed to finish in bounded time
- **No Crashes**: Cannot crash the kernel

### Attack Surface

- **Minimal**: eBPF runs in sandboxed environment
- **Auditable**: Source code is visible and inspectable
- **Type-Safe**: C code compiled with strict checks

### Best Practices

1. **Principle of Least Privilege**: Use strict mode by default
2. **Regular Audits**: Review eBPF map contents periodically
3. **Logging**: Enable logging for blocked connections
4. **Updates**: Keep kernel and ZTAP up-to-date

## Development

### Testing Changes

After modifying `filter.c` or `engine.c`:

```bash
cd bpf
make clean
make
make verify
```

### Adding Debug Output

Use `bpf_trace_printk()` for debugging:

```c
char fmt[] = "Blocked: IP=%x Port=%d\n";
bpf_trace_printk(fmt, sizeof(fmt), dest_ip, dest_port);
```

View output:

```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

### Running Tests (Linux Only)

```bash
# Run enforcer tests (requires Linux)
go test ./internal/enforcer -v

# Run native engine verification (requires Linux root + integration tag)
sudo go test -race -tags=integration -timeout=10m ./internal/enforcer -run '^(TestEBPFIntegrationPhase0KernelPreflight|TestLinuxEngine)' -v
```

The native suite loads the embedded engine, attaches it to temporary cgroups,
and exercises packet decisions, lifecycle status, slot cleanup, and repeated
apply/close cycles. The older `TestEBPFIntegration*` tests remain migration
coverage for `bpf/filter.c`.

## Platform Support

| Platform | eBPF Support | Fallback |
| -------- | ------------ | -------- |
| Linux    | Yes (Native) | N/A      |
| macOS    | No           | Firewall |
| Windows  | No           | Firewall |
| FreeBSD  | Limited      | Firewall |

Note: ZTAP supports Windows enforcement via WFP (Windows Filtering Platform), which is separate from eBPF.

## References

- [eBPF Documentation](https://ebpf.io/)
- [Cilium eBPF Library](https://github.com/cilium/ebpf)
- [Linux BPF Documentation](https://www.kernel.org/doc/html/latest/bpf/)
- [cgroup v2 Documentation](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html)
