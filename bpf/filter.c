// SPDX-License-Identifier: GPL-2.0
// eBPF program for network policy enforcement
// Self-contained definitions to avoid architecture-specific header issues

// BPF type definitions (from linux/bpf.h, but without dependencies)
typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

// BPF map types
#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_MAP_TYPE_LPM_TRIE 11
#define BPF_MAP_TYPE_RINGBUF 27

// BPF map flags
#define BPF_F_NO_PREALLOC 1

// BPF constants
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_ICMP 1
#define IPPROTO_ICMPV6 58

// BPF helper function declarations
static void *(*bpf_map_lookup_elem)(void *map, void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, void *key, void *value, unsigned long flags) = (void *)2;
static long (*bpf_skb_load_bytes)(const void *skb, __u32 offset, void *to, __u32 len) = (void *)26;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)5;
static __u64 (*bpf_get_current_cgroup_id)(void) = (void *)80;
static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size, __u64 flags) = (void *)131;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) = (void *)132;
static void (*bpf_ringbuf_discard)(void *data, __u64 flags) = (void *)133;

// Byte order conversion helpers (inline, not actual BPF helpers)
#define bpf_htons(x) __builtin_bswap16(x)
#define bpf_ntohs(x) __builtin_bswap16(x)
#define bpf_htonl(x) __builtin_bswap32(x)
#define bpf_ntohl(x) __builtin_bswap32(x)

// Compiler directives
#define __always_inline inline __attribute__((always_inline))
#define __attribute_const__ __attribute__((const))
#define SEC(name) __attribute__((section(name), used))

// BTF map definition macros (for cilium/ebpf v0.19+)
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

// Ethernet header
struct ethhdr
{
    unsigned char h_dest[6];
    unsigned char h_source[6];
    unsigned short h_proto;
};

// IP header (simplified for BPF)
struct iphdr
{
    unsigned char version_ihl;
    unsigned char tos;
    unsigned short tot_len;
    unsigned short id;
    unsigned short frag_off;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short check;
    unsigned int saddr;
    unsigned int daddr;
};

struct in6_addr
{
    union
    {
        __u8 u6_addr8[16];
        __u16 u6_addr16[8];
        __u32 u6_addr32[4];
    } in6_u;
#define s6_addr in6_u.u6_addr8
#define s6_addr32 in6_u.u6_addr32
};

// IPv6 header
struct ipv6hdr
{
    __u8 priority_version;
    __u8 flow_lbl[3];
    __u16 payload_len;
    __u8 nexthdr;
    __u8 hop_limit;
    struct in6_addr saddr;
    struct in6_addr daddr;
};

// TCP header (simplified)
struct tcphdr
{
    unsigned short source;
    unsigned short dest;
    unsigned int seq;
    unsigned int ack_seq;
    unsigned short doff_flags;
    unsigned short window;
    unsigned short check;
    unsigned short urg_ptr;
};

// UDP header
struct udphdr
{
    unsigned short source;
    unsigned short dest;
    unsigned short len;
    unsigned short check;
};

// Socket buffer structure for skb context
struct __sk_buff
{
    __u32 data;
    __u32 data_end;
};

// Policy key structure for IPv4 LPM trie (must match Go struct policyKeyLPM).
//
// LPM keys begin with prefixlen (bits), followed by:
//   meta(32) || cgroup_id(64) || ip(32)
//
// meta packs: (direction << 24) | (protocol << 16) | port
struct policy_key
{
    __u32 prefixlen;
    __u32 meta;
    __u64 cgroup_id;
    __u8 ip[4];
    __u8 _padding[4];
};

// Policy key structure for IPv6 LPM trie (must match Go struct policyKeyV6LPM).
struct policy_key_v6
{
    __u32 prefixlen;
    __u32 meta;
    __u64 cgroup_id;
    __u8 ip[16];
};

// Policy value structure (must match Go struct)
struct policy_value
{
    __u8 action; // 0 = block, 1 = allow
    __u8 _padding[3];
};

// enforcement_config controls optional runtime behaviors.
struct enforcement_config
{
    // If set, enforce policies only for cgroups present in enforced_cgroups.
    // If not set, use legacy behavior (default deny on miss).
    __u8 selected_only;
    __u8 _padding[3];
};

// BPF map definition using BTF-based approach (required by cilium/ebpf v0.19+)
// Modern cilium/ebpf expects map definitions in .maps section with BTF type info
struct
{
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 10000);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct policy_key);
    __type(value, struct policy_value);
} policy_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 10000);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct policy_key_v6);
    __type(value, struct policy_value);
} policy_map_v6 SEC(".maps");

// enforced_cgroups is a set of cgroup IDs that have at least one policy selecting them.
//
// When enforcement_config.selected_only=1, packets originating from cgroups not
// in this set are allowed (Kubernetes NetworkPolicy semantics).
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 200000);
    __type(key, __u64);
    __type(value, __u8);
} enforced_cgroups SEC(".maps");

// enforcement_config_map is a single-element array map storing enforcement_config.
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct enforcement_config);
} enforcement_config_map SEC(".maps");

// Flow event structure for real-time monitoring (must match Go struct in internal/flow/types.go)
struct flow_event
{
    __u64 timestamp_ns; // Kernel timestamp in nanoseconds
    __u32 src_ip[4];    // Source IP address (v4 uses first word)
    __u32 dest_ip[4];   // Destination IP address (v4 uses first word)
    __u16 src_port;     // Source port
    __u16 dest_port;    // Destination port
    __u8 protocol;      // Protocol (6=TCP, 17=UDP, 1=ICMP)
    __u8 direction;     // 0=egress, 1=ingress
    __u8 action;        // 0=blocked, 1=allowed
    __u8 family;        // 4=IPv4, 6=IPv6
};

// Ring buffer for flow events (256KB buffer)
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} flow_events SEC(".maps");

// Helper to emit flow event to ring buffer
static __always_inline void emit_flow_event(__u32 *src_ip, __u32 *dest_ip,
                                            __u16 src_port, __u16 dest_port,
                                            __u8 protocol, __u8 direction,
                                            __u8 action, __u8 family)
{
    struct flow_event *event;

    event = bpf_ringbuf_reserve(&flow_events, sizeof(*event), 0);
    if (!event)
        return;

    event->timestamp_ns = bpf_ktime_get_ns();

    if (family == 4)
    {
        // IPv4 flow consumers decode this field as a network-order uint32.
        event->src_ip[0] = bpf_ntohl(src_ip[0]);
        event->src_ip[1] = 0;
        event->src_ip[2] = 0;
        event->src_ip[3] = 0;
        event->dest_ip[0] = bpf_ntohl(dest_ip[0]);
        event->dest_ip[1] = 0;
        event->dest_ip[2] = 0;
        event->dest_ip[3] = 0;
    }
    else
    {
        for (int i = 0; i < 4; i++)
        {
            event->src_ip[i] = src_ip[i];
            event->dest_ip[i] = dest_ip[i];
        }
    }

    event->src_port = src_port;
    event->dest_port = dest_port;
    event->protocol = protocol;
    event->direction = direction;
    event->action = action;
    event->family = family;

    bpf_ringbuf_submit(event, 0);
}

// cgroup_skb programs receive an skb whose data starts at the network-layer
// header, not at an Ethernet header. Keep the offset explicit here: assuming
// an Ethernet header makes every cgroup ingress/egress flow look unparsable.
static __always_inline int parse_ipv4(struct __sk_buff *skb, __u32 *src_ip, __u32 *dest_ip,
                                      __u8 *protocol, __u16 *src_port, __u16 *dest_port)
{
    struct iphdr ip;

    if (bpf_skb_load_bytes(skb, 0, &ip, sizeof(ip)) < 0)
        return -1;

    // Check the network-layer version before interpreting the header.
    if ((ip.version_ihl >> 4) != 4)
        return -1;

    *src_ip = ip.saddr;
    *dest_ip = ip.daddr;
    *protocol = ip.protocol;

    // Calculate IP header length (IHL is in 32-bit words)
    __u8 ihl = (ip.version_ihl & 0x0F) * 4;
    if (ihl < sizeof(struct iphdr))
        ihl = sizeof(struct iphdr);

    // Parse port based on protocol
    if (ip.protocol == IPPROTO_TCP)
    {
        struct tcphdr tcp;
        if (bpf_skb_load_bytes(skb, ihl, &tcp, sizeof(tcp)) < 0)
            return -1;
        *src_port = bpf_ntohs(tcp.source);
        *dest_port = bpf_ntohs(tcp.dest);
    }
    else if (ip.protocol == IPPROTO_UDP)
    {
        struct udphdr udp;
        if (bpf_skb_load_bytes(skb, ihl, &udp, sizeof(udp)) < 0)
            return -1;
        *src_port = bpf_ntohs(udp.source);
        *dest_port = bpf_ntohs(udp.dest);
    }
    else
    {
        *src_port = 0;
        *dest_port = 0;
    }

    return 0;
}

// Helper to parse IPv6 packet and extract addresses and ports
static __always_inline int parse_ipv6(struct __sk_buff *skb, __u32 *src_ip, __u32 *dest_ip,
                                      __u8 *protocol, __u16 *src_port, __u16 *dest_port)
{
    struct ipv6hdr ip;

    if (bpf_skb_load_bytes(skb, 0, &ip, sizeof(ip)) < 0)
        return -1;

    if ((ip.priority_version >> 4) != 6)
        return -1;

    for (int i = 0; i < 4; i++)
    {
        src_ip[i] = ip.saddr.s6_addr32[i];
        dest_ip[i] = ip.daddr.s6_addr32[i];
    }
    *protocol = ip.nexthdr;

    // Parse port based on protocol (skipping IPv6 extensions for simplicity in this MVP)
    if (ip.nexthdr == IPPROTO_TCP)
    {
        struct tcphdr tcp;
        if (bpf_skb_load_bytes(skb, sizeof(struct ipv6hdr), &tcp, sizeof(tcp)) < 0)
            return -1;
        *src_port = bpf_ntohs(tcp.source);
        *dest_port = bpf_ntohs(tcp.dest);
    }
    else if (ip.nexthdr == IPPROTO_UDP)
    {
        struct udphdr udp;
        if (bpf_skb_load_bytes(skb, sizeof(struct ipv6hdr), &udp, sizeof(udp)) < 0)
            return -1;
        *src_port = bpf_ntohs(udp.source);
        *dest_port = bpf_ntohs(udp.dest);
    }
    else
    {
        *src_port = 0;
        *dest_port = 0;
    }

    return 0;
}

// Direction constants
#define DIRECTION_EGRESS 0
#define DIRECTION_INGRESS 1

#define LPM_FIXED_BITS 96
#define LPM_LOOKUP_PREFIXLEN_V4 (LPM_FIXED_BITS + 32)
#define LPM_LOOKUP_PREFIXLEN_V6 (LPM_FIXED_BITS + 128)

#define PACK_META(direction, protocol, port) (((__u32)(direction) << 24) | ((__u32)(protocol) << 16) | (__u32)(port))

// Main eBPF program for egress filtering
SEC("cgroup_skb/egress")
int filter_egress(struct __sk_buff *skb)
{
    __u32 src_ip[4] = {0}, dest_ip[4] = {0};
    __u8 protocol;
    __u16 src_port, dest_port;
    __u8 family = 0;

    // Parse packet
    if (parse_ipv4(skb, &src_ip[0], &dest_ip[0], &protocol, &src_port, &dest_port) == 0)
    {
        family = 4;
    }
    else if (parse_ipv6(skb, src_ip, dest_ip, &protocol, &src_port, &dest_port) == 0)
    {
        family = 6;
    }
    else
    {
        // If not IPv4/IPv6 or parse error, allow by default
        return 1;
    }

    if (family == 4)
    {
        __u32 cfg_k = 0;
        struct enforcement_config *cfg = bpf_map_lookup_elem(&enforcement_config_map, &cfg_k);
        __u8 selected_only = cfg ? cfg->selected_only : 0;
        __u64 cgid = bpf_get_current_cgroup_id();
        if (selected_only)
        {
            __u8 *present = bpf_map_lookup_elem(&enforced_cgroups, &cgid);
            if (!present)
            {
                emit_flow_event(src_ip, dest_ip, src_port, dest_port, protocol, DIRECTION_EGRESS, 1, 4);
                return 1;
            }
        }

        // Lookup policy in map (egress uses destination IP/port)
        __u8 lookup_proto = protocol;
        __u32 meta = PACK_META(DIRECTION_EGRESS, lookup_proto, dest_port);
        struct policy_key key = {
            .prefixlen = LPM_LOOKUP_PREFIXLEN_V4,
            .meta = meta,
            .cgroup_id = cgid,
        };
        __builtin_memcpy(key.ip, &dest_ip[0], sizeof(key.ip));

        struct policy_value *value = bpf_map_lookup_elem(&policy_map, &key);
        if (!value)
        {
            if (!selected_only)
            {
                // Backward-compatible fallback: treat cgroup_id=0 as "global" policy.
                key.cgroup_id = 0;
                value = bpf_map_lookup_elem(&policy_map, &key);
            }
        }
        if (value)
        {
            if (value->action == 1)
            {
                emit_flow_event(src_ip, dest_ip, src_port, dest_port, protocol, DIRECTION_EGRESS, 1, 4);
                return 1;
            }
            else
            {
                emit_flow_event(src_ip, dest_ip, src_port, dest_port, protocol, DIRECTION_EGRESS, 0, 4);
                return 0;
            }
        }
    }
    else if (family == 6)
    {
        __u32 cfg_k = 0;
        struct enforcement_config *cfg = bpf_map_lookup_elem(&enforcement_config_map, &cfg_k);
        __u8 selected_only = cfg ? cfg->selected_only : 0;
        __u64 cgid = bpf_get_current_cgroup_id();
        if (selected_only)
        {
            __u8 *present = bpf_map_lookup_elem(&enforced_cgroups, &cgid);
            if (!present)
            {
                emit_flow_event(src_ip, dest_ip, src_port, dest_port, protocol, DIRECTION_EGRESS, 1, 6);
                return 1;
            }
        }

        __u8 lookup_proto = protocol;
        if (lookup_proto == IPPROTO_ICMP)
            lookup_proto = IPPROTO_ICMPV6;
        __u32 meta = PACK_META(DIRECTION_EGRESS, lookup_proto, dest_port);
        struct policy_key_v6 key = {
            .prefixlen = LPM_LOOKUP_PREFIXLEN_V6,
            .meta = meta,
            .cgroup_id = cgid,
        };
        for (int i = 0; i < 4; i++)
        {
            __builtin_memcpy(&key.ip[i * 4], &dest_ip[i], sizeof(dest_ip[i]));
        }

        struct policy_value *value = bpf_map_lookup_elem(&policy_map_v6, &key);
        if (!value)
        {
            if (!selected_only)
            {
                key.cgroup_id = 0;
                value = bpf_map_lookup_elem(&policy_map_v6, &key);
            }
        }
        if (value)
        {
            if (value->action == 1)
            {
                emit_flow_event(src_ip, dest_ip, src_port, dest_port, protocol, DIRECTION_EGRESS, 1, 6);
                return 1;
            }
            else
            {
                emit_flow_event(src_ip, dest_ip, src_port, dest_port, protocol, DIRECTION_EGRESS, 0, 6);
                return 0;
            }
        }
    }

    // Default deny: if no policy matches, block
    emit_flow_event(src_ip, dest_ip, src_port, dest_port, protocol, DIRECTION_EGRESS, 0, family);
    return 0;
}

// Main eBPF program for ingress filtering
SEC("cgroup_skb/ingress")
int filter_ingress(struct __sk_buff *skb)
{
    __u32 src_ip[4] = {0}, dest_ip[4] = {0};
    __u8 protocol;
    __u16 src_port, dest_port;
    __u8 family = 0;

    // Parse packet
    if (parse_ipv4(skb, &src_ip[0], &dest_ip[0], &protocol, &src_port, &dest_port) == 0)
    {
        family = 4;
    }
    else if (parse_ipv6(skb, src_ip, dest_ip, &protocol, &src_port, &dest_port) == 0)
    {
        family = 6;
    }
    else
    {
        // If not IPv4/IPv6 or parse error, allow by default
        return 1;
    }

    if (family == 4)
    {
        __u32 cfg_k = 0;
        struct enforcement_config *cfg = bpf_map_lookup_elem(&enforcement_config_map, &cfg_k);
        __u8 selected_only = cfg ? cfg->selected_only : 0;
        __u64 cgid = bpf_get_current_cgroup_id();
        if (selected_only)
        {
            __u8 *present = bpf_map_lookup_elem(&enforced_cgroups, &cgid);
            if (!present)
            {
                emit_flow_event(src_ip, dest_ip, src_port, dest_port, protocol, DIRECTION_INGRESS, 1, 4);
                return 1;
            }
        }

        // Lookup policy in map (ingress uses source IP and destination port)
        __u8 lookup_proto = protocol;
        __u32 meta = PACK_META(DIRECTION_INGRESS, lookup_proto, dest_port);
        struct policy_key key = {
            .prefixlen = LPM_LOOKUP_PREFIXLEN_V4,
            .meta = meta,
            .cgroup_id = cgid,
        };
        __builtin_memcpy(key.ip, &src_ip[0], sizeof(key.ip));

        struct policy_value *value = bpf_map_lookup_elem(&policy_map, &key);
        if (!value)
        {
            if (!selected_only)
            {
                // Backward-compatible fallback: treat cgroup_id=0 as "global" policy.
                key.cgroup_id = 0;
                value = bpf_map_lookup_elem(&policy_map, &key);
            }
        }
        if (value)
        {
            if (value->action == 1)
            {
                emit_flow_event(src_ip, dest_ip, src_port, dest_port, protocol, DIRECTION_INGRESS, 1, 4);
                return 1;
            }
            else
            {
                emit_flow_event(src_ip, dest_ip, src_port, dest_port, protocol, DIRECTION_INGRESS, 0, 4);
                return 0;
            }
        }
    }
    else if (family == 6)
    {
        __u32 cfg_k = 0;
        struct enforcement_config *cfg = bpf_map_lookup_elem(&enforcement_config_map, &cfg_k);
        __u8 selected_only = cfg ? cfg->selected_only : 0;
        __u64 cgid = bpf_get_current_cgroup_id();
        if (selected_only)
        {
            __u8 *present = bpf_map_lookup_elem(&enforced_cgroups, &cgid);
            if (!present)
            {
                emit_flow_event(src_ip, dest_ip, src_port, dest_port, protocol, DIRECTION_INGRESS, 1, 6);
                return 1;
            }
        }

        __u8 lookup_proto = protocol;
        if (lookup_proto == IPPROTO_ICMP)
            lookup_proto = IPPROTO_ICMPV6;
        __u32 meta = PACK_META(DIRECTION_INGRESS, lookup_proto, dest_port);
        struct policy_key_v6 key = {
            .prefixlen = LPM_LOOKUP_PREFIXLEN_V6,
            .meta = meta,
            .cgroup_id = cgid,
        };
        for (int i = 0; i < 4; i++)
        {
            __builtin_memcpy(&key.ip[i * 4], &src_ip[i], sizeof(src_ip[i]));
        }

        struct policy_value *value = bpf_map_lookup_elem(&policy_map_v6, &key);
        if (!value)
        {
            if (!selected_only)
            {
                key.cgroup_id = 0;
                value = bpf_map_lookup_elem(&policy_map_v6, &key);
            }
        }
        if (value)
        {
            if (value->action == 1)
            {
                emit_flow_event(src_ip, dest_ip, src_port, dest_port, protocol, DIRECTION_INGRESS, 1, 6);
                return 1;
            }
            else
            {
                emit_flow_event(src_ip, dest_ip, src_port, dest_port, protocol, DIRECTION_INGRESS, 0, 6);
                return 0;
            }
        }
    }

    // Default deny: if no policy matches, block
    emit_flow_event(src_ip, dest_ip, src_port, dest_port, protocol, DIRECTION_INGRESS, 0, family);
    return 0;
}

// Alternative: Default allow mode for egress (for testing)
SEC("cgroup_skb/egress_permissive")
int filter_egress_permissive(struct __sk_buff *skb)
{
    __u32 src_ip, dest_ip;
    __u8 protocol;
    __u16 src_port, dest_port;

    if (parse_ipv4(skb, &src_ip, &dest_ip, &protocol, &src_port, &dest_port) < 0)
    {
        return 1;
    }

    __u32 meta = PACK_META(DIRECTION_EGRESS, protocol, dest_port);
    struct policy_key key = {
        .prefixlen = LPM_LOOKUP_PREFIXLEN_V4,
        .meta = meta,
        .cgroup_id = bpf_get_current_cgroup_id(),
    };
    __builtin_memcpy(key.ip, &dest_ip, sizeof(key.ip));

    struct policy_value *value = bpf_map_lookup_elem(&policy_map, &key);
    if (!value)
    {
        key.cgroup_id = 0;
        value = bpf_map_lookup_elem(&policy_map, &key);
    }
    if (value && value->action == 0)
    {
        // Explicitly blocked
        return 0;
    }

    // Default allow: if no explicit block, allow
    return 1;
}

// Alternative: Default allow mode for ingress (for testing)
SEC("cgroup_skb/ingress_permissive")
int filter_ingress_permissive(struct __sk_buff *skb)
{
    __u32 src_ip, dest_ip;
    __u8 protocol;
    __u16 src_port, dest_port;

    if (parse_ipv4(skb, &src_ip, &dest_ip, &protocol, &src_port, &dest_port) < 0)
    {
        return 1;
    }

    __u32 meta = PACK_META(DIRECTION_INGRESS, protocol, dest_port);
    struct policy_key key = {
        .prefixlen = LPM_LOOKUP_PREFIXLEN_V4,
        .meta = meta,
        .cgroup_id = bpf_get_current_cgroup_id(),
    };
    __builtin_memcpy(key.ip, &src_ip, sizeof(key.ip));

    struct policy_value *value = bpf_map_lookup_elem(&policy_map, &key);
    if (!value)
    {
        key.cgroup_id = 0;
        value = bpf_map_lookup_elem(&policy_map, &key);
    }
    if (value && value->action == 0)
    {
        // Explicitly blocked
        return 0;
    }

    // Default allow: if no explicit block, allow
    return 1;
}

char _license[] SEC("license") = "GPL";
