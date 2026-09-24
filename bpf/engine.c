// SPDX-License-Identifier: GPL-2.0
// Instance-owned Kubernetes NetworkPolicy engine.
//
// The active config is a one-entry array-of-maps. Each inner map contains one
// immutable {slot, epoch} record. Replacing the outer map entry publishes both
// fields with one map-pointer swap; an invocation keeps its old config map
// alive until it leaves the program, and the userspace in-flight counter lets
// the engine reclaim the corresponding policy slot safely.

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_MAP_TYPE_PERCPU_ARRAY 6
#define BPF_MAP_TYPE_LRU_HASH 9
#define BPF_MAP_TYPE_LRU_PERCPU_HASH 10
#define BPF_MAP_TYPE_LPM_TRIE 11
#define BPF_MAP_TYPE_ARRAY_OF_MAPS 12
#define BPF_MAP_TYPE_CGROUP_STORAGE 19
#define BPF_MAP_TYPE_RINGBUF 27

#define BPF_F_NO_PREALLOC 1
#define BPF_NOEXIST 1

#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

#define __always_inline inline __attribute__((always_inline))
#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#define __array(name, val) val *name[]

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *)2;
static long (*bpf_map_delete_elem)(void *map, const void *key) = (void *)3;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)5;
static long (*bpf_skb_load_bytes)(const void *skb, __u32 offset, void *to, __u32 len) = (void *)26;
static void *(*bpf_get_local_storage)(void *map, __u64 flags) = (void *)81;
static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size, __u64 flags) = (void *)131;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) = (void *)132;

#define bpf_ntohs(x) __builtin_bswap16(x)
#define bpf_ntohl(x) __builtin_bswap32(x)

struct __sk_buff {
    __u32 len;
    __u32 pkt_type;
    __u32 mark;
    __u32 queue_mapping;
    __u32 protocol;
    __u32 vlan_present;
    __u32 vlan_tci;
    __u32 vlan_proto;
    __u32 priority;
    __u32 ingress_ifindex;
    __u32 ifindex;
    __u32 tc_index;
    __u32 cb[5];
    __u32 hash;
    __u32 tc_classid;
    __u32 data;
    __u32 data_end;
    __u32 napi_id;
    __u32 family;
    __u32 remote_ip4;
    __u32 local_ip4;
    __u32 remote_ip6[4];
    __u32 local_ip6[4];
    __u32 remote_port;
    __u32 local_port;
    __u32 data_meta;
    __u64 flow_keys;
    __u64 tstamp;
    __u32 wire_len;
    __u32 gso_segs;
};

_Static_assert(__builtin_offsetof(struct __sk_buff, gso_segs) == 164,
               "__sk_buff GSO segment ABI changed");

struct ipv4_header {
    __u8 version_ihl;
    __u8 tos;
    __u16 total_length;
    __u16 identification;
    __u16 fragment_offset;
    __u8 ttl;
    __u8 protocol;
    __u16 checksum;
    __u32 source;
    __u32 destination;
};

struct ipv6_header {
    __u8 version_class;
    __u8 flow_label[3];
    __u16 payload_length;
    __u8 next_header;
    __u8 hop_limit;
    __u8 source[16];
    __u8 destination[16];
};

struct tcp_header {
    __u16 source;
    __u16 destination;
    __u32 sequence;
    __u32 acknowledgement;
    __u16 offset_flags;
    __u16 window;
    __u16 checksum;
    __u16 urgent;
};

struct udp_header {
    __u16 source;
    __u16 destination;
    __u16 length;
    __u16 checksum;
};

struct policy_rule_key {
    __u32 prefix_length;
    // slot: bit 31; direction: bit 30; protocol: bits 23..16; port: bits 15..0.
    __u32 meta;
    __u64 cgroup_id;
    __u8 peer[4];
    __u8 _padding[4];
};

struct subject_key {
    __u64 cgroup_id;
    __u32 slot;
    __u32 _padding;
};

struct subject_value {
    __u8 isolated;
    __u8 quarantined;
    __u8 _padding[6];
};

struct node_key {
    __u32 slot;
    __u8 address[4];
};

struct self_key {
    __u64 cgroup_id;
    __u32 slot;
    __u8 address[4];
};

struct active_config_value {
    __u32 active_slot;
    __u32 _padding;
    __u64 policy_epoch;
};

// BPF_MAP_TYPE_CGROUP_STORAGE keys include the cgroup inode and the attach
// type. Keeping the direction in the key gives ingress and egress links their
// own storage records while sharing one map object.
struct cgroup_storage_key {
    __u64 cgroup_id;
    __u32 attach_type;
    __u32 _padding;
};

struct connection_key {
    __u64 policy_epoch;
    __u64 cgroup_id;
    __u32 source;
    __u32 destination;
    __u16 source_port;
    __u16 destination_port;
    __u8 protocol;
    __u8 direction;
    __u8 _padding[2];
};

struct connection_value {
    __u64 expires_at_ns;
};

struct epoch_decision_key {
    __u64 policy_epoch;
    __u8 direction;
    __u8 action;
    __u8 reason;
    __u8 _padding[5];
};

struct epoch_event_drop_key {
    __u64 policy_epoch;
    __u32 reason;
    __u32 _padding;
};

struct flow_event {
    __u64 timestamp_ns;
    __u64 policy_epoch;
    __u64 cgroup_id;
    __u32 source_ip[4];
    __u32 destination_ip[4];
    __u16 source_port;
    __u16 destination_port;
    __u8 protocol;
    __u8 direction;
    __u8 action;
    __u8 reason;
    __u8 family;
    __u8 schema_version;
    __u8 _padding[6];
};

struct event_limiter_value {
    __u64 window_start_ns;
    __u32 emitted;
    __u32 _padding;
};

struct agent_status_value {
    __u32 schema_version;
    __u32 lifecycle_state;
    __u64 agent_epoch;
    __u64 heartbeat_ns;
};

_Static_assert(sizeof(struct policy_rule_key) == 24, "policy_rule_key ABI changed");
_Static_assert(sizeof(struct subject_key) == 16, "subject_key ABI changed");
_Static_assert(sizeof(struct subject_value) == 8, "subject_value ABI changed");
_Static_assert(sizeof(struct node_key) == 8, "node_key ABI changed");
_Static_assert(sizeof(struct self_key) == 16, "self_key ABI changed");
_Static_assert(sizeof(struct active_config_value) == 16, "active_config_value ABI changed");
_Static_assert(sizeof(struct cgroup_storage_key) == 16, "cgroup_storage_key ABI changed");
_Static_assert(sizeof(struct connection_key) == 32, "connection_key ABI changed");
_Static_assert(sizeof(struct epoch_decision_key) == 16, "epoch_decision_key ABI changed");
_Static_assert(sizeof(struct epoch_event_drop_key) == 16, "epoch_event_drop_key ABI changed");
_Static_assert(sizeof(struct event_limiter_value) == 16, "event_limiter_value ABI changed");
_Static_assert(sizeof(struct flow_event) == 72, "flow_event ABI changed");

struct active_config_inner_map_def {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__uint(value_size, 16);
};

// The active pointer's inner map is immutable after publication. Map-in-map
// replacement is the single commit operation for active_slot and policy_epoch.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
	__array(values, struct active_config_inner_map_def);
} active_config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 32768);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct policy_rule_key);
    __type(value, __u8);
} policy_rules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32768);
    __type(key, struct subject_key);
    __type(value, struct subject_value);
} subject_state SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32768);
    __type(key, struct node_key);
    __type(value, __u8);
} node_bypass SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32768);
    __type(key, struct self_key);
    __type(value, __u8);
} self_bypass SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct connection_key);
    __type(value, struct connection_value);
} conn_state SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024);
} flow_events SEC(".maps");

// reason_count (12) * two directions * two actions.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 48);
    __type(key, __u32);
    __type(value, __u64);
} decision_counts SEC(".maps");

// Detailed counters are keyed by policy epoch. The LRU bounds retained
// generations while preserving per-CPU updates for hot packet paths.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, 4096);
    __type(key, struct epoch_decision_key);
    __type(value, __u64);
} decision_epoch_counts SEC(".maps");

// 0 = rate-limited, 1 = ring-buffer reservation failure.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} event_drops SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct event_limiter_value);
} event_limiter SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, 1024);
    __type(key, struct epoch_event_drop_key);
    __type(value, __u64);
} event_drop_epoch_counts SEC(".maps");

// A zero count for the retired slot proves that no packet can still read its
// policy maps. A packet registers for the slot it observed, then reads the
// config again before touching slot data. If the config changed before it
// registered, it drops that guard and retries against the new slot.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} in_flight SEC(".maps");

// Packet identity is the cgroup to which the inherited link is attached.
struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_STORAGE);
    __type(key, struct cgroup_storage_key);
    __type(value, __u64);
} attached_cgroup SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct agent_status_value);
} agent_status SEC(".maps");

#define DIR_EGRESS 0
#define DIR_INGRESS 1
#define DIR_MASK(direction) ((__u8)(1U << (direction)))

#define REASON_UNISOLATED 0
#define REASON_NODE_BYPASS 1
#define REASON_SELF_BYPASS 2
#define REASON_CONNECTION 3
#define REASON_RULE 4
#define REASON_QUARANTINE 5
#define REASON_DEFAULT_DENY 6
#define REASON_MALFORMED 7
#define REASON_FRAGMENT 8
#define REASON_IPV6 9
#define REASON_UNSUPPORTED 10
#define REASON_CONFIG 11

#define ACTION_BLOCKED 0
#define ACTION_ALLOWED 1
#define FLOW_SCHEMA_VERSION 1
#define FLOW_LIMIT_PER_SECOND 100
#define NS_PER_SECOND 1000000000ULL
#define TCP_IDLE_NS (24ULL * 60 * 60 * NS_PER_SECOND)
#define UDP_IDLE_NS (30ULL * NS_PER_SECOND)
/* Coalesce expiry writes to roughly once per second per active connection. */
#define CONNECTION_REFRESH_INTERVAL_NS NS_PER_SECOND
#define IPV4_MORE_FRAGMENTS 0x2000
#define IPV4_FRAGMENT_OFFSET 0x1fff

enum packet_status {
    PACKET_VALID = 0,
    PACKET_IPV6,
    PACKET_MALFORMED,
    PACKET_FRAGMENT,
    PACKET_UNSUPPORTED,
};

struct packet_info {
    __u32 source_ip[4];
    __u32 destination_ip[4];
    __u16 source_port;
    __u16 destination_port;
    __u8 protocol;
    __u8 family;
    __u8 tcp_reset;
    __u8 _padding;
};

/* These helpers only target per-CPU maps. BPF execution cannot migrate
 * between CPUs, and each lookup returns the current CPU's value slot, so a
 * plain increment avoids an unnecessary atomic read-modify-write per packet.
 */
static __always_inline void increment_counter(void *map, __u32 key)
{
    __u64 *counter = bpf_map_lookup_elem(map, &key);
    if (counter)
        *counter += 1;
}

static __always_inline void increment_epoch_counter(void *map, const void *key)
{
    __u64 *counter = bpf_map_lookup_elem(map, key);
    if (counter) {
        *counter += 1;
        return;
    }

    __u64 first = 1;
    if (bpf_map_update_elem(map, key, &first, BPF_NOEXIST) < 0) {
        counter = bpf_map_lookup_elem(map, key);
        if (counter)
            *counter += 1;
    }
}

static __always_inline void count_decision(__u64 epoch, __u8 direction,
                                           __u8 action, __u8 reason)
{
    __u32 key = ((__u32)reason * 2 + direction) * 2 + action;
    increment_counter(&decision_counts, key);

    struct epoch_decision_key epoch_key = {
        .policy_epoch = epoch,
        .direction = direction,
        .action = action,
        .reason = reason,
    };
    increment_epoch_counter(&decision_epoch_counts, &epoch_key);
}

static __always_inline int parse_packet(struct __sk_buff *skb, struct packet_info *packet)
{
    __u8 first_byte = 0;
    if (skb->len < 1 || bpf_skb_load_bytes(skb, 0, &first_byte, sizeof(first_byte)) < 0)
        return PACKET_MALFORMED;

    __u8 version = first_byte >> 4;
    if (version == 6) {
        struct ipv6_header ip6 = {};
        if (skb->len < sizeof(ip6) || bpf_skb_load_bytes(skb, 0, &ip6, sizeof(ip6)) < 0)
            return PACKET_MALFORMED;
        if ((ip6.version_class >> 4) != 6)
            return PACKET_MALFORMED;
        packet->family = 6;
        packet->protocol = ip6.next_header;
        if (bpf_skb_load_bytes(skb, 8, packet->source_ip, 16) < 0 ||
            bpf_skb_load_bytes(skb, 24, packet->destination_ip, 16) < 0)
            return PACKET_MALFORMED;
        return PACKET_IPV6;
    }

    if (version != 4)
        return PACKET_MALFORMED;

    struct ipv4_header ip = {};
    if (skb->len < sizeof(ip) || bpf_skb_load_bytes(skb, 0, &ip, sizeof(ip)) < 0)
        return PACKET_MALFORMED;
    if ((ip.version_ihl >> 4) != 4)
        return PACKET_MALFORMED;

    __u32 header_length = (__u32)(ip.version_ihl & 0x0f) * 4;
    __u32 total_length = bpf_ntohs(ip.total_length);
    if (ip.protocol == IPPROTO_TCP && skb->gso_segs > 1 &&
        total_length < header_length + sizeof(struct tcp_header)) {
        // TCP GSO may reach the cgroup hook before the IPv4 length is
        // finalized. The kernel's GSO marker permits using the skb length
        // for header bounds; ordinary malformed packets still fail closed.
        total_length = skb->len;
    }
    if (header_length < sizeof(ip) || header_length > 60 ||
        total_length < header_length || total_length > skb->len)
        return PACKET_MALFORMED;

    packet->family = 4;
    packet->protocol = ip.protocol;
    packet->source_ip[0] = ip.source;
    packet->destination_ip[0] = ip.destination;

    __u16 fragment = bpf_ntohs(ip.fragment_offset);
    if (fragment & (IPV4_MORE_FRAGMENTS | IPV4_FRAGMENT_OFFSET))
        return PACKET_FRAGMENT;

    if (ip.protocol == IPPROTO_TCP) {
        struct tcp_header tcp = {};
        if (total_length < header_length + sizeof(tcp) ||
            bpf_skb_load_bytes(skb, header_length, &tcp, sizeof(tcp)) < 0)
            return PACKET_MALFORMED;

        __u16 offset_flags = bpf_ntohs(tcp.offset_flags);
        __u32 tcp_header_length = ((__u32)offset_flags >> 12) * 4;
        if (tcp_header_length < sizeof(tcp) || tcp_header_length > total_length - header_length)
            return PACKET_MALFORMED;
        packet->source_port = bpf_ntohs(tcp.source);
        packet->destination_port = bpf_ntohs(tcp.destination);
        packet->tcp_reset = (offset_flags & 0x0004) != 0;
        return PACKET_VALID;
    }

    if (ip.protocol == IPPROTO_UDP) {
        struct udp_header udp = {};
        if (total_length < header_length + sizeof(udp) ||
            bpf_skb_load_bytes(skb, header_length, &udp, sizeof(udp)) < 0)
            return PACKET_MALFORMED;
        __u32 udp_length = bpf_ntohs(udp.length);
        if (udp_length < sizeof(udp) || udp_length > total_length - header_length)
            return PACKET_MALFORMED;
        packet->source_port = bpf_ntohs(udp.source);
        packet->destination_port = bpf_ntohs(udp.destination);
        return PACKET_VALID;
    }

    return PACKET_UNSUPPORTED;
}

static __always_inline void record_event_drop(__u64 epoch, __u32 reason)
{
    increment_counter(&event_drops, reason);
    struct epoch_event_drop_key key = {.policy_epoch = epoch, .reason = reason};
    increment_epoch_counter(&event_drop_epoch_counts, &key);
}

static __always_inline int emit_flow_event(__u64 now, __u64 epoch, __u64 cgroup_id,
                                           __u8 direction, __u8 action, __u8 reason,
                                           const struct packet_info *packet)
{
    __u32 zero = 0;
    struct event_limiter_value *limiter = bpf_map_lookup_elem(&event_limiter, &zero);
    if (!limiter) {
        // Suppress events if the fixed limiter state is unexpectedly unavailable.
        record_event_drop(epoch, 0);
        return 0;
    }
    if (now - limiter->window_start_ns >= NS_PER_SECOND) {
        limiter->window_start_ns = now;
        limiter->emitted = 0;
    }
    if (limiter->emitted >= FLOW_LIMIT_PER_SECOND) {
        record_event_drop(epoch, 0);
        return 0;
    }
    limiter->emitted++;

    struct flow_event *event = bpf_ringbuf_reserve(&flow_events, sizeof(*event), 0);
    if (!event) {
        record_event_drop(epoch, 1);
        return 0;
    }

    event->timestamp_ns = now;
    event->policy_epoch = epoch;
    event->cgroup_id = cgroup_id;
    for (int i = 0; i < 4; i++) {
        if (packet->family == 4) {
            event->source_ip[i] = i == 0 ? bpf_ntohl(packet->source_ip[0]) : 0;
            event->destination_ip[i] = i == 0 ? bpf_ntohl(packet->destination_ip[0]) : 0;
        } else {
            event->source_ip[i] = packet->source_ip[i];
            event->destination_ip[i] = packet->destination_ip[i];
        }
    }
    event->source_port = packet->source_port;
    event->destination_port = packet->destination_port;
    event->protocol = packet->protocol;
    event->direction = direction;
    event->action = action;
    event->reason = reason;
    event->family = packet->family;
    event->schema_version = FLOW_SCHEMA_VERSION;
    for (int i = 0; i < 6; i++)
        event->_padding[i] = 0;
    bpf_ringbuf_submit(event, 0);
    return 1;
}

static __always_inline int decide(struct packet_info *packet, __u64 now, __u64 epoch,
                                  __u64 cgroup_id, __u8 direction, __u8 action, __u8 reason)
{
    count_decision(epoch, direction, action, reason);
    emit_flow_event(now, epoch, cgroup_id, direction, action, reason, packet);
    return action == ACTION_ALLOWED ? 1 : 0;
}

static __always_inline struct active_config_value *current_config(void)
{
    __u32 zero = 0;
    void *inner = bpf_map_lookup_elem(&active_config, &zero);
    if (!inner)
        return 0;
    return bpf_map_lookup_elem(inner, &zero);
}

static __always_inline __u64 attached_cgroup_id(void)
{
    __u64 *cgroup_id = bpf_get_local_storage(&attached_cgroup, 0);
    return cgroup_id ? *cgroup_id : 0;
}

static __always_inline int is_node_address(__u32 slot, __u32 address)
{
    struct node_key key = {.slot = slot};
    __builtin_memcpy(key.address, &address, sizeof(key.address));
    return bpf_map_lookup_elem(&node_bypass, &key) != 0;
}

static __always_inline int is_self_address(__u32 slot, __u64 cgroup_id,
                                           __u32 source, __u32 destination)
{
    if (source != destination)
        return 0;
    struct self_key key = {.cgroup_id = cgroup_id, .slot = slot};
    __builtin_memcpy(key.address, &source, sizeof(key.address));
    return bpf_map_lookup_elem(&self_bypass, &key) != 0;
}

static __always_inline struct connection_key connection_key_for(
    __u64 epoch, __u64 cgroup_id, __u8 direction, const struct packet_info *packet)
{
    struct connection_key key = {
        .policy_epoch = epoch,
        .cgroup_id = cgroup_id,
        .source = packet->source_ip[0],
        .destination = packet->destination_ip[0],
        .source_port = packet->source_port,
        .destination_port = packet->destination_port,
        .protocol = packet->protocol,
        .direction = direction,
    };
    return key;
}

static __always_inline struct connection_key reverse_connection_key(struct connection_key key)
{
    __u32 address = key.source;
    key.source = key.destination;
    key.destination = address;
    __u16 port = key.source_port;
    key.source_port = key.destination_port;
    key.destination_port = port;
    key.direction = key.direction == DIR_EGRESS ? DIR_INGRESS : DIR_EGRESS;
    return key;
}

static __always_inline void remember_reverse_connection(struct connection_key packet_key,
                                                        __u64 now, __u8 tcp_reset)
{
    struct connection_key reverse = reverse_connection_key(packet_key);
    if (tcp_reset) {
        bpf_map_delete_elem(&conn_state, &packet_key);
        bpf_map_delete_elem(&conn_state, &reverse);
        return;
    }

    const __u64 idle_ns = packet_key.protocol == IPPROTO_TCP ? TCP_IDLE_NS : UDP_IDLE_NS;
    struct connection_value *existing = bpf_map_lookup_elem(&conn_state, &reverse);
    if (existing && existing->expires_at_ns > now &&
        existing->expires_at_ns - now > idle_ns - CONNECTION_REFRESH_INTERVAL_NS)
        return;

    struct connection_value value = {
        .expires_at_ns = now + idle_ns,
    };
    bpf_map_update_elem(&conn_state, &reverse, &value, 0);
}

static __always_inline int allow_connection_state(struct connection_key key,
                                                  __u64 now, __u8 tcp_reset)
{
    /* The reverse tuple seeds state on the first allowed packet. */
    struct connection_key reverse = reverse_connection_key(key);
    struct connection_value *value = bpf_map_lookup_elem(&conn_state, &key);
    if (!value)
        value = bpf_map_lookup_elem(&conn_state, &reverse);
    if (!value || value->expires_at_ns <= now)
        return 0;

    if (tcp_reset) {
        bpf_map_delete_elem(&conn_state, &key);
        bpf_map_delete_elem(&conn_state, &reverse);
        return 1;
    }

    const __u64 idle_ns = key.protocol == IPPROTO_TCP ? TCP_IDLE_NS : UDP_IDLE_NS;
    if (value->expires_at_ns - now > idle_ns - CONNECTION_REFRESH_INTERVAL_NS)
        return 1;

    struct connection_value refreshed = {
        .expires_at_ns = now + idle_ns,
    };
    bpf_map_update_elem(&conn_state, &key, &refreshed, 0);
    bpf_map_update_elem(&conn_state, &reverse, &refreshed, 0);
    return 1;
}

static __always_inline int rule_matches(__u32 slot, __u64 cgroup_id,
                                        __u8 direction, const struct packet_info *packet)
{
    __u32 meta = (slot << 31) | ((__u32)direction << 30) |
                 ((__u32)packet->protocol << 16) | packet->destination_port;
    struct policy_rule_key key = {
        .prefix_length = 128,
        .meta = meta,
        .cgroup_id = cgroup_id,
    };
    const __u32 *peer = direction == DIR_EGRESS ? &packet->destination_ip[0] : &packet->source_ip[0];
    __builtin_memcpy(key.peer, peer, sizeof(key.peer));
    return bpf_map_lookup_elem(&policy_rules, &key) != 0;
}

static __always_inline int enforce_packet(struct __sk_buff *skb, __u8 direction, __u64 cgroup_id)
{
    __u64 *in_flight_count = 0;
    __u32 slot = 0;
    __u64 epoch = 0;

    // An old config can be replaced between the first read and the guard
    // increment. The second read prevents such a packet from using a retired
    // slot after userspace has observed its counter at zero. Compare the epoch
    // as well as the slot so two rapid flips cannot create an ABA match.
#pragma unroll
    for (int attempt = 0; attempt < 3; attempt++) {
        struct active_config_value *config = current_config();
        if (!config)
            break;
        slot = config->active_slot;
        epoch = config->policy_epoch;
        if (slot > 1)
            break;
        in_flight_count = bpf_map_lookup_elem(&in_flight, &slot);
        if (!in_flight_count)
            break;
        __sync_fetch_and_add(in_flight_count, 1);
        config = current_config();
        if (config && config->active_slot == slot && config->policy_epoch == epoch)
            break;
        __sync_fetch_and_sub(in_flight_count, 1);
        in_flight_count = 0;
    }

    if (!in_flight_count) {
        struct packet_info missing_config_packet = {};
        __u64 now = bpf_ktime_get_ns();
        return decide(&missing_config_packet, now, 0, cgroup_id, direction,
                      ACTION_BLOCKED, REASON_CONFIG);
    }

    __u64 now = bpf_ktime_get_ns();

    struct subject_key subject_key = {.cgroup_id = cgroup_id, .slot = slot};
    struct subject_value *subject = bpf_map_lookup_elem(&subject_state, &subject_key);
    if (!subject) {
        __sync_fetch_and_sub(in_flight_count, 1);
        return 1;
    }

    struct packet_info packet = {};
    int packet_status = parse_packet(skb, &packet);
    __u8 direction_mask = DIR_MASK(direction);
    if (!(subject->isolated & direction_mask)) {
        int result = decide(&packet, now, epoch, cgroup_id, direction,
                            ACTION_ALLOWED, REASON_UNISOLATED);
        __sync_fetch_and_sub(in_flight_count, 1);
        return result;
    }

    // Node/self exceptions apply only after the packet has passed the
    // supported TCP/UDP parser. Unsupported protocols must remain denied for
    // isolated directions even when their IPv4 address matches a bypass.
    if (packet_status == PACKET_VALID) {
        if (packet.family == 4) {
            __u32 peer = direction == DIR_EGRESS ? packet.destination_ip[0] : packet.source_ip[0];
            if (is_node_address(slot, peer)) {
                int result = decide(&packet, now, epoch, cgroup_id, direction,
                                    ACTION_ALLOWED, REASON_NODE_BYPASS);
                __sync_fetch_and_sub(in_flight_count, 1);
                return result;
            }
            if (is_self_address(slot, cgroup_id, packet.source_ip[0], packet.destination_ip[0])) {
                int result = decide(&packet, now, epoch, cgroup_id, direction,
                                    ACTION_ALLOWED, REASON_SELF_BYPASS);
                __sync_fetch_and_sub(in_flight_count, 1);
                return result;
            }
        }
    }

    if (subject->quarantined & direction_mask) {
        int result = decide(&packet, now, epoch, cgroup_id, direction,
                            ACTION_BLOCKED, REASON_QUARANTINE);
        __sync_fetch_and_sub(in_flight_count, 1);
        return result;
    }

    if (packet_status == PACKET_IPV6) {
        int result = decide(&packet, now, epoch, cgroup_id, direction,
                            ACTION_BLOCKED, REASON_IPV6);
        __sync_fetch_and_sub(in_flight_count, 1);
        return result;
    }
    if (packet_status == PACKET_FRAGMENT) {
        int result = decide(&packet, now, epoch, cgroup_id, direction,
                            ACTION_BLOCKED, REASON_FRAGMENT);
        __sync_fetch_and_sub(in_flight_count, 1);
        return result;
    }
    if (packet_status == PACKET_MALFORMED) {
        int result = decide(&packet, now, epoch, cgroup_id, direction,
                            ACTION_BLOCKED, REASON_MALFORMED);
        __sync_fetch_and_sub(in_flight_count, 1);
        return result;
    }
    if (packet_status != PACKET_VALID) {
        int result = decide(&packet, now, epoch, cgroup_id, direction,
                            ACTION_BLOCKED, REASON_UNSUPPORTED);
        __sync_fetch_and_sub(in_flight_count, 1);
        return result;
    }

    struct connection_key packet_key = connection_key_for(epoch, cgroup_id, direction, &packet);
    if (allow_connection_state(packet_key, now, packet.tcp_reset)) {
        int result = decide(&packet, now, epoch, cgroup_id, direction,
                            ACTION_ALLOWED, REASON_CONNECTION);
        __sync_fetch_and_sub(in_flight_count, 1);
        return result;
    }

    if (rule_matches(slot, cgroup_id, direction, &packet)) {
        remember_reverse_connection(packet_key, now, packet.tcp_reset);
        int result = decide(&packet, now, epoch, cgroup_id, direction,
                            ACTION_ALLOWED, REASON_RULE);
        __sync_fetch_and_sub(in_flight_count, 1);
        return result;
    }

    int result = decide(&packet, now, epoch, cgroup_id, direction,
                        ACTION_BLOCKED, REASON_DEFAULT_DENY);
    __sync_fetch_and_sub(in_flight_count, 1);
    return result;
}

SEC("cgroup_skb/egress")
int ztap_egress(struct __sk_buff *skb)
{
    return enforce_packet(skb, DIR_EGRESS, attached_cgroup_id());
}

SEC("cgroup_skb/ingress")
int ztap_ingress(struct __sk_buff *skb)
{
    return enforce_packet(skb, DIR_INGRESS, attached_cgroup_id());
}

char _license[] SEC("license") = "GPL";
