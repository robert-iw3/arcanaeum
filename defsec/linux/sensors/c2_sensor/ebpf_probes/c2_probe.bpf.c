/*
 * ==============================================================================
 * Script Name: c2_probe.bpf.c
 * Description: eBPF core telemetry and enforcement engine. Utilizes the
 * "Extract and Compute" pattern to maintain wire-speed performance.
 * Intercepts process execution, interval timings, and raw payloads.
 * Enforces active defense via XDP blackholing and bpf_send_signal
 * SIGKILL terminations based on dynamic map lookups.
 * ==============================================================================
 */

// go:build ignore
#include "vmlinux.h"

/* --- UAPI Fallbacks for generic vmlinux.h --- */
#ifndef XDP_PASS
enum xdp_action {
    XDP_ABORTED = 0,
    XDP_DROP,
    XDP_PASS,
    XDP_TX,
    XDP_REDIRECT,
};
#endif

#ifndef __BPF_MD_PTR
struct xdp_md {
    __u32 data;
    __u32 data_end;
    __u32 data_meta;
    __u32 ingress_ifindex;
    __u32 rx_queue_index;
    __u32 egress_ifindex;
};
#endif

struct trace_entry {
    short unsigned int type;
    unsigned char flags;
    unsigned char preempt_count;
    int pid;
};

struct trace_event_raw_sys_enter {
    struct trace_entry ent;
    long int id;
    long unsigned int args[6];
    char __data[0];
};

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define PAYLOAD_SAMPLE_SIZE 256
#define ETH_P_IP   0x0800
#define ETH_P_IPV6 0x86DD
#define AF_INET    2
#define AF_INET6   10

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// ==============================================================================
// DATA STRUCTURES
// ==============================================================================
struct event_t {
    u32 pid;
    u32 uid;
    u32 type;
    u8 af;
    u16 dns_flags;
    u8 _pad[1];
    u8 saddr[16];
    u8 daddr[16];
    u16 dport;
    u16 is_outbound;
    u32 packet_size;
    u64 ts;
    u64 interval_ns;
    char comm[16];
    u8 payload[PAYLOAD_SAMPLE_SIZE];
};

struct flow_key {
    u32 pid;
    u8  daddr[16];
};

struct udp_recv_stash {
    u64 msg_ptr;
    u8  daddr[16];
    u16 dport;
    u8  af;
    u8  _pad;
    u32 uid;
    char comm[16];
};

// ==============================================================================
// MAPS
// ==============================================================================
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024);
} rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10000);
    __type(key, u32);           // IPv4 address
    __type(value, u8);
} blocklist_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10000);
    __type(key, u8[16]);        // IPv6 address
    __type(value, u8);
} blocklist_v6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 50000);
    __type(key, struct flow_key);
    __type(value, u64);
} last_seen_ts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} drop_metrics SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 5000);
    __type(key, u32);
    __type(value, u8);
} trusted_pids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct udp_recv_stash);
} udp_recv_ctx SEC(".maps");

// ==============================================================================
// HELPERS
// ==============================================================================

/*
 * struct iov_iter's iov pointer was renamed from __iov to iov in kernel 6.4.
 * Kernel 6.0+ also introduced ITER_UBUF (single-buffer mode) where the
 * data pointer lives at iter.ubuf rather than iter.iov->iov_base.
 * CO-RE type flavors let us compile against all layouts and resolve at load time.
 */
struct iov_iter___pre64 {
    const struct iovec *__iov;
};

struct iov_iter___post64 {
    const struct iovec *iov;
};

struct iov_iter___ubuf {
    void *ubuf;
};

static __always_inline int read_msg_payload(struct msghdr *msg, void *buf, __u32 buf_sz) {
    struct iovec iov = {};
    const void *iov_ptr = NULL;

    /* Try ITER_UBUF first (kernel 6.0+, single-buffer sendmsg) */
    if (bpf_core_field_exists(struct iov_iter___ubuf, ubuf)) {
        struct iov_iter___ubuf *iter = (void *)&msg->msg_iter;
        const void *ubuf_ptr = BPF_CORE_READ(iter, ubuf);
        if (ubuf_ptr) {
            return bpf_probe_read_user(buf, buf_sz, ubuf_ptr);
        }
    }

    /* Fall back to ITER_IOVEC (pre-6.4 __iov vs post-6.4 iov) */
    if (bpf_core_field_exists(struct iov_iter___pre64, __iov)) {
        struct iov_iter___pre64 *iter = (void *)&msg->msg_iter;
        iov_ptr = BPF_CORE_READ(iter, __iov);
    } else {
        struct iov_iter___post64 *iter = (void *)&msg->msg_iter;
        iov_ptr = BPF_CORE_READ(iter, iov);
    }

    if (!iov_ptr)
        return -1;
    if (bpf_probe_read_kernel(&iov, sizeof(iov), iov_ptr) != 0)
        return -1;
    if (!iov.iov_base)
        return -1;
    return bpf_probe_read_user(buf, buf_sz, iov.iov_base);
}

static __always_inline void calculate_interval(struct event_t *e) {
    struct flow_key key = {};
    key.pid = e->pid;
    __builtin_memcpy(key.daddr, e->daddr, 16);

    u64 ts = e->ts;
    u64 *last_ts = bpf_map_lookup_elem(&last_seen_ts, &key);
    if (last_ts) {
        e->interval_ns = ts - *last_ts;
    } else {
        e->interval_ns = 0;
    }
    bpf_map_update_elem(&last_seen_ts, &key, &ts, BPF_ANY);
}

static __always_inline void read_sock_addrs(struct sock *sk, struct event_t *e) {
    u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);

    if (family == AF_INET) {
        e->af = 4;
        u32 saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        __builtin_memcpy(e->saddr, &saddr, 4);
        __builtin_memcpy(e->daddr, &daddr, 4);
    } else if (family == AF_INET6) {
        e->af = 6;
        BPF_CORE_READ_INTO(e->saddr, sk, __sk_common.skc_v6_rcv_saddr);
        BPF_CORE_READ_INTO(e->daddr, sk, __sk_common.skc_v6_daddr);
    }

    e->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
}

static __always_inline int check_blocklist(struct event_t *e) {
    if (e->af == 4) {
        u32 daddr;
        __builtin_memcpy(&daddr, e->daddr, 4);
        u8 *blocked = bpf_map_lookup_elem(&blocklist_v4, &daddr);
        if (blocked && *blocked == 1) return 1;
    } else if (e->af == 6) {
        u8 *blocked = bpf_map_lookup_elem(&blocklist_v6, e->daddr);
        if (blocked && *blocked == 1) return 1;
    }
    return 0;
}

static __always_inline int init_event(struct event_t *e) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    if (e->pid < 100) return -1;

    u8 *is_trusted = bpf_map_lookup_elem(&trusted_pids, &e->pid);
    if (is_trusted && *is_trusted == 1) return -1;

    e->ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    return 0;
}

// ==============================================================================
// XDP ENFORCEMENT (Dual-Stack)
// ==============================================================================
SEC("xdp")
int xdp_drop_malicious(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *iph = (struct iphdr *)(eth + 1);
        if ((void *)(iph + 1) > data_end) return XDP_PASS;

        u8 *b = bpf_map_lookup_elem(&blocklist_v4, &iph->daddr);
        if (b && *b == 1) return XDP_DROP;
        b = bpf_map_lookup_elem(&blocklist_v4, &iph->saddr);
        if (b && *b == 1) return XDP_DROP;

    } else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6h = (struct ipv6hdr *)(eth + 1);
        if ((void *)(ip6h + 1) > data_end) return XDP_PASS;

        u8 *b = bpf_map_lookup_elem(&blocklist_v6, &ip6h->saddr);
        if (b && *b == 1) return XDP_DROP;
        b = bpf_map_lookup_elem(&blocklist_v6, &ip6h->daddr);
        if (b && *b == 1) return XDP_DROP;
    }

    return XDP_PASS;
}

// ==============================================================================
// TELEMETRY HOOKS
// ==============================================================================

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));

    u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    if (e->pid < 100) { bpf_ringbuf_discard(e, 0); return 0; }

    e->ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->type = 1;
    e->af = 4;
    calculate_interval(e);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_memfd_create")
int trace_memfd_create(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));

    e->pid = bpf_get_current_pid_tgid() >> 32;
    if (e->pid < 100) { bpf_ringbuf_discard(e, 0); return 0; }

    e->ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->type = 5;
    e->af = 4;
    calculate_interval(e);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// --- TCP IPv4 Connect ---
SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(trace_tcp_v4_connect, struct sock *sk) {
    struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));

    if (init_event(e) < 0) { bpf_ringbuf_discard(e, 0); return 0; }

    e->type = 2;
    e->is_outbound = 1;
    read_sock_addrs(sk, e);

    if (check_blocklist(e)) {
        bpf_send_signal(9);
    }

    calculate_interval(e);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// --- TCP IPv6 Connect ---
SEC("kprobe/tcp_v6_connect")
int BPF_KPROBE(trace_tcp_v6_connect, struct sock *sk) {
    struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));

    if (init_event(e) < 0) { bpf_ringbuf_discard(e, 0); return 0; }

    e->type = 2;
    e->is_outbound = 1;
    read_sock_addrs(sk, e);

    if (check_blocklist(e)) {
        bpf_send_signal(9);
    }

    calculate_interval(e);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// --- TCP Send ---
SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(trace_tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size) {
    struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));

    if (init_event(e) < 0) { bpf_ringbuf_discard(e, 0); return 0; }

    e->is_outbound = 1;
    e->packet_size = size;
    read_sock_addrs(sk, e);

    e->type = 3;
    if (size >= PAYLOAD_SAMPLE_SIZE && (e->dport == 80 || e->dport == 443 || e->dport == 8080 || e->dport == 8443)) {
        e->type = 7;
        read_msg_payload(msg, &e->payload, sizeof(e->payload));
    }

    calculate_interval(e);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// --- TCP Recv ---
SEC("kprobe/tcp_recvmsg")
int BPF_KPROBE(trace_tcp_recvmsg, struct sock *sk, struct msghdr *msg, size_t len) {
    struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));

    if (init_event(e) < 0) { bpf_ringbuf_discard(e, 0); return 0; }

    e->type = 4;
    e->is_outbound = 0;
    e->packet_size = len;
    read_sock_addrs(sk, e);
    calculate_interval(e);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// --- UDP Send (+ DNS payload capture) ---
SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(trace_udp_sendmsg, struct sock *sk, struct msghdr *msg, size_t len) {
    struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));

    if (init_event(e) < 0) { bpf_ringbuf_discard(e, 0); return 0; }

    e->is_outbound = 1;
    e->packet_size = len;
    read_sock_addrs(sk, e);

    if (e->daddr[0] == 0 && e->daddr[1] == 0 && e->daddr[2] == 0 && e->daddr[3] == 0) {
        void *msg_name = BPF_CORE_READ(msg, msg_name);
        if (msg_name) {
            if (e->af == 4 || e->af == 0) {
                struct sockaddr_in addr = {};
                if (bpf_probe_read_user(&addr, sizeof(addr), msg_name) == 0) {
                    __builtin_memcpy(e->daddr, &addr.sin_addr.s_addr, 4);
                    e->dport = bpf_ntohs(addr.sin_port);
                    e->af = 4;
                }
            }
        }
    }

    e->type = 3;
    if (e->dport == 53) {
        e->type = 6;
        if (read_msg_payload(msg, &e->payload, sizeof(e->payload)) == 0) {
            e->dns_flags = (e->payload[2] << 8) | e->payload[3];
        }
    }

    calculate_interval(e);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// --- File Access Hooks (Exfiltration Tracking) ---

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));

    u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid >> 32;
    if (e->pid < 100) { bpf_ringbuf_discard(e, 0); return 0; }

    u8 *is_trusted = bpf_map_lookup_elem(&trusted_pids, &e->pid);
    if (is_trusted && *is_trusted == 1) { bpf_ringbuf_discard(e, 0); return 0; }

    const char *pathname = (const char *)ctx->args[1];
    bpf_probe_read_user_str(&e->payload, sizeof(e->payload), pathname);

    if (e->payload[0] != '/' ||
        (__builtin_memcmp(e->payload, "/etc/shadow", 11) != 0 &&
         __builtin_memcmp(e->payload, "/etc/passwd", 11) != 0 &&
         __builtin_memcmp(e->payload, "/root/", 6) != 0 &&
         __builtin_memcmp(e->payload, "/home/", 6) != 0 &&
         __builtin_memcmp(e->payload, "/proc/", 6) != 0)) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->type = 8;
    e->af = 4;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// --- UDP Recv ---
SEC("kprobe/udp_recvmsg")
int BPF_KPROBE(trace_udp_recvmsg_entry, struct sock *sk, struct msghdr *msg, size_t len) {
    struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        u32 key = 0;
        u64 *drop_cnt = bpf_map_lookup_elem(&drop_metrics, &key);
        if (drop_cnt) __sync_fetch_and_add(drop_cnt, 1);
        return 0;
    }
    __builtin_memset(e, 0, sizeof(*e));

    if (init_event(e) < 0) { bpf_ringbuf_discard(e, 0); return 0; }

    e->type = 4;
    e->is_outbound = 0;
    e->packet_size = len;
    read_sock_addrs(sk, e);

    u16 remote_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    if (remote_port == 53) {
        e->type = 6;
        u32 zero = 0;
        struct udp_recv_stash stash = {};
        stash.msg_ptr = (u64)msg;
        __builtin_memcpy(stash.daddr, e->daddr, 16);
        stash.dport = e->dport;
        stash.af = e->af;
        stash.uid = e->uid;
        __builtin_memcpy(stash.comm, e->comm, 16);
        bpf_map_update_elem(&udp_recv_ctx, &zero, &stash, BPF_ANY);
    }

    calculate_interval(e);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kretprobe/udp_recvmsg")
int BPF_KRETPROBE(trace_udp_recvmsg_exit, int ret) {
    if (ret <= 0) return 0;

    u32 zero = 0;
    struct udp_recv_stash *stash = bpf_map_lookup_elem(&udp_recv_ctx, &zero);
    if (!stash || stash->msg_ptr == 0) return 0;

    struct msghdr *msg = (struct msghdr *)stash->msg_ptr;

    struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        struct udp_recv_stash empty = {};
        bpf_map_update_elem(&udp_recv_ctx, &zero, &empty, BPF_ANY);
        return 0;
    }
    __builtin_memset(e, 0, sizeof(*e));

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = stash->uid;
    e->ts = bpf_ktime_get_ns();
    e->type = 9;
    e->is_outbound = 0;
    e->af = stash->af;
    e->dport = stash->dport;
    __builtin_memcpy(e->daddr, stash->daddr, 16);
    __builtin_memcpy(e->comm, stash->comm, 16);

    if (read_msg_payload(msg, &e->payload, sizeof(e->payload)) == 0) {
        e->dns_flags = (e->payload[2] << 8) | e->payload[3];
    }

    struct udp_recv_stash empty = {};
    bpf_map_update_elem(&udp_recv_ctx, &zero, &empty, BPF_ANY);

    bpf_ringbuf_submit(e, 0);
    return 0;
}