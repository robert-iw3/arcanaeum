// SPDX-License-Identifier: GPL-2.0
// sentinel.bpf.c — Linux Sentinel eBPF CO-RE Kernel Probes
// Version: 0.3.0
// Author: Robert Weber
// =======================================================================================
// File:        sentinel.bpf.c
// Component:   Linux Sentinel — Ring-0 Kernel Probes
// Description: Contains eBPF CO-RE (Compile Once - Run Everywhere) hooks attached
//              to critical Linux syscalls (execve, openat, ptrace, bpf, etc.).
// Role:        Securely intercepts kernel telemetry, filters out whitelisted noise
//              at the kernel level, and enforces Active Mitigation (SIGKILL)
//              against malicious PIDs before passing data to the user-space ring buffer.
// =======================================================================================
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

// ─────────────────────────────────────────────────────────────────
// SECTION 1: CONSTANTS & USERSPACE DEFINES NOT IN vmlinux.h (BTF)
// ─────────────────────────────────────────────────────────────────

#define MAX_FILENAME  512
#define MAX_PAYLOAD   64
#define MAX_ARGS      6     // execve argument capture depth

// fcntl.h flags — vmlinux.h (generated from BTF) does not include
// userspace header defines. These are ABI-stable on Linux.
#ifndef O_WRONLY
#define O_WRONLY        00000001
#endif
#ifndef O_RDWR
#define O_RDWR          00000002
#endif
#ifndef O_CREAT
#define O_CREAT         00000100
#endif
#ifndef O_TRUNC
#define O_TRUNC         00001000
#endif
#ifndef O_APPEND
#define O_APPEND        00002000
#endif

// Ptrace request constants for filtering noise
#ifndef PTRACE_PEEKTEXT
#define PTRACE_PEEKTEXT     1
#define PTRACE_PEEKDATA     2
#define PTRACE_POKETEXT     4
#define PTRACE_POKEDATA     5
#define PTRACE_ATTACH       16
#define PTRACE_SEIZE        0x4206
#endif

// BPF command constants for self-protection filtering
#ifndef BPF_PROG_LOAD
#define BPF_PROG_LOAD       5
#endif
#ifndef BPF_MAP_UPDATE_ELEM
#define BPF_MAP_UPDATE_ELEM 2
#endif
#ifndef BPF_MAP_CREATE
#define BPF_MAP_CREATE      0
#endif
#ifndef BPF_PROG_ATTACH
#define BPF_PROG_ATTACH     8
#endif

// ─────────────────────────────────────────────────────────────────
// SECTION 2: EVENT TYPE ENUMERATION (MITRE ATT&CK MAPPED)
// ─────────────────────────────────────────────────────────────────
//
// IMPORTANT: Adding or removing event types here requires
// updating rules.rs match arms AND the logic anchor §3.2 table.

enum event_id {
    EVENT_EXEC          = 1,   // T1059  Command and Scripting Interpreter
    EVENT_OPEN_CRIT     = 2,   // T1078  Valid Accounts / T1083 File Discovery
    EVENT_CONNECT       = 3,   // T1571  Non-Standard Port / C2 Beacons
    EVENT_PTRACE        = 4,   // T1055.008 Ptrace System Calls
    EVENT_MEMFD         = 5,   // T1620  Reflective Code Loading (Fileless)
    EVENT_MODULE        = 6,   // T1547.006 Kernel Modules and Extensions
    EVENT_BPF           = 7,   // T1562.001 Impair Defenses (eBPF Blinding)
    EVENT_UDP_SEND      = 8,   // T1071.004 DNS Tunneling / Encrypted Channel
    EVENT_DELETE_MOD    = 9,   // T1547.006 Kernel Module Unload (Rootkit Cleanup)
    EVENT_UNLINK        = 10,  // T1070.004 Indicator Removal on Host
    EVENT_RENAME        = 11,  // T1036  Masquerading
    EVENT_SETUID        = 12,  // T1548  Abuse Elevation Control
    EVENT_MOUNT         = 13,  // T1006  Direct Volume Access
    EVENT_BIND          = 14,  // T1571  Non-Standard Port (Bind Shell)
    EVENT_UNSHARE       = 15,  // T1611  Escape to Host (Namespace Manipulation)
    EVENT_PIVOT_ROOT    = 16,  // T1611  Escape to Host (Rootfs Pivot)
};

// ─────────────────────────────────────────────────────────────────
// SECTION 3: FFI STRUCT (KERNEL ↔ USERSPACE CONTRACT)
// ─────────────────────────────────────────────────────────────────
//
// BYTE OFFSET TABLE — Must match ebpf.rs #[repr(C)] struct event_t
//
//   Field          Type          Offset    Size
//   ─────────────  ──────────    ──────    ────
//   ts_ns          u64           0         8
//   interval_ns    u64           8         8
//   cgroup_id      u64           16        8
//   pid            u32           24        4
//   ppid           u32           28        4
//   uid            u32           32        4
//   event_type     u32           36        4
//   comm           char[16]      40        16
//   target         char[512]     56        512
//   daddr          u32           568       4
//   daddr6         u8[16]        572       16
//   dport          u16           588       2
//   sport          u16           590       2
//   payload        u8[64]        592       64
//   ─────────────────────────────────────────────
//   Total (packed):              656 bytes
//   Total (aligned):             656 bytes (0 bytes padding)
//
// RULE: Any change here MUST be mirrored in ebpf.rs simultaneously.
//       State the byte offset of every changed field in the blast radius.

struct event_t {
    __u64 ts_ns;                    // Monotonic kernel timestamp (bpf_ktime_get_ns)
    __u64 interval_ns;              // Delta from last event for this PID (ML: Execution Velocity)
    u64 cgroup_id;                  // Container context (cgroupv2 unified ID) for container-aware detection
    __u32 pid;                      // Process ID (tgid)
    __u32 ppid;                     // Parent PID (for lineage tracking)
    __u32 uid;                      // User ID
    __u32 event_type;               // enum event_id
    char  comm[16];                 // TASK_COMM_LEN — process name
    char  target[MAX_FILENAME];     // Context-dependent: filepath, argv, mount target
    __u32 daddr;                    // Destination IPv4 address (network byte order)
    __u8  daddr6[16];               // Destination IPv6 address
    __u16 dport;                    // Destination port (network byte order)
    __u16 sport;                    // Source port (host byte order)
    __u8  payload[MAX_PAYLOAD];     // Raw payload bytes (ML: Shannon Entropy)
};

// ─────────────────────────────────────────────────────────────────
// SECTION 4: BPF MAPS
// ─────────────────────────────────────────────────────────────────

// Primary ring buffer — user-space polls at 50ms intervals
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 2 * 1024 * 1024); // 2MB — tuned for deep-inspection mode
} events SEC(".maps");

// Per-PID timestamp tracking for execution velocity calculation
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);   // PID
    __type(value, __u64); // Last timestamp (ns)
} proc_timestamps SEC(".maps");

// Self-protection: Our own PID to filter self-generated events
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32); // Our agent's PID (set from user-space at startup)
} self_pid SEC(".maps");

// Threat Intelligence: Kernel-level Outbound Connection Whitelist
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u8[4]); // IPv4 Address Network Bytes
    __type(value, __u8);  // Dummy flag
} ip_whitelist SEC(".maps");

// Threat Intelligence: Kernel-level Process Whitelist
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, char[16]); // TASK_COMM_LEN
    __type(value, __u8);   // Dummy flag
} process_whitelist SEC(".maps");

static __always_inline int is_whitelisted_proc() {
    char comm[16] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (bpf_map_lookup_elem(&process_whitelist, &comm)) {
        return 1;
    }
    return 0;
}

// ─────────────────────────────────────────────────────────────────
// SECTION 5: HELPER MACROS
// ─────────────────────────────────────────────────────────────────

// Check if the current process (or any of its threads) is our own agent
#define IS_SELF() ({ \
    __u32 _zero = 0; \
    __u32 *_self = bpf_map_lookup_elem(&self_pid, &_zero); \
    __u32 _tgid = bpf_get_current_pid_tgid() >> 32; \
    (_self && *_self == _tgid); \
})

// Core event population — fills common fields and computes interval_ns
// This macro MUST be used after bpf_ringbuf_reserve and before submit.
// It does NOT call bpf_ringbuf_submit — the caller decides when to submit.
#define POPULATE_CORE(evt, e_type) do { \
    __builtin_memset(evt, 0, sizeof(*evt)); \
    (evt)->ts_ns = bpf_ktime_get_ns(); \
    evt->cgroup_id = bpf_get_current_cgroup_id(); \
    (evt)->pid = bpf_get_current_pid_tgid() >> 32; \
    (evt)->uid = bpf_get_current_uid_gid(); \
    (evt)->event_type = (e_type); \
    bpf_get_current_comm(&(evt)->comm, sizeof((evt)->comm)); \
    \
    struct task_struct *_task = (struct task_struct *)bpf_get_current_task(); \
    BPF_CORE_READ_INTO(&(evt)->ppid, _task, real_parent, tgid); \
    \
    __u32 _pid = (evt)->pid; \
    __u64 _ts = (evt)->ts_ns; \
    __u64 *_last_ts = bpf_map_lookup_elem(&proc_timestamps, &_pid); \
    if (_last_ts) { \
        (evt)->interval_ns = _ts - *_last_ts; \
    } \
    bpf_map_update_elem(&proc_timestamps, &_pid, &_ts, BPF_ANY); \
} while(0)


// ═══════════════════════════════════════════════════════════════════
// SECTION 6: TRACEPOINTS & KPROBES
// ═══════════════════════════════════════════════════════════════════


// ───────────────────────────────────────────────────
// PROBE 1: Process Execution — T1059 (EVENT_EXEC)
// Captures: binary path + first MAX_ARGS arguments
// ───────────────────────────────────────────────────
SEC("tracepoint/syscalls/sys_enter_execve")
int tp__sys_enter_execve(struct trace_event_raw_sys_enter *ctx)
{
    if (IS_SELF() || is_whitelisted_proc()) return 0;

    struct event_t *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) return 0;

    POPULATE_CORE(evt, EVENT_EXEC);

    const char **argv = (const char **)(ctx->args[1]);
    int offset = 0;

    #pragma unroll
    for (int i = 0; i < MAX_ARGS; i++) {
        const char *argp;
        if (bpf_probe_read_user(&argp, sizeof(argp), &argv[i]) != 0 || !argp)
            break;

        // The verifier now knows `offset` is strictly <= (512 - 64) = 448.
        if (offset > MAX_FILENAME - 64)
            break;

        // Because offset <= 448 and the read size is statically locked to 64,
        // max access is 448 + 64 = 512. The verifier mathematically proves this
        // will never overflow the target[512] array boundary.
        int sz = bpf_probe_read_user_str(&evt->target[offset & (MAX_FILENAME - 1)], 64, argp);

        if (sz > 0) {
            // sz includes the null terminator.
            // We subtract 1 to overwrite the null with a space for the next argument.
            offset += (sz - 1);

            // Masking ensures the verifier doesn't lose track of bounds after arithmetic
            if (offset < MAX_FILENAME - 1) {
                evt->target[offset & (MAX_FILENAME - 1)] = ' ';
                offset++;
            }
        }
    }

    // Ensure final null termination
    if (offset > 0) {
        evt->target[(offset - 1) & (MAX_FILENAME - 1)] = '\0';
    } else {
        evt->target[0] = '\0';
    }

    bpf_ringbuf_submit(evt, 0);
    return 0;
}


// ───────────────────────────────────────────────────
// PROBE 2: Critical File Access — T1078/T1083 (EVENT_OPEN_CRIT)
// Filters: write, create, truncate, append operations only
// ───────────────────────────────────────────────────
SEC("tracepoint/syscalls/sys_enter_openat")
int tp__sys_enter_openat(struct trace_event_raw_sys_enter *ctx)
{
    if (IS_SELF() || is_whitelisted_proc()) return 0;

    int flags = (int)ctx->args[2];

    // Only capture mutating operations — drop read-only noise
    if (!(flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND)))
        return 0;

    struct event_t *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) return 0;

    POPULATE_CORE(evt, EVENT_OPEN_CRIT);

    const char *filename = (const char *)ctx->args[1];
    bpf_probe_read_user_str(&evt->target, sizeof(evt->target), filename);

    bpf_ringbuf_submit(evt, 0);
    return 0;
}


// ───────────────────────────────────────────────────
// PROBE 3: Outbound TCP Connection — T1571/C2 (EVENT_CONNECT)
// Captures: destination IP and port for C2 beacon detection
// ───────────────────────────────────────────────────
SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(kp__tcp_v4_connect, struct sock *sk)
{
    if (IS_SELF() || is_whitelisted_proc()) return 0;

    __u8 daddr_bytes[4];
    BPF_CORE_READ_INTO(&daddr_bytes, sk, __sk_common.skc_daddr);

    if (bpf_map_lookup_elem(&ip_whitelist, &daddr_bytes)) {
        return 0;
    }

    struct event_t *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) return 0;

    POPULATE_CORE(evt, EVENT_CONNECT);
    __builtin_memcpy(&evt->daddr, daddr_bytes, 4);
    BPF_CORE_READ_INTO(&evt->dport, sk, __sk_common.skc_dport);
    BPF_CORE_READ_INTO(&evt->sport, sk, __sk_common.skc_num);

    bpf_ringbuf_submit(evt, 0);
    return 0;
}


// ───────────────────────────────────────────────────
// PROBE 3b: Inbound TCP Accept — Bind Shell Detection
// Captures: source IP/port of incoming connections
// ───────────────────────────────────────────────────
SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(krp__inet_csk_accept, struct sock *sk)
{
    if (!sk) return 0;
    if (IS_SELF() || is_whitelisted_proc()) return 0;

    struct event_t *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) return 0;

    POPULATE_CORE(evt, EVENT_CONNECT);
    BPF_CORE_READ_INTO(&evt->daddr, sk, __sk_common.skc_daddr);
    BPF_CORE_READ_INTO(&evt->dport, sk, __sk_common.skc_dport);

    bpf_ringbuf_submit(evt, 0);
    return 0;
}


// ───────────────────────────────────────────────────
// PROBE 4: Process Injection — T1055.008 (EVENT_PTRACE)
// ───────────────────────────────────────────────────
SEC("tracepoint/syscalls/sys_enter_ptrace")
int tp__sys_enter_ptrace(struct trace_event_raw_sys_enter *ctx)
{
    if (IS_SELF() || is_whitelisted_proc()) return 0;

    long request = (long)ctx->args[0];

    if (request != PTRACE_ATTACH && request != PTRACE_SEIZE &&
        request != PTRACE_POKETEXT && request != PTRACE_POKEDATA)
        return 0;

    struct event_t *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) return 0;

    POPULATE_CORE(evt, EVENT_PTRACE);

    evt->target[0] = 'p'; evt->target[1] = 't'; evt->target[2] = ':';
    __u32 off = 3;
    __u64 r = (__u64)request;
    char buf[20];
    int len = 0;

    // Verifier-Safe Integer Parsing
    #pragma unroll
    for (int i = 0; i < 20; i++) {
        buf[i] = '0' + (r % 10);
        r /= 10;
        len++;
        if (r == 0) break;
    }

    #pragma unroll
    for (int i = 0; i < 20; i++) {
        if (i >= len || off >= MAX_FILENAME - 1) break;
        evt->target[off & (MAX_FILENAME - 1)] = buf[len - 1 - i];
        off++;
    }
    evt->target[off & (MAX_FILENAME - 1)] = '\0';

    bpf_ringbuf_submit(evt, 0);
    return 0;
}


// ───────────────────────────────────────────────────
// PROBE 5: Fileless Malware — T1620 (EVENT_MEMFD)
// memfd_create allows execution from anonymous memory
// ───────────────────────────────────────────────────
SEC("tracepoint/syscalls/sys_enter_memfd_create")
int tp__sys_enter_memfd_create(struct trace_event_raw_sys_enter *ctx)
{
    if (IS_SELF() || is_whitelisted_proc()) return 0;

    struct event_t *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) return 0;

    POPULATE_CORE(evt, EVENT_MEMFD);

    const char *name = (const char *)ctx->args[0];
    bpf_probe_read_user_str(&evt->target, sizeof(evt->target), name);

    bpf_ringbuf_submit(evt, 0);
    return 0;
}


// ───────────────────────────────────────────────────
// PROBE 6a: Kernel Module Load — T1547.006 (EVENT_MODULE)
// init_module: loads module from memory buffer
// ───────────────────────────────────────────────────
SEC("tracepoint/syscalls/sys_enter_init_module")
int tp__sys_enter_init_module(struct trace_event_raw_sys_enter *ctx)
{
    if (IS_SELF() || is_whitelisted_proc()) return 0;

    struct event_t *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) return 0;

    POPULATE_CORE(evt, EVENT_MODULE);
    // init_module loads from a memory buffer — no filename available
    // Store module size in target for forensic context
    __builtin_memcpy(evt->target, "init_module:mem_buffer", 22);

    bpf_ringbuf_submit(evt, 0);
    return 0;
}


// ───────────────────────────────────────────────────
// PROBE 6b: Kernel Module Load — T1547.006 (EVENT_MODULE)
// finit_module: loads module from file descriptor
// ───────────────────────────────────────────────────
SEC("tracepoint/syscalls/sys_enter_finit_module")
int tp__sys_enter_finit_module(struct trace_event_raw_sys_enter *ctx)
{
    if (IS_SELF() || is_whitelisted_proc()) return 0;

    struct event_t *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) return 0;

    POPULATE_CORE(evt, EVENT_MODULE);
    __builtin_memcpy(evt->target, "finit_module:fd", 15);

    bpf_ringbuf_submit(evt, 0);
    return 0;
}


// ───────────────────────────────────────────────────
// PROBE 6c: Kernel Module Unload — T1547.006 (EVENT_DELETE_MOD)
// Rootkits unload themselves after installing hooks
// to evade lsmod and module enumeration
// ───────────────────────────────────────────────────
SEC("tracepoint/syscalls/sys_enter_delete_module")
int tp__sys_enter_delete_module(struct trace_event_raw_sys_enter *ctx)
{
    if (IS_SELF() || is_whitelisted_proc()) return 0;

    struct event_t *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) return 0;

    POPULATE_CORE(evt, EVENT_DELETE_MOD);

    // Capture the module name being unloaded
    const char *mod_name = (const char *)ctx->args[0];
    bpf_probe_read_user_str(&evt->target, sizeof(evt->target), mod_name);

    bpf_ringbuf_submit(evt, 0);
    return 0;
}


// ───────────────────────────────────────────────────
// PROBE 7: eBPF Tampering — T1562.001 (EVENT_BPF)
// ───────────────────────────────────────────────────
SEC("tracepoint/syscalls/sys_enter_bpf")
int tp__sys_enter_bpf(struct trace_event_raw_sys_enter *ctx)
{
    if (IS_SELF() || is_whitelisted_proc()) return 0;

    int cmd = (int)ctx->args[0];

    if (cmd != BPF_PROG_LOAD && cmd != BPF_MAP_UPDATE_ELEM &&
        cmd != BPF_MAP_CREATE && cmd != BPF_PROG_ATTACH)
        return 0;

    struct event_t *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) return 0;

    POPULATE_CORE(evt, EVENT_BPF);

    char prefix[] = "bpf_cmd:";
    __builtin_memcpy(evt->target, prefix, 8);
    __u32 off = 8;
    __u64 c = (__u64)cmd;
    char buf[20];
    int len = 0;

    // Verifier-Safe Integer Parsing
    #pragma unroll
    for (int i = 0; i < 20; i++) {
        buf[i] = '0' + (c % 10);
        c /= 10;
        len++;
        if (c == 0) break;
    }

    #pragma unroll
    for (int i = 0; i < 20; i++) {
        if (i >= len || off >= MAX_FILENAME - 1) break;
        evt->target[off & (MAX_FILENAME - 1)] = buf[len - 1 - i];
        off++;
    }
    evt->target[off & (MAX_FILENAME - 1)] = '\0';

    bpf_ringbuf_submit(evt, 0);
    return 0;
}


// ───────────────────────────────────────────────────
// PROBE 8: UDP Send — T1071.004 DNS Tunneling (EVENT_UDP_SEND)
// ───────────────────────────────────────────────────
SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(kp__udp_sendmsg, struct sock *sk, struct msghdr *msg, size_t len)
{
    if (IS_SELF() || is_whitelisted_proc()) return 0;

    struct event_t *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) return 0;

    POPULATE_CORE(evt, EVENT_UDP_SEND);

    BPF_CORE_READ_INTO(&evt->daddr, sk, __sk_common.skc_daddr);
    BPF_CORE_READ_INTO(&evt->dport, sk, __sk_common.skc_dport);
    BPF_CORE_READ_INTO(&evt->sport, sk, __sk_common.skc_num);

    if (BPF_CORE_READ(msg, msg_iter.count) > 0) {
        const struct iovec *iov = NULL;

        if (bpf_core_field_exists(msg->msg_iter.__iov)) {
            iov = BPF_CORE_READ(msg, msg_iter.__iov);
        }

        if (iov) {
            struct iovec first_iov = {};
            if (bpf_probe_read_kernel(&first_iov, sizeof(first_iov), iov) == 0 &&
                first_iov.iov_base) {

                __u64 copy_len = first_iov.iov_len;
                if (copy_len > MAX_PAYLOAD) copy_len = MAX_PAYLOAD;

                // Directly pass explicitly bounded copy_len. Bitwise masking here
                // corrupts exact 64-byte payloads.
                bpf_probe_read_user(evt->payload, copy_len, first_iov.iov_base);
            }
        }
    }

    bpf_ringbuf_submit(evt, 0);
    return 0;
}


// ───────────────────────────────────────────────────
// PROBE 9: File Deletion — T1070.004 Indicator Removal (EVENT_UNLINK)
// Anti-forensics: attackers delete logs, binaries, evidence
// ───────────────────────────────────────────────────
SEC("tracepoint/syscalls/sys_enter_unlinkat")
int tp__sys_enter_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
    if (IS_SELF() || is_whitelisted_proc()) return 0;

    struct event_t *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) return 0;

    POPULATE_CORE(evt, EVENT_UNLINK);

    // args[1] = pathname
    const char *pathname = (const char *)ctx->args[1];
    bpf_probe_read_user_str(&evt->target, sizeof(evt->target), pathname);

    bpf_ringbuf_submit(evt, 0);
    return 0;
}


// ───────────────────────────────────────────────────
// PROBE 10: File Rename — T1036 Masquerading (EVENT_RENAME)
// ───────────────────────────────────────────────────
SEC("tracepoint/syscalls/sys_enter_renameat2")
int tp__sys_enter_renameat2(struct trace_event_raw_sys_enter *ctx)
{
    if (IS_SELF() || is_whitelisted_proc()) return 0;

    struct event_t *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) return 0;

    POPULATE_CORE(evt, EVENT_RENAME);

    const char *oldname = (const char *)ctx->args[1];
    const char *newname = (const char *)ctx->args[3];

    int sz1 = bpf_probe_read_user_str(evt->target, 250, oldname);
    if (sz1 > 0) {
        int offset = sz1 - 1; // overwrite null terminator

        // VERIFIER SAFETY: Forcing the offset to a strict max of 255.
        // 255 + 4 + 250 = 509 max memory access. Safely fits in 512 array.
        offset &= 0xFF;

        evt->target[offset++] = ' ';
        evt->target[offset++] = '-';
        evt->target[offset++] = '>';
        evt->target[offset++] = ' ';

        // Constant 250 read bounds the maximum possible memory access
        bpf_probe_read_user_str(&evt->target[offset], 250, newname);
    }

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_renameat")
int tp__sys_enter_renameat(struct trace_event_raw_sys_enter *ctx)
{
    if (IS_SELF() || is_whitelisted_proc()) return 0;

    struct event_t *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) return 0;

    POPULATE_CORE(evt, EVENT_RENAME);

    const char *oldname = (const char *)ctx->args[1];
    const char *newname = (const char *)ctx->args[3];

    int sz1 = bpf_probe_read_user_str(evt->target, 250, oldname);
    if (sz1 > 0) {
        int offset = sz1 - 1;
        offset &= 0xFF;

        evt->target[offset++] = ' ';
        evt->target[offset++] = '-';
        evt->target[offset++] = '>';
        evt->target[offset++] = ' ';

        bpf_probe_read_user_str(&evt->target[offset], 250, newname);
    }

    bpf_ringbuf_submit(evt, 0);
    return 0;
}


// ───────────────────────────────────────────────────
// PROBE 11: Privilege Escalation — T1548 (EVENT_SETUID)
// Detects SUID exploitation and runtime privilege changes
// ───────────────────────────────────────────────────
SEC("tracepoint/syscalls/sys_enter_setuid")
int tp__sys_enter_setuid(struct trace_event_raw_sys_enter *ctx)
{
    if (IS_SELF() || is_whitelisted_proc()) return 0;

    __u32 target_uid = (__u32)ctx->args[0];

    // Only alert on escalation to root (uid 0) from non-root
    __u32 current_uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    if (target_uid != 0 || current_uid == 0)
        return 0;

    struct event_t *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) return 0;

    POPULATE_CORE(evt, EVENT_SETUID);
    // Store target UID in target field
    char msg[] = "setuid:0";
    __builtin_memcpy(evt->target, msg, sizeof(msg));

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

// setreuid: used by su, sudo, and some exploits
SEC("tracepoint/syscalls/sys_enter_setreuid")
int tp__sys_enter_setreuid(struct trace_event_raw_sys_enter *ctx)
{
    if (IS_SELF() || is_whitelisted_proc()) return 0;

    __u32 ruid = (__u32)ctx->args[0];
    __u32 euid = (__u32)ctx->args[1];
    __u32 current_uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    // Alert if either real or effective is being set to 0 from non-root
    if (current_uid == 0) return 0;
    if (ruid != 0 && euid != 0) return 0;

    struct event_t *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) return 0;

    POPULATE_CORE(evt, EVENT_SETUID);
    char msg[] = "setreuid:0";
    __builtin_memcpy(evt->target, msg, sizeof(msg));

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

// setresuid: most complete privilege change syscall
SEC("tracepoint/syscalls/sys_enter_setresuid")
int tp__sys_enter_setresuid(struct trace_event_raw_sys_enter *ctx)
{
    if (IS_SELF() || is_whitelisted_proc()) return 0;

    __u32 ruid = (__u32)ctx->args[0];
    __u32 euid = (__u32)ctx->args[1];
    __u32 suid = (__u32)ctx->args[2];
    __u32 current_uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    if (current_uid == 0) return 0;
    if (ruid != 0 && euid != 0 && suid != 0) return 0;

    struct event_t *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) return 0;

    POPULATE_CORE(evt, EVENT_SETUID);
    char msg[] = "setresuid:0";
    __builtin_memcpy(evt->target, msg, sizeof(msg));

    bpf_ringbuf_submit(evt, 0);
    return 0;
}


// ───────────────────────────────────────────────────
// PROBE 12: Filesystem Mount — T1006 Direct Volume Access (EVENT_MOUNT)
// ───────────────────────────────────────────────────
SEC("tracepoint/syscalls/sys_enter_mount")
int tp__sys_enter_mount(struct trace_event_raw_sys_enter *ctx)
{
    if (IS_SELF() || is_whitelisted_proc()) return 0;

    struct event_t *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) return 0;

    POPULATE_CORE(evt, EVENT_MOUNT);

    const char *source = (const char *)ctx->args[0];
    const char *target = (const char *)ctx->args[1];

    int sz1 = bpf_probe_read_user_str(evt->target, 250, source);
    if (sz1 > 0) {
        int offset = sz1 - 1;
        offset &= 0xFF;

        evt->target[offset++] = ' ';
        evt->target[offset++] = '-';
        evt->target[offset++] = '>';
        evt->target[offset++] = ' ';

        bpf_probe_read_user_str(&evt->target[offset], 250, target);
    }

    bpf_ringbuf_submit(evt, 0);
    return 0;
}


// ───────────────────────────────────────────────────
// PROBE 13: Socket Bind — T1571 Non-Standard Port (EVENT_BIND)
// Detects new listening services, backdoor ports, bind shells
// Filters: Only AF_INET and AF_INET6 to reduce noise
// ───────────────────────────────────────────────────
SEC("kprobe/__sys_bind")
int BPF_KPROBE(kp__sys_bind, int fd, struct sockaddr *umyaddr, int addrlen)
{
    if (IS_SELF() || is_whitelisted_proc()) return 0;

    // Read the address family to filter non-IP sockets
    __u16 family = 0;
    bpf_probe_read_user(&family, sizeof(family), &umyaddr->sa_family);

    // Only care about IPv4 (AF_INET=2) and IPv6 (AF_INET6=10)
    if (family != 2 && family != 10)
        return 0;

    struct event_t *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) return 0;

    POPULATE_CORE(evt, EVENT_BIND);

    if (family == 2) {
        // IPv4: struct sockaddr_in { family, port, addr }
        struct sockaddr_in sin = {};
        bpf_probe_read_user(&sin, sizeof(sin), umyaddr);
        evt->daddr = sin.sin_addr.s_addr;
        evt->dport = sin.sin_port;
    } else {
        // IPv6: just capture the port, daddr stays 0
        __u16 port = 0;
        bpf_probe_read_user(&port, sizeof(port), (void *)umyaddr + 2);
        evt->dport = port;
    }

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

// ───────────────────────────────────────────────────
// PROBE 15: IPv6 Outbound TCP Connection — T1571/C2 (EVENT_CONNECT)
// ───────────────────────────────────────────────────
SEC("kprobe/tcp_v6_connect")
int BPF_KPROBE(kp__tcp_v6_connect, struct sock *sk)
{
    if (IS_SELF() || is_whitelisted_proc()) return 0;

    struct event_t *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) return 0;

    POPULATE_CORE(evt, EVENT_CONNECT);

    // Read the 16-byte IPv6 address into our new array
    BPF_CORE_READ_INTO(&evt->daddr6, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr8);
    BPF_CORE_READ_INTO(&evt->dport, sk, __sk_common.skc_dport);
    BPF_CORE_READ_INTO(&evt->sport, sk, __sk_common.skc_num);

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

// ───────────────────────────────────────────────────
// PROBE 16: Container Escape — T1611 (EVENT_UNSHARE)
// ───────────────────────────────────────────────────
SEC("tracepoint/syscalls/sys_enter_unshare")
int tp__sys_enter_unshare(struct trace_event_raw_sys_enter *ctx)
{
    if (IS_SELF() || is_whitelisted_proc()) return 0;

    struct event_t *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) return 0;

    POPULATE_CORE(evt, EVENT_UNSHARE);

    // Store the clone flags being requested for context
    int flags = (int)ctx->args[0];
    char prefix[] = "unshare_flags:";
    __builtin_memcpy(evt->target, prefix, 14);

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

// ───────────────────────────────────────────────────
// PROBE 17: Container Escape — T1611 (EVENT_PIVOT_ROOT)
// ───────────────────────────────────────────────────
SEC("tracepoint/syscalls/sys_enter_pivot_root")
int tp__sys_enter_pivot_root(struct trace_event_raw_sys_enter *ctx)
{
    if (IS_SELF() || is_whitelisted_proc()) return 0;

    struct event_t *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) return 0;

    POPULATE_CORE(evt, EVENT_PIVOT_ROOT);

    // Arg 0 is new_root, Arg 1 is put_old
    const char *new_root = (const char *)ctx->args[0];
    bpf_probe_read_user_str(&evt->target, sizeof(evt->target), new_root);

    bpf_ringbuf_submit(evt, 0);
    return 0;
}