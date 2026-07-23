/*
 * EDDMC - network monitor eBPF program (tracepoint version)
 *
 * Uses tracepoint/syscalls/sys_enter_connect to capture outbound
 * connection attempts and reads the destination sockaddr from userspace.
 * This avoids including <net/sock.h> which pulls in <linux/bpf.h> and
 * causes compile errors on kernel 6.18 with BCC (incomplete bpf_task_work).
 *
 * Known stratum / mining pool ports:
 *   3333, 4444, 14444, 14433, 45700, 5555, 8333, 9999, 3032, 7777
 */

#include <uapi/linux/ptrace.h>
#include <uapi/linux/in.h>
#include <uapi/linux/in6.h>

#define MAX_PIDS 4096
#define AF_INET  2

static __always_inline int is_mining_port(u16 port) {
    return (port == 3333  || port == 4444  || port == 14444 ||
            port == 14433 || port == 45700 || port == 5555  ||
            port == 8333  || port == 9999  || port == 3032  ||
            port == 7777  || port == 3256  || port == 4045);
}

struct net_stats {
    u64 total_connections;
    u64 mining_pool_hits;
};

struct net_event {
    u32  pid;
    u32  daddr;
    u16  dport;
    u8   is_mining_port;
    u64  timestamp_ns;
    char comm[TASK_COMM_LEN];
};

BPF_HASH(net_stats, u32, struct net_stats, MAX_PIDS);
BPF_PERF_OUTPUT(net_events);

TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    /* Read the sockaddr structure from user memory */
    struct sockaddr_in sa = {};
    bpf_probe_read_user(&sa, sizeof(sa), (void *)args->uservaddr);

    /* Only care about IPv4 connections */
    if (sa.sin_family != AF_INET)
        return 0;

    u16 dport = ntohs(sa.sin_port);
    if (dport == 0)
        return 0;

    u8 mining = is_mining_port(dport);

    /* Update per-PID counters */
    struct net_stats *ns = net_stats.lookup(&pid);
    struct net_stats zero = {};
    if (!ns) {
        net_stats.update(&pid, &zero);
        ns = net_stats.lookup(&pid);
        if (!ns) return 0;
    }
    ns->total_connections++;
    if (mining) ns->mining_pool_hits++;

    /* Emit event */
    struct net_event ev = {};
    ev.pid            = pid;
    ev.daddr          = sa.sin_addr.s_addr;
    ev.dport          = dport;
    ev.is_mining_port = mining;
    ev.timestamp_ns   = bpf_ktime_get_ns();
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    net_events.perf_submit(args, &ev, sizeof(ev));

    return 0;
}

/*
 * net_stats is keyed by TGID -- only clean up on the thread-group leader's
 * exit (see mem_monitor.c for why). Without this, the fixed-size map never
 * shrinks and eventually fills permanently on a long-running host.
 */
TRACEPOINT_PROBE(sched, sched_process_exit) {
    u64 id  = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 tid = id;
    if (pid == tid) {
        net_stats.delete(&pid);
    }
    return 0;
}
