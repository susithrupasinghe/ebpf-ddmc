/*
 * EDDMC - syscall monitor eBPF program
 *
 * Tracks per-process syscall frequencies using the raw_syscalls tracepoint.
 * Syscall numbers are architecture-specific.
 *
 * ARM64 (aarch64) numbers are used here — the primary target platform.
 * x86-64 numbers are provided via #ifdef for portability.
 */

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define MAX_PIDS 4096

/* ── Syscall numbers ── */
#if defined(__TARGET_ARCH_arm64) || defined(__aarch64__)
  #define SYS_READ       63
  #define SYS_WRITE      64
  #define SYS_MMAP       222
  #define SYS_MPROTECT   226
  #define SYS_CLONE      220
  #define SYS_FUTEX      98
  #define SYS_NANOSLEEP  101
  #define SYS_SOCKET     198
  #define SYS_CONNECT    203
  #define SYS_SENDTO     206
  #define SYS_RECVFROM   207
  #define SYS_BRKMEM     214
#else
  /* x86-64 fallback */
  #define SYS_READ       0
  #define SYS_WRITE      1
  #define SYS_MMAP       9
  #define SYS_MPROTECT   10
  #define SYS_CLONE      56
  #define SYS_FUTEX      202
  #define SYS_NANOSLEEP  35
  #define SYS_SOCKET     41
  #define SYS_CONNECT    42
  #define SYS_SENDTO     44
  #define SYS_RECVFROM   45
  #define SYS_BRKMEM     12
#endif

/* Per-process syscall counters */
struct syscall_counts {
    u64 total;
    u64 futex;
    u64 mmap;
    u64 mprotect;
    u64 clone;
    u64 nanosleep;
    u64 read;
    u64 write;
    u64 socket;
    u64 connect;
    u64 send;
    u64 recv;
    u64 brk;
    char comm[TASK_COMM_LEN];
    u32 uid;
};

BPF_HASH(syscall_stats, u32, struct syscall_counts, MAX_PIDS);

TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    u64 nr  = args->id;

    struct syscall_counts *c = syscall_stats.lookup(&pid);
    struct syscall_counts zero = {};
    if (!c) {
        zero.uid = uid;
        bpf_get_current_comm(&zero.comm, sizeof(zero.comm));
        syscall_stats.update(&pid, &zero);
        c = syscall_stats.lookup(&pid);
        if (!c) return 0;
    }

    c->total++;

    if      (nr == SYS_FUTEX)     c->futex++;
    else if (nr == SYS_MMAP)      c->mmap++;
    else if (nr == SYS_MPROTECT)  c->mprotect++;
    else if (nr == SYS_CLONE)     c->clone++;
    else if (nr == SYS_NANOSLEEP) c->nanosleep++;
    else if (nr == SYS_READ)      c->read++;
    else if (nr == SYS_WRITE)     c->write++;
    else if (nr == SYS_SOCKET)    c->socket++;
    else if (nr == SYS_CONNECT)   c->connect++;
    else if (nr == SYS_SENDTO)    c->send++;
    else if (nr == SYS_RECVFROM)  c->recv++;
    else if (nr == SYS_BRKMEM)    c->brk++;

    return 0;
}

/*
 * syscall_stats is keyed by TGID -- only clean up on the thread-group
 * leader's exit (see mem_monitor.c for why). Without this, the fixed-size
 * map never shrinks and eventually fills permanently on a long-running host.
 */
TRACEPOINT_PROBE(sched, sched_process_exit) {
    u64 id  = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 tid = id;
    if (pid == tid) {
        syscall_stats.delete(&pid);
    }
    return 0;
}
