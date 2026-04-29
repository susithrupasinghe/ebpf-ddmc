/*
 * EDDMC - scheduler monitor eBPF program
 *
 * Tracks per-process CPU time and context-switch behaviour.
 * Cryptominers are almost always CPU-bound: they spend nearly all time
 * on-CPU and rarely yield voluntarily. We measure:
 *   - on_cpu_ns: total nanoseconds spent running on CPU
 *   - voluntary_switches: yielded the CPU (I/O wait, sleep)
 *   - involuntary_switches: preempted by scheduler (CPU-bound indicator)
 *   - thread_count: number of live threads in the process group
 */

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define MAX_PIDS 4096

struct sched_stats {
    u64 on_cpu_ns;
    u64 voluntary_switches;
    u64 involuntary_switches;
    u32 thread_count;
    u64 last_scheduled_ns;
    char comm[TASK_COMM_LEN];
};

struct thread_event {
    u32 tgid;
    u32 tid;
    u64 timestamp_ns;
    u8  is_fork;   /* 1 = thread created, 0 = thread exited */
    char comm[TASK_COMM_LEN];
};

BPF_HASH(sched_stats, u32, struct sched_stats, MAX_PIDS);
BPF_PERF_OUTPUT(sched_events);
BPF_PERF_OUTPUT(thread_events);

/* Called when a task is scheduled onto the CPU */
TRACEPOINT_PROBE(sched, sched_switch) {
    u64 now = bpf_ktime_get_ns();
    u32 prev_pid = args->prev_pid;
    u32 next_pid = args->next_pid;

    /* Account CPU time for the task being switched OUT */
    struct sched_stats *ps = sched_stats.lookup(&prev_pid);
    if (ps && ps->last_scheduled_ns > 0) {
        ps->on_cpu_ns += now - ps->last_scheduled_ns;
        ps->last_scheduled_ns = 0;
        /* prev_state == 0 means the task is still runnable (involuntary) */
        if (args->prev_state == 0)
            ps->involuntary_switches++;
        else
            ps->voluntary_switches++;
    }

    /* Record when the incoming task starts its CPU slice */
    struct sched_stats *ns = sched_stats.lookup(&next_pid);
    struct sched_stats zero = {};
    if (!ns) {
        bpf_get_current_comm(&zero.comm, sizeof(zero.comm));
        sched_stats.update(&next_pid, &zero);
        ns = sched_stats.lookup(&next_pid);
        if (!ns) return 0;
    }
    ns->last_scheduled_ns = now;

    return 0;
}

/* Track thread creation to count parallelism */
TRACEPOINT_PROBE(sched, sched_process_fork) {
    u32 parent_tgid = args->parent_pid;
    u32 child_pid   = args->child_pid;
    u64 now = bpf_ktime_get_ns();

    struct sched_stats *s = sched_stats.lookup(&parent_tgid);
    if (s) s->thread_count++;

    struct thread_event ev = {};
    ev.tgid = parent_tgid;
    ev.tid  = child_pid;
    ev.timestamp_ns = now;
    ev.is_fork = 1;
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    thread_events.perf_submit(args, &ev, sizeof(ev));

    return 0;
}

/* Track thread exit to decrement count */
TRACEPOINT_PROBE(sched, sched_process_exit) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    u64 now = bpf_ktime_get_ns();

    /* If PID == TID it's the main thread; mark the whole group done */
    struct sched_stats *s = sched_stats.lookup(&pid);
    if (s && s->thread_count > 0) s->thread_count--;

    struct thread_event ev = {};
    ev.tgid = pid;
    ev.tid  = tid;
    ev.timestamp_ns = now;
    ev.is_fork = 0;
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    thread_events.perf_submit(args, &ev, sizeof(ev));

    return 0;
}
