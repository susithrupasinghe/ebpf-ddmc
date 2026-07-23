/*
 * EDDMC - Memory Pattern Monitor
 *
 * Tracks mmap() calls to detect RandomX scratchpad allocations.
 *
 * RandomX (used by XMRig and most modern CPU miners) allocates exactly
 * N × 2,097,152 bytes (N × 2MB) of MAP_PRIVATE | MAP_ANONYMOUS memory
 * at startup — one 2MB scratchpad per mining thread. RandomX also
 * explicitly requests MAP_HUGETLB for this allocation when huge pages are
 * available on the host.
 *
 * An exact-2MB-multiple size ALONE is not a specific signal: 2MB is also
 * the standard Linux transparent-huge-page size, so any software that
 * aligns large buffers to huge-page boundaries for ordinary, mining-unrelated
 * performance reasons (observed in practice: fwupd, and Chromium/Electron's
 * allocator) coincidentally matches it too. What legitimate allocators
 * essentially never do is request MAP_HUGETLB *at the same time* as sizing
 * the allocation to an exact scratchpad multiple -- that specific
 * combination is what we track as the strong signal
 * (scratchpad_huge_allocs). A bare size match with no huge-page flag is
 * tracked separately (scratchpad_allocs) and treated as much weaker
 * evidence by the scorer.
 *
 * We also track mprotect() on large regions, which miners call to mark
 * scratchpads PROT_READ|PROT_WRITE after allocation.
 *
 * On ARM64:  mmap = 222,  mprotect = 226
 * MAP_PRIVATE = 0x02,  MAP_ANONYMOUS = 0x20  →  combined = 0x22
 */

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define MAP_PRIVATE    0x02
#define MAP_ANONYMOUS  0x20
#define MAP_HUGETLB    0x40000
#define MMAP_MINING_FLAGS  (MAP_PRIVATE | MAP_ANONYMOUS)

/* 2MB = size of one RandomX scratchpad */
#define SCRATCHPAD_SIZE  2097152ULL

#define MAX_PIDS 4096

struct mem_stats {
    u64 total_mmap_bytes;         /* all anonymous private mappings */
    u64 scratchpad_allocs;        /* size-only match: exact N×2MB (weak alone) */
    u64 scratchpad_huge_allocs;   /* STRONG signal: exact N×2MB AND MAP_HUGETLB together */
    u64 huge_page_requests;       /* MAP_HUGETLB requests, any size */
    u64 large_alloc_count;        /* allocations >= 1MB */
    u64 mprotect_large;           /* mprotect on regions >= 1MB */
};

struct mem_event {
    u32 pid;
    u64 length;
    u64 flags;
    u8  is_scratchpad;            /* 1 = exact multiple of 2MB */
    u8  is_huge;                  /* 1 = MAP_HUGETLB requested */
    u8  is_scratchpad_huge;       /* 1 = both of the above, same allocation */
    u64 timestamp_ns;
    char comm[TASK_COMM_LEN];
};

BPF_HASH(mem_stats, u32, struct mem_stats, MAX_PIDS);
BPF_PERF_OUTPUT(mem_events);

TRACEPOINT_PROBE(syscalls, sys_enter_mmap) {
    u32 pid  = bpf_get_current_pid_tgid() >> 32;
    u64 len  = args->len;
    u64 flags = args->flags;

    /* Only care about anonymous private mappings (no file backing) */
    if ((flags & MMAP_MINING_FLAGS) != MMAP_MINING_FLAGS)
        return 0;

    /* Skip tiny allocations (< 64 KB) — not scratchpads */
    if (len < 65536)
        return 0;

    struct mem_stats *ms = mem_stats.lookup(&pid);
    struct mem_stats zero = {};
    if (!ms) {
        mem_stats.update(&pid, &zero);
        ms = mem_stats.lookup(&pid);
        if (!ms) return 0;
    }

    ms->total_mmap_bytes += len;
    if (len >= 1048576) ms->large_alloc_count++;

    u8 is_scratchpad = 0;
    /* Exact multiple of 2MB → matches RandomX scratchpad size, but this
     * alone is not specific (see file header) */
    if (len >= SCRATCHPAD_SIZE && (len % SCRATCHPAD_SIZE) == 0) {
        ms->scratchpad_allocs++;
        is_scratchpad = 1;
    }

    u8 is_huge = (flags & MAP_HUGETLB) ? 1 : 0;
    if (is_huge) ms->huge_page_requests++;

    /* STRONG signal: scratchpad-sized AND huge-page-backed, same allocation */
    u8 is_scratchpad_huge = (is_scratchpad && is_huge) ? 1 : 0;
    if (is_scratchpad_huge) ms->scratchpad_huge_allocs++;

    /* Only emit events for large or noteworthy allocations */
    if (len >= 1048576 || is_scratchpad) {
        struct mem_event ev = {};
        ev.pid                = pid;
        ev.length             = len;
        ev.flags              = flags;
        ev.is_scratchpad      = is_scratchpad;
        ev.is_scratchpad_huge = is_scratchpad_huge;
        ev.is_huge            = is_huge;
        ev.timestamp_ns       = bpf_ktime_get_ns();
        bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
        mem_events.perf_submit(args, &ev, sizeof(ev));
    }

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_mprotect) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 len = args->len;

    if (len < 1048576) return 0;

    struct mem_stats *ms = mem_stats.lookup(&pid);
    struct mem_stats zero = {};
    if (!ms) {
        mem_stats.update(&pid, &zero);
        ms = mem_stats.lookup(&pid);
        if (!ms) return 0;
    }
    ms->mprotect_large++;

    return 0;
}

/*
 * mem_stats is keyed by TGID, so only clean up when the exiting task IS its
 * own thread-group leader -- otherwise a worker thread exiting early would
 * wipe live data still being written by sibling threads / the leader.
 * Without this, the map (fixed at MAX_PIDS entries, BCC has no way to make
 * it dynamic) fills up permanently on any long-running host with normal
 * process churn -- once full, update() for new PIDs fails silently (no
 * error, just silently untracked processes), which is a real reliability
 * problem for a server deployment that stays up for days/weeks.
 */
TRACEPOINT_PROBE(sched, sched_process_exit) {
    u64 id  = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 tid = id;
    if (pid == tid) {
        mem_stats.delete(&pid);
    }
    return 0;
}
