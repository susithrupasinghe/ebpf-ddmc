/*
 * EDDMC - Memory Pattern Monitor
 *
 * Tracks mmap() calls to detect RandomX scratchpad allocations.
 *
 * RandomX (used by XMRig and most modern CPU miners) allocates exactly
 * N × 2,097,152 bytes (N × 2MB) of MAP_PRIVATE | MAP_ANONYMOUS memory
 * at startup — one 2MB scratchpad per mining thread.  This is one of the
 * most specific and stable behavioural signatures for CPU cryptomining.
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
    u64 scratchpad_allocs;        /* allocations that are exact N×2MB */
    u64 huge_page_requests;       /* MAP_HUGETLB requests */
    u64 large_alloc_count;        /* allocations >= 1MB */
    u64 mprotect_large;           /* mprotect on regions >= 1MB */
};

struct mem_event {
    u32 pid;
    u64 length;
    u64 flags;
    u8  is_scratchpad;            /* 1 = exact multiple of 2MB */
    u8  is_huge;                  /* 1 = MAP_HUGETLB requested */
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
    /* Exact multiple of 2MB → RandomX scratchpad */
    if (len >= SCRATCHPAD_SIZE && (len % SCRATCHPAD_SIZE) == 0) {
        ms->scratchpad_allocs++;
        is_scratchpad = 1;
    }

    u8 is_huge = (flags & MAP_HUGETLB) ? 1 : 0;
    if (is_huge) ms->huge_page_requests++;

    /* Only emit events for large or noteworthy allocations */
    if (len >= 1048576 || is_scratchpad) {
        struct mem_event ev = {};
        ev.pid           = pid;
        ev.length        = len;
        ev.flags         = flags;
        ev.is_scratchpad = is_scratchpad;
        ev.is_huge       = is_huge;
        ev.timestamp_ns  = bpf_ktime_get_ns();
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
