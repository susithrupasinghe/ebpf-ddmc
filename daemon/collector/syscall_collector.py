"""
EDDMC - Syscall Collector

Loads the syscall_monitor eBPF program via BCC and streams per-process
syscall statistics into the shared process state store.
"""

import os
import threading
import time
from bcc import BPF

EBPF_SRC = os.path.join(os.path.dirname(__file__), "../ebpf/syscall_monitor.c")

# RO2 closure round (Task 1.1/1.2): profiling attributed ~96% of one core to
# this collector's thread, the single biggest driver of the daemon's overall
# overhead figure -- far more than the detection engine's own scoring loop.
# Root cause: syscall_monitor.c's raw_syscalls/sys_enter tracepoint fires on
# EVERY syscall from EVERY process on the host and used to perf_submit() a
# full event for each one, driving a Python-side perf-buffer callback at that
# same host-wide rate. The per-event data it built (`syscall_events`, a raw
# timestamped syscall-number list) was never read anywhere outside this file
# except to be stripped back out before API serialisation (see
# daemon/ipc/socket_server.py's do_GET) -- confirmed via a full-repo grep, it
# had no scoring or detection consumer. The BPF hash-map poll below already
# independently maintains every counter the scorer actually uses, aggregated
# in-kernel, so removing the perf-event path (both here and in the .c source)
# has no detection-logic effect -- it deletes dead computation, not a signal.
POLL_INTERVAL_S = 1.0


class SyscallCollector:
    """
    Loads syscall_monitor.c and periodically polls its BPF hash-map counters.
    Writes per-PID syscall counts into `process_store` (dict shared with
    the detector).
    """

    def __init__(self, process_store: dict, lock: threading.Lock):
        self._store = process_store
        self._lock  = lock
        self._bpf   = None
        self._running = False

    def load(self):
        with open(EBPF_SRC, "r") as f:
            src = f.read()
        self._bpf = BPF(text=src)

    def _poll_bpf_maps(self):
        """Periodically sync the BPF hash-map counters into the store."""
        syscall_stats = self._bpf["syscall_stats"]
        for k, v in syscall_stats.items():
            pid = k.value
            with self._lock:
                if pid not in self._store:
                    comm = v.comm.decode("utf-8", errors="replace").rstrip("\x00")
                    self._store[pid] = _empty_process(pid, comm)
                sc = self._store[pid]["syscall_counts"]
                sc["total"]     = v.total
                sc["futex"]     = v.futex
                sc["mmap"]      = v.mmap
                sc["mprotect"]  = v.mprotect
                sc["clone"]     = v.clone
                sc["nanosleep"] = v.nanosleep
                sc["read"]      = v.read
                sc["write"]     = v.write
                sc["socket"]    = v.socket
                sc["connect"]   = v.connect
                sc["send"]      = v.send
                sc["recv"]      = v.recv
                sc["brk"]       = v.brk

    def start(self):
        self._running = True

        def _loop():
            while self._running:
                time.sleep(POLL_INTERVAL_S)
                self._poll_bpf_maps()

        t = threading.Thread(target=_loop, daemon=True, name="syscall-collector")
        t.start()

    def stop(self):
        self._running = False


def _empty_process(pid: int, comm: str) -> dict:
    return {
        "pid":   pid,
        "comm":  comm,
        "syscall_counts": {
            "total": 0, "futex": 0, "mmap": 0, "mprotect": 0,
            "clone": 0, "nanosleep": 0, "read": 0, "write": 0,
            "socket": 0, "connect": 0, "send": 0, "recv": 0, "brk": 0,
        },
        "sched": {
            "on_cpu_ns": 0,
            "voluntary_switches": 0,
            "involuntary_switches": 0,
            "thread_count": 1,
        },
        "net": {
            "total_connections": 0,
            "mining_pool_hits": 0,
        },
        "mem": {
            "total_mmap_bytes":   0,
            "scratchpad_allocs":  0,
            "huge_page_requests": 0,
            "large_alloc_count":  0,
            "mprotect_large":     0,
        },
        "score":      0.0,
        "confidence": "NONE",
        "mitigation": "NONE",
    }
