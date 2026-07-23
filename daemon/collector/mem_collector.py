"""
EDDMC - Memory Pattern Collector

Loads mem_monitor.c and syncs per-process memory allocation patterns
into the shared process store.  Key signal: RandomX scratchpad allocations
(exact multiples of 2MB anonymous private mappings).
"""

import os
import threading
import ctypes
from bcc import BPF

EBPF_SRC = os.path.join(os.path.dirname(__file__), "../ebpf/mem_monitor.c")


class MemEvent(ctypes.Structure):
    _fields_ = [
        ("pid",                ctypes.c_uint32),
        ("length",             ctypes.c_uint64),
        ("flags",              ctypes.c_uint64),
        ("is_scratchpad",      ctypes.c_uint8),
        ("is_huge",            ctypes.c_uint8),
        ("is_scratchpad_huge", ctypes.c_uint8),
        ("timestamp_ns",       ctypes.c_uint64),
        ("comm",               ctypes.c_char * 16),
    ]


class MemCollector:
    def __init__(self, process_store: dict, lock: threading.Lock):
        self._store   = process_store
        self._lock    = lock
        self._bpf     = None
        self._running = False

    def load(self):
        with open(EBPF_SRC, "r") as f:
            src = f.read()
        self._bpf = BPF(text=src)

    def _on_mem_event(self, cpu, data, size):
        ev   = ctypes.cast(data, ctypes.POINTER(MemEvent)).contents
        pid  = ev.pid
        comm = ev.comm.decode("utf-8", errors="replace").rstrip("\x00")

        with self._lock:
            if pid not in self._store:
                from daemon.collector.syscall_collector import _empty_process
                self._store[pid] = _empty_process(pid, comm)
            mem = self._store[pid].setdefault("mem", _empty_mem())
            mem["large_alloc_count"] += 1
            mem["total_mmap_bytes"]  += ev.length
            if ev.is_scratchpad:
                mem["scratchpad_allocs"] += 1
            if ev.is_huge:
                mem["huge_page_requests"] += 1
            if ev.is_scratchpad_huge:
                mem["scratchpad_huge_allocs"] += 1

    def _poll_bpf_maps(self):
        for k, v in self._bpf["mem_stats"].items():
            pid = k.value
            with self._lock:
                if pid not in self._store:
                    from daemon.collector.syscall_collector import _empty_process
                    self._store[pid] = _empty_process(pid, "")
                mem = self._store[pid].setdefault("mem", _empty_mem())
                mem["total_mmap_bytes"]        = v.total_mmap_bytes
                mem["scratchpad_allocs"]       = v.scratchpad_allocs
                mem["scratchpad_huge_allocs"]  = v.scratchpad_huge_allocs
                mem["huge_page_requests"]      = v.huge_page_requests
                mem["large_alloc_count"]       = v.large_alloc_count
                mem["mprotect_large"]          = v.mprotect_large

    def start(self):
        self._running = True
        self._bpf["mem_events"].open_perf_buffer(
            self._on_mem_event, page_cnt=64
        )

        def _loop():
            while self._running:
                self._bpf.perf_buffer_poll(timeout=200)
                self._poll_bpf_maps()

        t = threading.Thread(target=_loop, daemon=True, name="mem-collector")
        t.start()

    def stop(self):
        self._running = False


def _empty_mem() -> dict:
    return {
        "total_mmap_bytes":       0,
        "scratchpad_allocs":      0,
        "scratchpad_huge_allocs": 0,
        "huge_page_requests":     0,
        "large_alloc_count":      0,
        "mprotect_large":         0,
    }
