"""
EDDMC - Scheduler Collector

Loads sched_monitor.c and syncs scheduler statistics (CPU time,
context switches, thread count) into the shared process state store.
"""

import os
import threading
import ctypes
from bcc import BPF

EBPF_SRC = os.path.join(os.path.dirname(__file__), "../ebpf/sched_monitor.c")


class ThreadEvent(ctypes.Structure):
    _fields_ = [
        ("tgid",         ctypes.c_uint32),
        ("tid",          ctypes.c_uint32),
        ("timestamp_ns", ctypes.c_uint64),
        ("is_fork",      ctypes.c_uint8),
        ("comm",         ctypes.c_char * 16),
    ]


class SchedCollector:
    """
    Loads sched_monitor.c and polls sched/thread perf buffers.
    Syncs CPU time and context-switch counts into `process_store`.
    """

    def __init__(self, process_store: dict, lock: threading.Lock):
        self._store   = process_store
        self._lock    = lock
        self._bpf     = None
        self._running = False

    def load(self):
        with open(EBPF_SRC, "r") as f:
            src = f.read()
        self._bpf = BPF(text=src)

    def _on_thread_event(self, cpu, data, size):
        ev = ctypes.cast(data, ctypes.POINTER(ThreadEvent)).contents
        tgid = ev.tgid
        comm = ev.comm.decode("utf-8", errors="replace").rstrip("\x00")
        with self._lock:
            if tgid not in self._store:
                from daemon.collector.syscall_collector import _empty_process
                self._store[tgid] = _empty_process(tgid, comm)
            sched = self._store[tgid]["sched"]
            if ev.is_fork:
                sched["thread_count"] = max(sched["thread_count"] + 1, 1)
            else:
                sched["thread_count"] = max(sched["thread_count"] - 1, 0)

    def _poll_bpf_maps(self):
        sched_stats = self._bpf["sched_stats"]
        for k, v in sched_stats.items():
            pid = k.value
            with self._lock:
                if pid not in self._store:
                    from daemon.collector.syscall_collector import _empty_process
                    self._store[pid] = _empty_process(pid, "")
                sched = self._store[pid]["sched"]
                sched["on_cpu_ns"]            = v.on_cpu_ns
                sched["voluntary_switches"]   = v.voluntary_switches
                sched["involuntary_switches"] = v.involuntary_switches
                if v.thread_count > 0:
                    sched["thread_count"] = v.thread_count

    def start(self):
        self._running = True
        self._bpf["thread_events"].open_perf_buffer(
            self._on_thread_event, page_cnt=64
        )

        def _loop():
            while self._running:
                self._bpf.perf_buffer_poll(timeout=200)
                self._poll_bpf_maps()

        t = threading.Thread(target=_loop, daemon=True, name="sched-collector")
        t.start()

    def stop(self):
        self._running = False
