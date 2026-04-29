"""
EDDMC - Syscall Collector

Loads the syscall_monitor eBPF program via BCC and streams per-process
syscall statistics into the shared process state store.
"""

import os
import threading
import ctypes
from bcc import BPF

EBPF_SRC = os.path.join(os.path.dirname(__file__), "../ebpf/syscall_monitor.c")


class SyscallEvent(ctypes.Structure):
    _fields_ = [
        ("pid",          ctypes.c_uint32),
        ("uid",          ctypes.c_uint32),
        ("syscall_nr",   ctypes.c_uint64),
        ("timestamp_ns", ctypes.c_uint64),
        ("comm",         ctypes.c_char * 16),
    ]


class SyscallCollector:
    """
    Loads syscall_monitor.c and continuously polls the perf ring buffer.
    Writes per-PID syscall counts into `process_store` (dict shared with
    the detector).  Also maintains a window of raw events for timing analysis.
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

    def _on_syscall_event(self, cpu, data, size):
        ev = ctypes.cast(data, ctypes.POINTER(SyscallEvent)).contents
        pid  = ev.pid
        comm = ev.comm.decode("utf-8", errors="replace").rstrip("\x00")

        with self._lock:
            if pid not in self._store:
                self._store[pid] = _empty_process(pid, comm)
            self._store[pid]["comm"] = comm
            self._store[pid]["syscall_events"].append({
                "nr": ev.syscall_nr,
                "ts": ev.timestamp_ns,
            })
            # Keep only last 2000 events per process (sliding window)
            if len(self._store[pid]["syscall_events"]) > 2000:
                self._store[pid]["syscall_events"] = \
                    self._store[pid]["syscall_events"][-2000:]

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
        # page_cnt=256 gives 1 MB ring buffer — reduces "Possibly lost samples"
        self._bpf["syscall_events"].open_perf_buffer(
            self._on_syscall_event, page_cnt=256
        )

        def _loop():
            while self._running:
                self._bpf.perf_buffer_poll(timeout=200)
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
        "syscall_events": [],
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
        "score":      0.0,
        "confidence": "NONE",
        "mitigation": "NONE",
    }
