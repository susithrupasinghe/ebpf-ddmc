"""
EDDMC - Scheduler Collector

Loads sched_monitor.c and syncs scheduler statistics (CPU time,
context switches, thread count) into the shared process state store.
"""

import logging
import os
import threading
import ctypes
from bcc import BPF

EBPF_SRC = os.path.join(os.path.dirname(__file__), "../ebpf/sched_monitor.c")
logger = logging.getLogger("eddmc.collector")

# Must match MAX_PIDS in sched_monitor.c. Used only to compute a utilisation
# warning here -- the real capacity is enforced in the .c source.
_SCHED_STATS_MAX_ENTRIES = 65536
_SCHED_STATS_WARN_THRESHOLD = 0.8  # log once utilisation crosses this fraction


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
        self._high_utilisation_warned = False

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
        """
        sched_stats is keyed by raw TID (one entry per thread -- see
        sched_monitor.c). Reading each entry's own on_cpu_ns/switch counts
        directly, as this used to do, means a process whose real work runs
        on worker threads (not its leader) reads as almost entirely idle:
        the exit-time fold in sched_monitor.c only recovers a worker's
        stats once that worker exits, which for a long-lived multi-threaded
        process (e.g. a miner still running when this poll happens) may
        never occur during the whole observation window.

        Fixed here: group every live entry by its `tgid` field (set at
        fork time in sched_monitor.c; 0 means "unknown group, own pid is
        its own tgid" -- covers threads that predate this program loading)
        and sum on_cpu_ns/voluntary/involuntary across the whole group on
        every poll, live, regardless of whether any thread has exited yet.
        Only the group leader's process_store entry is written -- a
        non-leader TID's raw entry is not turned into its own store row,
        since it does not correspond to a real top-level /proc/<pid> the
        rest of the daemon would ever meaningfully track on its own.
        """
        sched_stats = self._bpf["sched_stats"]
        groups = {}  # effective_tgid -> {"on_cpu_ns":..,"voluntary":..,"involuntary":..,"thread_count":..}
        raw_entries = 0
        for k, v in sched_stats.items():
            raw_entries += 1
            tid = k.value
            effective_tgid = v.tgid if v.tgid else tid
            g = groups.setdefault(effective_tgid, {"on_cpu_ns": 0, "voluntary": 0, "involuntary": 0, "thread_count": 0})
            g["on_cpu_ns"]    += v.on_cpu_ns
            g["voluntary"]    += v.voluntary_switches
            g["involuntary"]  += v.involuntary_switches
            if v.thread_count > g["thread_count"]:
                g["thread_count"] = v.thread_count  # only the leader's own entry carries a real count

        # A full map makes every subsequent map.update() fail silently (BCC
        # surfaces no error), after which every process gets zero scheduler
        # data for the rest of its life -- exactly the defect found during
        # the 2026-08 re-evaluation round. Log once (not every poll) when
        # utilisation crosses the warning threshold, so this fails loudly
        # instead of silently next time, however large MAX_PIDS ends up
        # needing to be on a given host.
        if not self._high_utilisation_warned and raw_entries >= _SCHED_STATS_MAX_ENTRIES * _SCHED_STATS_WARN_THRESHOLD:
            self._high_utilisation_warned = True
            logger.warning(
                "sched_stats BPF map at %d/%d entries (%.0f%%) -- approaching capacity. "
                "Once full, scheduler data silently stops updating for new processes. "
                "Consider raising MAX_PIDS in sched_monitor.c or restarting the daemon.",
                raw_entries, _SCHED_STATS_MAX_ENTRIES,
                100.0 * raw_entries / _SCHED_STATS_MAX_ENTRIES,
            )

        for tgid, g in groups.items():
            with self._lock:
                if tgid not in self._store:
                    from daemon.collector.syscall_collector import _empty_process
                    self._store[tgid] = _empty_process(tgid, "")
                sched = self._store[tgid]["sched"]
                sched["on_cpu_ns"]            = g["on_cpu_ns"]
                sched["voluntary_switches"]   = g["voluntary"]
                sched["involuntary_switches"] = g["involuntary"]
                if g["thread_count"] > 0:
                    sched["thread_count"] = g["thread_count"]

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
