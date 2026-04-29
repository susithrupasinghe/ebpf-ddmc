"""
EDDMC - Network Collector

Loads net_monitor.c (tracepoint/syscalls/sys_enter_connect) and streams
TCP connection events. No kprobes needed — avoids the bpf_task_work
compile issue on kernel 6.18.
"""

import os
import threading
import ctypes
import socket as _socket
from bcc import BPF

EBPF_SRC = os.path.join(os.path.dirname(__file__), "../ebpf/net_monitor.c")


class NetEvent(ctypes.Structure):
    _fields_ = [
        ("pid",            ctypes.c_uint32),
        ("daddr",          ctypes.c_uint32),
        ("dport",          ctypes.c_uint16),
        ("is_mining_port", ctypes.c_uint8),
        ("timestamp_ns",   ctypes.c_uint64),
        ("comm",           ctypes.c_char * 16),
    ]


class NetCollector:
    """
    Monitors outbound TCP connect() syscalls and updates process_store
    with connection counts and mining-pool hit counts.
    No kprobes — pure tracepoint, works on kernel 6.18+.
    """

    def __init__(self, process_store: dict, lock: threading.Lock):
        self._store   = process_store
        self._lock    = lock
        self._bpf     = None
        self._running = False

    def load(self):
        with open(EBPF_SRC, "r") as f:
            src = f.read()
        # Pure tracepoint — no kprobe attachment needed
        self._bpf = BPF(text=src)

    def _on_net_event(self, cpu, data, size):
        ev   = ctypes.cast(data, ctypes.POINTER(NetEvent)).contents
        pid  = ev.pid
        comm = ev.comm.decode("utf-8", errors="replace").rstrip("\x00")

        # Convert little-endian packed IPv4 to dotted string
        try:
            daddr_str = _socket.inet_ntoa(ev.daddr.to_bytes(4, "little"))
        except Exception:
            daddr_str = "unknown"

        with self._lock:
            if pid not in self._store:
                from daemon.collector.syscall_collector import _empty_process
                self._store[pid] = _empty_process(pid, comm)
            net = self._store[pid]["net"]
            net["total_connections"] += 1
            if ev.is_mining_port:
                net["mining_pool_hits"] += 1
                hits = net.setdefault("pool_connections", [])
                hits.append({
                    "dst":  daddr_str,
                    "port": ev.dport,
                    "ts":   ev.timestamp_ns,
                })
                if len(hits) > 50:
                    net["pool_connections"] = hits[-50:]

    def start(self):
        self._running = True
        self._bpf["net_events"].open_perf_buffer(
            self._on_net_event, page_cnt=64
        )

        def _loop():
            while self._running:
                self._bpf.perf_buffer_poll(timeout=200)

        t = threading.Thread(target=_loop, daemon=True, name="net-collector")
        t.start()

    def stop(self):
        self._running = False
