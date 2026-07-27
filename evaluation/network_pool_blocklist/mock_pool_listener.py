#!/usr/bin/env python3
"""
EDDMC Evaluation — mock stratum-port listener.

EDDMC's net_collector detects mining-pool traffic by destination PORT
(daemon/ebpf/net_monitor.c: is_mining_port()), not by domain name — so
validating that signal doesn't require reaching real CoinBlockerLists-listed
domains over the internet. This spins up harmless local TCP listeners on
every port EDDMC treats as a mining-pool port, so pool_connect_client.py can
connect to 127.0.0.1 on each one and exercise the exact same connect()
codepath a real miner hitting a real pool would.

Usage: python3 mock_pool_listener.py [--hold SECONDS]
"""

import argparse
import socket
import threading

# Must match is_mining_port() in daemon/ebpf/net_monitor.c
MINING_PORTS = [3333, 4444, 14444, 14433, 45700, 5555, 8333, 9999, 3032, 7777, 3256, 4045]


def _serve(port: int, hold: float, stop_evt: threading.Event):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(5)
    srv.settimeout(0.5)
    while not stop_evt.is_set():
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            continue
        conn.settimeout(hold)
        try:
            conn.recv(256)
        except Exception:
            pass
        conn.close()
    srv.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hold", type=float, default=1.0, help="Seconds to keep each accepted connection open")
    args = ap.parse_args()

    stop_evt = threading.Event()
    threads = [
        threading.Thread(target=_serve, args=(p, args.hold, stop_evt), daemon=True)
        for p in MINING_PORTS
    ]
    for t in threads:
        t.start()

    print(f"[mock-pool] listening on 127.0.0.1: {MINING_PORTS}")
    print("[mock-pool] Ctrl-C to stop")
    try:
        while True:
            threading.Event().wait(1)
    except KeyboardInterrupt:
        stop_evt.set()
        print("\n[mock-pool] stopped")


if __name__ == "__main__":
    main()
