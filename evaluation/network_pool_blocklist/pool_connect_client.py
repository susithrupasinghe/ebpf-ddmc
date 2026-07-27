#!/usr/bin/env python3
"""
EDDMC Evaluation — pool-hits test client.

Connects to 127.0.0.1 on every known stratum/mining port (see
mock_pool_listener.py) with a short pause between each, so the connect()
tracepoint fires once per port under THIS process's own PID. Run this while
mock_pool_listener.py is up and eddmc is tracking this PID via
results_capture.py — you should see net.mining_pool_hits climb and the
score jump to the detection.pool_floor (default 50, MEDIUM) after the
first hit.
"""

import argparse
import socket
import time

MINING_PORTS = [3333, 4444, 14444, 14433, 45700, 5555, 8333, 9999, 3032, 7777, 3256, 4045]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pause", type=float, default=2.0, help="Seconds between each port connection")
    args = ap.parse_args()

    print(f"[client] pid={__import__('os').getpid()}")
    for port in MINING_PORTS:
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=2)
            s.send(b"test\n")
            print(f"[client] connected to 127.0.0.1:{port}")
            s.close()
        except OSError as exc:
            print(f"[client] failed to connect to port {port}: {exc}")
        time.sleep(args.pause)
    print("[client] done")


if __name__ == "__main__":
    main()
