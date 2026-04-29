"""
EDDMC CLI

Connects to the running daemon's HTTP API and provides human-friendly
commands for status checking, alert monitoring, and mitigation control.

Usage:
  eddmc status
  eddmc watch              (live-updating process table)
  eddmc alerts             (tail alert log)
  eddmc revoke <pid>       (lift mitigations)
  eddmc kill <pid>         (manually terminate)
  eddmc config             (show running config)
"""

import argparse
import json
import sys
import time
import urllib.request
import urllib.error

API_BASE = "http://127.0.0.1:7373"


def _get(path: str) -> dict | list:
    try:
        with urllib.request.urlopen(f"{API_BASE}{path}", timeout=3) as r:
            return json.loads(r.read())
    except urllib.error.URLError:
        print("Cannot connect to EDDMC daemon. Is it running?", file=sys.stderr)
        sys.exit(1)


def _post(path: str) -> dict:
    req = urllib.request.Request(f"{API_BASE}{path}", method="POST", data=b"")
    try:
        with urllib.request.urlopen(req, timeout=3) as r:
            return json.loads(r.read())
    except urllib.error.URLError:
        print("Cannot connect to EDDMC daemon.", file=sys.stderr)
        sys.exit(1)


def cmd_status(_args):
    data = _get("/api/status")
    print(f"  Status   : {data['status']}")
    print(f"  Uptime   : {data['uptime']}s")
    print(f"  Tracked  : {data['tracked']} processes")


def cmd_watch(_args):
    """Live-updating process table — refreshes every 3 seconds."""
    try:
        while True:
            procs = _get("/api/processes")
            suspicious = [p for p in procs if p.get("confidence", "NONE") != "NONE"]
            print(f"\033[2J\033[H", end="")  # clear screen
            print(f"{'PID':>7}  {'COMM':<20}  {'SCORE':>6}  {'CONF':<10}  {'MITIGATION'}")
            print("-" * 65)
            for p in sorted(procs, key=lambda x: x.get("score", 0), reverse=True)[:30]:
                conf = p.get("confidence", "NONE")
                color = {
                    "CRITICAL": "\033[31m",
                    "HIGH":     "\033[33m",
                    "MEDIUM":   "\033[93m",
                    "LOW":      "\033[96m",
                    "NONE":     "",
                }.get(conf, "")
                reset = "\033[0m" if color else ""
                print(f"{p['pid']:>7}  {p['comm']:<20}  {p.get('score',0):>6.1f}  "
                      f"{color}{conf:<10}{reset}  {p.get('mitigation','NONE')}")
            print(f"\n  {len(suspicious)} suspicious / {len(procs)} tracked  "
                  f"[Ctrl-C to exit]")
            time.sleep(3)
    except KeyboardInterrupt:
        pass


def cmd_alerts(_args):
    alerts = _get("/api/alerts")
    if not alerts:
        print("No alerts yet.")
        return
    for a in reversed(alerts[-20:]):
        ts = time.strftime("%H:%M:%S", time.localtime(a.get("timestamp", 0)))
        print(f"[{ts}] pid={a['pid']} comm={a['comm']:<16} "
              f"score={a['score']:.1f} conf={a['confidence']} action={a['action']}")
        for r in a.get("reasons", []):
            print(f"         • {r}")


def cmd_revoke(args):
    pid = args.pid
    resp = _post(f"/api/revoke/{pid}")
    if resp.get("ok"):
        print(f"Mitigations revoked for pid {pid}")
    else:
        print(f"Failed: {resp}")


def cmd_kill(args):
    pid = args.pid
    resp = _post(f"/api/kill/{pid}")
    if resp.get("ok"):
        print(f"Kill signal sent to pid {pid}")
    else:
        print(f"Failed: {resp}")


def cmd_config(_args):
    cfg = _get("/api/config")
    print(json.dumps(cfg, indent=2))


def main():
    parser = argparse.ArgumentParser(
        prog="eddmc",
        description="EDDMC — CPU Cryptojacking Detection Daemon CLI",
    )
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("status",  help="Show daemon status")
    sub.add_parser("watch",   help="Live process monitor")
    sub.add_parser("alerts",  help="Show recent alerts")
    sub.add_parser("config",  help="Show running configuration")

    p_revoke = sub.add_parser("revoke", help="Lift mitigations from a PID")
    p_revoke.add_argument("pid", type=int)

    p_kill = sub.add_parser("kill", help="Manually terminate a PID")
    p_kill.add_argument("pid", type=int)

    args = parser.parse_args()
    dispatch = {
        "status":  cmd_status,
        "watch":   cmd_watch,
        "alerts":  cmd_alerts,
        "revoke":  cmd_revoke,
        "kill":    cmd_kill,
        "config":  cmd_config,
    }

    if args.command not in dispatch:
        parser.print_help()
        sys.exit(1)

    dispatch[args.command](args)


if __name__ == "__main__":
    main()
