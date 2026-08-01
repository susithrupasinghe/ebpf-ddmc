#!/usr/bin/env python3
"""
EDDMC Evaluation — capture full platform facts + git SHA at the start of every
evaluation run (P0-3 acceptance criteria: "generated automatically at the
start of every evaluation run from now on").

Written because the thesis (§3.8, §5.2.3) specifies a Contabo cloud VPS,
Ubuntu 24.04, Linux 6.x, 4 vCPU, 12 GB RAM (x86-64) -- but this evaluation
ran on an aarch64 shared development VM. That mismatch has real consequences
(3 of 4 fetched ELF malware samples were unrunnable due to architecture;
RandomX huge-page behaviour is architecture-sensitive) and needs to be
documented precisely and automatically for every run, not asserted once and
left to go stale.

Usage: python3 capture_platform.py [--out evaluation/results/platform.json]
"""
import argparse
import json
import os
import platform
import subprocess
import sys


def _run(cmd):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return r.stdout.strip()
    except Exception as exc:
        return f"(unavailable: {exc})"


def _read(path):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError as exc:
        return f"(unavailable: {exc})"


def _git_sha(repo_dir):
    try:
        r = subprocess.run(
            ["git", "-C", repo_dir, "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=10,
        )
        sha = r.stdout.strip()
        dirty = subprocess.run(
            ["git", "-C", repo_dir, "status", "--porcelain"],
            capture_output=True, text=True, timeout=10,
        ).stdout.strip()
        return {"sha": sha, "dirty": bool(dirty), "dirty_files": dirty.splitlines() if dirty else []}
    except Exception as exc:
        return {"sha": None, "error": str(exc)}


def _btf_available():
    return os.path.exists("/sys/kernel/btf/vmlinux")


def _bpf_kernel_config():
    kver = _run(["uname", "-r"])
    config_path = f"/boot/config-{kver}"
    flags = ["CONFIG_BPF", "CONFIG_BPF_SYSCALL", "CONFIG_BPF_EVENTS", "CONFIG_DEBUG_INFO_BTF"]
    result = {}
    if os.path.exists(config_path):
        text = _read(config_path)
        for flag in flags:
            hit = [l for l in text.splitlines() if l.startswith(f"{flag}=")]
            result[flag] = hit[0].split("=", 1)[1] if hit else "not set / not present"
    else:
        for flag in flags:
            result[flag] = f"(config file not readable: {config_path})"
    result["btf_vmlinux_present"] = _btf_available()
    return result


def _cgroup_version():
    mounts = _read("/proc/mounts")
    if "cgroup2" in mounts:
        return "v2 (unified)"
    if "cgroup " in mounts:
        return "v1 (legacy)"
    return "unknown"


def capture(repo_dir):
    return {
        "captured_for": "EDDMC evaluation run (P0-3)",
        "thesis_target_platform": {
            "provider": "Contabo cloud VPS",
            "os": "Ubuntu 24.04",
            "kernel": "Linux 6.x",
            "arch": "x86-64",
            "vcpus": 4,
            "ram_gb": 12,
            "source": "thesis §3.8, §5.2.3",
        },
        "actual_platform": {
            "uname_a": _run(["uname", "-a"]),
            "machine_arch": platform.machine(),
            "python_platform": platform.platform(),
            "kernel_release": _run(["uname", "-r"]),
            "cpu_count_logical": os.cpu_count(),
            "os_release": _read("/etc/os-release"),
            "cgroup_version": _cgroup_version(),
        },
        "lscpu": _run(["lscpu"]),
        "ebpf_btf_config": _bpf_kernel_config(),
        "architecture_mismatch_note": (
            "Thesis specifies x86-64 (Contabo VPS); this run executed on "
            f"{platform.machine()}. This is a documented, explicit limitation, "
            "not an oversight -- see reports/EVALUATION_ROUND2.md P0-3."
        ),
        "git": _git_sha(repo_dir),
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default=None)
    ap.add_argument("--repo-dir", default=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    args = ap.parse_args()

    out_path = args.out or os.path.join(args.repo_dir, "evaluation", "results", "platform.json")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)

    data = capture(args.repo_dir)
    with open(out_path, "w") as f:
        json.dump(data, f, indent=2)

    print(f"[platform] wrote {out_path}")
    print(f"[platform] arch={data['actual_platform']['machine_arch']} "
          f"kernel={data['actual_platform']['kernel_release']} "
          f"git_sha={data['git'].get('sha', '?')[:12]} "
          f"dirty={data['git'].get('dirty', '?')}")


if __name__ == "__main__":
    main()
