#!/usr/bin/env python3
"""
Local, no-BCC, no-root simulation of the two-node fingerprint-registry
experiment described in the thesis (S3.10.6): Node A confirms a miner and
submits its fingerprint; Node B, with no prior detection history, checks a
newly-seen process against the registry. A near-duplicate XMRig variant
should be elevated; a benign gcc-like process should not match.

This only exercises the registry client/server logic. It does not require
eBPF/BCC/root -- BehaviouralFingerprint objects are constructed directly
instead of being built from live kernel telemetry.

Run:
    1) start the registry server:  bash registry/run.sh
    2) python3 scripts/test_registry.py
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from daemon.detector.fingerprint import (
    BehaviouralFingerprint,
    MemoryProfile,
    NetworkProfile,
    ParallelismProfile,
    SchedulerProfile,
    SyscallProfile,
    TemporalProfile,
)
from daemon.detector.scorer import score
from daemon.fingerprint.assessor import FingerprintAssessor
from daemon.fingerprint.matcher import FingerprintMatcher
from daemon.fingerprint.packager import package
from daemon.fingerprint.submitter import FingerprintSubmitter

REGISTRY_URL = os.environ.get("EDDMC_REGISTRY_URL", "http://127.0.0.1:8321")


def miner_fingerprint(pid: int, jitter: float = 0.0) -> BehaviouralFingerprint:
    return BehaviouralFingerprint(
        pid=pid,
        comm="xmrig",
        syscall=SyscallProfile(
            futex_ratio=0.55 + jitter, io_ratio=0.005, nanosleep_ratio=0.01,
            total_syscalls=50000,
        ),
        parallelism=ParallelismProfile(thread_count=4, thread_cpu_ratio=1.0, cpu_percent=97.0),
        memory=MemoryProfile(scratchpad_allocs=4, scratchpad_mb=8.0),
        scheduler=SchedulerProfile(cpu_bound_ratio=min(0.97 + jitter, 0.99)),
        temporal=TemporalProfile(first_seen=time.time(), age_seconds=90.0),
        network=NetworkProfile(pool_connections=3, total_connections=3),
    )


def benign_fingerprint(pid: int) -> BehaviouralFingerprint:
    return BehaviouralFingerprint(
        pid=pid,
        comm="gcc",
        syscall=SyscallProfile(
            futex_ratio=0.02, io_ratio=0.35, nanosleep_ratio=0.0, total_syscalls=80000,
        ),
        parallelism=ParallelismProfile(thread_count=2, thread_cpu_ratio=0.5, cpu_percent=60.0),
        memory=MemoryProfile(scratchpad_allocs=0),
        scheduler=SchedulerProfile(cpu_bound_ratio=0.3),
        temporal=TemporalProfile(first_seen=time.time(), age_seconds=90.0),
        network=NetworkProfile(pool_connections=0, total_connections=1),
    )


def main():
    print(f"== Node A: confirming a miner against {REGISTRY_URL} ==")
    assessor = FingerprintAssessor(sustained_critical_seconds=60.0)

    fp_a = miner_fingerprint(pid=1001)
    result_a = score(fp_a)
    print(f"  score={result_a.score} confidence={result_a.confidence}")

    t0 = time.time()
    gate = assessor.evaluate(result_a, now=t0)
    print(f"  gate check @0s   -> {'PASS' if gate else 'pending (needs sustained window)'}")
    gate = assessor.evaluate(result_a, now=t0 + 65)
    print(f"  gate check @65s  -> {'PASS' if gate else 'FAIL'}")

    if not gate:
        print("Gate failed -- check thresholds. Aborting.")
        return

    fingerprint = package(fp_a, gate)
    print(f"  packaged fingerprint_id={fingerprint['fingerprint_id'][:16]}...")

    submitter = FingerprintSubmitter(REGISTRY_URL)
    submitter.submit_async(fingerprint)
    time.sleep(1.0)  # let the background submit thread finish against the local server

    print(f"\n== Node B: independent instance, no prior detection history ==")
    matcher = FingerprintMatcher(REGISTRY_URL, threshold=0.85, refresh_interval_hours=1.0)
    matcher.start()
    time.sleep(0.5)

    print("  checking a near-duplicate XMRig variant (different PID, slight jitter)...")
    variant = miner_fingerprint(pid=2002, jitter=0.01)
    match = matcher.match(variant)
    print(f"  -> {match if match else 'NO MATCH'}")

    print("  checking a benign gcc-like process...")
    benign = benign_fingerprint(pid=3003)
    match_benign = matcher.match(benign)
    print(f"  -> {match_benign if match_benign else 'NO MATCH (correct)'}")

    ok = bool(match) and not match_benign
    print(f"\n{'PASS' if ok else 'FAIL'}: variant matched={bool(match)}, benign matched={bool(match_benign)}")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
