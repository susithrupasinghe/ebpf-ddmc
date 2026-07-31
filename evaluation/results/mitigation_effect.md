# Mitigation effect: real CPU% before vs. after THROTTLE (Chapter 6 data extraction, Task 7)

Source: `task7_mitigation_effect.csv` — a fresh capture of real XMRig (`--bench=1M --randomx-mode=light -t 1`, chosen to fit this test host's limited free memory) against a just-restarted daemon, so this round's `cpu_percent` capture-schema change and the process-store state were both guaranteed clean. n=90 total ticks.

THROTTLE first applied at t=67.9s (pid=21868, comm=xmrig).

| Window | n ticks | mean cpu_percent | min | max |
|---|---|---|---|---|
| Before enforcement (mitigation=NONE) | 0 | n/a | n/a | n/a |
| After enforcement (mitigation=THROTTLE) | 23 | 92.6% | 92.6% | 92.6% |

**No clean before/after comparison could be established this round.** All 41 pre-detection (mitigation=NONE) ticks in this capture have an empty `cpu_percent` field (41 missing of 41) — see Finding below. Only the post-THROTTLE reading is usable, and even that should be read as a single data point, not a validated before/after delta.

## Finding: cpu_percent is not populated during the pre-detection window

`daemon/detector/engine.py`'s per-tick store update (where this round's Task 7 change added the `cpu_percent` field) runs unconditionally for every scored PID, so this is not a simple code-path bug in that line. Empirically, in this capture, `cpu_percent` is the empty string for every one of the 40 pre-detection ticks (t=0 to t=40.6, all confidence=NONE), then becomes the literal string `'0.0'` at the exact tick confidence first reaches LOW (t=41.6s), then real non-trivial values once mitigation=THROTTLE engages. The `'0.0'` at the LOW transition is consistent with psutil's own documented `Process.cpu_percent(interval=None)` convention — it returns 0.0 on the first-ever sampled call for a given `psutil.Process` instance, with real percentages only from the second call onward (`daemon/detector/fingerprint.py:_cpu_percent()`, module-level `_procs` cache). Taken together, this suggests `_cpu_percent(pid)` — and by extension the full fingerprint-build path that touches this field — was not actually being reached/cached for this PID before its first LOW-tier detection, for a reason not root-caused in this session (a resource-prioritisation short-circuit for low-scoring PIDs is one candidate, but this was not confirmed by reading further into the scan loop). Reporting the gap rather than a guessed root cause.

## Caveat

`cpu_percent` uses psutil's `Process.cpu_percent(interval=None)` convention: it returns 0.0 on a process's first-ever sampled call (no baseline yet), by psutil's own documented behaviour -- see `daemon/detector/fingerprint.py:_cpu_percent()` and the same artefact discussed in `evaluation/replay_scorer.py`'s docstring (Task 1). Combined with the Finding above, this means the very first non-empty `cpu_percent` reading for any PID is always an artefact, not a real measurement, regardless of which tier it happens to land in.

