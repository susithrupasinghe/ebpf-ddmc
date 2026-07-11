# EDDMC — Session Handoff Notes

Written by Claude on 2026-07-11, at the end of a working session on this repo
(done on macOS, where the eBPF daemon itself cannot run — only the registry
side was tested end-to-end). Read this first if you're continuing the work
in a new session, especially on the Ubuntu VM/VPS where the daemon actually
runs. Point a new Claude Code session at this file (e.g. "read HANDOFF.md and
continue") to pick up full context without re-explaining everything.

---

## 1. What this repo is

EDDMC — an MSc dissertation project (IIT/University of Westminster,
W2121694, supervised by Dr. Navod Neranjan). An eBPF-based Linux daemon that
detects CPU cryptojacking (XMRig/RandomX-style miners) via deterministic,
explainable behavioural scoring (not ML), with graduated mitigation
(alert → cgroup throttle → iptables block → suspend/kill) and an optional
Electron GUI. The thesis document is `reports/EDDMC_Thesis_Interim
Report_W2121694.docx` (Chapters 1–5 written; Chapters 6 "Results" and 7
"Conclusion" are still empty placeholders as of this session).

## 2. The core finding from this session: thesis vs. code gap

Early in this session I read the full thesis and did a full codebase scan.
The single biggest finding: **the thesis's flagship "novel" contribution —
the Distributed Behavioural Fingerprint Registry — was fully described in
the thesis (§1.5, §1.6, RQ6, §3.10.6, §3.12, §5.5.7) but did not exist
anywhere in the codebase.** No `daemon/fingerprint/` package, no registry
server, nothing. Everything else in the thesis (collector, detector,
scorer, mitigator, CLI, Electron UI) *did* match the code reasonably well.

I also found smaller thesis-vs-code drift, some now fixed, some still open
(see §7 below).

**This session's main deliverable was building the registry so RQ6 becomes
answerable.** See §4.

## 3. Novelty/gap research (web-search-backed, done this session)

Answering the user's question "is this novel enough, can it actually detect
cryptojacking":

- **Closest prior art confirmed real**: CryptoGuard (Park et al., ASIACCS
  2025, https://arxiv.org/abs/2510.18324) — syscall sketch/sliding-window
  features → two-phase deep learning, F1 ~96%/92%, 0.06% CPU overhead.
  It's ML-based; EDDMC's deterministic/explainable framing is a real,
  legitimate differentiation against it, not just a strawman.
- **Kim et al. 2025** (https://www.mdpi.com/2079-9292/14/6/1208) — also
  real, also ML-based. Same differentiation applies.
- **What real-world tools actually do**: Falco's default cryptomining
  detection is binary-name/hash matching and command-line string matching
  (e.g. "xmrig" in a macro, "stratum+tcp" string match) — trivially beaten
  by renaming the binary. EDDMC's behavioural-fingerprint approach is
  genuinely deeper than what's deployed in practice today. Good news for
  the novelty argument.
- **Distributed fingerprint sharing**: no cryptojacking-specific paper found
  doing this. Closest adjacent concept is MISP (general threat-intel
  sharing) — but MISP shares file hashes / fuzzy hashes of *binaries*, not
  eBPF-derived *behavioural feature vectors*. That's a real, defensible
  distinction — keep it precise in the thesis (don't imply cross-org threat
  sharing itself is new; only the behaviour-vector-based mechanism for
  cryptojacking specifically is).
- **Evasion caveats surfaced by research** (worth a line in
  limitations/future work): io_uring syscall bypass, rootkit tampering with
  the BPF ring buffer itself, splitting mining work across multiple child
  processes to dilute any single PID's futex/mmap ratios below threshold.
  None of these are handled by the current design.

Full source list is in the earlier chat turn if needed; the above is the
condensed, actionable version.

## 4. What was built this session: the Distributed Fingerprint Registry

### New files
- `registry/` (renamed this session from `registry_server/`) — standalone
  FastAPI + SQLite service, independent of any daemon instance.
  - `app.py` — FastAPI app. Endpoints:
    - `POST /api/v1/fingerprints` — submit a fingerprint (202 Accepted)
    - `GET /api/v1/fingerprints` — list confirmed fingerprints (JSON array)
    - `GET /api/v1/fingerprints/pending` — list pending (manual-review mode)
    - `GET /api/v1/fingerprints/stats` — counts, last-updated, per-process breakdown
    - `POST /api/v1/fingerprints/{id}/confirm` — manually confirm a pending one
  - `db.py` — raw `sqlite3` storage layer (no ORM), dedupes by `fingerprint_id`
    (re-submissions bump `submission_count`, don't create duplicate rows).
  - `run.sh` — dev launcher: `uvicorn registry.app:app --host 0.0.0.0 --port 8321`
  - `requirements.txt` — `fastapi`, `uvicorn[standard]`
  - **`EDDMC_REGISTRY_AUTO_CONFIRM`** env var (default `true`) controls whether
    a submission is trusted immediately (dev/simulation) or held `pending` for
    manual review via the confirm endpoint (the conservative mode the thesis
    describes for production — flip this to `false` there).

- `daemon/fingerprint/` — the four client-side modules Ch.5.5.7 already
  claimed existed. Now they do:
  - `assessor.py` — `FingerprintAssessor.evaluate(result, now=None)`. Gate:
    (1) CRITICAL sustained ≥ `sustained_critical_seconds` (60s default),
    (2) `pool_connections > 0`, (3) `futex_ratio≥0.40 AND cpu_bound_ratio≥0.92
    AND thread_cpu_ratio≥1.0` all simultaneously, (4) best-effort SHA-256 of
    `/proc/<pid>/exe`. All four must pass. `now` param exists so tests can
    inject simulated time instead of sleeping 60 real seconds.
  - `packager.py` — `feature_vector(fp)` (the single source of truth for the
    8-dim vector, shared with matcher.py), `package(fp, evidence)` (builds
    the JSON payload: one-way SHA-256 hostname hash as `node_id`, SHA-256 of
    the feature vector as `fingerprint_id`, no PII).
  - `submitter.py` — `FingerprintSubmitter.submit_async()`, background
    thread, one retry after 5 minutes on failure, never blocks local
    detection/mitigation.
  - `matcher.py` — `FingerprintMatcher`, downloads confirmed set at startup
    + hourly refresh, `match(fp)` does cosine similarity, threshold 0.85
    default, returns best match above threshold.

### Wiring
- `daemon/detector/engine.py` — `DetectionEngine` now takes an optional
  `fingerprint_matcher` param. In `_scan()`, right after scoring, if the
  matcher finds a similarity match and the current tier is below HIGH, the
  `ScoringResult` is mutated in place to HIGH/BLOCK with an explanatory
  reason appended (elevation without waiting for the full observation
  window — this is the registry's core detection-acceleration benefit).
- `daemon/main.py` — instantiates `FingerprintAssessor`/`Submitter`/`Matcher`
  only if `cfg["fingerprint_registry"]["enabled"]` is true. `on_detection`
  callback now also runs the assessor and submits on gate-pass.
- `daemon/config/defaults.yaml` — new `fingerprint_registry:` section,
  **`enabled: false` by default** (opt-in, per the thesis's own ethics
  chapter §3.12 — no data leaves the host unless explicitly turned on).

### ⚠️ One naming adaptation you must reflect in the thesis text
The 8-feature vector uses **`randomx_signature`** (binary 0/1, derived from
`scratchpad_allocs > 0`) instead of the thesis's **`mmap_ratio`** (a
continuous ratio). Why: `daemon/detector/fingerprint.py`'s `MemoryProfile`
tracks a discrete scratchpad-allocation *count*, not a continuous mmap
syscall ratio — there was nothing to compute a ratio from without adding new
collector plumbing. Same discriminative signal, different representation.
**Update §5.5.2/§5.5.7 of the thesis to say `randomx_signature`, not
`mmap_ratio`,** or an examiner comparing thesis text to code will catch it.

### Also: FastAPI + SQLite, not Flask
The thesis (§5.2.2, Table 1) says the registry server is Flask. Per your
choice this session, it's actually **FastAPI + SQLite**. **Update the thesis
tech-stack table and §5.5.7 text to say FastAPI**, not Flask, for the
registry server specifically (Flask is still correct for nothing else in
this codebase — the daemon's own IPC is a raw Unix-socket HTTP server, not
Flask either; see §7 below, that was already a pre-existing thesis/code
mismatch before this session).

## 5. Repo structure changes (folder reorg, this session)

```
ebpf-ddmc/
├── daemon/          # core detection daemon (cli/ stays nested inside —
│                    #   tightly coupled to the Unix socket transport)
│   ├── ebpf/            eBPF C programs (syscall, sched, net, mem monitors)
│   ├── collector/       Python BCC collectors
│   ├── detector/        fingerprint.py (data model), scorer.py, engine.py
│   ├── fingerprint/     NEW — registry client (assessor/packager/submitter/matcher)
│   ├── mitigator/       throttler, blocker, suspender, terminator, policy
│   ├── alerts/          Alert bus (JSONL)
│   ├── ipc/             Unix-socket HTTP API (Docker-style)
│   ├── cli/             eddmc CLI
│   ├── config/          defaults.yaml + loader
│   └── main.py          entry point
├── registry/        # RENAMED from registry_server/ this session
│   ├── app.py, db.py, run.sh, requirements.txt
├── client-app/      # RENAMED from ui/ this session (Electron GUI)
├── scripts/
│   ├── install.sh, run_daemon.sh, test_miner.sh
│   └── test_registry.py   NEW — local no-BCC, no-root two-node simulation
└── reports/         # thesis documents (.docx)
```

All references to the old names were swept and fixed: `install.sh`,
`README.md`, `defaults.yaml`, `registry/run.sh`, `registry/app.py`'s
docstring/import, `scripts/test_registry.py`, `client-app/package.json`'s
`name` field. I also fixed pre-existing stale README references to
`daemon/daemon.py`/`daemon/api_server.py` (the real entry point is
`daemon/main.py`; there is no separate api_server.py — the IPC server lives
in `daemon/ipc/socket_server.py`).

**Not yet committed to git** — everything from this session (the reorg
shows as deletes of `ui/*` + untracked `client-app/`, since git doesn't know
it's a rename until you `git add`). Decide when you want to commit.

## 6. How to run everything

### On a Mac / non-Linux dev machine (no BCC/eBPF available)
Only the registry side is runnable here:
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r registry/requirements.txt pyyaml psutil
bash registry/run.sh                       # registry on :8321
python3 scripts/test_registry.py           # in a second terminal, same venv
```
`client-app/` (`npm install && npm start`) will also launch and poll for the
daemon, but shows "Daemon offline" with no local daemon/socket present.

### On the Ubuntu VM (the real target — daemon needs Linux 6.x + BCC + root)
```bash
sudo bash scripts/install.sh          # BCC, python deps, systemd unit, CLI shim, npm install
sudo systemctl start eddmc            # or: sudo python3 daemon/main.py --log-level INFO
eddmc watch                           # live process/score table
eddmc alerts                          # streaming alerts
bash scripts/test_miner.sh            # synthetic CPU-bound load to trigger a detection
```

To enable the fingerprint registry there, edit `daemon/config/defaults.yaml`:
```yaml
fingerprint_registry:
  enabled: true
  registry_url: http://<registry-host>:8321
```
For the real two-node experiment (thesis §3.10.6): run `registry/` on one
node (or a third neutral host), point both EDDMC daemons at it, run XMRig on
Node A first to get it confirmed, then start XMRig on Node B and measure
time-to-HIGH-tier-alert with vs without the registry enabled.

## 7. Known issues / inconsistencies still open (not fixed this session)

These were flagged during the codebase scan but are **out of scope for the
registry work** — listed here so they aren't lost:

1. **`scorer.py` hardcodes weights and tier thresholds** rather than reading
   them from `defaults.yaml`'s `detection:` section, even though the config
   file documents `alert_threshold`/`throttle_threshold`/etc. as if they were
   live knobs. This undercuts the thesis's "every weight is tunable via YAML
   without touching code" claim (§1.3.1, §5.5.3). Fix: wire `scorer.py`'s
   `W` dict and `_tier()` boundaries to read from `cfg["detection"]`.
2. **`daemon/detector/features.py`** looks like dead/duplicate code — a
   differently-shaped flat feature-dict extractor that overlaps with
   `fingerprint.py` but isn't imported/called by `engine.py` anywhere.
   Either delete it or document why it's kept.
3. Thesis says the daemon's HTTP API is **Flask on localhost:7373**; actual
   implementation is a **Unix domain socket** (Docker-style,
   `daemon/ipc/socket_server.py`), arguably a better engineering call, but
   the thesis §5.2.2/Table 1/§5.4 text needs to say Unix socket, not Flask
   + port 7373, for *that* component. (Flask is now correctly used for the
   *registry* server built this session — don't conflate the two when
   editing the thesis.)
4. `scripts/test_miner.sh` uses `stress-ng`/a SHA-256 busy-loop as a miner
   stand-in — it won't trigger the RandomX-scratchpad or mining-pool-network
   signals, only syscall/scheduler/parallelism ones. Real XMRig/cpuminer-multi
   runs (as described in thesis §5.3) need to happen separately for the
   actual Chapter 6 evaluation data.
5. Chapters 6 ("Results and Evaluation") and 7 ("Conclusion and Future
   Work") in the thesis docx are still empty placeholders.

## 8. Suggested next steps, roughly in priority order

1. On the Ubuntu VM: confirm the daemon still loads correctly with the new
   `daemon/fingerprint/` imports and `fingerprint_registry` config section
   (should be a no-op when `enabled: false`, but verify — this session's
   testing was necessarily registry-only, no BCC available on macOS).
2. Run the real two-node registry experiment per thesis §3.10.6 (two VMs,
   or the same VM twice with different ports as a first smoke test).
3. Fix item 1 in §7 (wire scorer.py to config) — cheap, and it's needed for
   the "auditable and tunable" claim to actually be true.
4. Update the thesis text for the three items flagged with ⚠️ above
   (`randomx_signature` naming, FastAPI not Flask for the registry, Unix
   socket not Flask:7373 for the daemon API) before anyone diffs prose
   against the repo.
5. Run the actual evaluation workloads (XMRig full-speed/throttled/renamed,
   cpuminer-multi, gcc/ffmpeg/pgbench benign set) and start writing Chapter 6.
6. Consider softening "first-ever" novelty language per §3 above.

---
*End of handoff notes. If you're a new Claude session reading this: the user
(Susith) is continuing an MSc dissertation implementation on an Ubuntu VM.
The person who wrote this file (a prior Claude session) did all testing on
macOS where the actual eBPF daemon cannot run — treat anything under "on the
Ubuntu VM" above as unverified until you confirm it there.*
