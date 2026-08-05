# EDDMC — eBPF-based Daemon for Detection and Mitigation of CPU Cryptojacking

MSc Research Artifact | IIT / University of Westminster | W2121694

EDDMC is a Linux daemon that detects CPU cryptojacking (XMRig/RandomX-style
miners) using deterministic, explainable behavioural scoring built on eBPF
telemetry — not machine learning — and applies a graduated mitigation
response (alert → cgroup CPU throttle → iptables network block → suspend →
kill). It ships with a CLI, an optional Electron dashboard, and an optional
opt-in distributed fingerprint-sharing registry.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Electron UI                          │
│    Dashboard · Process Table · Alerts · Config              │
└──────────────────────┬──────────────────────────────────────┘
                       │  HTTP JSON API (localhost:7373)
┌──────────────────────▼──────────────────────────────────────┐
│                     EDDMC Daemon                            │
│                                                             │
│  eBPF Collectors  ──▶  Detection Engine  ──▶  Mitigation   │
│  syscall / sched       Feature Extractor      ALERT         │
│  net monitors          Scorer [0-100]         THROTTLE      │
│                        NONE/LOW/MED/           BLOCK        │
│                        HIGH/CRITICAL          TERMINATE     │
│                                                             │
│  Alert Bus (Unix socket + JSONL log + HTTP API)             │
└─────────────────────────────────────────────────────────────┘
                     Linux Kernel (eBPF hooks)
```

## Behavioral Fingerprinting Features

| Feature | Why it matters |
|---|---|
| `futex_ratio` | Miners use heavy mutex sync across hash threads |
| `io_ratio` | Miners compute, not I/O — very low read/write share |
| `cpu_bound_ratio` | Near 1.0 = never yields voluntarily (CPU-bound) |
| `thread_density` | Miners launch N threads matching CPU core count |
| `pool_hits` | Direct TCP to known stratum port (3333/4444/etc) |
| `mmap_ratio` | Large scratch-buffer allocations for hash state |
| `nanosleep_ratio` | Throttling miners sleep periodically |
| `cpu_percent` | Sustained 90%+ CPU from psutil |

## Score Tiers and Mitigation Cascade

| Score | Tier | Action |
|---|---|---|
| 0-19 | NONE | No action |
| 20-39 | LOW | Alert + log |
| 40-59 | MEDIUM | Alert + cgroup CPU throttle (30%) |
| 60-79 | HIGH | + iptables network block |
| 80-100 | CRITICAL | + SIGSTOP; SIGKILL if `auto_kill=true` |

---

## Requirements

### Hardware

- x86-64 or ARM64 host with 2+ CPU cores (thread-density and CPU-bound
  signals are weaker/meaningless on a single core)
- No GPU or special hardware required
- Tested on aarch64 (Apple Silicon–virtualised Ubuntu VM); x86-64 is the
  primary target platform assumed by the thesis

### Software

- Linux kernel **5.8+** (6.x recommended) with eBPF enabled
  (`CONFIG_BPF`, `CONFIG_BPF_SYSCALL`, `CONFIG_BPF_EVENTS`) and BTF support
  (`/sys/kernel/btf/vmlinux`) for CO-RE
- **cgroup v2** mounted (required for CPU throttling; `install.sh` warns if
  missing)
- Root privileges, or `CAP_BPF` + `CAP_NET_ADMIN` + `CAP_SYS_ADMIN` (loading
  eBPF programs, installing iptables rules, and signalling arbitrary PIDs
  all require elevated privileges)
- `iptables` (network-block mitigation tier)
- Node.js 18+ and npm (only if you build/run the Electron UI)

## Languages, Libraries and Frameworks

| Component | Language | Key libraries/frameworks |
|---|---|---|
| Daemon (`daemon/`) | Python 3.10+ | `bcc`/BCC (eBPF, via `python3-bpfcc`), `psutil`, `PyYAML` |
| eBPF programs (`daemon/ebpf/*.c`) | C (BPF, tracepoint-based) | BCC's clang/LLVM BPF backend |
| Fingerprint Registry (`registry/`) | Python 3.10+ | FastAPI, Uvicorn, Pydantic, SQLite |
| Client dashboard (`client-app/`) | JavaScript/JSX | Electron, React 18, Vite |
| CLI (`daemon/cli/`) | Python 3.10+ | stdlib only, talks to the daemon over a Unix socket |
| Evaluation harness (`evaluation/`) | Python 3, Bash | pandas/matplotlib-style report generation, Puppeteer + `wabt` (WASM track) |

## Installation

```bash
git clone <this-repo-url>
cd ebpf-ddmc
sudo bash scripts/install.sh
```

`scripts/install.sh` (run as root):

1. Checks the kernel for eBPF/BTF support and warns (does not fail) if a
   flag is missing.
2. Installs system packages via `apt`: `python3`, `bpfcc-tools`,
   `python3-bpfcc`, `libbpf-dev`, `bpftool`, `iptables`, `libcap2-bin`,
   `psmisc`.
3. Installs Python dependencies — prefers `python3-psutil`/`python3-yaml`
   via `apt` (avoids PEP 668 issues); falls back to a `.venv` with
   `--system-site-packages` (needed so `bcc` from `apt` is still importable)
   if the apt packages aren't sufficient.
4. Creates `/var/log/eddmc` (mode `750`).
5. Checks that cgroup v2 is mounted (warns if not — throttling needs it).
6. Installs and enables an `eddmc.service` systemd unit.
7. Symlinks the `eddmc` CLI to `/usr/local/bin/eddmc`.

This is Debian/Ubuntu-oriented (`apt-get`); on another distro, install the
equivalent packages manually and skip to step 3 below.

## Dependency Installation (manual / non-apt path)

Daemon (`daemon/requirements.txt`):
```bash
# bcc must come from your distro's package manager, not pip
# e.g. Ubuntu/Debian: apt install bpfcc-tools python3-bpfcc
pip3 install -r daemon/requirements.txt   # psutil>=5.9.0, PyYAML>=6.0
```

Fingerprint registry (`registry/requirements.txt`, optional component):
```bash
pip3 install -r registry/requirements.txt   # fastapi>=0.110, uvicorn[standard]>=0.29
```

Client dashboard (optional):
```bash
cd client-app && npm install
```

Evaluation harness extras (only needed to reproduce specific tracks):
```bash
sudo apt install upx-ucl            # packed_binary track
cd evaluation/browser_wasm && npm install   # browser_wasm track (Puppeteer + wabt)
```

## Configuration

Configuration lives in `daemon/config/defaults.yaml` (committed, documents
every key) with an optional, gitignored `daemon/config/local.yaml` for
machine-specific overrides (merged automatically at startup — see
`daemon/config/config.py`). Pass `--config /path/to/custom.yaml` to
`daemon/main.py` to use a different file entirely.

Key sections in `defaults.yaml`:

| Section | Controls |
|---|---|
| `daemon` | scan interval, PID file, log level/path, IPC socket path |
| `detection` | alert/throttle/block/terminate score thresholds, hard-evidence floors (pool/scratchpad), min syscalls/age before scoring, allowlists, per-feature weights |
| `mitigation` | `auto_kill`, `dry_run`, cgroup root, per-tier throttle quotas, SIGTERM grace period |
| `ui` | HTTP API port (`7373`) and CORS setting for the Electron UI |
| `fingerprint_registry` | opt-in flag (default `false`), registry URL, similarity threshold, sync options |

No `.env` file or secrets management is used — all configuration is plain
YAML, and no value in it is a credential.

## Running the System

```bash
# Directly
sudo python3 daemon/main.py [--config PATH] [--dry-run] [--log-level {DEBUG,INFO,WARNING,ERROR}]

# Via systemd (after install.sh)
sudo systemctl start eddmc
sudo systemctl status eddmc
journalctl -u eddmc -f

# CLI (talks to the running daemon over /tmp/eddmc.sock)
eddmc status      # daemon status + uptime + tracked process count
eddmc watch       # live-updating process/score table
eddmc alerts      # last 20 alerts
eddmc config      # dump running config as JSON
eddmc revoke <pid>
eddmc kill <pid>

# Electron dashboard
cd client-app && npm install && npm start

# Trigger a synthetic test detection
bash scripts/test_miner.sh [threads]
```

Full command reference: [CLI_COMMANDS.md](CLI_COMMANDS.md).

### Dry-run mode
```bash
sudo python3 daemon/main.py --dry-run
```
Runs full detection and scoring but skips actually applying any mitigation
action (throttle/block/suspend/kill) — useful for tuning thresholds safely.

### Distributed Behavioural Fingerprint Registry (optional)

Disabled by default (`fingerprint_registry.enabled: false`) — no data
leaves the host unless explicitly turned on. Dev/local instance:
```bash
bash registry/run.sh                 # FastAPI + SQLite, http://127.0.0.1:8321
python3 scripts/test_registry.py     # local, no-BCC/no-root registry logic simulation
```

## Evaluation / Reproducing Results

`evaluation/` contains a reproducible test harness mapping literature-cited
datasets/tools (XMRig, CoinBlockerLists, wasmbench/NoCoin, MalwareBazaar,
etc.) to test tracks against the running daemon.

```bash
sudo python3 daemon/main.py --log-level INFO &     # start the daemon first, every track needs it

bash evaluation/xmrig_ground_truth/run_xmrig_test.sh 10M
bash evaluation/network_pool_blocklist/run_pool_hits_test.sh
bash evaluation/evasion_throttled_miner/run_throttled_miner_test.sh 1 3M
bash evaluation/detector_overhead/run_overhead_baseline.sh 60
bash evaluation/detector_overhead/run_overhead_loaded.sh 60 3M
bash evaluation/packed_binary/run_packed_test.sh 3M    # requires: sudo apt install upx-ucl

# or run everything in sequence:
bash evaluation/run_all.sh
python3 evaluation/generate_report.py   # synthesizes evaluation/results/REPORT.md
```

Consolidated evaluation logic lives in `evaluation/eddmc_eval.py`; results
are written under `evaluation/results/`.

### Dataset preparation

Most tracks are self-contained (they generate or run their own synthetic
workload — no external dataset download needed). Two tracks need explicit
preparation:

- **`browser_wasm/`** — compile the test WASM module first:
  ```bash
  cd evaluation/browser_wasm && npm install && node build_wasm.js
  ```
- **`malware_corpus/`** — real, live cryptojacking malware. Only attempt
  this on a host you are certain is isolated/disposable, and follow this
  protocol: snapshot the VM before running anything and revert immediately
  after; samples execute inside a network namespace with loopback only and
  as an unprivileged user, under a hard timeout, gated behind a mandatory
  `--i-understand-the-risk` flag; check for persistence (crontab,
  `/etc/cron.d`, systemd units, shell profiles) after every run.
  ```bash
  bash evaluation/malware_corpus/fetch_sok_dataset.sh   # public hash/domain metadata only, safe
  export MB_API_KEY=your_malwarebazaar_key              # see External Services below
  bash evaluation/malware_corpus/fetch_malwarebazaar.sh
  ```

## External Services / API Keys

- **None required to run EDDMC itself** — the daemon, scorer, mitigator,
  CLI, and Electron UI are fully self-contained and talk only to the local
  kernel and a local Unix socket/HTTP API.
- **Fingerprint registry** (`registry/`) is a local/self-hosted FastAPI
  service, not a third-party dependency — you run your own instance; no key
  needed.
- **Only the `malware_corpus/` evaluation track** needs an external
  credential: a free MalwareBazaar API key (`MB_API_KEY`, register at
  https://bazaar.abuse.ch/) to download real malware samples for that one
  optional, high-risk track. A VirusTotal Intelligence key is an alternative
  path for the same track (per-hash lookups) but is not scripted.

## Default User Credentials / Test Accounts

Not applicable — EDDMC has **no authentication layer**. The daemon's HTTP
API binds to `localhost:7373` and the fingerprint registry defaults to
`127.0.0.1:8321`; both are trusted by proximity (local-only) rather than by
login. There are no user accounts, default passwords, or test logins
anywhere in the system. If you expose either service beyond localhost, add
your own authentication/network controls first.

## Known Limitations

- **GIL scan-latency inflation**: the detection engine's scan loop shares
  Python's GIL with the eBPF collector threads. Under sustained high event
  volume (e.g. an active miner), scan gaps can run to roughly double the
  configured `scan_interval`; a process whose entire lifetime fits inside
  one such gap can be missed entirely.
- **Browser-based WASM miners are weakly detected**: the current signal set
  (RandomX scratchpad allocation, stratum-port connections) doesn't match
  an in-page WASM hash loop's behavioural profile — this is a disclosed
  detection gap, not a bug.
- **Revoke-display gap**: after `eddmc revoke <pid>` lifts real enforcement,
  the CLI/UI status column can continue to show the prior CRITICAL tier,
  because tier display only re-fires on a strict score increase.
- **No Windows support**: EDDMC is a Linux/eBPF-only agent; fileless
  PowerShell-based miners (Purple Fox, Lemon Duck, Tor2Mine) are explicitly
  out of scope.
- **No authentication** on the local HTTP API or registry service (see
  above) — both are intended for local/trusted-network use only.
- **Detector overhead**: the daemon's own steady-state CPU usage is
  non-trivial on this evaluation hardware. Already mitigated somewhat by
  removing a dead syscall-event perf-submit path and adding an idle-process
  scoring pre-filter, but overhead remains above the design target.

## Project Structure

```
ebpf-ddmc/
├── daemon/
│   ├── ebpf/            eBPF C programs (syscall, sched, net monitors)
│   ├── collector/       Python BCC collectors
│   ├── detector/        Feature extractor + deterministic scorer
│   ├── fingerprint/     Distributed Behavioural Fingerprint Registry client
│   │                    (assessor, packager, submitter, matcher)
│   ├── mitigator/       throttler, blocker, suspender, terminator, policy
│   ├── alerts/          Alert bus (IPC + JSONL)
│   ├── ipc/             Unix-socket HTTP API (CLI + client-app)
│   ├── cli/             eddmc CLI commands
│   ├── config/          YAML config
│   └── main.py          Main entry point
├── registry/
│   ├── app.py           FastAPI registry server
│   ├── db.py            SQLite storage layer
│   └── run.sh           Dev launcher
├── client-app/
│   └── src/
│       ├── main/        Electron main process
│       ├── renderer/    Dashboard (HTML + JS)
│       └── preload.js   Secure IPC bridge
├── evaluation/          Reproducible test harness (per-track run scripts)
├── reports/             Thesis-facing evaluation reports and results
└── scripts/
    ├── install.sh       System install
    ├── test_miner.sh    Synthetic miner for testing
    └── test_registry.py Local no-BCC fingerprint-registry simulation
```
