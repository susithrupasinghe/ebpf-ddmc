# EDDMC — eBPF-based Daemon for Detection and Mitigation of CPU Cryptojacking

MSc Research Artifact | IIT / University of Westminster | W2121694

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
| 80-100 | CRITICAL | + SIGSTOP; SIGKILL if auto_kill=true |

## Quick Start

```bash
# 1. Install (requires root)
sudo bash scripts/install.sh

# 2. Start daemon
sudo python3 daemon/daemon.py --log-level INFO

# 3. CLI monitoring
eddmc watch
eddmc alerts

# 4. UI
cd ui && npm install && npm start

# 5. Trigger test detection
bash scripts/test_miner.sh
```

## Dry-run mode
```bash
sudo python3 daemon/daemon.py --dry-run
```

## Project Structure

```
ebpf-ddmc/
├── daemon/
│   ├── ebpf/            eBPF C programs (syscall, sched, net monitors)
│   ├── collector/       Python BCC collectors
│   ├── detector/        Feature extractor + deterministic scorer
│   ├── mitigator/       throttler, blocker, suspender, terminator, policy
│   ├── alerts/          Alert bus (IPC + JSONL)
│   ├── cli/             eddmc CLI commands
│   ├── config/          YAML config
│   ├── api_server.py    HTTP JSON API for UI
│   └── daemon.py        Main entry point
├── ui/
│   └── src/
│       ├── main/        Electron main process
│       ├── renderer/    Dashboard (HTML + JS)
│       └── preload.js   Secure IPC bridge
└── scripts/
    ├── install.sh       System install
    └── test_miner.sh    Synthetic miner for testing
```

## Requirements

- Linux kernel 5.8+ (6.x recommended), BTF enabled, cgroup v2
- Python 3.10+, `python3-bpfcc` (apt)
- Root / CAP_BPF + CAP_NET_ADMIN + CAP_SYS_ADMIN
- Node.js 18+ (UI only)
