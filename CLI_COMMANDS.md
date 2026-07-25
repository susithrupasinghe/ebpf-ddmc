# EDDMC — CLI Command Reference

All commands assume you're at the repo root unless noted otherwise.

## 1. Install

```bash
sudo bash scripts/install.sh
```
Installs system/Python deps, creates `/var/log/eddmc`, registers the
`eddmc.service` systemd unit, symlinks the `eddmc` CLI to
`/usr/local/bin/eddmc`, and installs `client-app/` npm deps.

## 2. Running the daemon

Directly:
```bash
sudo python3 daemon/main.py [--config PATH] [--dry-run] [--log-level {DEBUG,INFO,WARNING,ERROR}]
```

Via the helper script (auto-installs `psutil`/`yaml` if missing):
```bash
sudo bash scripts/run_daemon.sh [--dry-run] [--log-level DEBUG]
```

Via systemd (after `install.sh`):
```bash
sudo systemctl start eddmc      # start
sudo systemctl stop eddmc       # stop
sudo systemctl restart eddmc    # restart
sudo systemctl status eddmc     # status
sudo systemctl enable eddmc     # start on boot
journalctl -u eddmc -f          # follow logs
```

Flags:
| Flag | Effect |
|---|---|
| `--config PATH` | Load config from a custom YAML instead of the default |
| `--dry-run` | Force `mitigation.dry_run = true` (detect/alert only, no throttle/block/kill) |
| `--log-level` | Override `daemon.log_level` (`DEBUG`/`INFO`/`WARNING`/`ERROR`) |

## 3. `eddmc` CLI (talks to the running daemon over `/tmp/eddmc.sock`)

```bash
eddmc status                                     # daemon status + uptime + tracked process count
eddmc watch                                      # live-updating process/score table (refreshes every 3s)
eddmc alerts                                      # last 20 alerts from the alert bus
eddmc config                                      # dump running config as JSON
eddmc revoke <pid>                                # lift mitigations (throttle/block/suspend) from a PID
eddmc kill <pid>                                  # manually send SIGKILL to a PID
eddmc allowlist submit <path> [--description TEXT] # hash a binary and submit to the registry allowlist (pending admin review)
```

Without `install.sh`'s symlink, run it as a module instead:
```bash
sudo python3 -m daemon.cli.commands <command> [args]
```

## 4. Distributed Behavioural Fingerprint Registry

Dev launcher (FastAPI + SQLite, auto-reload):
```bash
bash registry/run.sh
```
Env vars it honors:
```bash
EDDMC_REGISTRY_PORT=8321                # listen port (default 8321)
EDDMC_REGISTRY_AUTO_CONFIRM=true        # auto-confirm submitted fingerprints (default true)
```

Equivalent manual invocation:
```bash
cd "$(git rev-parse --show-toplevel)"
uvicorn registry.app:app --host 0.0.0.0 --port 8321 --reload
```

No-BCC local simulation (for testing the registry without eBPF/root):
```bash
python3 scripts/test_registry.py
```

## 5. Client app (Electron GUI)

```bash
cd client-app
npm install
npm start
```

## 6. Testing detection

Synthetic CPU-bound/futex-heavy workload to trigger the detector:
```bash
bash scripts/test_miner.sh [threads]     # defaults to $(nproc); uses stress-ng if available, else a Python fallback
```
Watch it get flagged in another terminal:
```bash
eddmc watch
```

## Quick reference

```bash
sudo bash scripts/install.sh                 # one-time setup
sudo systemctl start eddmc                   # start daemon
eddmc watch                                  # live monitor
eddmc alerts                                 # recent alerts
bash scripts/test_miner.sh                   # trigger a test detection
cd client-app && npm start                   # GUI
bash registry/run.sh                         # fingerprint registry (dev)
```
