# Integrity check: duplicate daemon and dry-run history (2026-08-01)

Verifies whether the two environment problems found late in the 2026-08-01 data-extraction
session (a parallel systemd daemon, and a dry-run-by-default config) affected any previously
reported artefact. Evidence sources: `/var/log/eddmc/eddmc.log` (append-only across sessions),
`journalctl -u eddmc` (systemd's own record, authoritative for that daemon instance), git
history, and filesystem mtimes/birth times.

## Lead finding

**One figure destined for the dissertation overstates what it shows.** This session's own
`reports/CH6_DATA_EXTRACTION.md` (Task 4) describes a screenshot as capturing xmrig
"actively under MEDIUM/THROTTLE." The daemon's log for that exact moment
(`2026-07-31 23:53:06`) reads:

```
INFO eddmc.policy: [DRY-RUN] Would apply THROTTLE to pid=15944 (score=45.0)
```

No cgroup quota was ever applied — this was dry-run only. The score, confidence, and
reasons shown in the screenshot are all real and correctly computed; only the word
"actively" (implying real enforcement) is wrong. This is corrected below (A2) and the wording
in `CH6_DATA_EXTRACTION.md` should be fixed before the chapter cites it.

**Everything else checked — the fwupd false-positive incident, the packed/ground-truth/evasion
THROTTLE results behind the confusion matrix and RQ5 — is independently confirmed as REAL
enforcement**, unaffected by either problem. Detail follows.

---

## A1. Blast radius of the duplicate daemon

**Window, established from `journalctl -u eddmc` (authoritative — this is systemd's own
record of starting/stopping its managed process, not inferred):**

```
2026-08-01 00:06:15  systemd: Started eddmc.service   (pid=20069)
2026-08-01 00:37:56  systemd: Started eddmc.service   (pid=26201, auto-restart after pid=20069 was killed)
2026-08-01 00:39:13  systemd: Stopped eddmc.service    (user ran `sudo systemctl stop eddmc`)
```

**Duplicate window: 2026-08-01 00:06:15 → 2026-08-01 00:39:13 (≈33 minutes).** During this
entire window a systemd-managed instance was running. It overlapped with manually-started
instances at two points confirmed from `/var/log/eddmc/eddmc.log`'s own "EDDMC starting —
pid=X" lines: pid=21671 (started 00:19:50, stopped 00:32:07) and pid=25728 (started 00:36:40,
outlived the systemd stop by ~2.5 minutes). A third manual instance, pid=18407 (started
00:00:39, before the systemd window began), has no logged clean shutdown before pid=20069
appears — plausibly the origin of the systemd restart chain if it crashed or was OOM-killed
(no graceful-shutdown line is expected in that case), but this specific detail could not be
confirmed further and is reported as unconfirmed rather than asserted.

**Per-artefact check:**

| Artefact | Captured | Verdict |
|---|---|---|
| `screenshot_eddmc_status.png` / `screenshot_scored_process_list.png` / `screenshot_medium_alert_breakdown.png` | Raw captures at 2026-07-31 23:53:47–23:56:06 (file mtimes) | **Outside the window** — over 9 hours before the systemd instance even started (2026-08-01 00:06:15). |
| Live re-checks of Claude Code CLI / VS Code (`false_positive_cases.md`) | Same capture session, 2026-07-31 23:53–23:58 | **Outside the window**, same reasoning. |
| `mitigation_effect.md` / underlying captures | `task7_mitigation_effect.csv` mtime 2026-08-01 00:21:51 | **Inside the window.** This is the second Task-7 attempt already flagged in `mitigation_effect.md` as contaminated by PID-reuse from a killed orphan process — the duplicate daemon is the concrete mechanism behind that contamination (two daemons, two independent process-store dicts, competing for the same PID's history via the socket). This capture was already superseded by later, clean measurements (`task7_diag.csv`, 00:41:50, after the window closed; `mitigation_effect_v2.csv`, 01:11:42) and never used as a final figure. No further correction needed beyond what `mitigation_effect.md` already states. |

**Specific anomaly: 889 vs. 1,144 vs. ~1,912 tracked processes.** Two daemons do not "split"
a shared process-store — each runs as a separate OS process with its own independent
in-memory dict; whichever one holds the Unix socket at query time answers, and its answer
size depends only on its own uptime. This is moot for the specific screenshot in question
regardless: `screenshot_eddmc_status.png`'s raw capture (23:53:47) predates the duplicate
window entirely (Task 4 finding above), so no duplicate-daemon explanation applies. The real
explanation is uptime: this capture ran against a daemon started at 23:49:29 (**258.5s**
uptime, 889 tracked), versus `reports/EVALUATION_ROUND2.md`'s 903s-uptime capture (1,144
tracked) and `REPORT.md`'s dedicated overhead-measurement session (~1,912, from a much longer
continuous run, `overhead_idle_baseline.csv`, 60 samples). More observation time monotonically
finds more distinct processes; this is expected behaviour, not a degraded state, and the
figures need no recapturing on these grounds. (Whether resource contention from two daemons
sharing eBPF perf-buffer bandwidth causes *dropped events* rather than a *split count* is a
plausible secondary effect, but is not needed to explain this specific number and was not
separately tested.)

## A2. Dry-run history of every mitigation claim

`daemon/config/local.yaml` is gitignored (no version history available). Its filesystem
**birth time is 2026-07-19 15:40:48**; its **last-modified time is 2026-07-28 03:16:17**,
unchanged since. The daemon's own append-only log (`/var/log/eddmc/eddmc.log`, spans back to
April) distinguishes real enforcement (`[THROTTLE] pid=X ... quota=30% (30000/100000 µs)` +
later `[UNTHROTTLE] pid=X released from cgroup`) from dry-run (`[DRY-RUN] Would apply ...`)
unambiguously, and was used as the primary evidence below rather than trying to reconstruct
the gitignored file's content history.

| Claim | Source | Verdict | Evidence |
|---|---|---|---|
| fwupd + 4 other false positives actually throttled | `reports/CHAPTER_06_RESULTS.md` §6.4 (2026-07-24) | **Confirmed enforced** | Log 2026-07-24 01:29–04:21 shows real `[THROTTLE] ... quota=30%` and `[UNTHROTTLE] ... released from cgroup` for multiple pids in this exact window, including the fwupd-associated pid. |
| "Mitigation mode: live (dry_run=false) throughout both sessions... every THROTTLE recorded below is a real cgroup v2 cpu.max quota" | `evaluation/results/FINAL_EVALUATION_SUMMARY.md` (written 2026-07-28 02:27) | **Confirmed enforced** | Written before local.yaml's 03:16:17 modification; cross-checked against `packed_xmrig_3M.csv`'s capture window (below), which shows real enforcement. |
| "mitigation this round ran in live mode (dry_run=false), and every THROTTLE decision was independently checked against /sys/fs/cgroup/.../cpu.max" | `reports/EVALUATION_ROUND2.md` (written 2026-07-28 19:04) | **Confirmed enforced** | The three THROTTLE-tier tracks behind this claim — `xmrig_ground_truth_1M.csv` (2026-07-27 23:41), `evasion_throttled_1thread_3M.csv` (2026-07-27 23:46), `packed_xmrig_3M.csv` (2026-07-28 00:27) — were all captured **before** local.yaml's 03:16:17 modification. Log cross-reference for `packed_xmrig_3M` (pid=87792) confirms real `[THROTTLE] ... quota=30%` at 00:23:24 and `[UNTHROTTLE]` at 00:28:19. Report text was written after the 03:16:17 config change but describes data captured well before it — an accurate historical claim about the data it cites, not a claim about the report's own writing-time environment. |
| Task 4 screenshot: xmrig "actively under MEDIUM/THROTTLE" | `reports/CH6_DATA_EXTRACTION.md` (this session) | **Confirmed dry-run only — correction needed** | See Lead finding above: log line at the exact capture timestamp reads `[DRY-RUN] Would apply THROTTLE`. |
| Task 7's real 99.7%→30.0% CPU-reduction result | `evaluation/results/mitigation_effect.md` (this session) | **Confirmed enforced** | This measurement was explicitly taken with `dry_run=false` via a scoped `--config` override, verified live (`eddmc config` showed `"dry_run": false`) before the run — this is the one live measurement this session that was deliberately checked at the time, not reconstructed after the fact. |

**Boundary established**: real enforcement (dry_run=false) is confirmed for every checked
claim up to and including captures on 2026-07-28 before 03:16:17. From 2026-07-28 03:16:17
onward, `local.yaml` set `dry_run: true`, confirmed still in effect through the entirety of
today's session (2026-08-01) except for the one explicit, logged override used for the final
Task 7 measurement. No other report reviewed makes a mitigation-effectiveness claim about data
captured in that dry-run-by-default window without an explicit, checked override.

## A3. Capture CSVs unaffected

All 13 CSVs behind the confusion matrix (`confusion_matrix_v2.md`) and the ablation
(`ablation_leave_one_out.md`) have mtimes between **2026-07-27 23:17:09** and **2026-07-28
00:27:43** — three to four days before today's session, and well before either problem
window (duplicate daemon: 2026-08-01 00:06–00:39; dry-run-by-default: confirmed continuously
in effect since 2026-07-28 03:16, i.e. also after these captures). None were modified this
session; they were only read, by `replay_scorer.py` and the confusion-matrix/ablation
scripts. Quantitative results in Chapter 6 built from these CSVs stand unaffected by either
problem.

## A4. Restored state

Confirmed at time of writing:

- No `daemon/main.py` process running (`ps aux` clean).
- `systemctl is-active eddmc` → `inactive`.
- No stray xmrig or other miner process running (`ps aux` clean).
- `/tmp/eddmc.sock` does not exist (no daemon currently listening).
- `daemon/config/local.yaml` unmodified — `mitigation.dry_run: true`, mtime still
  2026-07-28 03:16:17, exactly as before this session's temporary `--config` override was
  ever used.

This is the fully restored, normal, idle state. The daemon was not left running; when next
started with the ordinary command (`sudo python3 daemon/main.py ...`, no `--config` flag),
it will pick up `local.yaml`'s `dry_run: true` as before.

## Recommendation

Fix the wording in `reports/CH6_DATA_EXTRACTION.md`'s Task 4 section (and this session's
`SESSION_SUMMARY_2026-08-01.md`, which repeats the same phrasing) to state that the screenshot
shows the daemon's *decided* mitigation tier under dry-run, not applied enforcement. If the
dissertation specifically wants a screenshot demonstrating real enforcement, one would need to
be recaptured with `dry_run: false` (the infrastructure for that — a scoped `--config`
override, not touching `local.yaml` — already exists from this session's Task 7 work); this
was not done as part of this integrity check since it wasn't asked for and is a live-system
action outside Part A's investigate-and-restore scope.
