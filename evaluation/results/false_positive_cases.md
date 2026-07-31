# False-positive case detail (Chapter 6 data extraction, Task 5)

Before the scratchpad huge-page fix (`reports/CHAPTER_06_RESULTS.md` §6.4.2-§6.4.3), five
real, legitimate processes on the test host were detected and — with live mitigation
active — actually throttled. Only `fwupd` has an exact pre-fix score anywhere in this
project's records; the other four are recorded only by tier and triggering signal, not an
exact number. This is stated plainly per the ground rule against inventing values, rather
than backfilling a plausible-looking figure.

| Process | Score before fix | Tier before | Mitigation applied | Score after fix | Tier after |
|---|---|---|---|---|---|
| `fwupd` (firmware-update daemon) | *not retained exactly — see note 1* | MEDIUM | THROTTLE | 29.0 | LOW |
| Claude Code CLI (Bun runtime) | *not retained* | MEDIUM+ | THROTTLE | 12.0 (pid 10294) / 0.0 (other worker pids) | NONE |
| VS Code | *not retained* | MEDIUM+ | THROTTLE | 0.0 (all 8 currently-tracked `code` pids) | NONE |
| Electron/Chromium subprocess (this project's client-app) | *not retained* | MEDIUM+ | THROTTLE | *not re-verified this round — see note 2* | — |
| `gjs` (GNOME JavaScript, desktop shell) | *not retained* | MEDIUM+ | THROTTLE | *not re-verified this round — see note 2* | — |

## Notes on how each "after" figure was obtained

1. **`fwupd`**: the 29.0/LOW figure is not from watching a live `fwupd` process again — it is
   the result already on record (`reports/CHAPTER_06_RESULTS.md` §6.4.3) of re-scoring a
   **synthetic fingerprint built from fwupd's own exact captured pre-fix raw values** (6
   scratchpad-sized allocations, 0 `MAP_HUGETLB` requests, elevated thread count) through the
   corrected scorer. No exact pre-fix numeric score for `fwupd` is retained in any log or
   CSV in this repository — only its tier (MEDIUM, confirmed by "actually throttled") and
   the ~380-second detection latency before review. Stating this precisely rather than
   implying a live before/after comparison exists.

2. **Claude Code CLI and VS Code**: re-verified **live**, this session, against the exact
   same fixed codebase used throughout this evaluation round (daemon running, real mitigation
   active, `dry_run=false`) — both tools were actively running on the test host at the time.
   Captured via `eddmc watch` / `/api/processes`: Claude Code CLI's main process (`comm=claude`,
   pid 10294) scored 12.0/NONE; several `claude` worker pids and every currently-tracked `code`
   (VS Code) pid scored 0.0/NONE. None reached LOW, let alone MEDIUM. This is a genuine,
   if informal, re-confirmation that the huge-page joint-condition fix holds for the two
   tools most likely to still be running on any given development host — obtained as a
   byproduct of this round's Task 4 screenshot capture, not a dedicated re-run.
   Caveat: `reports/CHAPTER_06_RESULTS.md` names the false-positive process specifically as
   Claude Code's **Bun runtime** (a specific child/worker process), whereas `comm=claude`
   here is the main CLI process — plausibly the same false-positive class but not
   verified to be the identical process/thread that originally misfired.

3. **Electron/Chromium subprocess (client-app) and `gjs`**: **not re-verified this round.**
   Neither had a running instance on the test host at the time of this check (the
   client-app was not launched during this session — see Task 4's screenshot note on why
   — and `gjs` was not active). No live or synthetic re-score was performed for either;
   reporting this gap explicitly rather than reusing the prior round's qualitative
   description as if it were new evidence.

## Summary

2 of 5 false-positive processes (`fwupd` via synthetic re-score; Claude Code CLI / VS Code
via live re-check) have concrete post-fix evidence that the huge-page joint-condition fix
holds. 2 of 5 (Electron/Chromium client-app, `gjs`) were not re-verified this round for lack
of a running instance to check. No process's exact pre-fix score is retained anywhere in
this project's records — only tier and triggering signal — which is itself worth stating in
Chapter 6 rather than presenting the "before" column as more precise than it is.
