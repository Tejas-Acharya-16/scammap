# State (Sun 1 Nov 2026, 01:00 IST)

Goal: full marks on the seven scoring rows plus the bonus, with the live server healthy when the judges' tool runs.

Live: https://scammap-yp1k.onrender.com (app at `/`, judge console at `/judge`). Engine v1.3 (pending merge), trust config `d7a23b4c`.

## Verified (who ran it, when, where the output is)

| What | Result | Run by |
|---|---|---|
| Engine tests | 205 passed, 2 known limits (xfail) | Claude chat, 31 Oct 18:15 |
| Full repo suite incl. Playwright | 224 to 233 passed, 2 xfailed, CI green | Claude Code, 31 Oct 23:40 |
| Judge console on live | "Run all checks" 26/26, live checks 9/9 | Claude Code, 31 Oct 18:40 |
| Attack table over https on live | 1,677 reports, 0 rejected, 0 failures, 2 known limits (`tests/attack/LIVE_ATTACK_TABLE.txt`) | Codex, 31 Oct 22:50 |
| Lookup formats and speed on live | 4 formats, one answer; p95 216 ms on new connections, 107 ms on keep-alive (`tests/api/LIVE_LOOKUP_CHECK.txt`) | Codex, 31 Oct 23:21 |
| Privacy canaries on live | No canary value in any reply; number masked (`tests/privacy/LIVE_PRIVACY_CHECK.txt`) | Codex, 31 Oct 23:21 |
| Input variants | 31 of 31 realistic variants accepted (`tests/api/INPUT_VARIANTS.txt`) | Codex, 1 Nov 00:11 |
| Bulk load | 2,000 reports, 16 connections: 0 x 429, 0 x 5xx, 0 timeouts on a server capped at 0.1 CPU (local replica, not live) | Claude Code, 1 Nov 00:15 |
| Licence, 4 steps on live | Lock at expiry (403), restore with no restart, tampered file 400, survives a redeploy | Claude Code, 31 Oct 18:39 to 18:46 |
| Docker on localhost | `docker compose up`: /health 200 on port 8080 | Antigravity, 1 Nov 00:25 |

## Added since 01:00 (branch `ai-watchdog`, stacked on `live-map`)

- AI watchdog: advisory `ai_watchdog` on every lookup with 3+ reports; judge console AI section (6 checks, 32/32 over 40 seeds); Check card shows it in English and Hindi. Held-out in our simulator: AUC 0.915; flags 94 of 230 planted campaigns that beat the rules; wrongly flags 22 of 749 confirmed real waves. Tests: 336 passed, 2 xfailed; e2e 29 passed (Claude, 1 Nov 04:31).

## Open issues

1. Stored XSS in how a reported link is shown: fix written (security hardening patches), not merged yet.
2. Render free instance sleeps after 15 minutes idle and is slow during a bulk upload: keep-awake monitor on `/health`; a paid instance for judging.
3. Known limits: reports with empty notes; friends who each pick a different area; rings of 3 to 7.
4. Repository visibility for the judges: ask the organisers (public, or shared).
5. Hindi strings need a check by a Hindi speaker.

## Next three tasks

1. Merge the security hardening, then check `/judge` 26/26 on live.
2. Record the backup video (`VIDEO_SCRIPT.md`) on seeded demo data.
3. Checkpoint 2 at 06:00; before judging: `POST /admin/reset`, then the read-only smoke test.

## Licence rehearsals

| # | When | Result |
|---|---|---|
| 1 | 31 Oct 18:39 to 18:46, live | All 4 steps passed, no restart |
| 2 | to do | |
| 3 | to do | |
