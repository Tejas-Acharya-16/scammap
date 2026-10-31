# CyberForge 2026: team rules (read before every task)

PHASE: BUILD
<!-- Tejas changes the line above to "PHASE: BUILD" once he has confirmed the organisers started the build clock (scheduled 11:00 IST on Sat 31 Oct 2026; the schedule is indicative). The organisers' brief for our statement is already out, which suggests the clock has started. If this line is missing, treat the phase as PRE-BRIEFING. -->
STATEMENT: Community Scam Map for India: Report and verify scams in seconds, anonymously. Refer to it by title, not number.
<!-- Picked on site on 31 Oct by team Smashers. Top source: the organisers' brief "Community Scam Map: Student Brief" (29 Oct), kept OUT of the repo. Our readings of it: docs/PROBLEM_CARD.md and docs/BUILD_SPEC.md. -->

## Statement rules (Community Scam Map)
- Read docs/PROBLEM_CARD.md and docs/BUILD_SPEC.md before any task. For daily work they replace Part 3 onward of the pack. If either disagrees with the organisers' brief, the brief wins: stop and tell Tejas.
- The brief and the organisers' problem-statement PDF are organiser material. Never commit them or quote them in the repo, README, deck or video. Paraphrase only. The data tables in BUILD_SPEC section 16 (areas, verified numbers, scam types, channels) may be used as data files.
- The API paths, field names, status codes and error strings in BUILD_SPEC section 3 are the organisers' test interface. They are frozen. Spelling matters: `/license` and `LICENSE_EXPIRED` use S; the screen text "Licence expired. Contact your provider." uses C.
- No hard-coded rules for specific numbers, UPI IDs, links or senders. The judges load secret data and check for this. The verified list is a data file, not a rule.
- Verdicts come from deterministic code. No LLM in the request path, and none may set, raise or lower a verdict. AI helps us write code only.
- Privacy. Breaking any of these disqualifies the team:
  - Never store, log or return a reporter's name, phone, email, exact location or coordinates, raw IP address, user agent, raw `reporter_id`, raw `ip_prefix` or note text.
  - `reporter_id` and `ip_prefix` arrive in the report body as the reporter's pretend identity. HMAC both with TRUST_SALT at once and keep only the hashes.
  - Never log request bodies or query strings. Error messages never echo input.
  - Show a value in full only after 3 different voices. Say "reported", never "scammer", "fraud" or "fraudster".
  - Never look up or scrape people on social media or people-search sites.
- Licence. The private signing key never goes in Git, a prompt, a log or a server. The public key is a constant in code. The gate runs on every request. Expired means 403 `LICENSE_EXPIRED` except /health and /license. Never delete data on expiry. All licence state lives in the database, not on disk.
- Original work: all code in this repo is written during the event. Do not paste code from Tejas's earlier projects, earlier hackathons or Round 1. Libraries are fine and go in DISCLOSURE.md.
- Synthetic data only: obviously fake numbers (for example +91 90000 xxxxx), `.example` links, made-up UPI names. The made-up shops in BUILD_SPEC section 16 are the organisers' test data.
- 192.168.60.13 is the organisers' file server (README: "Mitigata edge file share. Public-facing artifact mirror. Internal services are NOT exposed here."). We used it only to download our own brief. Do not download anything else, do not upload, rename or delete, do not try logins, do not scan the network, do not contact any other host.
- Do not claim real-world accuracy. Say "in our tests" or "against the tricks we modelled".

Team: Tejas Prakash (tech lead, integrator, server and security core) and Bhumika (product, UX, web app, README, demo, QA).
Event: CyberForge 2026 final round, Mitigata x HackCulture, Bengaluru. Theme: AI and Cybersecurity.
Build clock: Sat 31 Oct 11:00 to Sun 1 Nov 11:00 IST. Feature freeze Sun 09:00. Submission window Sun 11:00 to 11:30. The timetable is indicative; if the start moves, shift the other times by the same amount.
Pre-event pack: CyberForge_Complete_Pack.md stays OUT of this repo (it was written before the event). Everything the build needs is in this file, docs/PROBLEM_CARD.md and docs/BUILD_SPEC.md. Do not ask for the pack; Tejas pastes one part of it only if a task needs it.

## Phase rules
- PRE-BRIEFING: research with sources, Problem Card drafts, questions for the organisers, tool and quota checks, registration. Do NOT write solution code, create a solution repo, or commit to a problem-specific architecture.
- BUILD: everything below applies in full.

## Source of truth, in order
1. The organisers' brief and any later organiser instruction.
2. docs/BUILD_SPEC.md, then docs/PROBLEM_CARD.md.
3. Test and evaluation output in this repo (`make test`, `make attack`, `make smoke`).
4. The pack.
5. Your own knowledge. Never use it for event facts, prices, limits, versions or dates.

## Rules
1. Never state a result you have not run. Show the command and its output. Anything not run is UNVERIFIED.
2. Never invent citations, datasets, metrics, CVEs, APIs, URLs or capabilities. If unsure, say so, or search and cite.
3. Synthetic data only. No real personal data. Test only against systems we own or the organisers provide or authorise. If the target is unclear, ask.
4. Defensive work only. No malware, no harmful payloads, nothing aimed at real-world systems.
5. Do not paste organiser-provided confidential material or datasets into any external service without asking the humans first.
6. Small diffs. One feature per branch or worktree. Touch only the folders in your brief. Do not change the API in BUILD_SPEC section 3 without asking.
7. Write acceptance tests before code. Tests must pass before you report done. Never edit expected outcomes to make results pass.
8. Secrets live in environment variables and are never committed. .env is ignored. .env.example holds placeholders only. Licence private keys live outside the repo.
9. Simplest architecture that works. The stack is in BUILD_SPEC section 1. No new framework, queue or database without human approval.
10. Deterministic code for the core. v1 uses no LLM at runtime. If one is ever added, its output passes a verifier or is labelled unverified.
11. Every demo path works on the live URL and on localhost via `docker compose up`. The licence demo works with no restart.
12. Record every third-party library, API, dataset and AI tool in /DISCLOSURE.md when you first use it.
13. Do not claim "deployed", "real-time", "secure", "accurate" or "novel" without evidence. Label simulated and synthetic data.
14. If a decision is costly and cannot be inferred, ask one focused question. Otherwise state the assumption and continue.
15. Do not rewrite stable code, delete files or add major dependencies without explaining the benefit and risk first.
16. UI: follow Part 6.9 of the pack (light surfaces, one green accent, monospace for identifiers; a dark evidence panel only if the optional attack screen is built). Use open-source fonts and icons and list them in /DISCLOSURE.md. Never use Mitigata's or any third party's logo, name or copied assets.

## Working agreement
- At most 2 agents per laptop, one per folder, each in its own git worktree. Tejas's laptop: Claude Code (T1, main checkout) and Antigravity (T3, worktree `../scammap-tests`, branch `tests-agent`). Never two agents in one working tree. The API is frozen.
- Merge at least every 2 hours. Main stays green. The other human reads the diff.
- Update STATE.md hourly: goal, decisions, open issues, next three tasks, licence rehearsal times.
- Log any decision that took more than 10 minutes in DECISIONS.md: question, options, chosen and why, what would change our mind, cost of being wrong, status.
- Report after each task: files changed, commands run, test results, what is not done, risks.
- Done means the tests ran and you saw the output. For server work, also `make smoke URL=<live url>`.
- Feature freeze Sun 09:00. After that, bug fixes only.
- Rehearse the licence demo three times and log the times.
- Cut order when time is short: attack-arena screen, map tiles (use a list), extra attack scenarios beyond the brief's four plus the real waves, APK, polish. Never cut: deploy, licence demo, report flow in Hindi or icons, privacy tests, trust rules and the attack table, README, DISCLOSURE, the backup video.
- Outside help: none during the event. Only the two team members and their AI tools write or design anything.

## Folders (BUILD phase)
- /app (server; not /app/static, /app/engine or /app/data), /tools, /deploy, /tests/unit, Makefile: Tejas (Claude Code, T1).
- /app/engine, /app/data, /tests/engine: E1, the engine written and tested in Claude chat (BUILD_SPEC section 15). T1 wires it and never rewrites it. A change goes through Tejas, with a test and a fresh attack table.
- /tests/api, /tests/attack, /tests/privacy: T3, the Antigravity agent (black-box tests and the attack table; BUILD_SPEC section 15). It never edits /app. T1 wires its suites into the Makefile.
- /web, /docs, /tests/e2e: Bhumika. `make web` writes the built site to /app/static; ask Tejas before committing there.
- /licenses: long.json and expired.json (public data; never a key).
- Make targets: make dev, web, test (includes tests/engine), attack, smoke URL=, perf URL=, privacy, docker.

## Quota habits
- Sonnet for implementation, Opus for architecture and stubborn bugs, Haiku for boilerplate. Run /clear between unrelated tasks. Check /usage hourly and keep about 20% in reserve. Do not leave agents running unattended with write access to main.

## Antigravity (T3)
- It may read this file as a rule (reported for the IDE since v1.20.5; UNVERIFIED for the 2.0 app), so the T3 prompt also tells it to read this file. Keep this file under 12,000 characters (reported rules cap).
- Its settings: no access to files outside the workspace, and terminal commands ask first (names from a third-party guide; UNVERIFIED in 2.0). The licence private key lives outside every folder an agent can see.
- Give it the repo and docs/BUILD_SPEC.md only: never the organisers' PDFs or file-server files (rule 5).
- If its quota locks, do not wait for the reset: a second Claude Code session takes the worktree, with tests/README.md as the handoff.
- Windows: if `make` is not installed, run the commands inside the Makefile directly.

## Style when talking to the humans
- Role: act as a senior practitioner with 30+ years in cybersecurity and AI: decisive, specific, sceptical of hype. It is a working stance only. Never claim experience, results or sources you do not have.
- Plain English, short sentences, direct. No warm-up phrases, no filler praise.
- Say what is verified and what is guessed. Give one recommendation, then the reason.
