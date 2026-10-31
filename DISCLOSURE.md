# Disclosure

Everything in this repository was written during CyberForge 2026 (Sat 31 Oct 11:00 to Sun 1 Nov 2026, IST)
by Team Smashers (Tejas Prakash, Bhumika) with the AI tools listed below. No code comes from earlier projects
or earlier hackathons.

## Libraries the server runs on (`requirements.txt`)

| Library | What we use it for | Licence |
|---|---|---|
| FastAPI | HTTP API | MIT |
| Uvicorn | ASGI server | BSD-3-Clause |
| SQLAlchemy | Database access (SQLite locally, PostgreSQL on the server) | MIT |
| psycopg 3 | PostgreSQL driver | LGPL-3.0 |
| Pydantic | Request models | MIT |
| PyNaCl | Ed25519 check of the licence signature | Apache-2.0 |
| httpx | Test client | BSD-3-Clause |
| pytest | Tests | MIT |

## Test-only tools (`requirements-dev.txt`)

| Tool | What we use it for | Licence |
|---|---|---|
| Playwright 1.63.0 with Chromium | Phone-size browser tests of the app (`tests/e2e`) | Apache-2.0 |

## In the browser

- qrcodejs 1.0.0, loaded from cdnjs, draws the QR code on the judge console (`/judge`). The page works without it.
- No web fonts: the pages use the device's system fonts (Inter where the device already has it). Both pages share one stylesheet, `app/static/theme.css`, written for this project.
- The map pin in the header is drawn in CSS. No logo, image or asset from any other site or company is used.
- Icons are Unicode emoji, drawn by the device's own emoji font. No icon pack and no third-party logos.

## Services and images

- Render: the web service and its PostgreSQL database.
- GitHub and GitHub Actions: the repository and the test run on every push.
- Docker images `python:3.12-slim` and `postgres:16-alpine` for `docker compose up`.

## Data

- No real personal data anywhere. All test and demo data is synthetic: numbers in `+91 90000 xxxxx`,
  made-up UPI IDs, `.example` links, reporter IDs such as `r_demo_N`, networks in `10.x.y`.
- The reference tables in `app/data` (areas, the verified list, scam types, channels) come from the data
  tables in the organisers' brief and are used as data files, as the event rules allow. The shops in the
  verified list are the organisers' made-up test businesses.
- The message reader's training data, `tools/ai/messages.jsonl` (591 messages), and its 10 held-out test messages
  (`tests/unit/data/ai_heldout.jsonl`) were written by Claude Code during the event. They are synthetic: `+91 90000`
  numbers, `.example` links, made-up UPI IDs, banks and shops. No real message and no third-party dataset.
  The model is trained by our own code (`tools/ai/train_reader.py`, standard library only). No pre-trained model,
  and no library in the browser: `app/static/ai/reader.js` is written for this project.

## AI tools

They helped us write code, tests and documents. None of them runs inside the product: every verdict comes
from deterministic code, and no model is called while the server answers a request. The product has one model
of its own, the on-device message reader (see Data): it runs in the browser, only suggests a kind of scam,
and never sets a verdict.

| Tool | What it helped with |
|---|---|
| Claude (claude.ai chat, Anthropic) | Planning, the trust engine and its tests (`app/engine`, `tests/engine`), the judge console sandbox, reviews, the security review |
| Claude Code (Anthropic) | Server, licence, deployment, CI, web app changes, Playwright tests, the on-device message reader and its synthetic messages |
| Google Antigravity (with the Claude and Gemini models it offers) | README, Docker files, the demo seed script, the video script |
| OpenAI Codex | Black-box tests: live attack table, live lookup and privacy checks, input variants |
