# app/engine: the core of Community Scam Map

Normaliser, masking, trust rules, verdicts, map and alerts. Pure Python 3.12, standard library
only, no I/O, no clock reads, no network, no LLM. Written during the event (31 Oct 2026) by
Claude in chat, from docs/BUILD_SPEC.md v2.2; tested with `tests/engine`.

Owner: E1 (Claude chat, via Tejas). Claude Code (T1) calls it and does not rewrite it. If a
test or a judge-facing behaviour needs a change, tell Tejas, change it with a test, and rerun
the attack table.

## Files
| File | What |
|---|---|
| `normalise.py` | One standard form per identifier; masking (98XXXXX210, r***@okaxis, sbi***.in/..., HD****) |
| `fingerprint.py` | Keyed hashes: reporter, network, note words. Raw values never leave it |
| `trust.py` | Links reports into voices; points; counted voices for map and alerts |
| `engine.py` | In-memory model and the handlers for the seven API routes (not the licence) |
| `registry.py` | Areas, verified values, scam types, channels: loaded from `app/data/*.json` |
| `config.py` | `TrustConfig`, every dial in one place; its hash is in each lookup |
| `../data/*.json` | Data from the brief's appendices: data, never code (the judges grep for hard-coded numbers) |

## Wiring it into FastAPI (T1)
```python
import os
from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from app.engine import Engine, Registry

REGISTRY = Registry.from_dir(Path(__file__).parent / "data")
ENGINE = Engine(REGISTRY, salt=os.environ["TRUST_SALT"])   # refuse to start without it

# at start-up, after the tables exist:
#   ENGINE.load(db.all_report_rows(), db.all_challenge_rows())

def client_ip(request: Request):
    # Used only when a report has no ip_prefix. Hashed at once inside the engine. Never logged.
    fwd = request.headers.get("x-forwarded-for", "")
    return fwd.split(",")[0].strip() or (request.client.host if request.client else None)

@app.post("/reports")
async def post_report(request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "invalid_body"}, status_code=400)
    status, reply = ENGINE.handle_report(body, clock.now(), client_ip(request), persist=db.insert_report)
    return JSONResponse(reply, status_code=status)

@app.get("/lookup")
def lookup(type: str | None = None, value: str | None = None):
    status, reply = ENGINE.lookup(type, value, clock.now())
    return JSONResponse(reply, status_code=status)

@app.get("/map")
def map_(pincode: str | None = None, days: str | None = None, radius_km: str | None = None):
    status, reply = ENGINE.map(pincode, days, radius_km, clock.now())
    return JSONResponse(reply, status_code=status)

@app.get("/alerts")
def alerts(pincode: str | None = None):
    status, reply = ENGINE.alerts(pincode, clock.now())
    return JSONResponse(reply, status_code=status)

@app.post("/challenges")
async def challenges(request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "invalid_body"}, status_code=400)
    status, reply = ENGINE.handle_challenge(body, clock.now(), persist=db.insert_challenge)
    return JSONResponse(reply, status_code=status)

@app.post("/admin/reset")
def reset():
    db.delete_reports_and_challenges()      # rows first, then memory
    ENGINE.reset()
    return {"ok": True}
```
- `clock.now()` is T1's injected clock and must return an aware datetime. Tests use a fake one.
- `persist(row)` must raise if the insert fails; the engine then leaves memory unchanged.
- The licence gate, size limit, 404/405 JSON, 422-to-400 override and logging rules stay in T1's
  middleware (BUILD_SPEC sections 3, 9 and 10). Never log the request body or the query string.

## Tables (SQLAlchemy Core; same on sqlite and Postgres)
```python
from sqlalchemy import BigInteger, Boolean, Column, Integer, MetaData, Table, Text
md = MetaData()
TEXT_COLS = ["report_id", "identifier_type", "identifier", "occurred_at", "reported_at", "received_at",
             "rid", "org", "channel", "scam_type", "scam_type_key", "pincode", "note_hash", "shingles"]
reports = Table("reports", md, Column("id", Integer, primary_key=True, autoincrement=True),
                *[Column(c, Text) for c in TEXT_COLS],
                Column("ntok", Integer), Column("has_screenshot", Boolean), Column("amount_lost_inr", BigInteger))
challenges = Table("challenges", md, Column("challenge_id", Text, primary_key=True),
                   *[Column(c, Text) for c in ["identifier_type", "identifier", "claimant_name",
                                                "contact_email", "proof_note", "created_at", "status"]])
kv = Table("kv", md, Column("k", Text, primary_key=True), Column("v", Text))   # licence, latest clock (T1)
```
`db.insert_report(row)` inserts the dict from `Report.to_row()` as is. `all_report_rows()` returns
dicts in insertion order (`ORDER BY id`). Times are stored as ISO text; `from_row` also accepts
datetimes, so timestamp columns work too.

## What is stored per report (privacy, BUILD_SPEC section 10)
`report_id`, identifier type and standard form, `occurred_at`, `reported_at`, `received_at`,
`rid` and `org` (keyed hashes of reporter_id and network prefix), channel, scam type (and the
key used for NEW_TYPE), pincode, note fingerprint (keyed hash, keyed word hashes, word count),
`has_screenshot`, `amount_lost_inr`. Never: the note text, raw reporter_id, raw ip_prefix, IP,
user agent, locality text, coordinates. `tests/engine/test_privacy.py` checks this with canaries.

## Commands
```
python -m pytest tests/engine -q              # 205 tests + 2 known limits (xfail)
python -m tests.engine.scenarios --seeds 60   # the attack table (add --compare for v1)
python -m tests.engine.bench                  # speed at 5,000 reports
```

## Rule 7 (v1.2): a coordinated burst is one voice
Raised by the mentor at checkpoint 1: "one person asks 10 friends to report". When 8 or more voices with
no track record come from ONE area within 6 hours (occurred time) and make up at least 80% of the voices
on a number, `trust.burst_core` finds them and `trust.merge_burst` turns them into one linked voice: no
weight, never on the map or in alerts. The lookup reply carries `trust.burst_voices` (size of the merged
burst) and `trust.hold` (set only when the burst changed the answer). Track records count a burst once,
so a ring cannot confirm a number by bursting it and then use that as history. Tests: `tests/engine/test_burst.py`.

## Judge console sandbox (`app/demo.py`)
`run(REGISTRY, ENGINE.config, seed)` builds a FRESH Engine with the same code and config and replays the
brief's tricks, the checkpoint-1 ring, real waves, alerts, privacy canaries, the verified list and a dispute.
26 checks, about 0.1 s. It never touches the live engine or the database.
