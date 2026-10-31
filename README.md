# Community Scam Map for India

Report and verify scams in seconds, anonymously.

**Live:** <https://scammap-yp1k.onrender.com> (opens on Report; <https://scammap-yp1k.onrender.com/#check> opens Check)
**Judge console:** <https://scammap-yp1k.onrender.com/judge>

One website, two pages, one look:

- **The app (`/`)**: Check, Report and My area, on a phone or a laptop. English and हिन्दी, icons for every choice, no login, no name, no phone number asked. On a laptop a side panel explains the trust rules and links to the judge console.
- **The judge console (`/judge`)**: one button runs every scoring check on a fresh sandbox copy of the engine (never the live data); read-only checks of the live API; the licence panel (upload `licenses/expired.json` to lock, `licenses/long.json` to unlock, no restart); a QR code that opens the app on your phone.
- Security notes: [SECURITY.md](SECURITY.md). Libraries, services and AI tools: [DISCLOSURE.md](DISCLOSURE.md).

---

## Run locally

**Requirements:** Python 3.12+ (or Docker). Install into a virtual environment: a plain `pip install` is refused by the system Python on recent Ubuntu, Debian and Homebrew (`externally-managed-environment`).

macOS / Linux (on Debian or Ubuntu, `sudo apt install python3-venv` first if `venv` is missing):

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
export TRUST_SALT=my-local-salt   # any stable string; changing it splits reporter histories
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --no-access-log
```

Windows (PowerShell):

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
$env:TRUST_SALT = "my-local-salt"
.venv\Scripts\python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --no-access-log
```

The server uses SQLite by default. On a fresh database it installs the licence in `licenses/long.json` by itself, so it answers at once. Check it from a second terminal:

```bash
curl http://127.0.0.1:8000/health                                     # {"ok":true}
curl "http://127.0.0.1:8000/lookup?type=phone&value=%2B919876543210"  # 200, verdict NO_REPORTS
```

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
Invoke-RestMethod "http://127.0.0.1:8000/lookup?type=phone&value=%2B919876543210"
```

Or with Docker (app + Postgres):

```bash
docker compose up --build
# Server at http://localhost:8000 (docker-compose.yml maps port 8000 to the app)
```

---

## API

JSON in and out. Times are ISO 8601 with `+05:30`. Errors: `{"error": "<code>"}`. No login on any route.

| Route | Method | Success | Errors |
|---|---|---|---|
| `/health` | GET | `200 {"ok": true}` | — |
| `/reports` | POST | `201 {"report_id", "case_id", "merged"}` | `400 {"error": "…"}` |
| `/lookup?type=&value=` | GET | `200` (verdict object, plus a signed `attestation`: see [Signed answers](#signed-answers)) | `400` for impossible values |
| `/attestation/key` | GET | `200 {"alg": "Ed25519", "key_id", "public_key"}` | — |
| `/map?pincode=&days=7&radius_km=2` | GET | `200 {"clusters": [...]}` | `400` for malformed pincode |
| `/alerts?pincode=` | GET | `200 {"alerts": [...]}` | `400` for malformed pincode |
| `/admin/reset` | POST | `200 {"ok": true}` | — |
| `/challenges` | POST | `201 {"challenge_id", "status": "under_review"}` | `400` |
| `/license` | GET | `200` (licence status) | — |
| `/license` | POST | `200` (installed licence) | `400 {"error": "INVALID_LICENSE"}` |

When the licence is not valid, every route except `/health`, `/license` and static files returns `403 {"error": "LICENSE_EXPIRED"}`.

Unknown routes return `404 {"error": "not_found"}`. Wrong method returns `405 {"error": "method_not_allowed"}`. Error messages never echo user input.

---

## How the trust rules work

The system counts independent **voices**, not raw reports. A number is marked KNOWN_SCAM only when at least 3 voices report it and they add up to at least 1.5 points. Fewer voices means SUSPICIOUS. No reports means NO_REPORTS. No single signal decides: who reported, from which network, when, from which area, with what track record.

1. **Junk is turned away at the door.** A number, UPI ID, link or sender that cannot exist, an area we do not cover, or an impossible time is rejected before anything is stored.

2. **One person is one voice.** Reports on one number are linked into one voice when they share a reporter identity (at any time), or a network within 24 hours. Many reports from the same connection within a short time count as one person.

3. **Copy-paste is one voice, when the copies arrive together.** The same text, or a lightly edited copy of a long text, posted by 3 or more different reporters within 6 hours links those reports. If a number carries 2 or more such pasted texts, texts shared by even two people in that window are linked too. Copies spread over days are not linked: real victims often repeat the same words from a news story or a form.

4. **A burst of new accounts is one voice.** When 8 or more voices with no track record arrive within 6 hours and make up at least 80% of the voices on the number, they count as one voice if they come from one area, or if they wrote no words of their own. This is the "one person asks 10 friends" case.

5. **Track record.** A voice counts 1.0 points when its reporter earlier reported a different number that at least two other independent voices confirmed (and that number is not verified or disputed). Otherwise 0.5.

6. **Notes never block an honest report.** A voice weighs the same with or without a note. Three different people on their own networks, spread over time, make a number KNOWN_SCAM whatever they wrote. A linked group (rules 2 to 4) is one voice and adds no weight.

7. **Threshold.** A number is KNOWN_SCAM when at least 3 voices report it and they add up to at least 1.5 points. A verified number is always VERIFIED_BUSINESS, whatever is reported. A disputed number is never KNOWN_SCAM.

8. **Map and alerts count only clean voices.** None of the tricks (friends, same network, one person, copy-paste, bursts) can move the map or trigger alerts.

---

## Known limits

We say these out loud. In our tests:

- **Friends who each pick a different area and write their own words, arriving together,** look like a real wave and are not stopped. The verified list protects listed businesses; disputes protect everyone else.
- **A real wave in which 8 or more people paste one example sentence within 2 hours** waits as SUSPICIOUS: it looks exactly like a copy-paste campaign.
- **A real local wave of 8 or more brand-new people in one area within 6 hours** waits as SUSPICIOUS until people from other areas, other days or with a track record confirm it.
- **A small ring of 3 to 7** can still mark a number, and a ring can build a track record by first reporting numbers its members also report.
- **People behind one network prefix within 24 hours** (a campus, carrier NAT, a family) count as one voice and add no weight.

---

## How the licence works

The server runs under a signed licence. An Ed25519 public key is built into the server code. The private key never leaves the operator's machine and is never in this repository.

- A licence file contains a licensee name, an expiry time, and a signature.
- `POST /license` verifies the signature, stores the licence in the database, and swaps the in-memory copy. No restart needed.
- `GET /license` shows the current licensee, expiry, status (`valid`, `expired`, `none`, `clock_rollback`) and seconds remaining.
- When the licence is expired (or missing, or the clock has rolled back by more than 2 minutes), every route except `/health` and `/license` returns `403 {"error": "LICENSE_EXPIRED"}`.
- Data is never deleted on expiry. Uploading a valid licence restores full service instantly.
- The web app polls `/license` every 10 seconds. When the licence expires, it shows "Licence expired. Contact your provider." When a valid licence is uploaded, the app recovers by itself.

**Licence demo, no private key needed.** Run it from the repository folder. Set `URL` to `http://127.0.0.1:8000` locally, `http://localhost:8000` with Docker, or the live address. `licenses/expired.json` is a correctly signed licence whose date has passed; `licenses/long.json` runs to 31 Jan 2027.

```bash
URL=http://127.0.0.1:8000

# 1. The licence is valid. Add one synthetic report so step 3 can show the data survives.
curl $URL/license                                  # "status":"valid"
curl -X POST $URL/reports -H 'content-type: application/json' -d '{"report_id":"demo-licence-1","occurred_at":"2026-10-31T12:00:00+05:30","reporter_id":"r_demo_licence","channel":"Phone call","scam_type":"otp-call","identifier_type":"phone","identifier_value":"+91 90000 00042","pincode":"560102","note":"demo report to show the data survives the licence check"}'
curl "$URL/lookup?type=phone&value=9000000042"     # "report_count":1

# 2. Install the expired licence. Every API route answers 403 {"error":"LICENSE_EXPIRED"},
#    and the app (open $URL in a browser) shows "Licence expired. Contact your provider." at its next check (every 10 s).
curl -X POST $URL/license -H 'content-type: application/json' --data @licenses/expired.json   # "status":"expired"
for r in "lookup?type=phone&value=9000000042" "map?pincode=560102" "alerts?pincode=560102"; do
  curl -s -o /dev/null -w "GET /$r -> %{http_code}\n" "$URL/$r"; done
for r in reports challenges demo/run; do
  curl -s -o /dev/null -w "POST /$r -> %{http_code}\n" -X POST "$URL/$r" -H 'content-type: application/json' -d '{}'; done
curl $URL/health                                   # still 200: /health and /license stay open

# 3. Install the long licence. The API is back at once, with no restart and the same data;
#    the app clears the expired screen at its next check, within 15 s.
curl -X POST $URL/license -H 'content-type: application/json' --data @licenses/long.json      # "status":"valid"
curl "$URL/lookup?type=phone&value=9000000042"     # 200, "report_count":1 as in step 1

# 4. Change one digit (expiry 2027 -> 2028) and upload the copy: the signature check fails.
sed 's/2027-01-31/2028-01-31/' licenses/long.json > tampered.json
curl -X POST $URL/license -H 'content-type: application/json' --data @tampered.json          # 400 {"error":"INVALID_LICENSE"}
curl $URL/license                                  # unchanged: still the long licence, "status":"valid"
```

`POST /admin/reset` is behind the licence too. It is left out above because with a valid licence it deletes every report.

The same steps in Windows PowerShell. An error status shows up in the `catch`, which prints the code:

```powershell
$URL = "http://127.0.0.1:8000"
# 1
Invoke-RestMethod "$URL/license"
Invoke-RestMethod -Method Post -Uri "$URL/reports" -ContentType "application/json" -Body '{"report_id":"demo-licence-1","occurred_at":"2026-10-31T12:00:00+05:30","reporter_id":"r_demo_licence","channel":"Phone call","scam_type":"otp-call","identifier_type":"phone","identifier_value":"+91 90000 00042","pincode":"560102","note":"demo report to show the data survives the licence check"}'
Invoke-RestMethod "$URL/lookup?type=phone&value=9000000042"
# 2
Invoke-RestMethod -Method Post -Uri "$URL/license" -ContentType "application/json" -InFile licenses\expired.json
foreach ($r in "lookup?type=phone&value=9000000042", "map?pincode=560102", "alerts?pincode=560102") {
  try { Invoke-RestMethod "$URL/$r" | Out-Null; "GET /$r -> 200" } catch { "GET /$r -> $([int]$_.Exception.Response.StatusCode)" } }
foreach ($r in "reports", "challenges", "demo/run") {
  try { Invoke-RestMethod -Method Post -Uri "$URL/$r" -ContentType "application/json" -Body '{}' | Out-Null; "POST /$r -> 200" } catch { "POST /$r -> $([int]$_.Exception.Response.StatusCode)" } }
Invoke-RestMethod "$URL/health"
# 3
Invoke-RestMethod -Method Post -Uri "$URL/license" -ContentType "application/json" -InFile licenses\long.json
Invoke-RestMethod "$URL/lookup?type=phone&value=9000000042"
# 4
(Get-Content licenses\long.json -Raw).Replace("2027-01-31", "2028-01-31") | Set-Content -Encoding ascii tampered.json
try { Invoke-RestMethod -Method Post -Uri "$URL/license" -ContentType "application/json" -InFile tampered.json } catch { [int]$_.Exception.Response.StatusCode }
Invoke-RestMethod "$URL/license"
```

**Operator only** (needs the private key, which is never in this repository): mint a short licence for a live countdown.

```bash
python tools/make_license.py --licensee "Demo Bank" --minutes 5 > lic5.json
curl -X POST $URL/license -H 'content-type: application/json' --data @lic5.json
```

---

## Signed answers

Every `GET /lookup` answer carries one extra field, `attestation`: a signed copy of what this server said. A bank or insurer that pins our public key can later check that an answer came from this ScamMap server, and when. **It proves which server said what and when. It does not prove that the verdict is right.**

- `GET /attestation/key` returns `{"alg": "Ed25519", "key_id", "public_key"}` (base64). It sits behind the licence gate like every API route, and so does `/lookup`: a server without a valid licence answers 403 and signs nothing.
- The attestation is `{"v": 1, "key_id", "issued_at", "type", "value_sha256", "verdict", "voices", "report_count", "config", "sig"}`. `sig` is the Ed25519 signature over the canonical JSON (sorted keys, no spaces, UTF-8) of every other field. Changing, adding or removing any field breaks it. The other answer fields are unchanged.
- `value_sha256` is the SHA-256 of the value's standard form (`+919876543210`), so every way of typing one number gives one hash. `voices` is `distinct_reporters`. `config` is the trust-rules hash, so an answer is tied to the rules that produced it. `issued_at` is this server's clock in IST.
- No new secret: the key's seed is HMAC-SHA256(key=`TRUST_SALT`, msg=`scammap-attestation-v1`). The same `TRUST_SALT` gives the same key after every restart. `key_id` is the first 8 hex characters of SHA-256 of the public key. The seed is never stored, logged or returned.

Check an answer (Python with PyNaCl, from the repository folder):

```bash
curl -s "$URL/attestation/key" > key.json            # pin this once, and keep its key_id
curl -s "$URL/lookup?type=phone&value=%2B919000055501" > answer.json
python tools/verify_attestation.py answer.json key.json --value "+91 90000 55501"
# prints VALID (exit 0) or INVALID (exit 1)
```

On `/judge`, the "Verify an answer" panel does the same check in the browser with tweetnacl, and "Tamper" flips the verdict to show INVALID.

Limits:
- Anyone who holds `TRUST_SALT` can sign. It is already the secret that keys the reporter hashes. Changing it changes the key, and it also stops new reports from linking to older reports by the same reporter, so it is not a casual step.
- `issued_at` is the server's own claim, not a third-party timestamp.
- `value_sha256` does not hide a phone number: trying every number finds it. Treat an attestation like the number itself, and share it only with someone who already has the number.
- A local run without `TRUST_SALT` uses a public default salt, so anyone can forge its answers. Pin only the live server's key.
- Signing adds about 0.1 ms per lookup (p95, in process, in our bench): `python -m pytest tests/unit/test_attestation.py -k p95 -s`.

---

## Privacy

Security notes (what we protect, how, what is open by design, known limits): see [SECURITY.md](SECURITY.md).

### What is stored per report

Report ID, identifier type and normalised value, `occurred_at`, `reported_at`, hashed reporter identity (`rid`), hashed network prefix (`org`), channel, scam type, pincode, note hash, note shingle hashes, word count, `has_screenshot`, `amount_lost_inr`, server receive time.

Reporter identity and network prefix are HMAC-SHA256 hashed with a secret salt before storage. Only the hashes are kept.

### What is never stored, logged or returned

Reporter name, phone number, email, exact location or coordinates, raw IP address, user agent, raw reporter identity, raw network prefix, the note text, screenshots. GPS is never requested. We do not collect or look up anything on social media or people-search sites.

### Display rules

A value is shown in full only after 3 different voices report it and it is not under dispute. Below that threshold, values are masked (e.g. `98XXXXX210`).

### Logging

One line per request: time, method, path (without the query string), status, duration, request ID. No bodies, no IPs in our own logs. The hosting platform may log IPs at the infrastructure level.

---

## Proof

All results below are from our own synthetic data and generators. They are not from the judges' tool and do not represent results on unknown data. We quote them as "in our tests".

### Live proof (on the https server, synthetic data)

| What | Result | Output |
|---|---|---|
| Attack scenarios over HTTP (engine v1.2, commit `d141030`, 31 Oct 21:48 IST) | 1,677 reports, 0 rejected, 0 failures, 2 known limits | [tests/attack/LIVE_ATTACK_TABLE.txt](tests/attack/LIVE_ATTACK_TABLE.txt) |
| Lookup formats and speed (31 Oct 23:17 IST) | 4 ways of writing one number give one answer; p95 216 ms on new connections, 107 ms on a kept-open connection, from our laptop | [tests/api/LIVE_LOOKUP_CHECK.txt](tests/api/LIVE_LOOKUP_CHECK.txt) |
| Privacy canaries (31 Oct 23:21 IST) | No canary value in any reply; the number stays masked | [tests/privacy/LIVE_PRIVACY_CHECK.txt](tests/privacy/LIVE_PRIVACY_CHECK.txt) |
| Bulk upload, 2,000 reports, 16 connections, no retries (1 Nov 01:55 IST) | 2,000 accepted, 0 × 429, 0 × 5xx, 0 timeouts; lookups during the upload p95 582 ms on the free instance | [tests/api/LIVE_BULK_LOAD.txt](tests/api/LIVE_BULK_LOAD.txt) |
| Realistic input variants (in process) | 31 of 31 accepted | [tests/api/INPUT_VARIANTS.txt](tests/api/INPUT_VARIANTS.txt) |

### Test commands

```bash
# Engine tests (256 passed, 2 known limits)
python -m pytest tests/engine -q

# Everything except the browser tests (333 passed, 2 known limits)
python -m pytest tests -q --ignore=tests/e2e

# Browser tests, phone and laptop size (29 passed; first run: python -m playwright install chromium)
python -m pytest tests/e2e -q

# In-process attack table (60 seeds, ~20 seconds)
python -m tests.engine.scenarios --seeds 60 --compare
```

### Attack table (in our tests, config `d7a23b4c`, engine v1.3)

**Real waves — should be detected:**

| Scenario | Seeds | Result |
|---|---|---|
| 8 reporters with history, spread over 13 days | 60 | 100% detected |
| 8 brand-new reporters, spread | 60 | 100% detected |
| 6 brand-new, all within 2 hours | 60 | 100% detected |
| 3 brand-new, own words | 60 | 100% detected |
| 8 new, templated notes | 60 | 100% detected |
| 8 new, half with empty notes | 60 | 100% detected |
| 10 reporters on only 15 shared networks | 60 | 100% detected |
| 8 new, short notes of 3 to 4 words | 60 | 100% detected |
| 8 new, 4 on 2 shared networks, days apart | 60 | 100% detected |
| 7 new, notes from a list of 10 texts | 60 | 100% detected |
| 4 new, notes from a list of 10 texts | 60 | 100% detected |
| 12 new within 3 hours, across 6 areas | 60 | 100% detected |
| 20 friends in one hour + 3 real people elsewhere | 60 | 100% detected |
| 8 new, all empty notes | 60 | 100% detected |
| Lazy test data: 5 people, empty notes, a week, any area | 60 | 100% detected |
| Lazy test data: 5 people, one example note, a week | 60 | 98% detected |
| Lazy test data: 12 people, 3 template notes, a week | 60 | 100% detected |
| Lazy test data: 3 people, empty notes, 3 days | 60 | 100% detected |
| Lazy test data: 3 people, one example note, 3 days | 60 | 92% detected |

**Tricks — should be stopped:**

| Scenario | Seeds | Result |
|---|---|---|
| 40 friends, same note, 40 networks | 60 | 0% — stopped |
| 40 friends, empty notes | 60 | 0% — stopped |
| 22 accounts, one network, varied notes | 60 | 0% — stopped |
| 22 accounts, one network, empty notes | 60 | 0% — stopped |
| 22 accounts, one network, spread over 5 days | 60 | 0% — stopped |
| One person ×6, same network | 60 | 0% — stopped |
| One person ×6, rotating networks | 60 | 0% — stopped |
| 20 accounts on 2 networks, same note | 60 | 0% — stopped |
| 40 friends, 5 canned short phrases | 60 | 0% — stopped |
| 40 friends, 5 canned long phrases | 60 | 0% — stopped |
| 40 friends, notes from a list of 10 texts | 60 | 0% — stopped |
| 3 attackers × 10 accounts, 3 networks | 60 | 0% — stopped |
| 40 friends report a verified business | 60 | 0% — VERIFIED_BUSINESS held |
| 1 person + 10 friends, own words, one area, 1 hour | 60 | 0% — stopped |
| 40 friends, one note, 1 hour, any area | 60 | 0% — stopped |
| 40 friends, empty notes, 1 hour, any area | 60 | 0% — stopped |
| 40 friends, own varied notes, 40 networks, one area | 60 | 0% — stopped |
| 40 friends, lightly reworded (up to 3 word swaps) | 60 | 0% — stopped |

**Known limits (not stopped, in our tests):**

| Scenario | Seeds | Result |
|---|---|---|
| 1 person + 10 friends, each picks another area | 60 | 100% — not stopped |
| Lazy test data: 8 people, one example note, within 2 hours | 60 | 0% detected (stays SUSPICIOUS) |

**Alerts (in our tests, 15 seeds each):**

| Scenario | Expected | Result |
|---|---|---|
| 14 voices in 7 days, 10 today | SPIKE | 100% |
| Normal area, 3 today | No alert | 100% |
| No history, 5 today | SPIKE | 100% |
| New type, 3 people | NEW_TYPE | 100% |
| New type, 1 person in own words | NEW_TYPE | 100% |
| Type seen 10 days ago | No NEW_TYPE | 100% |
| 10 empty notes, one number | No alert | 100% |
| 10 empty notes, 10 numbers | SPIKE | 100% |
| Trick: 1 person + 10 friends, one area, 1 hour | No alert | 100% |
| Trick: 40 friends, own varied notes, one area | No alert | 100% |
| Trick: 40 friends, lightly reworded | No alert | 100% |
| Every trick above in a quiet area | No alert | 100% |

---

## Team

**Team Smashers** — CyberForge 2026 final round, Mitigata × HackCulture, Bengaluru

- **Tejas Prakash** — tech lead, server, trust rules, licence, integration
- **Bhumika** — product, UX, web app, documentation, demo, QA

All code in this repository was written during the event. Third-party libraries and tools are listed in [DISCLOSURE.md](DISCLOSURE.md).
