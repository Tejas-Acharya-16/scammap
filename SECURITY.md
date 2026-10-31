# Security

One page. Each claim names the test or command that checks it. "In our tests" means our own generators and checks, not the judges' tool and not real-world security. Anything we did not run is marked UNVERIFIED.

## What we protect
1. **Reporters.** Nobody should be able to tell who reported a number.
2. **Numbers with fewer than 3 voices.** They are never shown in full, and never called more than "reported".
3. **The licence.** Only a file signed by the operator can start or extend service.

## How we protect it
| What | Control | Checked by |
|---|---|---|
| Reporter identity | `reporter_id` and `ip_prefix` are hashed with a keyed hash (HMAC-SHA256, `TRUST_SALT`) when a report arrives. The raw values are never stored, logged or returned. | `tests/engine/test_privacy.py` |
| Notes | The note text is never stored. We keep keyed fingerprints of its words, used only to spot copy-paste. | `tests/engine/test_privacy.py` |
| Logs | One line per request: time, method, route name, status, duration, request id. No bodies, query strings, IPs, or paths typed by a person (those log as `(other)`). | `tests/unit/test_input_limits.py` |
| Masking and wording | A value is shown in full only after 3 voices (`98XXXXX210` before). The app says "reported". | `tests/engine`, `tests/unit/test_security_doc.py` |
| Script injection | Two layers. The URL normaliser percent-encodes every path character outside RFC 3986 (and `'`). The pages escape every API value they put into HTML (`esc()`). | `tests/engine/test_normalise_url_encoding.py`, `tests/e2e/test_xss_playwright.py` |
| Response headers | CSP, `nosniff`, `no-referrer`, `X-Frame-Options: DENY`, HSTS, Permissions-Policy on every response, errors included. | `tests/unit/test_security_headers.py`, `tests/e2e/test_security_headers_playwright.py` |
| Request limits | 16 KB body cap (also for chunked bodies). Errors never echo input; an unhandled error is `{"error":"server_error"}` with no detail. No CORS headers. No API docs routes. | `tests/unit/test_input_limits.py` |
| Licence | Ed25519. The public key is a constant in the code; the private key is never in the repo or on the server. The gate runs on every request, state lives in the database, expiry never deletes data, and a new file restores service with no restart. | `python -m tests.blackbox.smoke URL --licence ...` |
| Trust rules | Counting voices, not reports, so fake reports do not move a verdict. See the README. | `tests/engine`, `python -m tests.blackbox.attack URL` |
| Start-up | With a non-sqlite `DATABASE_URL`, the server refuses to start without a `TRUST_SALT`. | `tests/unit/test_input_limits.py` |
| Database | All queries go through SQLAlchemy Core with bound parameters. We found no raw SQL. | code search, not a test |

## Open by design
- **`POST /admin/reset`** deletes all reports and disputes. The organisers' API requires it so their tool can clear data between batches. Anyone can call it. A real deployment would remove it or put it behind authentication.
- **No login on any route.** A login before the report form scores zero, so anyone can post a report. The trust rules are the control, not identity.
- **`POST /license`** is open, but only accepts a file signed with the operator's key.
- **`/judge` and `POST /demo/run`** are public. They run a sandbox copy of the engine, never live data or the database, one run at a time (`429 busy` otherwise).
- **Disputes** keep a business name and email so it can be contacted. They are stored only for that, never returned or logged.

## Known limits
- **The CSP allows `'unsafe-inline'` scripts** (each page is one file with inline script). So the CSP does not stop an injected inline script. Escaping and encoding are the real defence. The CSP still blocks outside scripts, outside connections and framing.
- **Pseudonymous, not unlinkable.** One device's reports link to each other through its hashed id. Someone holding the database and `TRUST_SALT` can test guesses for network prefixes. The host platform may log IP addresses.
- **Trust-rule holes** are listed in the README under "Known limits". A wave of new accounts on different networks that look genuine is the main one.
- **`X-Forwarded-For`.** If a report has no `ip_prefix`, we take the first `X-Forwarded-For` entry as its network. A client can set that header. Which entry is right on our host is UNVERIFIED, so we have not changed it.
- **No rate limits** on any route, so a flood of valid reports would grow storage. Only `/demo/run` has a lock.
- **`ALLOW_RESET`** is read but not enforced; `/admin/reset` is always on.
- **Container** runs as root. `docker-compose.yml` publishes Postgres on port 5432 with a development password. It is for local use only.
- **Tracebacks** of unhandled errors go to the host's logs, never to the client. Whether an exception message can hold user input is UNVERIFIED.
- **Dependencies** are version ranges, not pins, and no dependency audit was run (UNVERIFIED).
- **Evidence** is our own tests. There has been no outside review or penetration test.
