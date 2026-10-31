"""Community Scam Map server. ASGI app is app.main:app.

Wires the pure engine (app/engine) to FastAPI, SQLAlchemy (sqlite locally,
Postgres via DATABASE_URL) and middleware (BUILD_SPEC sections 2, 3 and 10).
Licence gate (section 9): Ed25519, every request, no restart to swap.
"""
from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from sqlalchemy import BigInteger, Boolean, Column, Integer, MetaData, Table, Text, create_engine, select, delete
from starlette.middleware.base import BaseHTTPMiddleware

from app import demo
from app.engine import Engine, Registry
from app.license import LicenseState, EXEMPT_PATHS, STATIC_PREFIX

# ── logging (section 10) ─────────────────────────────────────────────────────
# One line per request: time, method, path (no query string), status, duration.
# No bodies, no IPs.
logger = logging.getLogger("scammap")
logging.basicConfig(
    format="%(asctime)s %(levelname)s %(message)s",
    level=logging.INFO,
)

# ── database schema (engine README: same on sqlite and Postgres) ─────────────
metadata = MetaData()

TEXT_COLS = [
    "report_id", "identifier_type", "identifier", "occurred_at", "reported_at",
    "received_at", "rid", "org", "channel", "scam_type", "scam_type_key",
    "pincode", "note_hash", "shingles",
]

reports_table = Table(
    "reports", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    *[Column(c, Text) for c in TEXT_COLS],
    Column("ntok", Integer),
    Column("has_screenshot", Boolean),
    Column("amount_lost_inr", BigInteger),
)

challenges_table = Table(
    "challenges", metadata,
    Column("challenge_id", Text, primary_key=True),
    *[Column(c, Text) for c in [
        "identifier_type", "identifier", "claimant_name",
        "contact_email", "proof_note", "created_at", "status",
    ]],
)

kv_table = Table(
    "kv", metadata,
    Column("k", Text, primary_key=True),
    Column("v", Text),
)


# ── helpers ──────────────────────────────────────────────────────────────────
def _make_db_url(raw: str) -> str:
    """Rewrite postgres:// to postgresql+psycopg:// (Render gotcha)."""
    if raw.startswith("postgres://"):
        return "postgresql+psycopg://" + raw[len("postgres://"):]
    if raw.startswith("postgresql://"):
        return "postgresql+psycopg://" + raw[len("postgresql://"):]
    return raw


def _build_engine():
    raw = os.environ.get("DATABASE_URL", "sqlite:///./dev.db")
    url = _make_db_url(raw)
    if url.startswith("sqlite"):
        return create_engine(url, connect_args={"check_same_thread": False})
    return create_engine(url, pool_pre_ping=True, pool_size=5, max_overflow=0)


# ── injected clock ───────────────────────────────────────────────────────────

class Clock:
    """Production clock. Tests replace this."""
    @staticmethod
    def now() -> datetime:
        return datetime.now(timezone.utc)


clock = Clock()

# ── licence state (in-memory, backed by kv table) ────────────────────────────
LICENSE = LicenseState()
_last_clock_write: float = 0  # monotonic time of last clock guard write


# ── database operations ─────────────────────────────────────────────────────
class DB:
    def __init__(self, db_engine):
        self.engine = db_engine

    def create_tables(self):
        metadata.create_all(self.engine)

    def insert_report(self, row: dict):
        with self.engine.begin() as conn:
            conn.execute(reports_table.insert().values(**row))

    def insert_challenge(self, row: dict):
        with self.engine.begin() as conn:
            conn.execute(challenges_table.insert().values(**row))

    def all_report_rows(self) -> list[dict]:
        with self.engine.connect() as conn:
            result = conn.execute(select(reports_table).order_by(reports_table.c.id))
            return [dict(r._mapping) for r in result]

    def all_challenge_rows(self) -> list[dict]:
        with self.engine.connect() as conn:
            result = conn.execute(select(challenges_table))
            return [dict(r._mapping) for r in result]

    def delete_reports_and_challenges(self):
        with self.engine.begin() as conn:
            conn.execute(delete(reports_table))
            conn.execute(delete(challenges_table))

    # ── kv store (for licence, clock guard) ─────────────────────────────
    def kv_get(self, key: str) -> str | None:
        with self.engine.connect() as conn:
            row = conn.execute(
                select(kv_table.c.v).where(kv_table.c.k == key)
            ).first()
            return row[0] if row else None

    def kv_set(self, key: str, value: str):
        with self.engine.begin() as conn:
            existing = conn.execute(
                select(kv_table.c.k).where(kv_table.c.k == key)
            ).first()
            if existing:
                conn.execute(
                    kv_table.update().where(kv_table.c.k == key).values(v=value)
                )
            else:
                conn.execute(kv_table.insert().values(k=key, v=value))


# ── client IP helper (engine README) ─────────────────────────────────────────
def client_ip(request: Request) -> str | None:
    """Used only when a report has no ip_prefix. Hashed inside the engine. Never logged."""
    fwd = request.headers.get("x-forwarded-for", "")
    return fwd.split(",")[0].strip() or (request.client.host if request.client else None)


# ── globals built at start-up ────────────────────────────────────────────────
TRUST_SALT = os.environ.get("TRUST_SALT", "")
ALLOW_RESET = os.environ.get("ALLOW_RESET", "1").strip() in ("1", "true", "yes")
MAX_BODY_BYTES = 16 * 1024  # 16 KiB request body limit (one report is well under 2 KiB)


REGISTRY = Registry.from_dir(Path(__file__).parent / "data")
INDEX_HTML = Path(__file__).parent / "static" / "index.html"
JUDGE_HTML = Path(__file__).parent / "static" / "judge.html"
LIVE_HTML = Path(__file__).parent / "static" / "live.html"
THEME_CSS = Path(__file__).parent / "static" / "theme.css"   # the shared look of / and /judge
PAGES = frozenset({"/", "/judge", "/live"})  # served on GET only; exempt from the licence gate

# Which deploy is answering (headers on /health)
COMMIT = os.environ.get("RENDER_GIT_COMMIT", "dev")[:7]
STARTED_AT = datetime.now(timezone.utc).isoformat(timespec="seconds")


def check_salt_for_database(db_url: str, salt: str) -> str:
    """The salt keys every reporter and network hash. A public default would let anyone who can read
    the database undo the hashes of guessable values (network prefixes), so only a local sqlite run
    may fall back to one. A set but too short salt on sqlite is left to the engine, which refuses it."""
    if len(salt) >= 8:
        return salt
    if not _make_db_url(db_url).startswith("sqlite"):
        raise RuntimeError("TRUST_SALT must be set (at least 8 characters) when DATABASE_URL is not sqlite")
    if salt:
        return salt
    logger.warning("TRUST_SALT not set; using insecure default for local dev")
    return "dev-salt-insecure"


TRUST_SALT = check_salt_for_database(os.environ.get("DATABASE_URL", "sqlite:///./dev.db"), TRUST_SALT)

ENGINE = Engine(REGISTRY, salt=TRUST_SALT)


def _load_license_from_db(db: DB):
    """Restore licence and clock guard from kv table at startup."""
    raw = db.kv_get("license")
    if raw:
        try:
            data = json.loads(raw)
            ok, _ = LICENSE.verify_and_install(data)
            if ok:
                logger.info("restored licence: %s expires %s", LICENSE.licensee, LICENSE.expires_at)
            else:
                logger.warning("stored licence failed verification")
        except Exception:
            logger.warning("stored licence is corrupt")
    else:
        # Install the default long licence on a fresh database
        default_path = Path(__file__).parent.parent / "licenses" / "long.json"
        if default_path.exists():
            try:
                data = json.loads(default_path.read_text())
                ok, _ = LICENSE.verify_and_install(data)
                if ok:
                    db.kv_set("license", json.dumps(data))
                    logger.info("installed default licence: %s", LICENSE.licensee)
            except Exception:
                logger.warning("default licence file is corrupt")

    # Restore clock guard
    saved = db.kv_get("latest_clock")
    if saved:
        try:
            from app.engine.timeutil import parse_time
            dt = parse_time(saved)
            if dt:
                LICENSE.set_latest_clock(dt)
                logger.info("restored clock guard: %s", dt.isoformat())
        except Exception:
            pass


def _persist_clock_guard(db: DB, now: datetime):
    """Write the latest time seen to kv at most every 30 seconds."""
    global _last_clock_write
    mono = time.monotonic()
    if mono - _last_clock_write >= 30:
        LICENSE.update_clock(now)
        db.kv_set("latest_clock", now.isoformat())
        _last_clock_write = mono


# ── lifespan ─────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    db_engine = _build_engine()
    db = DB(db_engine)
    db.create_tables()
    app.state.db = db

    # Load existing reports and challenges into memory
    report_rows = db.all_report_rows()
    challenge_rows = db.all_challenge_rows()
    n = ENGINE.load(report_rows, challenge_rows)
    logger.info("loaded %d reports and %d challenges from database", n, len(challenge_rows))

    # Restore licence and clock guard
    _load_license_from_db(db)
    LICENSE.update_clock(clock.now())

    yield

    db_engine.dispose()


async def _read_json(request: Request):
    """request.json(), with lone surrogates replaced by "?". JSON text such as "\\ud800" parses into a
    string that cannot be encoded to UTF-8, so hashing or storing it would fail with a 500. Paired
    surrogates (an emoji) were already joined by the parser and are kept."""
    body = await request.json()
    return json.loads(json.dumps(body, ensure_ascii=False).encode("utf-8", "replace"))


# ── FastAPI app ──────────────────────────────────────────────────────────────
# docs, redoc and openapi.json are off: the API is fixed and written in the README.
app = FastAPI(title="Community Scam Map", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)


# ── middleware ───────────────────────────────────────────────────────────────

_KNOWN_PATHS: frozenset | None = None


def loggable_path(path: str) -> str:
    """Only the app's own routes are logged by name. Anything else is "(other)": a path is user input,
    and it can hold line breaks (log forging) or a value someone typed into the address bar."""
    global _KNOWN_PATHS
    if _KNOWN_PATHS is None:
        _KNOWN_PATHS = frozenset(r.path for r in app.routes if hasattr(r, "path"))
    return path if path in _KNOWN_PATHS else "(other)"


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Log one line per request: time, method, route, status, duration, req id.
    No bodies, no IPs, no query strings, no user-typed paths."""

    async def dispatch(self, request: Request, call_next):
        req_id = str(uuid.uuid4())[:8]
        start = time.monotonic()
        response = await call_next(request)
        elapsed_ms = (time.monotonic() - start) * 1000
        # route name only (privacy, section 10)
        logger.info("%s %s %d %.0fms req=%s", request.method, loggable_path(request.url.path),
                    response.status_code, elapsed_ms, req_id)
        return response


_TOO_LARGE = json.dumps({"error": "request_too_large"}).encode()


class BodySizeLimitMiddleware:
    """Reject a request body larger than MAX_BODY_BYTES.

    A declared Content-Length is checked up front. A body with no Content-Length (chunked) is counted
    as the app reads it; when it passes the cap the app is given an empty end-of-body and whatever it
    answers is replaced by 413, so a handler that swallows the read error cannot hide the overflow.
    Pure ASGI, so it sees the real byte count, not just a header."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        declared = dict(scope["headers"]).get(b"content-length")
        if declared is not None:
            try:
                if int(declared) > MAX_BODY_BYTES:
                    await self._reply_413(send)
                    return
            except ValueError:
                pass
        state = {"total": 0, "over": False, "started": False}

        async def counting_receive():
            if state["over"]:
                return {"type": "http.request", "body": b"", "more_body": False}
            message = await receive()
            if message["type"] == "http.request":
                state["total"] += len(message.get("body", b""))
                if state["total"] > MAX_BODY_BYTES:
                    state["over"] = True
                    return {"type": "http.request", "body": b"", "more_body": False}
            return message

        async def guarded_send(message):
            if state["over"]:
                if message["type"] == "http.response.start" and not state["started"]:
                    state["started"] = True
                    await self._reply_413(send)
                return                      # drop the app's own answer
            await send(message)

        try:
            await self.app(scope, counting_receive, guarded_send)
        except Exception:
            if state["over"] and not state["started"]:
                await self._reply_413(send)
            else:
                raise

    @staticmethod
    async def _reply_413(send):
        await send({"type": "http.response.start", "status": 413, "headers": [
            (b"content-type", b"application/json"), (b"content-length", str(len(_TOO_LARGE)).encode())]})
        await send({"type": "http.response.body", "body": _TOO_LARGE})


CSP = ("default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
       "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
       "img-src 'self' data: https://tile.openstreetmap.org; connect-src 'self'; "
       "frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
SECURITY_HEADERS = {
    "Content-Security-Policy": CSP,
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Strict-Transport-Security": "max-age=31536000",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}
_SECURITY_HEADER_PAIRS = [(k.lower().encode(), v.encode()) for k, v in SECURITY_HEADERS.items()]
_SECURITY_HEADER_NAMES = frozenset(k for k, _ in _SECURITY_HEADER_PAIRS)


class SecurityHeadersMiddleware:
    """Add the security headers to every HTTP response: pages, JSON, errors, the 403 licence answer.
    The outermost middleware, so nothing an inner layer sends can skip it."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                headers = [(k, v) for k, v in message.get("headers", []) if k.lower() not in _SECURITY_HEADER_NAMES]
                message = {**message, "headers": headers + _SECURITY_HEADER_PAIRS}
            await send(message)

        await self.app(scope, receive, send_with_headers)


class LicenseGateMiddleware(BaseHTTPMiddleware):
    """Return 403 LICENSE_EXPIRED on every non-exempt route when the licence
    is invalid. Runs on EVERY request (section 9.2). Also persists the clock guard."""

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        # Exempt: /health, /license (GET and POST), the app pages (GET / and /judge only), static files
        if (path in EXEMPT_PATHS or path.startswith(STATIC_PREFIX + "/")
                or (path in PAGES and request.method == "GET")):
            return await call_next(request)

        now = clock.now()
        LICENSE.update_clock(now)

        # Persist clock guard periodically
        if hasattr(request.app.state, "db"):
            _persist_clock_guard(request.app.state.db, now)

        if not LICENSE.is_valid(now):
            return JSONResponse({"error": "LICENSE_EXPIRED"}, status_code=403)

        return await call_next(request)


# Order: security headers -> body size -> licence gate -> logging -> routes
# Middleware is applied in reverse order (last added = outermost)
app.add_middleware(RequestLoggingMiddleware)
app.add_middleware(LicenseGateMiddleware)
app.add_middleware(BodySizeLimitMiddleware)
app.add_middleware(SecurityHeadersMiddleware)


# ── 422→400 override ────────────────────────────────────────────────────────
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """The brief wants 400, not 422. Error messages never echo input."""
    return JSONResponse({"error": "invalid_body"}, status_code=400)


# ── JSON 500 ─────────────────────────────────────────────────────────────────
@app.exception_handler(Exception)
async def server_error_handler(request: Request, exc: Exception):
    """No stack trace, no detail, never the input. This handler runs outside the middleware stack, so
    the security headers are added here as well."""
    return JSONResponse({"error": "server_error"}, status_code=500, headers=SECURITY_HEADERS)


# ── JSON 404 and 405 ────────────────────────────────────────────────────────
@app.exception_handler(404)
async def not_found_handler(request: Request, exc):
    return JSONResponse({"error": "not_found"}, status_code=404)


@app.exception_handler(405)
async def method_not_allowed_handler(request: Request, exc):
    return JSONResponse({"error": "method_not_allowed"}, status_code=405)


# ── routes ───────────────────────────────────────────────────────────────────

@app.get("/")
def index():
    # The web app. Exempt from the licence gate so it can show the expired screen.
    return FileResponse(INDEX_HTML, media_type="text/html")


@app.get("/judge")
def judge():
    # Judge console. Exempt from the licence gate like "/".
    return FileResponse(JUDGE_HTML, media_type="text/html")


@app.get("/live")
def live_page():
    # The live scam map. Exempt from the licence gate like "/"; its data route /live/summary is gated.
    return FileResponse(LIVE_HTML, media_type="text/html")


@app.get(STATIC_PREFIX + "/theme.css")
def theme_css():
    # One stylesheet for both pages. Under /static, so it loads while the licence is expired too.
    return FileResponse(THEME_CSS, media_type="text/css")


@app.get("/health")
def health():
    return JSONResponse({"ok": True}, headers={"X-Commit": COMMIT, "X-Started": STARTED_AT})


@app.get("/license")
def get_license():
    return JSONResponse(LICENSE.to_get_response(clock.now()))


@app.post("/license")
async def post_license(request: Request):
    try:
        body = await _read_json(request)
    except Exception:
        return JSONResponse({"error": "INVALID_LICENSE"}, status_code=400)
    if not isinstance(body, dict):
        return JSONResponse({"error": "INVALID_LICENSE"}, status_code=400)
    ok, error = LICENSE.verify_and_install(body)
    if not ok:
        return JSONResponse({"error": error}, status_code=400)
    # Persist to kv
    app.state.db.kv_set("license", json.dumps(body))
    logger.info("licence installed: %s expires %s", LICENSE.licensee, LICENSE.expires_at)
    return JSONResponse(LICENSE.to_get_response(clock.now()))


@app.post("/reports")
async def post_report(request: Request):
    try:
        body = await _read_json(request)
    except Exception:
        return JSONResponse({"error": "invalid_body"}, status_code=400)
    status, reply = ENGINE.handle_report(
        body, clock.now(), client_ip(request), persist=app.state.db.insert_report
    )
    return JSONResponse(reply, status_code=status)


@app.get("/lookup")
def lookup(type: str | None = None, value: str | None = None):
    status, reply = ENGINE.lookup(type, value, clock.now())
    return JSONResponse(reply, status_code=status)


@app.get("/map")
def map_view(pincode: str | None = None, days: str | None = None, radius_km: str | None = None):
    status, reply = ENGINE.map(pincode, days, radius_km, clock.now())
    return JSONResponse(reply, status_code=status)


@app.get("/alerts")
def alerts(pincode: str | None = None):
    status, reply = ENGINE.alerts(pincode, clock.now())
    return JSONResponse(reply, status_code=status)


@app.get("/live/summary")
def live_summary(days: str | None = None):
    # The live scam map's data: areas, top scam types, most reported numbers, alerts. Licence-gated.
    status, reply = ENGINE.live_summary(clock.now(), days)
    return JSONResponse(reply, status_code=status)


@app.post("/challenges")
async def post_challenge(request: Request):
    try:
        body = await _read_json(request)
    except Exception:
        return JSONResponse({"error": "invalid_body"}, status_code=400)
    status, reply = ENGINE.handle_challenge(
        body, clock.now(), persist=app.state.db.insert_challenge
    )
    return JSONResponse(reply, status_code=status)


@app.post("/admin/reset")
def admin_reset():
    app.state.db.delete_reports_and_challenges()
    ENGINE.reset()
    return {"ok": True}


_DEMO_LOCK = threading.Lock()  # one sandbox run at a time


@app.post("/demo/run")
async def demo_run(request: Request):
    # Judge console checks in a sandbox engine (app/demo.py): never the live data or the DB.
    # Optional {"seed": int}; a bad or empty body counts as {}.
    try:
        body = await request.json()
    except Exception:
        body = {}
    seed = body.get("seed") if isinstance(body, dict) else None
    if not isinstance(seed, int) or isinstance(seed, bool):
        seed = None
    if not _DEMO_LOCK.acquire(blocking=False):
        return JSONResponse({"error": "busy"}, status_code=429)
    try:
        result = await run_in_threadpool(demo.run, REGISTRY, ENGINE.config, seed)
    finally:
        _DEMO_LOCK.release()
    return JSONResponse(result)
