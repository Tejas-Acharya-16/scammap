"""Shared fixtures for the phone tests (tests/e2e).

`base_url` starts a throwaway server on a temporary sqlite file; `browser` is one headless
Chromium; `new_page(lang, **context_options)` opens a 390x844 touch phone. Synthetic data only.

Needs Playwright and its Chromium:
    pip install -r requirements-dev.txt
    python -m playwright install chromium
Without them every test here is skipped, so `python -m pytest tests -q` still runs on a laptop.
CI sets E2E_REQUIRED=1, which turns a missing Playwright or browser into a failure.
"""
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

from datetime import datetime, timedelta, timezone

import httpx
import pytest

REQUIRED = os.environ.get("E2E_REQUIRED") == "1"
try:
    from playwright.sync_api import sync_playwright
except ImportError:
    if REQUIRED:
        raise
    sync_playwright = None

ROOT = Path(__file__).resolve().parents[2]
PHONE = {"viewport": {"width": 390, "height": 844}, "is_mobile": True, "has_touch": True,
         "device_scale_factor": 2}


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="session")
def browser():
    if sync_playwright is None:
        pytest.skip("Playwright is not installed (pip install -r requirements-dev.txt)")
    with sync_playwright() as p:
        try:
            b = p.chromium.launch()
        except Exception as e:  # Chromium not downloaded on this machine
            if REQUIRED:
                raise
            pytest.skip(f"Chromium for Playwright is missing ({type(e).__name__}); "
                        "run: python -m playwright install chromium")
        yield b
        b.close()


@pytest.fixture(scope="session")
def base_url(browser, tmp_path_factory):
    tmp = tmp_path_factory.mktemp("e2e")
    port = _free_port()
    env = dict(os.environ, DATABASE_URL="sqlite:///" + (tmp / "e2e.db").as_posix(),
               TRUST_SALT="e2e-test-salt", ALLOW_RESET="1")
    log = open(tmp / "server.log", "wb")
    proc = subprocess.Popen([sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1",
                             "--port", str(port), "--no-access-log"],
                            cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
    url = f"http://127.0.0.1:{port}"
    try:
        with httpx.Client(trust_env=False, timeout=2) as c:
            for _ in range(150):
                if proc.poll() is not None:
                    break
                try:
                    if c.get(url + "/health").status_code == 200:
                        break
                except httpx.HTTPError:
                    pass
                time.sleep(0.1)
            else:
                proc.kill()
            if proc.poll() is not None:
                log.flush()
                pytest.fail("server did not start:\n" + (tmp / "server.log").read_text()[-2000:])
        yield url
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        log.close()


@pytest.fixture
def api(base_url):
    with httpx.Client(base_url=base_url, trust_env=False, timeout=5) as c:
        yield c


@pytest.fixture
def new_page(browser):
    """new_page(lang="en", **context_options) -> a page on a 390x844 touch phone.
    lang="hi" stands for a reader who picked हिन्दी on an earlier visit (the choice is remembered)."""
    contexts = []

    def make(lang="en", **extra):
        ctx = browser.new_context(**{**PHONE, **extra})
        if lang == "hi":
            ctx.add_init_script("try{localStorage.setItem('lang','hi')}catch(e){}")
        contexts.append(ctx)
        return ctx.new_page()

    yield make
    for ctx in contexts:
        ctx.close()


# ---- security tests (stored XSS, headers) -------------------------------------------------
IST = timezone(timedelta(hours=5, minutes=30))
# A page that runs this is a failed test. It hooks alert() too, so onload=alert(1) is caught.
INIT_SCRIPT = "window.__pwned = []; window.alert = function (x) { window.__pwned.push('alert:' + x); };"
# different words per reporter: near-identical notes are merged into one voice by the trust rules
NOTES = [
    "The text said my electricity would be cut tonight unless I clicked the link and paid a fee",
    "Got a message from an unknown number about a parcel stuck at customs, wanted a small payment",
    "Someone pretending to be my bank asked me to verify my account through a strange website",
    "A WhatsApp contact I did not know sent a prize notice and asked for card details to claim it",
]


@pytest.fixture(scope="session")
def live_server(base_url):
    return base_url


@pytest.fixture
def page(browser):
    ctx = browser.new_context(viewport={"width": 390, "height": 844})
    ctx.add_init_script(INIT_SCRIPT)
    pg = ctx.new_page()
    yield pg
    ctx.close()


def post_report(base: str, value: str, i: int, itype: str = "url") -> int:
    """One report from reporter i: own reporter id, own network, own words (a full voice)."""
    when = datetime.now(IST) - timedelta(minutes=5 + i)
    body = {
        "report_id": f"e2e-{abs(hash(value)) % 10**8}-{i}", "occurred_at": when.isoformat(),
        "reported_at": when.isoformat(), "reporter_id": f"e2e-reporter-{i}",
        "ip_prefix": f"{20 + 30 * i}.{40 + i}.{i}.0/24",   # three unrelated networks
        "channel": "SMS or WhatsApp", "scam_type": "fake-kyc-link", "identifier_type": itype,
        "identifier_value": value, "pincode": "560102", "note": NOTES[i % len(NOTES)],
        "has_screenshot": False, "amount_lost_inr": 0,
    }
    return httpx.post(base + "/reports", json=body, timeout=5, trust_env=False).status_code
