"""AT-6.1 (BUILD_SPEC 11.1 and 13): one report on a 390x844 phone takes 6 interactions or fewer.

One interaction = one tap, one paste into a box, or one step of a native picker (open it,
choose an item: 2). Scrolling also counts, so every control must already be on screen when it
is used; the helper fails the test instead of letting Playwright scroll for us.

The test starts its own server on a temporary sqlite file and posts synthetic numbers only
(+91 90000 xxxxx). It needs Playwright and its Chromium:
    pip install -r requirements-dev.txt
    python -m playwright install chromium
Without them the module is skipped, so `python -m pytest tests -q` still runs on a laptop.
CI sets E2E_REQUIRED=1, which turns a missing browser into a failure instead of a skip.
"""
import os
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest

REQUIRED = os.environ.get("E2E_REQUIRED") == "1"
try:
    from playwright.sync_api import sync_playwright
except ImportError:
    if REQUIRED:
        raise
    pytest.skip("Playwright is not installed (pip install -r requirements-dev.txt)",
                allow_module_level=True)

ROOT = Path(__file__).resolve().parents[2]
PHONE = {"viewport": {"width": 390, "height": 844}, "is_mobile": True, "has_touch": True,
         "device_scale_factor": 2}
BUDGET = 6
# Every field the app sends today (BUILD_SPEC 3). The faster flow must keep all of them.
API_FIELDS = {"report_id", "occurred_at", "reported_at", "reporter_id", "channel", "scam_type",
              "identifier_type", "identifier_value", "pincode", "note", "has_screenshot",
              "amount_lost_inr"}
SMS = "SMS or WhatsApp"
POST_LABEL = {"en": "Post report", "hi": "भेजें"}
JUST_NOW = {"en": "Just now", "hi": "अभी"}


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def base_url(tmp_path_factory):
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


@pytest.fixture(scope="module")
def browser():
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


class Phone:
    """Drives the page like a person and writes down every interaction."""

    def __init__(self, page):
        self.page, self.steps = page, []

    def on_screen(self, selector) -> bool:
        box = self.page.locator(selector).bounding_box()
        height = self.page.viewport_size["height"]
        return box is not None and box["y"] >= 0 and box["y"] + box["height"] <= height

    def _reachable(self, selector):
        assert self.on_screen(selector), f"{selector} is off screen: a person would have to scroll"

    def tap(self, selector, what):
        self._reachable(selector)
        self.page.locator(selector).tap()
        self.steps.append("tap " + what)

    def paste(self, selector, text):
        self._reachable(selector)
        self.page.locator(selector).fill(text)
        self.steps.append("paste")

    def pick(self, selector, value, what):
        self._reachable(selector)
        self.page.locator(selector).select_option(value)
        self.steps += ["open " + what, "choose " + what]


def _focused(page) -> str:
    return page.evaluate("document.activeElement ? document.activeElement.id : ''")


def _lookup(base_url, value) -> dict:
    with httpx.Client(trust_env=False, timeout=5) as c:
        r = c.get(base_url + "/lookup", params={"type": "phone", "value": value})
    assert r.status_code == 200
    return r.json()


def _wait_for_result(page):
    page.locator("#rdone .verdict").wait_for(timeout=10_000)
    assert page.locator("#again").is_visible()


@pytest.mark.parametrize("lang", ["en", "hi"])
def test_one_report_takes_six_interactions_or_fewer(base_url, browser, lang):
    first = {"en": 11001, "hi": 12001}[lang]
    n1, n2, n3 = ("+91 90000 %05d" % (first + i) for i in range(3))
    ctx = browser.new_context(**PHONE)
    if lang == "hi":  # a Hindi reader who picked हिन्दी on an earlier visit (the choice is remembered)
        ctx.add_init_script("try{localStorage.setItem('lang','hi')}catch(e){}")
    page = ctx.new_page()
    sent = []
    page.on("request", lambda r: sent.append(r.post_data_json)
            if r.method == "POST" and r.url.endswith("/reports") else None)
    page.goto(base_url + "/")

    # 1. First report in a fresh browser: SMS, fake KYC link, home area left as it is, just now.
    phone = Phone(page)
    phone.tap('nav button[data-tab="report"]', "Report tab")
    assert _focused(page) == "rv", "the number box should have focus when Report opens"
    assert page.locator("#post").inner_text() == POST_LABEL[lang]
    phone.paste("#rv", n1)
    phone.tap(f'#channels [data-ch="{SMS}"]', SMS)
    phone.pick("#stype", "fake-kyc-link", "kind of scam")
    assert page.locator("#when .chip.on").inner_text() == JUST_NOW[lang]
    phone.tap("#post", "Post")
    _wait_for_result(page)
    assert len(phone.steps) <= BUDGET, phone.steps
    body = sent[-1]
    assert API_FIELDS <= set(body), API_FIELDS - set(body)
    assert (body["channel"], body["scam_type"], body["identifier_type"], body["pincode"]) == \
        (SMS, "fake-kyc-link", "phone", "560102")
    occurred = datetime.fromisoformat(body["occurred_at"].replace("Z", "+00:00"))
    assert abs((datetime.now(timezone.utc) - occurred).total_seconds()) < 120  # "Just now"
    assert _lookup(base_url, n1)["report_count"] == 1

    # 2. "Report another": fresh box with focus, channel and "Just now" kept; this time a new area.
    phone = Phone(page)
    phone.tap("#again", "Report another")
    assert _focused(page) == "rv" and page.input_value("#rv") == ""
    assert page.locator("#channels .tile.on").get_attribute("data-ch") == SMS
    assert page.locator("#when .chip.on").inner_text() == JUST_NOW[lang]
    phone.paste("#rv", n2)
    phone.pick("#parea", "560034", "area")
    phone.tap("#post", "Post")
    _wait_for_result(page)
    assert len(phone.steps) <= BUDGET, phone.steps
    assert (sent[-1]["identifier_value"], sent[-1]["channel"], sent[-1]["pincode"]) == \
        (n2, SMS, "560034")

    # 3. Next visit (reload): the last channel and area are remembered.
    page.reload()
    phone = Phone(page)
    phone.tap('nav button[data-tab="report"]', "Report tab")
    assert _focused(page) == "rv"
    assert page.locator("#channels .tile.on").get_attribute("data-ch") == SMS
    assert page.input_value("#parea") == "560034"
    phone.paste("#rv", n3)
    phone.pick("#stype", "fake-kyc-link", "kind of scam")
    phone.tap("#post", "Post")
    _wait_for_result(page)
    assert len(phone.steps) <= BUDGET, phone.steps
    assert (sent[-1]["channel"], sent[-1]["pincode"]) == (SMS, "560034")
    ctx.close()
