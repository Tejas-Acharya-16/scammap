"""The judge console's "Verify an answer" panel: VALID for a real answer, INVALID after tampering.

The page loads tweetnacl 1.0.3 from cdnjs with an integrity hash. The sandbox has no route to cdnjs,
so these tests answer that exact URL with a byte-identical copy (tests/e2e/assets): the browser still
checks the integrity hash, so a wrong pinned hash fails here too. Synthetic numbers only.
"""
import base64
import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx

from app.attestation import verify

ROOT = Path(__file__).resolve().parents[2]
JUDGE = ROOT / "app" / "static" / "judge.html"
NACL_URL = "https://cdnjs.cloudflare.com/ajax/libs/tweetnacl/1.0.3/nacl-fast.min.js"
ASSET = Path(__file__).parent / "assets" / "tweetnacl-1.0.3-nacl-fast.min.js"
LAPTOP = {"viewport": {"width": 1280, "height": 800}, "is_mobile": False, "device_scale_factor": 1}
IST = timezone(timedelta(hours=5, minutes=30))
NUMBER = "+91 90000 63001"
NOTES = ["Caller said my KYC would lapse today and sent a link to update it",
         "Got an SMS that my bank account is blocked unless I verify on a website",
         "A man claiming to be from the bank asked me to open a link and enter my card"]


def serve_nacl(route):
    route.fulfill(status=200, body=ASSET.read_bytes(),
                  headers={"content-type": "application/javascript; charset=utf-8",
                           "access-control-allow-origin": "*"})


def seed(base_url):
    now = datetime.now(IST)
    with httpx.Client(base_url=base_url, trust_env=False, timeout=5) as c:
        for i in range(3):
            when = (now - timedelta(minutes=15 * (i + 1))).isoformat()
            c.post("/reports", json={
                "report_id": f"signed-e2e-{i}", "occurred_at": when, "reported_at": when,
                "reporter_id": f"signed-e2e-r{i}", "ip_prefix": f"{60 + 30 * i}.{70 + i}.{i}.0/24",
                "channel": "Phone call", "scam_type": "fake-kyc-link", "identifier_type": "phone",
                "identifier_value": NUMBER, "pincode": "560102", "note": NOTES[i],
                "has_screenshot": False, "amount_lost_inr": 0})
        js = c.get("/lookup", params={"type": "phone", "value": NUMBER}).json()
        key = c.get("/attestation/key").json()
    assert js["verdict"] == "KNOWN_SCAM"
    return key


def test_pinned_integrity_hash_matches_tweetnacl_1_0_3():
    html = JUDGE.read_text(encoding="utf-8")
    m = re.search(r'<script src="' + re.escape(NACL_URL) + r'" integrity="(sha512-[^"]+)" crossorigin="anonymous"', html)
    assert m, "tweetnacl must be pinned to 1.0.3 with an integrity hash"
    assert m.group(1) == "sha512-" + base64.b64encode(hashlib.sha512(ASSET.read_bytes()).digest()).decode()


def test_verify_panel_shows_valid_then_invalid_after_tampering(base_url, new_page):
    key = seed(base_url)
    page = new_page("en", **LAPTOP)
    page.route(NACL_URL, serve_nacl)
    page.goto(base_url + "/judge")
    page.fill("#vq", NUMBER)
    page.click("#vBtn")
    page.wait_for_selector("#vResult")
    assert page.inner_text("#vResult") == "VALID", page.inner_text("#vOut")
    assert "KNOWN_SCAM" in page.inner_text("#vOut") and key["key_id"] in page.inner_text("#vOut")
    assert not page.is_visible("#vResult.bad")
    page.click("#vTamper")
    page.wait_for_selector("#vResult.bad")
    assert page.inner_text("#vResult") == "INVALID"
    assert "NO_REPORTS" in page.inner_text("#vOut")


def test_browser_and_server_agree_on_the_signed_bytes(base_url, new_page):
    """The page's canonical JSON is the server's: the browser accepts exactly what Python accepts."""
    key = seed(base_url)
    att = httpx.get(base_url + "/lookup", params={"type": "phone", "value": NUMBER}, trust_env=False).json()["attestation"]
    assert verify(att, base64.b64decode(key["public_key"]))
    page = new_page("en", **LAPTOP)
    page.route(NACL_URL, serve_nacl)
    page.goto(base_url + "/judge")
    page.wait_for_selector("#vBtn")
    ok = page.evaluate("async a => (await checkSig(a))[0]", att)
    bad = page.evaluate("async a => (await checkSig({...a, voices: a.voices + 1}))[0]", att)
    assert ok is True and bad is False


def test_without_the_library_the_panel_says_not_checked(base_url, new_page):
    page = new_page("en", **LAPTOP)
    page.route(NACL_URL, lambda route: route.abort())
    page.goto(base_url + "/judge")
    page.fill("#vq", "1930")
    page.click("#vBtn")
    page.wait_for_selector("#vResult.idle")
    assert page.inner_text("#vResult") == "NOT CHECKED"
    assert "verify_attestation.py" in page.inner_text("#vOut")
    assert not page.is_visible("#vTamper")
