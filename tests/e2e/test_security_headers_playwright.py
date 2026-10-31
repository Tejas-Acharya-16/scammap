"""The CSP must not break the pages: /, /judge and the licence-expired screen.

Only CSP violations fail these tests. A blocked network request (the sandbox has no route to
cdnjs.cloudflare.com for the judge console's QR code) is not a CSP violation.
"""
import json
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[2]
CSP = ("default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
       "style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; "
       "base-uri 'none'; form-action 'self'")


def watch_csp(page):
    seen = []
    page.on("console", lambda m: seen.append(m.text) if "content security policy" in m.text.lower() else None)
    page.on("pageerror", lambda e: seen.append("pageerror: " + str(e)))
    return seen


def test_app_page_works_under_the_csp(live_server, page):
    seen = watch_csp(page)
    resp = page.goto(live_server + "/#check")
    assert resp.headers["content-security-policy"] == CSP
    assert page.inner_text("header b")                                  # the title strings rendered (inline script ran)
    page.fill("#q", "1930")
    page.click("#go")                                                   # fetch() under connect-src 'self'
    page.wait_for_selector("#result .verdict")
    assert "VERIFIED_BUSINESS" in page.get_attribute("#result .verdict", "class")
    page.click("nav button[data-tab=report]")
    assert page.is_visible("#post")
    page.click("nav button[data-tab=area]")
    page.wait_for_selector("#clusters")
    page.click("#l-hi")                                                 # language switch (innerHTML paths)
    assert page.evaluate("document.documentElement.lang") == "hi"
    assert not page.is_visible("#expired")
    assert seen == []


def test_judge_console_works_under_the_csp(live_server, page):
    seen = watch_csp(page)
    resp = page.goto(live_server + "/judge")
    assert resp.headers["content-security-policy"] == CSP
    page.click("#runAll")                                               # POST /demo/run, then renders every row
    page.wait_for_selector("#runSum:has-text('checks passed')", timeout=90_000)   # not wait_for_function: it uses eval, the CSP forbids it
    assert page.locator("#rows details").count() > 10
    # the QR library comes from cdnjs; with no route to it (sandbox) the page reports it missing.
    # That is a network failure, not a CSP violation, so only CSP messages and other errors count.
    assert [s for s in seen if "QRCode" not in s] == []


def test_licence_expired_screen_works_under_the_csp(live_server, page):
    expired = json.loads((ROOT / "licenses" / "expired.json").read_text(encoding="utf-8"))
    long_ = json.loads((ROOT / "licenses" / "long.json").read_text(encoding="utf-8"))
    seen = watch_csp(page)
    try:
        assert httpx.post(live_server + "/license", json=expired, timeout=5).status_code == 200
        resp = page.goto(live_server + "/#check")
        assert resp.status == 200 and resp.headers["content-security-policy"] == CSP
        page.wait_for_selector("#expired:not(.hidden)")
        assert "Licence expired. Contact your provider." in page.inner_text("#expired")
        assert httpx.get(live_server + "/lookup", params={"type": "phone", "value": "1930"}, timeout=5).status_code == 403
    finally:
        assert httpx.post(live_server + "/license", json=long_, timeout=5).status_code == 200
    page.reload()                                                       # recovers with no restart
    page.wait_for_selector("#expired.hidden", state="attached")
    assert seen == []
