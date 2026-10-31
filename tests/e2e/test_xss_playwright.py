"""Stored XSS: 3 people report a link with markup in its path, then someone checks it.

Layer (a), the URL normaliser, is tested in tests/engine/test_normalise_url_encoding.py.
Layer (b), escaping in index.html, is tested here on its own: the API answer is replaced with
hostile values in every field, so this passes only if the page escapes by itself.
"""
import json

import httpx

from .conftest import post_report

XSS_LINK = "evil.example/<svg/onload=alert(1)>"
# if either of these runs, it pushes to window.__pwned
PAYLOAD = '<img src=x onerror="window.__pwned.push(\'img\')"><svg/onload="window.__pwned.push(\'svg\')">'


def assert_nothing_ran(page, *scopes):
    page.wait_for_timeout(400)  # let any handler fire
    assert page.evaluate("window.__pwned") == []
    for s in scopes:
        assert page.locator(f"{s} img, {s} svg, {s} script").count() == 0, s


def answer_with(hostile, verdict):
    # a factory: Playwright calls a handler as (route, request), so a default argument would catch the request
    return lambda route: fulfil(route, {**hostile, "verdict": verdict})


def fulfil(route, body, status=200):
    route.fulfill(status=status, content_type="application/json", body=json.dumps(body))


def test_reported_link_with_markup_is_shown_as_text_and_runs_nothing(live_server, page):
    httpx.post(live_server + "/admin/reset", timeout=5)
    for i in (1, 2, 3):
        assert post_report(live_server, XSS_LINK, i) == 201
    r = httpx.get(live_server + "/lookup", params={"type": "url", "value": XSS_LINK}, timeout=5).json()
    assert r["distinct_reporters"] == 3 and "evil.example" in r["display_value"]   # unmasked: the dangerous case

    page.goto(live_server + "/")
    page.fill("#q", XSS_LINK)
    page.click("#go")
    page.wait_for_selector("#result .mono")
    assert_nothing_ran(page, "#result")
    assert page.inner_text("#result .mono") == r["display_value"]
    assert "evil.example/%3Csvg/onload=alert(1)%3E" in page.inner_text("#result .mono")


def test_the_page_escapes_every_lookup_field_on_its_own(live_server, page):
    # verdict, display_value, last_seen, scam_type, distinct_reporters and label all hostile
    hostile = {"verdict": PAYLOAD, "display_value": PAYLOAD, "report_count": PAYLOAD, "distinct_reporters": PAYLOAD,
               "first_seen": PAYLOAD, "last_seen": PAYLOAD, "scam_type": PAYLOAD, "label": PAYLOAD,
               "challenged": True, "evidence": [{"occurred_at": PAYLOAD, "channel": PAYLOAD, "scam_type": PAYLOAD,
                                                 "pincode": PAYLOAD}], "trust": {"voices": PAYLOAD, "hold": False}}
    page.route("**/lookup**", lambda route: fulfil(route, hostile))
    page.goto(live_server + "/")
    page.fill("#q", "9000011111")
    page.click("#go")
    page.wait_for_selector("#result .mono")
    assert_nothing_ran(page, "#result")
    assert page.inner_text("#result .mono") == PAYLOAD          # shown literally

    for verdict in ("VERIFIED_BUSINESS", "KNOWN_SCAM", "SUSPICIOUS", "NO_REPORTS"):   # label and sentences
        page.unroute("**/lookup**")
        page.route("**/lookup**", answer_with(hostile, verdict))
        page.fill("#q", "9000011112")
        page.click("#go")
        page.wait_for_selector(f"#result .verdict.v-{verdict}")      # locators, not eval: the CSP forbids eval
        assert_nothing_ran(page, "#result")
    page.unroute("**/lookup**")
    page.route("**/lookup**", lambda route: fulfil(route, {**hostile, "verdict": "VERIFIED_BUSINESS"}))
    page.fill("#q", "9000011113")
    page.click("#go")
    page.wait_for_selector("#result:has-text('<img src=x')")
    assert PAYLOAD in page.inner_text("#result")                 # the label, literally


def test_the_page_escapes_map_and_alert_fields_on_its_own(live_server, page):
    page.route("**/map**", lambda route: fulfil(route, {"clusters": [
        {"pincode": PAYLOAD, "locality": PAYLOAD, "city": PAYLOAD, "count": PAYLOAD,
         "top_scam_type": PAYLOAD, "severity": PAYLOAD, "lat": PAYLOAD, "lng": PAYLOAD}]}))
    page.route("**/alerts**", lambda route: fulfil(route, {"alerts": [
        {"type": "SPIKE", "pincode": PAYLOAD, "window": "24h", "count": PAYLOAD, "baseline_per_day": PAYLOAD},
        {"type": "NEW_TYPE", "pincode": PAYLOAD, "scam_type": PAYLOAD, "window": "24h"}]}))
    page.goto(live_server + "/")
    page.click("nav button[data-tab=area]")
    page.wait_for_selector("#clusters .cluster")
    assert_nothing_ran(page, "#clusters", "#alerts")
    assert PAYLOAD in page.inner_text("#clusters")
    assert PAYLOAD in page.inner_text("#alerts")


def test_judge_console_escapes_a_hostile_lookup_answer(live_server, page):
    page.route("**/lookup**", lambda route: fulfil(route, {
        "verdict": PAYLOAD, "display_value": PAYLOAD, "report_count": PAYLOAD, "distinct_reporters": PAYLOAD,
        "trust": {"burst_voices": PAYLOAD}}))
    page.goto(live_server + "/judge")
    page.fill("#q", "9000011111")
    page.click("#qBtn")
    page.wait_for_selector("#qOut code")
    assert_nothing_ran(page, "#qOut")
