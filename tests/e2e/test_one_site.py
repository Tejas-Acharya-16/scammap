"""/ and /judge are one website: one header, one theme, and on a laptop the app in the centre.

Checked on a 390x844 phone and a 1280x800 laptop. Fixtures (throwaway server, Chromium, phone
pages) are in conftest.py. Synthetic data only: +91 90000 4xxxx.
"""
import json
import re
from pathlib import Path

import httpx
import pytest

import tests.e2e.test_report_flow as flow

ROOT = Path(__file__).resolve().parents[2]
LAPTOP = {"viewport": {"width": 1280, "height": 800}, "is_mobile": False, "has_touch": True, "device_scale_factor": 1}
DEVANAGARI = re.compile("[ऀ-ॿ]")

HEADER_JS = r"""() => {
  const h = document.querySelector('header.site');
  if (!h) return null;
  const root = document.documentElement;
  return {
    brand: h.querySelector('.brand b').innerText.replace(/\s+/g, ' ').trim(),
    nav: [...h.querySelectorAll('nav.sitenav > *')].map(e => e.innerText.trim()),
    lang: !!h.querySelector('#l-en') && !!h.querySelector('#l-hi'),
    pill: !!h.querySelector('#licPill'),
    accent: getComputedStyle(root).getPropertyValue('--accent').trim(),
    theme: [...document.styleSheets].some(s => (s.href || '').endsWith('/static/theme.css') && s.cssRules.length > 20),
    wide: root.scrollWidth > root.clientWidth,
  };
}"""


def open_page(new_page, size, lang="en"):
    return new_page(lang) if size == "phone" else new_page(lang, **LAPTOP)


@pytest.mark.parametrize("size", ["phone", "laptop"])
def test_app_and_judge_console_share_one_header_and_theme(base_url, new_page, size):
    seen = {}
    for path in ("/", "/judge"):
        page = open_page(new_page, size)
        page.goto(base_url + path)
        page.wait_for_selector("#licPill.ok", timeout=10_000)   # not wait_for_function: it uses eval, the CSP forbids it
        seen[path] = page.evaluate(HEADER_JS)
    app, judge = seen["/"], seen["/judge"]
    assert app and judge, seen
    judge_label = "Judge" if size == "phone" else "Judge console"
    live_label = "Map" if size == "phone" else "Live map"
    ai_label = "AI" if size == "phone" else "AI Shield"
    for got in (app, judge):
        assert got["brand"] == "Community Scam Map"
        assert got["nav"] == ["Check", "Report", "My area", live_label, ai_label, judge_label], got["nav"]
        assert got["lang"] and got["pill"] and got["theme"], got
        assert not got["wide"], got
    assert app["accent"] == judge["accent"] == "#00C96B"


def test_laptop_shows_the_app_in_the_centre_with_a_side_panel(base_url, new_page):
    page = open_page(new_page, "laptop")
    page.goto(base_url + "/")
    box = page.evaluate("""() => {
      const r = e => document.querySelector(e).getBoundingClientRect();
      return {W: document.documentElement.clientWidth, app: r('main.app'), side: r('aside.side'),
              rules: [...document.querySelectorAll('aside.side li')].map(e => e.innerText.trim()),
              links: [...document.querySelectorAll('aside.side a')].map(e => e.getAttribute('href'))};
    }""")
    centre = (box["app"]["left"] + box["app"]["right"]) / 2
    assert abs(centre - box["W"] / 2) <= 2, box
    assert 380 <= box["app"]["width"] <= 460, box
    assert box["side"]["width"] > 200 and box["side"]["right"] <= box["app"]["left"], box
    assert len(box["rules"]) == 3 and all(box["rules"]), box["rules"]
    assert "/judge" in box["links"] and any("readme" in (h or "").lower() for h in box["links"]), box["links"]
    # the side panel fits on one laptop screen
    assert box["side"]["bottom"] <= 800, box


def test_phone_shows_only_the_app(base_url, new_page):
    page = open_page(new_page, "phone")
    page.goto(base_url + "/")
    assert not page.is_visible("aside.side")
    assert page.is_visible("#rform")


def test_judge_nav_opens_the_app_on_the_right_tab(base_url, new_page):
    page = open_page(new_page, "laptop")
    page.goto(base_url + "/judge")
    page.click("nav.sitenav >> text=Check")
    page.wait_for_url(base_url + "/#check")
    assert page.is_visible("#q") and not page.is_visible("#rform")
    page.goto(base_url + "/judge")
    page.click("nav.sitenav >> text=My area")
    page.wait_for_url(base_url + "/#area")
    page.wait_for_selector("#clusters")
    assert page.is_visible("#aarea")
    page.click("nav.sitenav >> text=Judge console")
    page.wait_for_url(base_url + "/judge")


def test_one_language_setting_for_the_whole_site(base_url, new_page):
    page = open_page(new_page, "phone")
    page.goto(base_url + "/judge")
    assert not page.is_visible("#hiNote")
    page.tap("#l-hi")
    assert page.evaluate("document.documentElement.lang") == "hi"
    nav = page.locator("nav.sitenav > *").all_inner_texts()
    assert all(DEVANAGARI.search(t) for t in nav), nav
    assert page.is_visible("#hiNote")
    page.goto(base_url + "/")                                  # the app opens in Hindi too
    assert page.evaluate("document.documentElement.lang") == "hi"
    assert page.inner_text('nav button[data-tab="check"]') == "जाँचें"
    assert page.inner_text("#post") == "भेजें"
    page.tap("#l-en")
    page.goto(base_url + "/judge")
    assert page.evaluate("document.documentElement.lang") == "en"


def test_licence_pill_and_expired_screen_on_both_pages(base_url, new_page):
    expired = json.loads((ROOT / "licenses" / "expired.json").read_text(encoding="utf-8"))
    long_ = json.loads((ROOT / "licenses" / "long.json").read_text(encoding="utf-8"))
    app = open_page(new_page, "phone")
    judge = open_page(new_page, "laptop")
    try:
        assert httpx.post(base_url + "/license", json=expired, timeout=5, trust_env=False).status_code == 200
        app.goto(base_url + "/")
        app.wait_for_selector("#expired:not(.hidden)")
        assert "Licence expired. Contact your provider." in app.inner_text("#expired")
        assert "bad" in app.get_attribute("#licPill", "class")
        judge.goto(base_url + "/judge")
        judge.wait_for_selector("#licPill.bad")
        assert judge.inner_text("#licTxt").lower() == "expired"
        assert judge.is_visible("#lockBanner")
    finally:
        assert httpx.post(base_url + "/license", json=long_, timeout=5, trust_env=False).status_code == 200
    app.reload()
    app.wait_for_selector("#licPill.ok")
    assert not app.is_visible("#expired")


@pytest.mark.parametrize("size", ["phone", "laptop"])
def test_one_report_is_five_taps_or_fewer(base_url, api, new_page, size):
    """First report in a fresh browser: paste, then taps only. Every control on screen, no scrolling."""
    number = {"phone": "+91 90000 41001", "laptop": "+91 90000 42001"}[size]
    page = open_page(new_page, size)
    page.goto(base_url + "/")
    phone = flow.Phone(page)
    phone.paste("#rv", number)
    phone.tap('#channels [data-ch="SMS or WhatsApp"]', "SMS")
    phone.tap(flow.KYC, "kind: fake KYC link")
    phone.tap("#post", "Post")
    page.locator("#rdone .verdict").wait_for(timeout=10_000)
    taps = [s for s in phone.steps if s.startswith("tap ")]
    assert len(taps) <= 5 and len(phone.steps) <= flow.BUDGET, phone.steps
    assert api.get("/lookup", params={"type": "phone", "value": number}).json()["report_count"] == 1
