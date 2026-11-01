"""The Scam Arena page (/arena) on a 390x844 phone: presets, Launch, the outcome banner, the AI attacker,
Hindi, no sideways scroll, and the page loading with an expired licence. Sandbox only, synthetic data."""
import json
import re
from pathlib import Path

import tests.e2e.test_phone_screens as screens

ROOT = Path(__file__).resolve().parents[2]
DEVANAGARI = re.compile("[ऀ-ॿ]")


def licence(api, name):
    assert api.post("/license", json=json.loads((ROOT / "licenses" / name).read_text(encoding="utf-8"))).status_code == 200


def test_preset_launch_shows_caught(base_url, new_page):
    page = new_page("en")
    page.goto(base_url + "/arena")
    page.click("#presets >> text=40 friends vs the bakery")
    assert page.input_value("#s-reports") == "40" and page.input_value("#s-accounts") == "40"
    page.click("#launch")
    page.wait_for_selector("#banner.caught", timeout=15000)
    assert page.inner_text("#banner").strip() == "CAUGHT"
    out = page.inner_text("#result")
    assert "40 reports" in out and "in this sandbox" in out, out
    assert page.locator("#bill").inner_text().strip()
    problems = page.evaluate(screens.LAYOUT_JS)
    assert not problems, problems


def test_ai_attacker_shows_a_result_and_loads_its_plan(base_url, new_page):
    page = new_page("en")
    page.goto(base_url + "/arena")
    page.click("#redteam")
    page.wait_for_selector("#redOut .red-sum", timeout=20000)
    summary = page.inner_text("#redOut .red-sum")
    assert re.search(r"Tried \d+ plans in [\d.]+ s\. \d+ beat the rules; the AI flagged \d+ of them\.", summary), summary
    load = page.locator("#redOut button.load").first
    load.click()
    page.wait_for_selector("#banner:not(.idle)", timeout=15000)
    problems = page.evaluate(screens.LAYOUT_JS)
    assert not problems, problems


def test_hindi_toggle_changes_the_heading(base_url, new_page):
    page = new_page("en")
    page.goto(base_url + "/arena")
    en = page.inner_text("h1")
    page.click("#l-hi")
    hi = page.inner_text("h1")
    assert hi != en and DEVANAGARI.search(hi), (en, hi)
    assert DEVANAGARI.search(page.inner_text("#launch"))
    nav = page.locator("nav.sitenav > *").all_inner_texts()
    assert all(DEVANAGARI.search(t) for t in nav), nav
    problems = page.evaluate(screens.LAYOUT_JS)
    assert not problems, problems
    page.click("#l-en")


def test_page_loads_with_an_expired_licence(base_url, api, new_page):
    licence(api, "expired.json")
    try:
        page = new_page("en")
        page.goto(base_url + "/arena")
        assert page.inner_text("h1").strip()
        page.click("#launch")
        page.wait_for_selector("#lockBanner:not(.hidden)", timeout=15000)
        assert "LICENSE_EXPIRED" in page.inner_text("#lockBanner")
    finally:
        licence(api, "long.json")


def test_judge_console_has_a_play_the_attacker_card(base_url, new_page):
    page = new_page("en")
    page.goto(base_url + "/judge")
    page.click("#arenaCard a")
    page.wait_for_url(base_url + "/arena")
    assert page.inner_text("h1").strip()
