"""AI Call Shield in the browser (/shield, 390x844 phone): same answers as Python, the demo call, no network request
with the call's words, Hindi, layout, the expired licence and the judge console card. Synthetic data only."""
import json
import re
import sys
from pathlib import Path

import tests.e2e.test_phone_screens as screens

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools" / "ai"))
import train_shield as ts  # noqa: E402

MODEL = json.loads((ROOT / "app" / "static" / "ai" / "shield_model.json").read_text(encoding="utf-8"))
HELDOUT = [json.loads(x) for x in (ROOT / "tests" / "unit" / "data" / "shield_heldout.jsonl").read_text(encoding="utf-8").splitlines()]
DEVANAGARI = re.compile("[ऀ-ॿ]")


def open_shield(new_page, base_url, lang="en"):
    page = new_page(lang)
    page.goto(base_url + "/shield")
    assert page.evaluate("() => ScamMapShield.load()") is True
    return page


def panel(page):
    return page.evaluate("() => ({...document.getElementById('panel').dataset})")


def test_browser_follows_calls_exactly_like_python(base_url, new_page):
    page = open_shield(new_page, base_url)
    for call in HELDOUT:
        js = page.evaluate("ls => ScamMapShield.decode(ls)", call["lines"])
        py = ts.decode(MODEL, call["lines"])
        assert (js["playbook"], js["step"], js["next"]) == (py["playbook"], py["step"], py["next"]), call["id"]
        assert abs(js["playbook_p"] - py["playbook_p"]) < 1e-3 and abs(js["step_p"] - py["step_p"]) < 1e-3, call["id"]
    assert page.evaluate("() => ScamMapShield.decode(['Hello, who is speaking', 'Okay sir'])") is None


def test_demo_call_is_followed_step_by_step_and_predicted(base_url, new_page):
    page = open_shield(new_page, base_url)
    page.evaluate("() => ScamMapShieldPage.playDemo('arrest', 50)")
    page.wait_for_function("() => ScamMapShieldPage.state().lines.length === 5")
    page.wait_for_selector("#panel[data-step='pay']")
    assert panel(page)["playbook"] == "digital-arrest"
    steps = page.locator("#transcript .bubble").evaluate_all("els => els.map(e => e.dataset.step)")
    assert steps == ["hook", "accuse", "video", "isolate", "pay"], steps
    assert "4 of 4" in page.inner_text("#score")
    assert page.inner_text("#script") == "Digital arrest"
    assert "1930" in page.inner_text("#do") and page.get_attribute("#call1930", "href") == "tel:1930"
    family = page.get_attribute("#family", "href")
    from urllib.parse import unquote
    text = unquote(family.split("?text=", 1)[1])
    assert family.startswith("https://wa.me/?text=") and "Digital arrest" in text
    assert not [w for w in ("innocent", "Mumbai", "passports", "Skype") if w in text], text   # never the caller's words
    problems = page.evaluate(screens.LAYOUT_JS)
    assert not problems, problems


def test_typed_lines_never_leave_the_phone(base_url, new_page):
    page = new_page("en")
    log = []
    page.route("**/*", lambda route: (log.append((route.request.url, route.request.post_data or "")), route.continue_()))
    page.goto(base_url + "/shield")
    assert page.evaluate("() => ScamMapShield.load()") is True
    page.wait_for_load_state("networkidle")
    loaded = len(log)
    assert any(u.endswith("/static/ai/shield_model.json") for u, _ in log[:loaded])
    for line in ("Sir bank se bol raha hoon, KYC update karna hai, warna account block",
                 "Abhi aapke phone pe OTP aayega, woh mujhe bata do"):
        page.fill("#line", line)
        page.click("#add")
    page.wait_for_selector("#panel[data-playbook='bank-kyc']")
    page.wait_for_timeout(500)
    later = [x for x in log[loaded:] if not x[0].endswith("/license")]
    assert later == [], later
    assert not [x for x in log if any(w in (x[0] + x[1]).lower() for w in ("otp", "kyc update", "bata do"))], log


def test_hindi_page_and_menu(base_url, new_page):
    page = open_shield(new_page, base_url, lang="hi")
    assert DEVANAGARI.search(page.inner_text("h1"))
    page.evaluate("() => ScamMapShieldPage.playDemo('upi', 50)")
    page.wait_for_selector("#panel[data-step='pin']")
    assert DEVANAGARI.search(page.inner_text("#next")) and DEVANAGARI.search(page.inner_text("#do"))
    nav = page.locator("nav.sitenav > *").all_inner_texts()
    assert all(DEVANAGARI.search(t) for t in nav), nav
    problems = page.evaluate(screens.LAYOUT_JS)
    assert not problems, problems


def test_expired_licence_locks_the_page(base_url, api, new_page):
    lic = lambda name: json.loads((ROOT / "licenses" / name).read_text(encoding="utf-8"))
    assert api.post("/license", json=lic("expired.json")).status_code == 200
    try:
        page = new_page("en")
        page.goto(base_url + "/shield")
        page.wait_for_selector("#lockBanner:not(.hidden)", timeout=10_000)
        assert "Licence expired. Contact your provider." in page.inner_text("#lockBanner")
    finally:
        assert api.post("/license", json=lic("long.json")).status_code == 200


def test_judge_console_card_opens_the_shield(base_url, new_page):
    page = new_page("en")
    page.goto(base_url + "/judge")
    page.click("#shieldCard a")
    page.wait_for_url(base_url + "/shield")
    assert page.inner_text("h1").strip()
