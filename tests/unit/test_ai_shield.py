"""AI Call Shield: its data, its model file and the guarantees around it.

The model runs in the browser (app/static/ai/shield.js). These tests check the committed files with the same maths in
Python (tools/ai/train_shield.py); tests/e2e/test_ai_shield.py checks the browser gives the same answers.
"""
import json
import re
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools" / "ai"))
import shield_data as sd  # noqa: E402
import train_shield as ts  # noqa: E402

import app.main as main  # noqa: E402

DATA = ROOT / "tools" / "ai" / "shield_lines.jsonl"
MODEL = ROOT / "app" / "static" / "ai" / "shield_model.json"
JS = ROOT / "app" / "static" / "ai" / "shield.js"
PAGE = ROOT / "app" / "static" / "shield.html"
HELDOUT = ROOT / "tests" / "unit" / "data" / "shield_heldout.jsonl"


def rows(path):
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]


@pytest.fixture(scope="module")
def model():
    return json.loads(MODEL.read_text(encoding="utf-8"))


def test_model_has_four_scripts_of_five_steps_plus_chatter(model):
    assert model["version"] == "shield-v1"
    assert [b["id"] for b in model["playbooks"]] == ["digital-arrest", "bank-kyc", "task-job", "upi-refund"]
    assert all(len(b["steps"]) == 5 for b in model["playbooks"])
    assert len(model["classes"]) == 21 and model["classes"][-1] == "chatter"
    for b in model["playbooks"]:
        for s in b["steps"]:
            assert s["en"] and s["hi"] and s["do_en"] and s["do_hi"], s
            assert re.search("[ऀ-ॿ]", s["hi"] + s["do_hi"])
    assert MODEL.stat().st_size < 300_000


def test_committed_files_are_exactly_what_the_scripts_write(tmp_path, model):
    assert DATA.read_text(encoding="utf-8") == "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in sd.build())
    out = tmp_path / "model.json"
    assert ts.main(["--out", str(out)]) == 0
    assert json.loads(out.read_text(encoding="utf-8")) == model


def test_held_out_calls_are_new_and_followed(model, capsys):
    train = {r["text"] for r in rows(DATA)}
    calls = rows(HELDOUT)
    assert len(calls) == 12 and not train & {line for c in calls for line in c["lines"]}
    got = ts.check_heldout(model)
    print(got["script_right"], got["step_right"], got["next_right"], "of", got["calls"])
    assert got["script_right"] >= 10 and got["step_right"] >= 9              # floors; the README quotes the actual numbers
    assert {k: got[k] for k in ("calls", "script_right", "step_right", "next_right")} == model["heldout"]


def test_cross_validation_numbers_are_in_the_model(model):
    cv = model["cross_validation"]
    assert cv["folds"] == 5 and cv["lines"] == len(rows(DATA))
    assert 0 < cv["step_accuracy"] <= cv["script_accuracy"] <= 1


def test_chatter_and_empty_calls_give_no_reading(model):
    assert ts.decode(model, []) is None
    assert ts.decode(model, ["Hello, who is speaking", "Haan ji, boliye", "हाँ जी, बोलिए"]) is None


def test_data_is_synthetic():
    text = DATA.read_text(encoding="utf-8") + HELDOUT.read_text(encoding="utf-8") + PAGE.read_text(encoding="utf-8")
    for m in re.finditer(r"(?:\+91[\s-]?)?\b[6-9]\d{4}[\s-]?\d{5}\b", text):
        assert re.sub(r"\D", "", m.group())[-10:].startswith("90000"), m.group()
    for host in re.findall(r"\b([a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|in|net|org|co|io|xyz|info|app))\b", text):
        assert False, host


def test_the_shield_code_makes_one_request_and_never_sends_the_call():
    js = JS.read_text(encoding="utf-8")
    assert len(re.findall(r"\bfetch\(", js)) == 1 and 'MODEL_URL = "/static/ai/shield_model.json"' in js
    page = PAGE.read_text(encoding="utf-8")
    assert re.findall(r"fetch\(([^)]*)\)", page) == ['"/license"']   # the page's only request is the licence check
    for code in (js, page):
        for banned in ("XMLHttpRequest", "sendBeacon", "WebSocket", "EventSource", "localStorage.setItem(\"lines"):
            assert banned not in code, banned
        assert not re.search(r"scammer|fraud", code, re.I)               # say "reported" and "scam calls" (team rule)


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite:///" + (tmp_path / "test.db").as_posix())
    with TestClient(main.app) as c:
        yield c


def test_page_and_files_are_served_even_when_the_licence_has_expired(client):
    lic = json.loads((ROOT / "licenses" / "expired.json").read_text(encoding="utf-8"))
    assert client.post("/license", json=lic).status_code == 200
    page = client.get("/shield")
    assert page.status_code == 200 and page.content == PAGE.read_bytes()
    js = client.get("/static/ai/shield.js")
    assert js.status_code == 200 and js.headers["content-type"].startswith("application/javascript")
    m = client.get("/static/ai/shield_model.json")
    assert m.status_code == 200 and m.json()["version"] == "shield-v1"
    assert js.headers["x-content-type-options"] == "nosniff"


def test_every_page_links_to_the_shield():
    for name in ("index.html", "judge.html", "live.html", "arena.html", "shield.html"):
        assert 'class="nai' in (ROOT / "app" / "static" / name).read_text(encoding="utf-8") and 'href="/shield"' in \
            (ROOT / "app" / "static" / name).read_text(encoding="utf-8"), name
