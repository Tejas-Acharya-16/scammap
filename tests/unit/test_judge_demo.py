"""GET /judge, POST /demo/run and the /health deploy headers."""
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import app.main as main

ROOT = Path(__file__).resolve().parents[2]
JUDGE = ROOT / "app" / "static" / "judge.html"
IST = timezone(timedelta(hours=5, minutes=30))


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite:///" + (tmp_path / "test.db").as_posix())
    with TestClient(main.app) as c:
        yield c


def install_expired(client):
    lic = json.loads((ROOT / "licenses" / "expired.json").read_text(encoding="utf-8"))
    assert client.post("/license", json=lic).status_code == 200


def test_judge_page(client):
    r = client.get("/judge")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/html")
    assert r.content == JUDGE.read_bytes()


def test_judge_page_loads_when_licence_expired(client):
    install_expired(client)
    assert client.get("/judge").status_code == 200
    assert client.post("/judge").status_code == 403


def test_judge_page_has_no_docs_link_while_docs_are_off(client):
    assert client.get("/docs").status_code == 404
    assert b'href="/docs"' not in JUDGE.read_bytes()


@pytest.mark.parametrize("body", [b"", b"{not json", b"[1, 2]", b'{"seed": "x"}', b'{"seed": true}', b"{}"])
def test_demo_run_bad_or_empty_body_is_treated_as_empty(client, body):
    r = client.post("/demo/run", content=body, headers={"content-type": "application/json"})
    assert r.status_code == 200
    assert r.json()["total"] > 0


def test_demo_run_with_seed_passes_every_check(client):
    r = client.post("/demo/run", json={"seed": 7})
    js = r.json()
    assert r.status_code == 200
    assert js["seed"] == 7
    assert js["live_data_touched"] is False
    assert js["passed"] == js["total"], [c for s in js["sections"] for c in s["checks"] if not c["ok"]]


def test_demo_run_does_not_touch_live_data(client):
    report = {
        "report_id": "rep_unit_demo", "occurred_at": (datetime.now(IST) - timedelta(hours=1)).isoformat(),
        "reporter_id": "r_unit_demo", "ip_prefix": "10.20.30", "channel": "Phone call",
        "scam_type": "digital-arrest", "identifier_type": "phone", "identifier_value": "+91 90000 31031",
        "pincode": "560102", "note": "unit test report",
    }
    assert client.post("/reports", json=report).status_code == 201
    query = {"type": "phone", "value": "+91 90000 31031"}
    rows = main.app.state.db.all_report_rows()
    before = client.get("/lookup", params=query).json()
    assert client.post("/demo/run", json={"seed": 3}).status_code == 200
    assert main.app.state.db.all_report_rows() == rows
    assert client.get("/lookup", params=query).json() == before


def test_demo_run_is_licence_gated(client):
    install_expired(client)
    r = client.post("/demo/run", json={})
    assert r.status_code == 403
    assert r.json() == {"error": "LICENSE_EXPIRED"}


def test_demo_run_get_is_json_405(client):
    r = client.get("/demo/run")
    assert r.status_code == 405
    assert r.headers["content-type"].startswith("application/json")


def test_demo_run_one_at_a_time(client):
    assert main._DEMO_LOCK.acquire(blocking=False)
    try:
        r = client.post("/demo/run", json={})
    finally:
        main._DEMO_LOCK.release()
    assert r.status_code == 429
    assert r.json() == {"error": "busy"}


def test_health_names_the_running_instance(client):
    r = client.get("/health")
    assert r.json() == {"ok": True}
    assert r.headers["x-commit"] and r.headers["x-started"]


def test_live_summary_route(client):
    r = client.get("/live/summary")
    assert r.status_code == 200
    assert set(r.json()) >= {"updated_at", "areas", "top_types", "top_numbers", "alerts", "total"}
    assert client.post("/live/summary").status_code == 405
    install_expired(client)
    assert client.get("/live/summary").status_code == 403


def test_live_page_is_served_even_when_the_licence_is_expired(client):
    r = client.get("/live")
    assert r.status_code == 200 and "Live scam map" in r.text and "/live/summary" in r.text
    install_expired(client)
    assert client.get("/live").status_code == 200          # page loads and shows the expired screen
    assert client.get("/live/summary").status_code == 403  # its data is gated
