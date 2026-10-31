"""The README licence demo, step by step, with no private key (BUILD_SPEC 9, AT-5.x).

1. GET /license shows valid; one synthetic report goes in.
2. POST licenses/expired.json: every API route answers 403 LICENSE_EXPIRED, while /health,
   /license and the app page stay open (so the app can show its expired screen).
3. POST licenses/long.json: back at once, same app (no restart), the report still there.
4. POST a copy of long.json with one digit changed: 400 INVALID_LICENSE, licence unchanged.

The report body is read from the README itself, so this fails if the README's command breaks.
"""
import json
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import app.main as main

ROOT = Path(__file__).resolve().parents[2]
README = (ROOT / "README.md").read_text(encoding="utf-8")
LONG = (ROOT / "licenses" / "long.json").read_bytes()
EXPIRED = (ROOT / "licenses" / "expired.json").read_bytes()
JSON = {"content-type": "application/json"}
LOOKUP = {"type": "phone", "value": "9000000042"}
# Every API route behind the licence gate (GET /, GET /judge, /health and /license stay open).
GATED = [("GET", "/lookup?type=phone&value=9000000042"), ("GET", "/map?pincode=560102"),
         ("GET", "/alerts?pincode=560102"), ("POST", "/reports"), ("POST", "/challenges"),
         ("POST", "/demo/run"), ("POST", "/admin/reset")]


def _readme_report() -> dict:
    """The demo report body exactly as the README's bash and PowerShell steps send it."""
    bash = re.findall(r"curl -X POST \$URL/reports .*? -d '(\{.*?\})'", README)
    pwsh = re.findall(r'"\$URL/reports" .*? -Body \'(\{.*?\})\'', README)
    assert len(bash) == 1 and len(pwsh) == 1, "README should send the demo report once in each shell"
    assert json.loads(bash[0]) == json.loads(pwsh[0]), "bash and PowerShell steps send different bodies"
    return json.loads(bash[0])


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite:///" + (tmp_path / "test.db").as_posix())
    with TestClient(main.app) as c:
        yield c


def test_readme_licence_demo_runs_without_the_private_key(client):
    # 1. Valid, and one synthetic report in.
    assert client.get("/license").json()["status"] == "valid"
    assert client.post("/reports", json=_readme_report()).status_code == 201
    before = client.get("/lookup", params=LOOKUP).json()
    assert before["report_count"] == 1

    # 2. Expired: every API route is 403; /health, /license and the app page stay open.
    r = client.post("/license", content=EXPIRED, headers=JSON)
    assert r.status_code == 200 and r.json()["status"] == "expired"
    for method, path in GATED:
        resp = client.request(method, path, json={} if method == "POST" else None)
        assert (resp.status_code, resp.json()) == (403, {"error": "LICENSE_EXPIRED"}), (method, path)
    assert client.get("/health").status_code == 200
    assert client.get("/license").json()["status"] == "expired"
    assert client.get("/").status_code == 200  # the app loads and shows its expired screen

    # 3. Long licence: back at once on the same running app, data intact.
    r = client.post("/license", content=LONG, headers=JSON)
    assert r.status_code == 200 and r.json()["status"] == "valid"
    after = client.get("/lookup", params=LOOKUP).json()
    assert after["report_count"] == before["report_count"] == 1

    # 4. One digit changed (expiry 2027 -> 2028, as the README's sed does): refused, licence kept.
    tampered = LONG.decode().replace("2027-01-31", "2028-01-31")
    assert sum(a != b for a, b in zip(tampered, LONG.decode())) == 1
    r = client.post("/license", content=tampered.encode(), headers=JSON)
    assert (r.status_code, r.json()) == (400, {"error": "INVALID_LICENSE"})
    lic = client.get("/license").json()
    assert lic["status"] == "valid" and lic["expires_at"] == json.loads(LONG)["expires_at"]
    assert client.get("/lookup", params=LOOKUP).json()["report_count"] == 1
