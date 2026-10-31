"""GET / serves the web app and stays reachable when the licence is not valid
(BUILD_SPEC 9.3: the app always loads, so it can show the expired screen)."""
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import app.main as main

ROOT = Path(__file__).resolve().parents[2]
INDEX = ROOT / "app" / "static" / "index.html"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite:///" + (tmp_path / "test.db").as_posix())
    with TestClient(main.app) as c:
        yield c


def install_expired(client):
    lic = json.loads((ROOT / "licenses" / "expired.json").read_text(encoding="utf-8"))
    assert client.post("/license", json=lic).status_code == 200
    assert client.get("/license").json()["status"] == "expired"


def test_index_is_the_web_app(client):
    r = client.get("/")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/html")
    assert r.content == INDEX.read_bytes()


def test_index_loads_when_licence_expired(client):
    install_expired(client)
    assert client.get("/lookup", params={"type": "phone", "value": "1930"}).status_code == 403
    r = client.get("/")
    assert r.status_code == 200
    assert r.content == INDEX.read_bytes()


def test_only_get_index_is_exempt(client):
    install_expired(client)
    r = client.post("/")
    assert r.status_code == 403
    assert r.json() == {"error": "LICENSE_EXPIRED"}
