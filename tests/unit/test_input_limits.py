"""Request body cap (16 KB, also for chunked bodies), CORS, log hygiene, startup salt check."""
import logging

import pytest
from fastapi.testclient import TestClient

import app.main as main

LIMIT = 16 * 1024


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite:///" + (tmp_path / "test.db").as_posix())
    with TestClient(main.app, raise_server_exceptions=False) as c:
        yield c


def padded(n_bytes: int) -> bytes:
    """A JSON object of exactly n_bytes bytes."""
    head, tail = b'{"note": "', b'"}'
    return head + b"a" * (n_bytes - len(head) - len(tail)) + tail


POST_ROUTES = ("/reports", "/challenges", "/license", "/demo/run", "/admin/reset")


@pytest.mark.parametrize("path", POST_ROUTES)
def test_body_over_the_cap_is_413_on_every_post_route(client, path):
    r = client.post(path, content=padded(LIMIT + 1), headers={"content-type": "application/json"})
    assert r.status_code == 413
    assert r.json() == {"error": "request_too_large"}


@pytest.mark.parametrize("path", ("/reports", "/challenges", "/license", "/demo/run"))   # the routes that read a body
def test_chunked_body_over_the_cap_is_413_too(client, path):
    def chunks():                       # no Content-Length header: the size is only known by counting
        body = padded(LIMIT + 1)
        for i in range(0, len(body), 1000):
            yield body[i:i + 1000]
    r = client.post(path, content=chunks(), headers={"content-type": "application/json"})
    assert r.status_code == 413
    assert r.json() == {"error": "request_too_large"}


def test_body_at_the_cap_is_not_413(client):
    r = client.post("/reports", content=padded(LIMIT), headers={"content-type": "application/json"})
    assert r.status_code != 413
    r = client.post("/reports", content=(lambda: (padded(LIMIT)[i:i + 1000] for i in range(0, LIMIT, 1000)))(),
                    headers={"content-type": "application/json"})
    assert r.status_code != 413


def test_a_normal_report_still_works(client):
    r = client.post("/reports", json={
        "report_id": "r1", "occurred_at": "2026-10-31T10:00:00+05:30", "reported_at": "2026-10-31T10:00:00+05:30",
        "reporter_id": "x", "ip_prefix": "10.0.0.0/24", "channel": "Phone call", "scam_type": "other",
        "identifier_type": "phone", "identifier_value": "+91 90000 12345", "pincode": "560102", "note": "",
        "has_screenshot": False, "amount_lost_inr": 0})
    assert r.status_code in (201, 400)          # 400 only if the date is outside the window; never 413
    assert r.status_code != 413


def test_no_cors_headers_are_ever_sent(client):
    for method, path in (("GET", "/lookup?type=phone&value=1930"), ("GET", "/health"), ("POST", "/reports"),
                         ("OPTIONS", "/reports"), ("OPTIONS", "/lookup")):
        r = client.request(method, path, headers={"origin": "https://evil.example",
                                                  "access-control-request-method": "POST"})
        assert not [h for h in r.headers if h.startswith("access-control-")], (method, path)
    assert client.options("/reports", headers={"origin": "https://evil.example",
                                               "access-control-request-method": "POST"}).status_code == 405


def test_the_request_log_never_holds_user_text(client, caplog):
    with caplog.at_level(logging.INFO, logger="scammap"):
        client.get("/%0aINJECTED%0dFORGED 200 0ms req=zzz")
        client.get("/lookup?type=phone&value=9876543210")
        client.get("/health")
    text = "\n".join(r.getMessage() for r in caplog.records)
    assert "INJECTED" not in text and "FORGED" not in text
    assert "9876543210" not in text
    for r in caplog.records:
        assert "\n" not in r.getMessage() and "\r" not in r.getMessage()
    assert "GET /lookup 200" in text and "GET /health 200" in text    # known routes still logged


def test_production_refuses_to_start_without_a_salt(monkeypatch):
    assert main.check_salt_for_database("sqlite:///./dev.db", "") == "dev-salt-insecure"   # local dev may default
    with pytest.raises(RuntimeError):
        main.check_salt_for_database("postgresql+psycopg://u:p@h/db", "")
    with pytest.raises(RuntimeError):
        main.check_salt_for_database("postgres://u:p@h/db", "short")
    assert main.check_salt_for_database("postgres://u:p@h/db", "a-long-enough-salt") == "a-long-enough-salt"


# ---- malformed JSON text must never become a 500 ----------------------------------------------
import json  # noqa: E402
from datetime import datetime, timedelta, timezone  # noqa: E402

_IST = timezone(timedelta(hours=5, minutes=30))


def _report(**kw):
    now = datetime.now(_IST).isoformat()
    body = {"report_id": "rs1", "occurred_at": now, "reported_at": now, "reporter_id": "r", "ip_prefix": "1.2.3.0/24",
            "channel": "Phone call", "scam_type": "other", "identifier_type": "url",
            "identifier_value": "evil.example/x", "pincode": "560102", "note": "hello there friend"}
    body.update(kw)
    return json.dumps(body).encode()          # ensure_ascii: a lone surrogate travels as the text \ud800


def test_lone_surrogates_never_cause_a_500(client):
    H = {"content-type": "application/json"}
    assert client.post("/reports", content=_report(identifier_value="a\ud800b.example"), headers=H).status_code == 400
    assert client.post("/reports", content=_report(reporter_id="a\ud800"), headers=H).status_code == 201
    assert client.post("/reports", content=_report(note="a\ud800b", report_id="rs2"), headers=H).status_code == 201
    assert client.post("/reports", content=_report(ip_prefix="\udfff", report_id="rs3"), headers=H).status_code == 201
    r = client.post("/challenges", content=json.dumps({"identifier_type": "url", "identifier_value": "evil.example/x",
                                                      "claimant_name": "a\ud800"}).encode(), headers=H)
    assert r.status_code == 201
    assert client.get("/health").status_code == 200


def test_paired_surrogates_are_kept(client):
    # an emoji arrives as a surrogate pair; json parses it into one character and it must survive
    H = {"content-type": "application/json"}
    assert client.post("/reports", content=_report(note="scam \U0001F6A8", report_id="rs4"), headers=H).status_code == 201


def test_deeply_nested_json_is_a_400_not_a_crash(client):
    H = {"content-type": "application/json"}
    assert client.post("/reports", content=b"[" * 10000, headers=H).status_code == 400
    assert client.post("/challenges", content=b'{"a":' * 3000, headers=H).status_code == 400
    assert client.get("/health").status_code == 200


def test_the_api_schema_page_is_not_served(client):
    assert client.get("/openapi.json").status_code == 404
