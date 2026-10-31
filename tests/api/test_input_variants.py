"""Manual request-shape probe using FastAPI's in-process TestClient.

Run: python tests/api/test_input_variants.py
Uses app.main:app, a synthetic TRUST_SALT, and a temporary SQLite database.
Results are written to INPUT_VARIANTS.txt beside this script. No reset endpoint is called.
"""
from __future__ import annotations

import copy
import json
import os
import sys
import tempfile
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Iterator


IST = timezone(timedelta(hours=5, minutes=30))
PHONE_BASELINE = "+91 90000 11223"
REPORTER_ID = "r_input_variants_synthetic"
IP_PREFIX = "10.9.8.7"
NOTE = "synthetic input variant report"


@contextmanager
def test_client_context() -> Iterator[tuple[object, object]]:
    """Set CI-style test env before app.main reads it, and isolate its database."""
    keys = ("TRUST_SALT", "DATABASE_URL", "ALLOW_RESET")
    old_env = {key: os.environ.get(key) for key in keys}
    with tempfile.TemporaryDirectory(prefix="scammap-input-variants-") as temp_dir:
        db_path = (Path(temp_dir) / "input-variants.sqlite").as_posix()
        os.environ["TRUST_SALT"] = "input-variants-test-" + uuid.uuid4().hex
        os.environ["DATABASE_URL"] = "sqlite:///" + db_path
        os.environ["ALLOW_RESET"] = "0"
        try:
            project_root = str(Path(__file__).resolve().parents[2])
            if project_root not in sys.path:
                sys.path.insert(0, project_root)
            from fastapi.testclient import TestClient
            import app.main as main_app

            with TestClient(main_app.app) as client:
                yield client, main_app
        finally:
            for key, value in old_env.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value


def request(client: object, method: str, path: str, body: dict | None = None) -> tuple[int, dict, str, dict]:
    response = client.request(method, path, json=body)  # type: ignore[attr-defined]
    text = response.text
    try:
        parsed = response.json() if text else {}
    except json.JSONDecodeError:
        parsed = {}
    return response.status_code, parsed if isinstance(parsed, dict) else {}, text, dict(response.headers)


def response_body_text(parsed: dict, raw: str, private_test_values: tuple[str, ...]) -> tuple[str, bool]:
    if parsed:
        rendered = json.dumps(parsed, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    else:
        rendered = raw or "<empty body>"
    leaked = False
    for value in private_test_values:
        if value and value in rendered:
            rendered = rendered.replace(value, "[REDACTED: private test input echoed]")
            leaked = True
    return rendered, leaked


def make_cases(server_time: datetime) -> list[dict]:
    local = server_time.astimezone(IST).replace(microsecond=0)
    utc = server_time.astimezone(timezone.utc).replace(microsecond=0)
    with_millis = local.replace(microsecond=123000)
    return [
        {"name": "occurred_at: UTC Z", "field": "occurred_at", "value": utc.strftime("%Y-%m-%dT%H:%M:%SZ"), "accept": True, "why": "Z is a valid ISO 8601 UTC offset."},
        {"name": "occurred_at: +05:30", "field": "occurred_at", "value": local.isoformat(timespec="seconds"), "accept": True, "why": "Explicit India offset."},
        {"name": "occurred_at: +0530", "field": "occurred_at", "value": local.strftime("%Y-%m-%dT%H:%M:%S%z"), "accept": True, "why": "Compact ISO 8601 offset."},
        {"name": "occurred_at: no timezone", "field": "occurred_at", "value": local.replace(tzinfo=None).isoformat(timespec="seconds"), "accept": True, "why": "The spec says naive times are read as IST."},
        {"name": "occurred_at: space instead of T", "field": "occurred_at", "value": local.isoformat(sep=" ", timespec="seconds"), "accept": True, "why": "Common ISO-style datetime separator; offset is explicit."},
        {"name": "occurred_at: milliseconds", "field": "occurred_at", "value": with_millis.isoformat(timespec="milliseconds"), "accept": True, "why": "ISO 8601 fractional seconds."},
        {"name": "occurred_at: date only", "field": "occurred_at", "value": local.date().isoformat(), "accept": False, "why": "A report occurrence needs a time; date-only has no time or offset."},
        {"name": "phone: +91 with spaces", "field": "identifier_value", "type": "phone", "value": "+91 98765 43210", "accept": True, "why": "Documented phone test vector."},
        {"name": "phone: leading zero", "field": "identifier_value", "type": "phone", "value": "09876543210", "accept": True, "why": "Documented phone test vector."},
        {"name": "phone: digits only", "field": "identifier_value", "type": "phone", "value": "9876543210", "accept": True, "why": "Documented phone test vector."},
        {"name": "phone: brackets and dashes", "field": "identifier_value", "type": "phone", "value": "(+91) 98765-43210", "accept": True, "why": "Documented phone test vector."},
        {"name": "phone: country code without plus", "field": "identifier_value", "type": "phone", "value": "91 9876543210", "accept": True, "why": "The spec strips a 91 country prefix when the length matches."},
        {"name": "phone: Bengaluru landline", "field": "identifier_value", "type": "phone", "value": "+91 80 4100 2233", "accept": True, "why": "Documented landline test vector."},
        {"name": "phone: toll-free", "field": "identifier_value", "type": "phone", "value": "1800 1600", "accept": True, "why": "Documented toll-free test vector."},
        {"name": "upi: upper case", "field": "identifier_value", "type": "upi", "value": "FRESHBAKES@OKAXIS", "accept": True, "why": "UPI normalization lowercases the value."},
        {"name": "upi: dotted handle", "field": "identifier_value", "type": "upi", "value": "name.surname@ybl", "accept": True, "why": "Plausible VPA handle; accepting common handle punctuation is useful."},
        {"name": "upi: payment URI", "field": "identifier_value", "type": "upi", "value": "upi://pay?pa=friend@ybl", "accept": True, "why": "The spec says to extract and validate the pa value."},
        {"name": "url: http scheme", "field": "identifier_value", "type": "url", "value": "http://link.example/path", "accept": True, "why": "The spec accepts http and normalizes it to https."},
        {"name": "url: www without scheme", "field": "identifier_value", "type": "url", "value": "www.link.example/path", "accept": True, "why": "The spec adds https when no scheme is present."},
        {"name": "url: defanged hxxps", "field": "identifier_value", "type": "url", "value": "hxxps://x[.]example/path", "accept": True, "why": "The spec de-fangs hxxp and [.] before validation."},
        {"name": "sender_id: VM prefix", "field": "identifier_value", "type": "sender_id", "value": "VM-HDFCBK", "accept": True, "why": "Documented sender test vector."},
        {"name": "sender_id: AD prefix and suffix", "field": "identifier_value", "type": "sender_id", "value": "AD-HDFCBK-S", "accept": True, "why": "The spec accepts a two-letter prefix and one-letter suffix."},
        {"name": "sender_id: lower case", "field": "identifier_value", "type": "sender_id", "value": "vm-hdfcbk", "accept": True, "why": "Sender IDs are normalized to uppercase."},
        {"name": "pincode: JSON number", "field": "pincode", "value": 560102, "accept": True, "why": "A registered pincode should accept an integer JSON representation."},
        {"name": "identifier_type: upper case", "field": "identifier_type", "value": "PHONE", "accept": True, "why": "Case-insensitive enum handling is robust for external test tools."},
        {"name": "channel: unknown value", "field": "channel", "value": "Synthetic chat channel", "accept": True, "why": "The spec maps unknown channels to Something else."},
        {"name": "scam_type: unknown value", "field": "scam_type", "value": "synthetic-unknown-type", "accept": True, "why": "The spec accepts unknown types as other."},
        {"name": "extra unknown field", "field": "unused_variant_field", "value": "synthetic-extra", "accept": True, "why": "Unknown optional metadata should not invalidate an otherwise valid report."},
        {"name": "missing reported_at", "field": "reported_at", "value": "(omitted)", "remove": True, "accept": True, "why": "Only occurred_at is required as a timestamp."},
        {"name": "missing note", "field": "note", "value": "(omitted)", "remove": True, "accept": True, "why": "Note text is optional."},
        {"name": "missing reporter_id", "field": "reporter_id", "value": "(omitted)", "remove": True, "accept": True, "why": "The spec defines a network-prefix fallback when reporter_id is missing."},
    ]


def run_variants(client: object, main_app: object) -> int:
    private_values = (REPORTER_ID, IP_PREFIX, NOTE)
    lines = [
        "Community Scam Map in-process input-variant probe",
        f"Timestamp: {datetime.now(IST).isoformat(timespec='seconds')} IST",
        "Target: app.main:app via FastAPI TestClient",
        "Environment: synthetic TRUST_SALT, temporary SQLite database, ALLOW_RESET=0.",
        "No /admin/reset call was made. All report inputs are synthetic test data.",
        "Response bodies are recorded; private test input is redacted if a response echoes it.",
        "The defanged URL uses .example to comply with the synthetic-data rule.",
        "Each variant changes one named field from a valid baseline for that identifier type; report_id is unique per request.",
        "",
    ]
    failed = False
    try:
        health_status, _, _, health_headers = request(client, "GET", "/health")
        date_header = next((v for k, v in health_headers.items() if k.casefold() == "date"), None)
        if health_status != 200:
            raise RuntimeError("in-process health check failed")
        if date_header:
            server_time = parsedate_to_datetime(date_header)
            if server_time.tzinfo is None:
                server_time = server_time.replace(tzinfo=timezone.utc)
        else:
            server_time = main_app.clock.now()  # type: ignore[attr-defined]
            lines.append("TestClient health response had no Date header; used the app clock for timestamps.")
        occurred = server_time.astimezone(IST).isoformat(timespec="seconds")
        run_marker = uuid.uuid4().hex[:12]

        base = {
            "report_id": "input-variant-" + run_marker + "-baseline",
            "occurred_at": occurred,
            "reported_at": occurred,
            "reporter_id": REPORTER_ID,
            "ip_prefix": IP_PREFIX,
            "channel": "Phone call",
            "scam_type": "digital-arrest",
            "identifier_type": "phone",
            "identifier_value": PHONE_BASELINE,
            "pincode": "560102",
            "locality": "HSR Layout",
            "city": "Bengaluru",
            "note": NOTE,
            "has_screenshot": False,
            "amount_lost_inr": 0,
        }

        def send_case(name: str, body: dict, expected_accept: bool, why: str) -> tuple[int, dict]:
            nonlocal failed
            status, parsed, raw, _ = request(client, "POST", "/reports", body)
            rendered, echoed_private_value = response_body_text(parsed, raw, private_values)
            accept_state = "accept" if expected_accept else "may reject"
            lines.append(f"{name} | expectation={accept_state} | HTTP {status} | body={rendered}")
            if echoed_private_value:
                lines.append("  PRIVACY FAILURE: response echoed private test input; value redacted.")
                failed = True
            if expected_accept and status != 201:
                lines.append(f"  400/other where acceptance is expected: {why}")
            if not expected_accept and status == 201:
                lines.append(f"  Accepted despite conservative expectation: {why}")
            failed |= (expected_accept and status != 201) or (not expected_accept and status == 201)
            return status, parsed

        baseline_status, _ = send_case("BASELINE valid report", base, True, "Baseline should be accepted.")
        failed |= baseline_status != 201
        cases = make_cases(server_time)
        acceptance_misses = []
        identifier_baselines = {
            "phone": PHONE_BASELINE,
            "upi": "sample@ybl",
            "url": "https://base.example/path",
            "sender_id": "ABCDEF",
        }
        for index, case in enumerate(cases, start=1):
            body = copy.deepcopy(base)
            body["report_id"] = f"input-variant-{run_marker}-{index:02d}"
            kind = case.get("type", "phone")
            body["identifier_type"] = kind
            body["identifier_value"] = identifier_baselines[kind]
            field = case["field"]
            if case.get("remove"):
                body.pop(field, None)
            else:
                body[field] = case["value"]
            if case.get("type"):
                body["identifier_type"] = case["type"]
            status, _ = send_case(case["name"], body, case["accept"], case["why"])
            if status == 400 and case["accept"]:
                acceptance_misses.append(case)
            if status not in (201, 400, 429):
                failed = True

        lines.extend(["", "400 responses judged acceptable:"])
        if acceptance_misses:
            for case in acceptance_misses:
                lines.append(f"- {case['name']}: {case['field']}={case['value']!r} — {case['why']}")
        else:
            lines.append("- None.")
        if any(case["name"] == "occurred_at: date only" and case["accept"] is False for case in cases):
            lines.append("Date-only occurred_at is not in the acceptable-400 list; it lacks a time and offset.")
    except Exception as exc:
        lines.append(f"CHECK ERROR: {type(exc).__name__}; no request details recorded.")
        failed = True

    lines.extend(["", f"Overall: {'REVIEW' if failed else 'COMPLETED'}"])
    output = "\n".join(lines) + "\n"
    Path(__file__).with_name("INPUT_VARIANTS.txt").write_text(output, encoding="utf-8")
    print(output, end="")
    return 1 if failed else 0


def main() -> int:
    try:
        with test_client_context() as (client, main_app):
            return run_variants(client, main_app)
    except Exception as exc:
        detail = f"; missing module={exc.name}" if isinstance(exc, ModuleNotFoundError) else ""
        output = "\n".join([
            "Community Scam Map in-process input-variant probe",
            f"Timestamp: {datetime.now(IST).isoformat(timespec='seconds')} IST",
            "Target: app.main:app via FastAPI TestClient",
            "No report request details recorded.",
            f"CHECK ERROR: {type(exc).__name__}{detail}",
            "",
            "Overall: REVIEW",
            "",
        ])
        Path(__file__).with_name("INPUT_VARIANTS.txt").write_text(output, encoding="utf-8")
        print(output, end="")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
