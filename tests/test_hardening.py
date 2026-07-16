"""Tests for production hardening: security headers, error handling,
path-scope enforcement, and gated recommendation execution."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config import validate_scan_path  # noqa: E402
from dashboard.server import SECURITY_HEADERS, create_app  # noqa: E402

PROTECTED_TARGET = r"C:\Windows\Temp" if os.name == "nt" else "/etc/ssh"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.delenv("DRIVESCAN_ALLOW_FILE_ACTIONS", raising=False)
    app = create_app(db_path=tmp_path / "test.db")
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


def test_security_headers_on_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    for header in SECURITY_HEADERS:
        assert header in resp.headers, f"missing security header {header}"
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"


def test_health_reports_status(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] in ("healthy", "degraded")


def test_exception_handler_returns_clean_json_500(tmp_path):
    app = create_app(db_path=tmp_path / "boom.db")

    @app.get("/boom")
    async def boom():
        raise RuntimeError("sensitive-internal-detail")

    with TestClient(app, raise_server_exceptions=False) as c:
        resp = c.get("/boom")
    assert resp.status_code == 500
    payload = resp.json()
    assert payload["error"] == "internal_error"
    assert "sensitive-internal-detail" not in resp.text


def test_http_exceptions_not_swallowed(client):
    resp = client.get("/api/files/999999")
    assert resp.status_code == 404


def test_validate_scan_path_rejects_protected():
    ok, reason = validate_scan_path(PROTECTED_TARGET)
    assert not ok
    assert "protected" in reason


def test_validate_scan_path_rejects_outside_allowlist(tmp_path):
    ok, reason = validate_scan_path(str(tmp_path), allowlist=[str(tmp_path / "only_here")])
    assert not ok
    assert "allowlist" in reason


def test_validate_scan_path_accepts_allowed(tmp_path):
    ok, reason = validate_scan_path(str(tmp_path))
    assert ok, reason


def test_execute_recommendation_403_when_actions_disabled(client):
    resp = client.post("/api/recommendations/1/execute")
    assert resp.status_code == 403
    payload = resp.json()
    assert payload["error"] == "action_disabled"


def test_execute_recommendation_403_without_confirm(client, monkeypatch):
    monkeypatch.setenv("DRIVESCAN_ALLOW_FILE_ACTIONS", "1")
    resp = client.post("/api/recommendations/1/execute", json={})
    assert resp.status_code == 403
    assert resp.json()["error"] == "action_disabled"


def test_scan_start_rejects_protected_path(client):
    resp = client.post("/api/scan/start", json={"paths": [PROTECTED_TARGET]})
    assert resp.status_code == 400
    payload = resp.json()
    assert payload["error"] == "path_rejected"
    assert payload["path_id"] == "redacted"
    assert PROTECTED_TARGET not in resp.text
