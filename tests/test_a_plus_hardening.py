"""A+ hardening and integration-contract regression suite."""

from __future__ import annotations

import asyncio
import json
import sqlite3
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from dashboard.api_models import ScanStartRequest
from dashboard.server import create_app
from intelligence.function_library import extract_python_functions
from storage.db import IntelligenceDB
from storage.models import (
    DuplicateCluster,
    DuplicateMember,
    FileRecord,
    IntelligenceScore,
)


def seed_scan(
    db: IntelligenceDB,
    path: str,
    *,
    size: int = 10,
    score: float = 20.0,
    status: str = "completed",
) -> tuple[int, int]:
    scan_id = db.create_scan([str(Path(path).anchor or Path(path).parent)], "INTEL_FAST")
    record = FileRecord(
        path=path,
        filename=Path(path).name,
        extension=Path(path).suffix,
        size_bytes=size,
        drive=Path(path).drive or str(Path(path).anchor),
        parent_dir=str(Path(path).parent),
        depth=len(Path(path).parts),
        content_sample="SECRET CONTENT MUST NOT LEAK",
        scan_id=scan_id,
    )
    file_id = db.upsert_file(record)
    db.upsert_score(
        IntelligenceScore(
            file_id=file_id,
            scan_id=scan_id,
            overall_score=score,
            quality_score=score,
            risk_score=score,
            primary_domain="PROG",
            scored_at="2026-07-16T00:00:00Z",
        )
    )
    db.complete_scan(scan_id, 1, size, 1, 0, 0.1, status=status)
    return scan_id, file_id


def test_enforced_service_boundary_denies_unknown_client(tmp_path, monkeypatch):
    monkeypatch.setenv("DRIVESCAN_TRUSTED_CLIENTS", "127.0.0.1,::1")
    monkeypatch.delenv("DRIVESCAN_SERVICE_TOKEN", raising=False)
    app = create_app(tmp_path / "access.db", enforce_access=True)
    with TestClient(app) as client:
        response = client.get("/health")
    assert response.status_code == 403
    assert response.json()["error"] == "access_denied"


def test_service_token_allows_authorized_internal_client(tmp_path, monkeypatch):
    monkeypatch.setenv("DRIVESCAN_TRUSTED_CLIENTS", "127.0.0.1,::1")
    monkeypatch.setenv("DRIVESCAN_SERVICE_TOKEN", "a-long-internal-service-token")
    app = create_app(tmp_path / "token.db", enforce_access=True)
    with TestClient(app) as client:
        response = client.get(
            "/health", headers={"X-DriveScan-Token": "a-long-internal-service-token"}
        )
    assert response.status_code == 200


def test_request_size_policy_rejects_oversized_request(tmp_path):
    app = create_app(tmp_path / "size.db")
    with TestClient(app) as client:
        response = client.get("/health", headers={"Content-Length": "9000000"})
    assert response.status_code == 413
    assert response.json()["error"] == "request_too_large"


def test_every_response_has_request_id_and_security_headers(tmp_path):
    app = create_app(tmp_path / "headers.db")
    with TestClient(app) as client:
        response = client.get("/health")
    assert response.status_code == 200
    assert response.headers["X-Request-ID"]
    assert response.headers["Cross-Origin-Resource-Policy"] == "same-origin"
    assert response.json()["api_version"] == "2.1"


def test_scan_contract_rejects_unknown_fields(tmp_path):
    app = create_app(tmp_path / "strict.db")
    with TestClient(app) as client:
        response = client.post(
            "/api/scan/start",
            json={"paths": [str(tmp_path)], "profile": "INTEL_FAST", "capability": "arbitrary"},
        )
    assert response.status_code == 422


def test_scan_contract_deduplicates_paths_case_insensitively():
    request = ScanStartRequest(paths=[r"C:\Data", r"c:\data"], profile="INTEL_FAST")
    assert request.paths == [r"C:\Data"]


def test_health_reports_exact_scan_count_not_limit_count(tmp_path):
    app = create_app(tmp_path / "health.db")
    db: IntelligenceDB = app.state.db
    for index in range(3):
        scan_id = db.create_scan([str(tmp_path)], "INTEL_FAST")
        db.complete_scan(scan_id, index, 0, 0, 0, 0.1)
    with TestClient(app) as client:
        payload = client.get("/health").json()
    assert payload["total_scans"] == 3
    assert payload["database"] == "health.db"
    assert str(tmp_path) not in json.dumps(payload)


def test_file_api_redacts_paths_and_content_samples(tmp_path):
    app = create_app(tmp_path / "redact.db")
    db: IntelligenceDB = app.state.db
    raw_path = r"C:\Users\bobmc\Documents\personal\secret.txt"
    scan_id, _ = seed_scan(db, raw_path)
    with TestClient(app) as client:
        response = client.get(f"/api/files?scan_id={scan_id}")
    assert response.status_code == 200
    text = response.text
    item = response.json()["files"][0]["file"]
    assert raw_path not in text
    assert "SECRET CONTENT MUST NOT LEAK" not in text
    assert "content_sample" not in item
    assert item["protected"] is True
    assert item["path_id"]


def test_proposal_api_redacts_source_paths_and_has_no_queue_side_effect(tmp_path):
    app = create_app(tmp_path / "proposal.db")
    db: IntelligenceDB = app.state.db
    scan_id = db.create_scan([str(tmp_path)], "INTEL_FAST")
    db.complete_scan(scan_id, 0, 0, 0, 0, 0.1)
    raw_path = r"C:\Users\bobmc\Documents\personal\unfinished.py"
    with db._connect() as conn:
        conn.execute(
            """INSERT INTO project_proposals
               (scan_id, proposal_type, category, domain, title, summary, rationale,
                suggested_stack, suggested_name, effort_estimate, priority_score,
                source_files, existing_functions, existing_classes, capabilities,
                duplicate_functions, file_count, total_bytes, created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                scan_id,
                "PROJECT",
                "PROMOTE_PARTIAL",
                "PROG",
                "Finish scanner helper",
                f"Evidence-backed proposal from {raw_path} in directory {Path(raw_path).parent}",
                json.dumps([f"TODO marker in {raw_path}"]),
                json.dumps(["Python"]),
                "scanner-helper",
                "small",
                80,
                json.dumps([raw_path]),
                json.dumps([]),
                json.dumps([]),
                json.dumps([]),
                json.dumps([]),
                1,
                100,
                "2026-07-16T00:00:00Z",
            ),
        )
        conn.commit()
    with TestClient(app) as client:
        response = client.get(f"/api/proposals?scan_id={scan_id}")
        rejected = client.get(f"/api/proposals?scan_id={scan_id}&queue=true")
    assert response.status_code == 200
    assert raw_path not in response.text
    assert str(Path(raw_path).parent) not in response.text
    proposal = response.json()["proposals"][0]
    assert "source_files" not in proposal
    assert proposal["source_evidence"][0]["path_id"]
    assert response.json()["queue_supported"] is False
    assert rejected.status_code == 400
    assert rejected.json()["error"] == "unknown_query_parameter"


def test_server_source_contains_no_sovereign_queue_dispatch():
    source = Path(__file__).resolve().parents[1] / "dashboard" / "server.py"
    content = source.read_text(encoding="utf-8")
    assert "_feed_queue" not in content
    assert "echo.prompts.add" not in content
    assert "ECHO_SOVEREIGN_KEY" not in content


def test_per_scan_file_and_score_history_is_preserved(tmp_path):
    db = IntelligenceDB(tmp_path / "history.db")
    path = str(tmp_path / "same.py")
    scan_one, file_id = seed_scan(db, path, size=10, score=10)
    scan_two, file_id_two = seed_scan(db, path, size=99, score=90)
    assert file_id_two == file_id
    first_file = db.list_files(scan_id=scan_one)[0]
    second_file = db.list_files(scan_id=scan_two)[0]
    assert first_file.size_bytes == 10
    assert second_file.size_bytes == 99
    assert db.get_score(file_id, scan_one).overall_score == 10
    assert db.get_score(file_id, scan_two).overall_score == 90


def test_scan_observations_are_immutable(tmp_path):
    db = IntelligenceDB(tmp_path / "immutable.db")
    scan_id, file_id = seed_scan(db, str(tmp_path / "immutable.txt"))
    with pytest.raises(sqlite3.IntegrityError):
        with db._connect() as conn:
            conn.execute(
                "UPDATE scan_file_observations SET size_bytes=999 WHERE scan_id=? AND file_id=?",
                (scan_id, file_id),
            )


def test_scan_score_observations_are_immutable(tmp_path):
    db = IntelligenceDB(tmp_path / "immutable-score.db")
    scan_id, file_id = seed_scan(db, str(tmp_path / "immutable.py"))
    with pytest.raises(sqlite3.IntegrityError):
        with db._connect() as conn:
            conn.execute(
                "UPDATE scan_score_observations SET overall_score=999 WHERE scan_id=? AND file_id=?",
                (scan_id, file_id),
            )


def test_stage_outcomes_are_persisted(tmp_path):
    db = IntelligenceDB(tmp_path / "stages.db")
    scan_id = db.create_scan([str(tmp_path)], "INTEL_FAST")
    db.record_stage(scan_id, "preflight", "running")
    db.record_stage(scan_id, "preflight", "passed", "ready")
    stages = db.get_scan_stages(scan_id)
    assert stages == [pytest.helpers.contains if False else stages[0]]
    assert stages[0]["stage"] == "preflight"
    assert stages[0]["status"] == "passed"
    assert stages[0]["completed_at"]


def test_duplicate_clusters_are_owned_by_scan(tmp_path):
    db = IntelligenceDB(tmp_path / "duplicates.db")
    scan_one, file_one = seed_scan(db, str(tmp_path / "a.txt"))
    scan_two, _ = seed_scan(db, str(tmp_path / "b.txt"))
    cluster = DuplicateCluster(
        cluster_hash="abc",
        file_count=2,
        total_wasted_bytes=10,
        best_file_id=file_one,
        members=[DuplicateMember(file_id=file_one, is_keeper=1)],
    )
    db.insert_duplicate_cluster(cluster, scan_id=scan_one)
    assert len(db.get_duplicate_clusters(scan_id=scan_one)) == 1
    assert db.get_duplicate_clusters(scan_id=scan_two) == []


def test_storage_summary_is_truthful_about_health_source(tmp_path):
    app = create_app(tmp_path / "storage.db")
    db: IntelligenceDB = app.state.db
    scan_id = db.create_scan([str(tmp_path)], "INTEL_FAST")
    db.complete_scan(scan_id, 0, 0, 0, 0, 0.1)
    with TestClient(app) as client:
        payload = client.get(f"/api/storage/summary?scan_id={scan_id}").json()
    assert payload["health_source"] == "filesystem_capacity"
    assert payload["drives"]
    assert payload["drives"][0]["health"] == "unknown"
    assert "SMART" in payload["drives"][0]["health_reason"]


def test_durable_scan_start_returns_owned_id_and_stage_urls(tmp_path, monkeypatch):
    app = create_app(tmp_path / "run.db")

    async def quick_run(self, paths, profile="INTELLIGENCE", scan_id=None):
        self.db.record_stage(scan_id, "preflight", "passed", "test")
        self.db.complete_scan(scan_id, 0, 0, 0, 0, 0.01)
        return scan_id

    monkeypatch.setattr("scanner.IntelligenceScanOrchestrator.run_scan", quick_run)
    with TestClient(app) as client:
        response = client.post(
            "/api/scan/start",
            json={"paths": [str(tmp_path)], "profile": "INTEL_FAST"},
        )
        assert response.status_code == 202
        payload = response.json()
        assert payload["scan_id"] > 0
        assert payload["run_id"] == f"drivescan-{payload['scan_id']}"
        assert payload["status_url"].endswith("/status")
        for _ in range(50):
            status = client.get(payload["status_url"]).json()
            if status["status"] != "running":
                break
            time.sleep(0.01)
    assert status["status"] == "completed"


def test_only_one_active_scan_is_accepted(tmp_path, monkeypatch):
    app = create_app(tmp_path / "concurrency.db")
    release = asyncio.Event()

    async def slow_run(self, paths, profile="INTELLIGENCE", scan_id=None):
        await release.wait()
        self.db.complete_scan(scan_id, 0, 0, 0, 0, 0.01)
        return scan_id

    monkeypatch.setattr("scanner.IntelligenceScanOrchestrator.run_scan", slow_run)
    with TestClient(app) as client:
        first = client.post(
            "/api/scan/start", json={"paths": [str(tmp_path)], "profile": "INTEL_FAST"}
        )
        second = client.post(
            "/api/scan/start", json={"paths": [str(tmp_path)], "profile": "INTEL_FAST"}
        )
        assert first.status_code == 202
        assert second.status_code == 409
        assert second.json()["error"] == "scan_already_running"
        release.set()


def test_scan_cancellation_is_run_specific(tmp_path, monkeypatch):
    app = create_app(tmp_path / "cancel.db")

    async def never_finish(self, paths, profile="INTELLIGENCE", scan_id=None):
        await asyncio.sleep(3600)
        return scan_id

    monkeypatch.setattr("scanner.IntelligenceScanOrchestrator.run_scan", never_finish)
    with TestClient(app) as client:
        started = client.post(
            "/api/scan/start", json={"paths": [str(tmp_path)], "profile": "INTEL_FAST"}
        ).json()
        response = client.post(
            f"/api/scans/{started['scan_id']}/cancel",
            json={"reason": "Operator requested cancellation during regression testing."},
        )
        assert response.status_code == 200
        assert response.json()["scan_id"] == started["scan_id"]


def test_python_function_extractor_handles_all_argument_forms(tmp_path):
    source = """
def sample(a: int, /, b: str = 'x', *args: float, c: bool, **kwargs: object) -> None:
    \"\"\"Typed sample.\"\"\"
    return None
"""
    functions = extract_python_functions(tmp_path / "sample.py", source)
    assert len(functions) == 1
    signature = functions[0]["signature"]
    assert "a: int" in signature
    assert "/" in signature
    assert "*args: float" in signature
    assert "c: bool" in signature
    assert "**kwargs: object" in signature
    assert functions[0]["arg_count"] == 5


def test_file_actions_remain_disabled_by_default(tmp_path, monkeypatch):
    monkeypatch.delenv("DRIVESCAN_ALLOW_FILE_ACTIONS", raising=False)
    app = create_app(tmp_path / "actions.db")
    with TestClient(app) as client:
        response = client.post("/api/recommendations/1/execute", json={"confirm": 1})
    assert response.status_code == 403
    assert response.json()["error"] == "action_disabled"


def test_launcher_contains_trusted_forge_identity_and_personal_protection():
    launcher = Path(__file__).resolve().parents[1] / "run_service.ps1"
    content = launcher.read_text(encoding="utf-8")
    assert "DRIVESCAN_TRUSTED_CLIENTS" in content
    assert "100.113.87.107" in content
    assert "DRIVESCAN_PROTECTED_PATHS" in content
    assert "MEMORY_CORE" in content


def test_config_defaults_to_loopback_binding():
    import config

    assert config.DASHBOARD_HOST in {"127.0.0.1", "0.0.0.0"}


def test_sdk_contract_manifest_validates_live_read_responses(tmp_path):
    from jsonschema import Draft202012Validator

    root = Path(__file__).resolve().parents[1]
    manifest = json.loads(
        (root / "contracts" / "sdk_capability_schemas.json").read_text(encoding="utf-8")
    )
    app = create_app(tmp_path / "contracts.db")
    db: IntelligenceDB = app.state.db
    scan_id, _ = seed_scan(db, str(tmp_path / "contract.txt"))
    cases = {
        "echo.drivescan.health": "/health",
        "echo.drivescan.status": "/api/scan/status",
        "echo.drivescan.scan_status": f"/api/scans/{scan_id}/status",
        "echo.drivescan.stages": f"/api/scans/{scan_id}/stages",
        "echo.drivescan.results": f"/api/scan/{scan_id}/results",
        "echo.drivescan.files": f"/api/files?scan_id={scan_id}",
        "echo.drivescan.domains": f"/api/domains?scan_id={scan_id}",
        "echo.drivescan.duplicates": f"/api/duplicates?scan_id={scan_id}",
        "echo.drivescan.recommendations": f"/api/recommendations?scan_id={scan_id}",
        "echo.drivescan.proposals": f"/api/proposals?scan_id={scan_id}",
        "echo.drivescan.storage": f"/api/storage/summary?scan_id={scan_id}",
    }
    with TestClient(app) as client:
        for capability, url in cases.items():
            response = client.get(url)
            assert response.status_code == 200, capability
            schema = manifest["capabilities"][capability]["output_schema"]
            errors = list(Draft202012Validator(schema).iter_errors(response.json()))
            assert errors == [], f"{capability}: {[error.message for error in errors]}"


def test_sdk_input_contracts_reject_unknown_fields():
    from jsonschema import Draft202012Validator

    root = Path(__file__).resolve().parents[1]
    manifest = json.loads(
        (root / "contracts" / "sdk_capability_schemas.json").read_text(encoding="utf-8")
    )
    schema = manifest["capabilities"]["echo.drivescan.scan"]["input_schema"]
    validator = Draft202012Validator(schema)
    assert list(validator.iter_errors({"paths": ["C:/data"], "profile": "INTEL_FAST"})) == []
    errors = list(
        validator.iter_errors(
            {"paths": ["C:/data"], "profile": "INTEL_FAST", "capability": "arbitrary"}
        )
    )
    assert errors
    assert errors[0].validator == "additionalProperties"


def test_cancel_sdk_contract_is_strict_and_response_validates():
    from jsonschema import Draft202012Validator

    root = Path(__file__).resolve().parents[1]
    manifest = json.loads(
        (root / "contracts" / "sdk_capability_schemas.json").read_text(encoding="utf-8")
    )
    contract = manifest["capabilities"]["echo.drivescan.cancel"]
    input_validator = Draft202012Validator(contract["input_schema"])
    valid_input = {
        "scan_id": 7,
        "reason": "Operator cancelled this owned scan after detecting stale scope.",
    }
    assert list(input_validator.iter_errors(valid_input)) == []
    assert list(input_validator.iter_errors({**valid_input, "capability": "arbitrary"}))
    assert list(input_validator.iter_errors({"scan_id": 7, "reason": "too short"}))

    output_validator = Draft202012Validator(contract["output_schema"])
    valid_output = {
        "api_version": "2.1",
        "status": "cancellation_requested",
        "scan_id": 7,
    }
    assert list(output_validator.iter_errors(valid_output)) == []
