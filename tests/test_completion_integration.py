"""Completion-level integration tests for the production scanner pipeline."""

from __future__ import annotations

import asyncio
from pathlib import Path

import scanner as scanner_module
from config import ScanConfig
from intelligence.classifier import ClassificationPipeline
from intelligence.engine_client import EngineClient
from scanner import IntelligenceScanOrchestrator
from storage.db import IntelligenceDB
from storage.models import ClassificationTier, FileSample


def test_local_classifier_emits_deterministic_persistable_result() -> None:
    """No external engine must still yield one truthful deterministic classification."""
    client = EngineClient()
    client._enabled = False
    pipeline = ClassificationPipeline(client)
    sample = FileSample(
        path=r"C:\work\service.py",
        filename="service.py",
        extension=".py",
        size_bytes=128,
        mime_type="text/x-python",
        keywords=["fastapi", "router", "service"],
        detected_domain="PYTHON",
        domain_confidence=0.95,
    )

    result = asyncio.run(pipeline.classify_file(sample, file_id=7, scan_id=11))

    assert result.tier == ClassificationTier.TIER1_FAST
    assert result.primary_domain == "PYTHON"
    assert result.primary_engine == "LOCAL_RULES_V1"
    assert len(result.classifications) == 1
    classification = result.classifications[0]
    assert classification.file_id == 7
    assert classification.scan_id == 11
    assert classification.engine_id == "LOCAL_RULES_V1"
    assert classification.domain == "PYTHON"
    assert classification.score == 0.95
    assert classification.determinism_hash
    assert len(classification.determinism_hash or "") == 64


def test_local_classifier_is_deterministic_for_same_evidence() -> None:
    """The same normalized evidence must produce the same classification digest."""
    client = EngineClient()
    client._enabled = False
    pipeline = ClassificationPipeline(client)
    sample = FileSample(
        path=r"C:\work\records.json",
        filename="records.json",
        extension=".json",
        size_bytes=64,
        mime_type="application/json",
        keywords=["records", "schema"],
        detected_domain="DATA",
        domain_confidence=0.8,
    )

    first = asyncio.run(pipeline.classify_file(sample, file_id=1, scan_id=2))
    second = asyncio.run(pipeline.classify_file(sample, file_id=1, scan_id=2))

    assert first.classifications[0].determinism_hash == second.classifications[0].determinism_hash


def test_end_to_end_scan_uses_local_fallback_and_truthful_degradation(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """A real scan without the engine must classify files and report degradation."""
    source = tmp_path / "project"
    source.mkdir()
    (source / "service.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n\n@app.get('/health')\ndef health():\n    return {'status': 'ok'}\n",
        encoding="utf-8",
    )
    (source / "records.json").write_text('{"records": [{"id": 1}]}', encoding="utf-8")
    (source / "notes.md").write_text("# Build notes\nTODO: add tests\n", encoding="utf-8")
    (source / "duplicate-a.txt").write_text("duplicate evidence", encoding="utf-8")
    (source / "duplicate-b.txt").write_text("duplicate evidence", encoding="utf-8")

    database = IntelligenceDB(tmp_path / "scan.db")
    orchestrator = IntelligenceScanOrchestrator(ScanConfig(max_depth=8), db=database)
    monkeypatch.setattr(scanner_module, "ENGINE_RUNTIME_URL", "")

    scan_id = asyncio.run(orchestrator.run_scan([str(source)], profile="INTEL_FAST"))

    scan = database.get_scan(scan_id)
    assert scan is not None
    assert scan.total_files >= 5
    assert scan.files_classified >= 5
    assert scan.status in {"completed_with_warnings", "degraded"}

    files = database.list_files(scan_id=scan_id, limit=100)
    assert len(files) >= 5
    classifications = [
        classification
        for file_record in files
        if file_record.id is not None
        for classification in database.get_classifications(file_record.id)
    ]
    assert len(classifications) >= 5
    assert {classification.engine_id for classification in classifications} == {"LOCAL_RULES_V1"}
    assert all(classification.determinism_hash for classification in classifications)

    stages = {stage["stage"]: stage for stage in database.get_scan_stages(scan_id)}
    assert stages["classification"]["status"] == "degraded"
    assert (
        "local" in (stages["classification"].get("detail") or "").lower()
        or "engine" in (stages["classification"].get("detail") or "").lower()
    )
    assert stages["discovery"]["status"] == "passed"
    assert stages["deduplication"]["status"] == "passed"


def test_engine_batch_adapter_uses_current_model_contract(monkeypatch) -> None:
    """The repaired EngineClient batch adapter must return current ClassificationResult models."""
    from storage.models import DomainResult, EngineResult

    client = EngineClient()
    client._enabled = True

    async def fake_query_domain(domain: str, query: str, mode: str = "FAST") -> DomainResult:
        del query, mode
        return DomainResult(
            domain=domain,
            results=[
                EngineResult(
                    engine_id="TEST_ENGINE",
                    domain=domain,
                    domain_label=domain,
                    topic="test",
                    conclusion="classified",
                    confidence="DEFENSIBLE",
                    score=0.9,
                    mode="FAST",
                )
            ],
            total_engines=1,
        )

    monkeypatch.setattr(client, "query_domain", fake_query_domain)
    sample = FileSample(
        path=r"C:\work\module.py",
        filename="module.py",
        extension=".py",
        size_bytes=32,
        mime_type="text/x-python",
        keywords=["module"],
        detected_domain="PYTHON",
        domain_confidence=0.9,
    )

    results = asyncio.run(client.batch_classify([sample]))

    assert len(results) == 1
    assert results[0].file_path == sample.path
    assert results[0].primary_domain == "PYTHON"
    assert results[0].primary_engine == "TEST_ENGINE"
    assert results[0].classifications[0].engine_id == "TEST_ENGINE"
