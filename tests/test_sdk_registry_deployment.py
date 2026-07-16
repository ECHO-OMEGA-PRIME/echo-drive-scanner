"""Tests for the governed Drive Scanner SDK registry deployment artifact."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from tools.sdk_registry_deployment import (
    CAPABILITY_METADATA,
    load_manifest,
    render_migration,
    validate_manifest,
)

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "contracts" / "sdk_capability_schemas.json"


def test_manifest_covers_complete_governed_lifecycle() -> None:
    data = load_manifest(MANIFEST)
    validate_manifest(data)

    assert len(data["capabilities"]) == 13
    assert set(data["capabilities"]) == set(CAPABILITY_METADATA)
    assert {
        "echo.drivescan.health",
        "echo.drivescan.scan",
        "echo.drivescan.scan_status",
        "echo.drivescan.stages",
        "echo.drivescan.cancel",
        "echo.drivescan.storage",
    }.issubset(data["capabilities"])


def test_all_boundary_schemas_reject_unknown_fields() -> None:
    data = load_manifest(MANIFEST)
    for capability, contract in data["capabilities"].items():
        assert contract["input_schema"]["additionalProperties"] is False, capability
        assert contract["output_schema"]["additionalProperties"] is False, capability


def test_proposals_remain_read_only() -> None:
    data = load_manifest(MANIFEST)
    proposal = data["capabilities"]["echo.drivescan.proposals"]
    assert proposal["method"] == "GET"
    assert proposal["output_schema"]["properties"]["queue_supported"]["const"] is False
    rendered = render_migration(data)
    assert "echo.prompts.add" not in rendered
    assert "queue=true" not in rendered


def test_mutations_are_tier_two_and_reads_are_not_over_tiered() -> None:
    data = load_manifest(MANIFEST)
    validate_manifest(data)
    assert CAPABILITY_METADATA["echo.drivescan.scan"]["tier"] == 2
    assert CAPABILITY_METADATA["echo.drivescan.cancel"]["tier"] == 2
    for capability, contract in data["capabilities"].items():
        tier = CAPABILITY_METADATA[capability]["tier"]
        if contract["method"] == "POST":
            assert tier >= 2
        else:
            assert tier <= 1


def test_rendered_migration_is_deterministic_and_idempotent() -> None:
    data = load_manifest(MANIFEST)
    first = render_migration(data)
    second = render_migration(json.loads(json.dumps(data)))

    assert first == second
    assert first.startswith("BEGIN;")
    assert first.rstrip().endswith("COMMIT;")
    assert first.count("ON CONFLICT (id) DO UPDATE SET") == 13
    assert "schema_version = EXCLUDED.schema_version" in first
    assert "health_status = 'amber'" in first
    assert "pending governed post-deployment invocation" in first


def test_scan_route_is_direct_and_no_stale_router_path_remains() -> None:
    data = load_manifest(MANIFEST)
    assert data["capabilities"]["echo.drivescan.scan"]["path"] == "/api/scan/start"
    migration = render_migration(data)
    assert "/sdk/drivescan/scan" not in migration
    assert "http://100.85.253.44:8460/api/scan/start" in migration


def test_cancel_contract_requires_auditable_reason() -> None:
    data = load_manifest(MANIFEST)
    schema = data["capabilities"]["echo.drivescan.cancel"]["input_schema"]
    assert set(schema["required"]) == {"scan_id", "reason"}
    assert schema["properties"]["reason"]["minLength"] == 20
    assert schema["properties"]["reason"]["maxLength"] == 500


def test_validation_rejects_unknown_fields_and_under_tiered_mutation() -> None:
    data = load_manifest(MANIFEST)
    invalid = copy.deepcopy(data)
    invalid["capabilities"]["echo.drivescan.health"]["input_schema"].pop("additionalProperties")
    with pytest.raises(ValueError, match="reject unknown fields"):
        validate_manifest(invalid)

    original = CAPABILITY_METADATA["echo.drivescan.cancel"]["tier"]
    CAPABILITY_METADATA["echo.drivescan.cancel"]["tier"] = 1
    try:
        with pytest.raises(ValueError, match="tier 2"):
            validate_manifest(data)
    finally:
        CAPABILITY_METADATA["echo.drivescan.cancel"]["tier"] = original
