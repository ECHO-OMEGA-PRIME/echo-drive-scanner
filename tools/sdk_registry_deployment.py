#!/usr/bin/env python
"""Render and validate the governed Echo SDK registry deployment for Drive Scanner.

This tool never opens a database connection and never reads credentials. It converts
the reviewed JSON contract manifest into an idempotent SQL migration that must be
executed through Echo's governed capability-registry write lane.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "contracts" / "sdk_capability_schemas.json"
DEFAULT_SQL = ROOT / "contracts" / "sdk_registry_migration_v2_2.sql"
BASE_URL = "http://100.85.253.44:8460"

CAPABILITY_METADATA: dict[str, dict[str, Any]] = {
    "echo.drivescan.health": {
        "description": "Drive Scanner v2.1: authenticated service and subsystem health.",
        "scope": "tier:0",
        "tier": 0,
        "timeout": 10,
    },
    "echo.drivescan.status": {
        "description": "Drive Scanner v2.1: latest scan status for discovery only.",
        "scope": "tier:0",
        "tier": 0,
        "timeout": 15,
    },
    "echo.drivescan.scan_status": {
        "description": "Drive Scanner v2.1: status and stages for one durable scan id.",
        "scope": "tier:0",
        "tier": 0,
        "timeout": 15,
    },
    "echo.drivescan.stages": {
        "description": "Drive Scanner v2.1: per-stage outcomes for one durable scan id.",
        "scope": "tier:0",
        "tier": 0,
        "timeout": 15,
    },
    "echo.drivescan.results": {
        "description": "Drive Scanner v2.1: immutable summary and stage evidence for one scan.",
        "scope": "tier:1",
        "tier": 1,
        "timeout": 30,
    },
    "echo.drivescan.files": {
        "description": "Drive Scanner v2.1: redacted per-scan file findings and scores.",
        "scope": "tier:1",
        "tier": 1,
        "timeout": 30,
    },
    "echo.drivescan.domains": {
        "description": "Drive Scanner v2.1: per-scan content-domain distribution.",
        "scope": "tier:0",
        "tier": 0,
        "timeout": 20,
    },
    "echo.drivescan.duplicates": {
        "description": "Drive Scanner v2.1: per-scan duplicate clusters and reclaim estimate.",
        "scope": "tier:0",
        "tier": 0,
        "timeout": 30,
    },
    "echo.drivescan.recommendations": {
        "description": "Drive Scanner v2.1: read-only prioritized storage recommendations.",
        "scope": "tier:1",
        "tier": 1,
        "timeout": 30,
    },
    "echo.drivescan.proposals": {
        "description": "Drive Scanner v2.1: read-only completion and new-build proposals.",
        "scope": "tier:1",
        "tier": 1,
        "timeout": 30,
    },
    "echo.drivescan.storage": {
        "description": "Drive Scanner v2.1: filesystem capacity summary without fabricated SMART health.",
        "scope": "tier:0",
        "tier": 0,
        "timeout": 20,
    },
    "echo.drivescan.scan": {
        "description": "Drive Scanner v2.1: start a guarded scan and return a durable scan id.",
        "scope": "tier:2",
        "tier": 2,
        "timeout": 120,
    },
    "echo.drivescan.cancel": {
        "description": "Drive Scanner v2.1: request cancellation of one active owned scan.",
        "scope": "tier:2",
        "tier": 2,
        "timeout": 30,
    },
}


def sha256_bytes(value: bytes) -> str:
    """Return the SHA-256 digest of bytes."""
    return hashlib.sha256(value).hexdigest()


def load_manifest(path: Path) -> dict[str, Any]:
    """Load and validate the top-level contract manifest."""
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("contract_version") != "2.2.0":
        raise ValueError("contract_version must be 2.2.0")
    capabilities = data.get("capabilities")
    if not isinstance(capabilities, dict):
        raise ValueError("manifest capabilities must be an object")
    if set(capabilities) != set(CAPABILITY_METADATA):
        missing = sorted(set(CAPABILITY_METADATA) - set(capabilities))
        extra = sorted(set(capabilities) - set(CAPABILITY_METADATA))
        raise ValueError(f"capability mismatch: missing={missing}, extra={extra}")
    return data


def validate_schema(schema: dict[str, Any], label: str) -> None:
    """Require strict top-level object schemas for every SDK boundary."""
    if schema.get("type") != "object":
        raise ValueError(f"{label} must be an object schema")
    if schema.get("additionalProperties") is not False:
        raise ValueError(f"{label} must reject unknown fields")


def validate_manifest(data: dict[str, Any]) -> None:
    """Validate routes, methods, schemas, and mutation classifications."""
    for capability, contract in data["capabilities"].items():
        if not isinstance(contract, dict):
            raise ValueError(f"{capability} contract must be an object")
        method = contract.get("method")
        path = contract.get("path")
        if method not in {"GET", "POST"}:
            raise ValueError(f"{capability} has unsupported method {method!r}")
        if not isinstance(path, str) or not path.startswith("/"):
            raise ValueError(f"{capability} has invalid path")
        validate_schema(contract["input_schema"], f"{capability}.input")
        validate_schema(contract["output_schema"], f"{capability}.output")
        metadata = CAPABILITY_METADATA[capability]
        if method == "POST" and metadata["tier"] < 2:
            raise ValueError(f"mutating capability {capability} must be tier 2+")
        if method == "GET" and metadata["tier"] > 1:
            raise ValueError(f"read capability {capability} is over-tiered")
    if (
        data["capabilities"]["echo.drivescan.proposals"]["output_schema"]["properties"][
            "queue_supported"
        ].get("const")
        is not False
    ):
        raise ValueError("proposal capability must remain read-only")


def sql_literal(value: str) -> str:
    """Quote a trusted generated SQL text literal."""
    return "'" + value.replace("'", "''") + "'"


def render_migration(data: dict[str, Any], base_url: str = BASE_URL) -> str:
    """Render one idempotent registry migration for all scanner capabilities."""
    statements = [
        "BEGIN;",
        "-- Generated from contracts/sdk_capability_schemas.json; do not hand-edit.",
    ]
    for capability in sorted(data["capabilities"]):
        contract = data["capabilities"][capability]
        metadata = CAPABILITY_METADATA[capability]
        input_json = json.dumps(contract["input_schema"], sort_keys=True, separators=(",", ":"))
        output_json = json.dumps(contract["output_schema"], sort_keys=True, separators=(",", ":"))
        method = contract["method"]
        args_mode = "json_body" if method == "POST" else "query"
        target_url = f"{base_url.rstrip('/')}{contract['path']}"
        values = {
            "id": capability,
            "description": metadata["description"],
            "handler_kind": "http",
            "target_url": target_url,
            "target_method": method,
            "args_mode": args_mode,
            "target_node": "hammer",
            "input": input_json,
            "output": output_json,
            "scope": metadata["scope"],
            "tier": int(metadata["tier"]),
            "timeout": int(metadata["timeout"]),
        }
        statements.append(
            "\n".join(
                [
                    "INSERT INTO arcanum_sdk.sdk_capabilities (",
                    "  id, description, handler_kind, target_url, target_method, args_mode,",
                    "  target_node, input_schema_json, output_schema_json, required_scope,",
                    "  rate_cost, danger_tier, schema_version, is_builtin, health_status,",
                    "  requires_guard_scan, never_archive, lifecycle_status, option_projections,",
                    "  default_timeout_seconds, never_breaker_block, static_headers, health_reason,",
                    "  created_at, updated_at",
                    ") VALUES (",
                    f"  {sql_literal(values['id'])}, {sql_literal(values['description'])}, 'http',",
                    f"  {sql_literal(values['target_url'])}, {sql_literal(values['target_method'])},",
                    f"  {sql_literal(values['args_mode'])}, 'hammer',",
                    f"  {sql_literal(values['input'])}::jsonb, {sql_literal(values['output'])}::jsonb,",
                    f"  {sql_literal(values['scope'])}, 1.0, {values['tier']}, 2, false, 'amber',",
                    "  true, true, 'active', '[]'::jsonb,",
                    f"  {values['timeout']}, false, '{{}}'::jsonb,",
                    "  'pending governed post-deployment invocation and schema validation',",
                    "  now(), now()",
                    ") ON CONFLICT (id) DO UPDATE SET",
                    "  description = EXCLUDED.description,",
                    "  handler_kind = EXCLUDED.handler_kind,",
                    "  target_url = EXCLUDED.target_url,",
                    "  target_method = EXCLUDED.target_method,",
                    "  args_mode = EXCLUDED.args_mode,",
                    "  target_node = EXCLUDED.target_node,",
                    "  input_schema_json = EXCLUDED.input_schema_json,",
                    "  output_schema_json = EXCLUDED.output_schema_json,",
                    "  required_scope = EXCLUDED.required_scope,",
                    "  danger_tier = EXCLUDED.danger_tier,",
                    "  schema_version = EXCLUDED.schema_version,",
                    "  health_status = 'amber',",
                    "  health_reason = EXCLUDED.health_reason,",
                    "  default_timeout_seconds = EXCLUDED.default_timeout_seconds,",
                    "  requires_guard_scan = true,",
                    "  never_archive = true,",
                    "  lifecycle_status = 'active',",
                    "  updated_at = now();",
                ]
            )
        )
    quoted_ids = ", ".join(sql_literal(item) for item in sorted(CAPABILITY_METADATA))
    statements.extend(
        [
            "",
            "-- Fail closed if the expected capability family is incomplete.",
            "DO $$",
            "BEGIN",
            f"  IF (SELECT count(*) FROM arcanum_sdk.sdk_capabilities WHERE id IN ({quoted_ids})) <> {len(CAPABILITY_METADATA)} THEN",
            "    RAISE EXCEPTION 'Drive Scanner capability reconciliation incomplete';",
            "  END IF;",
            "END $$;",
            "COMMIT;",
            "",
        ]
    )
    return "\n".join(statements)


def main() -> int:
    """Validate the manifest and render a deterministic governed migration."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--output", type=Path, default=DEFAULT_SQL)
    parser.add_argument("--base-url", default=BASE_URL)
    parser.add_argument("--check", action="store_true", help="Verify an existing migration matches")
    args = parser.parse_args()

    data = load_manifest(args.manifest)
    validate_manifest(data)
    rendered = render_migration(data, args.base_url)
    if args.check:
        existing = args.output.read_text(encoding="utf-8")
        if existing != rendered:
            raise SystemExit("registry migration is stale")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(rendered.encode("utf-8"))
    print(
        json.dumps(
            {
                "status": "valid",
                "capabilities": len(data["capabilities"]),
                "manifest_sha256": sha256_bytes(args.manifest.read_bytes()),
                "migration_sha256": sha256_bytes(args.output.read_bytes()),
                "output": str(args.output),
                "execution": "governed_registry_write_required",
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
