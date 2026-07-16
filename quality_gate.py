#!/usr/bin/env python
"""Deterministic A+ quality gate for Intelligent Drive Scanner."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ARTIFACT_DIR = ROOT / "artifacts" / "quality"

GATES: list[tuple[str, list[str]]] = [
    (
        "compile",
        [
            sys.executable,
            "-m",
            "compileall",
            "-q",
            "config.py",
            "scanner.py",
            "dashboard",
            "intelligence",
            "storage",
        ],
    ),
    ("dependency_integrity", [sys.executable, "-m", "pip", "check"]),
    ("lint", [sys.executable, "-m", "ruff", "check", ".", "--exclude", ".venv"]),
    (
        "full_types",
        [
            sys.executable,
            "-m",
            "mypy",
            ".",
            "--exclude",
            ".venv|artifacts|tests",
        ],
    ),
    ("tests", [sys.executable, "-m", "pytest", "-q"]),
    (
        "critical_coverage",
        [
            sys.executable,
            "-m",
            "pytest",
            "tests/test_hardening.py",
            "tests/test_a_plus_hardening.py",
            "--cov=dashboard.api_models",
            "--cov=dashboard.security",
            "--cov=config",
            "--cov-report=term-missing",
            "--cov-report=json:artifacts/critical-coverage.json",
            "-q",
        ],
    ),
    (
        "production_core_coverage",
        [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "--cov=scanner",
            "--cov=storage.db",
            "--cov=dashboard.server",
            "--cov=dashboard.security",
            "--cov=dashboard.api_models",
            "--cov=config",
            "--cov=intelligence.classifier",
            "--cov=intelligence.content_sampler",
            "--cov=intelligence.engine_client",
            "--cov=intelligence.function_library",
            "--cov=intelligence.deduplicator",
            "--cov=intelligence.recommender",
            "--cov=intelligence.relationship_mapper",
            "--cov=intelligence.scorer",
            "--cov=intelligence.project_advisor",
            "--cov-report=term-missing",
            "--cov-report=json:artifacts/production-core-coverage.json",
            "--cov-fail-under=55",
        ],
    ),
    (
        "sdk_registry_contract",
        [sys.executable, "tools/sdk_registry_deployment.py", "--check"],
    ),
    ("live_smoke", [sys.executable, "smoke_live.py"]),
    (
        "dependency_audit",
        [sys.executable, "-m", "pip_audit", "-r", "requirements.txt", "--progress-spinner", "off"],
    ),
]


def sha256_file(path: Path) -> str:
    """Return the SHA-256 digest of one artifact."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_gate(name: str, command: list[str]) -> dict[str, object]:
    """Execute one bounded quality command and persist its complete output."""
    started = datetime.now(UTC)
    completed = subprocess.run(
        command,
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=300,
        check=False,
    )
    ended = datetime.now(UTC)
    log_path = ARTIFACT_DIR / f"{name}.log"
    log_content = (
        f"COMMAND: {' '.join(command)}\nRETURN_CODE: {completed.returncode}\n\n"
        f"STDOUT:\n{completed.stdout.rstrip()}\n\nSTDERR:\n{completed.stderr.rstrip()}"
    )
    log_path.write_text(log_content.rstrip() + "\n", encoding="utf-8")
    return {
        "name": name,
        "passed": completed.returncode == 0,
        "return_code": completed.returncode,
        "started_at": started.isoformat(),
        "completed_at": ended.isoformat(),
        "duration_seconds": round((ended - started).total_seconds(), 3),
        "command": command,
        "log": str(log_path.relative_to(ROOT)),
        "log_sha256": sha256_file(log_path),
    }


def main() -> int:
    """Run all hard gates and emit a hash-complete report."""
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    results: list[dict[str, object]] = []
    for name, command in GATES:
        print(f"[gate] {name}")
        result = run_gate(name, command)
        results.append(result)
        print(f"       {'PASS' if result['passed'] else 'FAIL'}")
        if not result["passed"]:
            break

    report = {
        "report_version": "2.0",
        "generated_at": datetime.now(UTC).isoformat(),
        "repository": str(ROOT),
        "verdict": "PASS"
        if len(results) == len(GATES) and all(r["passed"] for r in results)
        else "FAIL",
        "gates": results,
    }
    report_path = ARTIFACT_DIR / "quality-gate-report.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    digest_path = ARTIFACT_DIR / "quality-gate-report.sha256"
    digest_path.write_text(f"{sha256_file(report_path)}  {report_path.name}\n", encoding="utf-8")
    print(f"QUALITY GATE: {report['verdict']}")
    print(f"REPORT: {report_path}")
    return 0 if report["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
