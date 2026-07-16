#!/usr/bin/env python
"""Run an evidence-backed read-only qualification scan over approved source roots."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from config import ScanConfig
from scanner import IntelligenceScanOrchestrator
from storage.db import IntelligenceDB

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ARTIFACT_DIR = ROOT / "artifacts" / "qualification"


def sha256_file(path: Path) -> str:
    """Return the SHA-256 digest of one file."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def source_tree_identity(path: Path) -> dict[str, Any]:
    """Hash relevant tracked and untracked source files without reading artifacts."""
    skipped_parts = {
        ".git",
        ".venv",
        "venv",
        "node_modules",
        "__pycache__",
        "artifacts",
        "data",
        "logs",
        "quarantine",
        ".pytest_cache",
    }
    allowed_suffixes = {
        ".py",
        ".toml",
        ".json",
        ".yaml",
        ".yml",
        ".sql",
        ".ps1",
    }
    try:
        output = subprocess.run(
            ["git", "-C", str(path), "ls-files", "--cached", "--others", "--exclude-standard"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
            check=True,
        ).stdout.splitlines()
        candidates = [path / item for item in output]
    except (OSError, subprocess.SubprocessError):
        candidates = [item for item in path.rglob("*") if item.is_file()]

    selected: list[tuple[str, Path]] = []
    for candidate in candidates:
        try:
            relative = candidate.relative_to(path)
        except ValueError:
            continue
        if any(part in skipped_parts for part in relative.parts):
            continue
        if candidate.suffix.lower() not in allowed_suffixes:
            continue
        if not candidate.is_file() or candidate.stat().st_size > 5 * 1024 * 1024:
            continue
        selected.append((relative.as_posix(), candidate))

    digest = hashlib.sha256()
    total_bytes = 0
    for relative_name, selected_file in sorted(selected):
        payload = selected_file.read_bytes()
        total_bytes += len(payload)
        digest.update(relative_name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(payload).digest())
        digest.update(b"\0")
    return {
        "source_tree_sha256": digest.hexdigest(),
        "source_file_count": len(selected),
        "source_bytes": total_bytes,
    }


def git_identity(path: Path) -> dict[str, Any]:
    """Return a bounded Git identity for one qualification root."""
    result: dict[str, Any] = {"name": path.name, "exists": path.exists()}
    if not path.exists():
        return result
    try:
        head = subprocess.run(
            ["git", "-C", str(path), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
            check=True,
        ).stdout.strip()
        branch = subprocess.run(
            ["git", "-C", str(path), "branch", "--show-current"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
            check=True,
        ).stdout.strip()
        status = subprocess.run(
            ["git", "-C", str(path), "status", "--porcelain"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=20,
            check=True,
        ).stdout.splitlines()
        result.update(
            {
                "git": True,
                "head": head,
                "branch": branch,
                "dirty_entries": len(status),
                **source_tree_identity(path),
            }
        )
    except (OSError, subprocess.SubprocessError):
        result.update({"git": False, **source_tree_identity(path)})
    return result


def classify_counts(database: IntelligenceDB, scan_id: int) -> dict[str, int]:
    """Count persisted classifications by engine without exposing file paths."""
    counts: dict[str, int] = {}
    for file_record in database.list_files(scan_id=scan_id, limit=1_000_000):
        if file_record.id is None:
            continue
        for classification in database.get_classifications(file_record.id):
            engine = classification.engine_id or "UNKNOWN"
            counts[engine] = counts.get(engine, 0) + 1
    return dict(sorted(counts.items()))


async def qualify(roots: list[Path], artifact_dir: Path, profile: str) -> dict[str, Any]:
    """Execute one isolated qualification scan and return redacted evidence."""
    artifact_dir.mkdir(parents=True, exist_ok=True)
    database_path = artifact_dir / "qualification.db"
    if database_path.exists():
        database_path.unlink()
    database = IntelligenceDB(database_path)
    orchestrator = IntelligenceScanOrchestrator(ScanConfig(max_depth=64), db=database)
    started = datetime.now(UTC)
    scan_id = await orchestrator.run_scan([str(root.resolve()) for root in roots], profile=profile)
    completed = datetime.now(UTC)

    scan = database.get_scan(scan_id)
    summary = database.get_scan_summary(scan_id)
    if scan is None or summary is None:
        raise RuntimeError("qualification scan completed without persisted summary")
    stages = database.get_scan_stages(scan_id)
    proposals = database.get_proposals(scan_id=scan_id, limit=10_000)
    duplicates = database.get_duplicate_clusters(scan_id=scan_id)
    recommendations = database.get_recommendations(scan_id=scan_id, limit=10_000)
    classifications = classify_counts(database, scan_id)

    failed_stages = [stage for stage in stages if stage.get("status") == "failed"]
    local_count = classifications.get("LOCAL_RULES_V1", 0)
    verdict = "PASS"
    reasons: list[str] = []
    if failed_stages:
        verdict = "FAIL"
        reasons.append("one or more required scan stages failed")
    if scan.total_files < 100:
        verdict = "FAIL"
        reasons.append("qualification dataset contained fewer than 100 files")
    minimum_classified = max(100, int(scan.total_files * 0.70))
    if scan.files_classified < minimum_classified:
        verdict = "FAIL"
        reasons.append("persisted classifications covered less than 70 percent of discovered files")
    if local_count != scan.files_classified:
        verdict = "FAIL"
        reasons.append(
            "deterministic local classification count did not match persisted classified files"
        )

    return {
        "report_version": "1.0",
        "generated_at": completed.isoformat(),
        "verdict": verdict,
        "reasons": reasons,
        "profile": profile,
        "scan_id": scan_id,
        "started_at": started.isoformat(),
        "completed_at": completed.isoformat(),
        "wall_seconds": round((completed - started).total_seconds(), 3),
        "roots": [git_identity(root) for root in roots],
        "scan": {
            "status": scan.status,
            "total_files": scan.total_files,
            "total_size_bytes": scan.total_size_bytes,
            "files_classified": scan.files_classified,
            "files_skipped": scan.files_skipped,
            "duration_seconds": scan.duration_seconds,
            "recommendation_count": len(recommendations),
            "proposal_count": len(proposals),
            "duplicate_cluster_count": len(duplicates),
            "wasted_bytes": sum(
                int(cluster.get("total_wasted_bytes", 0)) for cluster in duplicates
            ),
        },
        "classification_engines": classifications,
        "stages": stages,
        "privacy": {
            "full_paths_in_report": False,
            "content_samples_in_report": False,
            "database_committed": False,
        },
    }


def main() -> int:
    """Run qualification and emit a hash-pinned JSON report."""
    parser = argparse.ArgumentParser()
    parser.add_argument("roots", nargs="+", type=Path)
    parser.add_argument("--profile", default="INTEL_FAST")
    parser.add_argument("--artifact-dir", type=Path, default=DEFAULT_ARTIFACT_DIR)
    args = parser.parse_args()

    roots = [path for path in args.roots if path.exists()]
    if len(roots) != len(args.roots):
        missing = [str(path) for path in args.roots if not path.exists()]
        raise SystemExit(f"missing qualification roots: {missing}")
    report = asyncio.run(qualify(roots, args.artifact_dir, args.profile))
    report_path = args.artifact_dir / "qualification-report.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    digest = sha256_file(report_path)
    digest_path = args.artifact_dir / "qualification-report.sha256"
    digest_path.write_text(f"{digest}  {report_path.name}\n", encoding="utf-8")
    print(json.dumps({"verdict": report["verdict"], "report": str(report_path), "sha256": digest}))
    return 0 if report["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
