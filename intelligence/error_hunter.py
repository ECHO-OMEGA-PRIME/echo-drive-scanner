"""
Error Hunter — Scan files for error patterns and submit to GS343 error healing.
================================================================================
Scans log files and code for tracebacks, exceptions, and error patterns.
Deduplicates against existing GS343 templates. Submits new patterns.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
from loguru import logger
from pydantic import BaseModel, Field

# ─── Config ──────────────────────────────────────────────────────────────────

import os

GS343_URL = os.environ.get("DRIVESCAN_GS343_URL", "")
SHARED_BRAIN_URL = os.environ.get("DRIVESCAN_SHARED_BRAIN_URL", "")

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB for log files
LOG_EXTENSIONS = {".log", ".out", ".err"}
CODE_EXTENSIONS = {".py", ".js", ".ts", ".tsx", ".jsx"}

# ─── Error Patterns ──────────────────────────────────────────────────────────

PYTHON_TRACEBACK = re.compile(
    r"Traceback \(most recent call last\):\n"
    r"(?:  File .+\n    .+\n)+"
    r"(\w+(?:Error|Exception|Warning)): (.+)",
    re.MULTILINE,
)

PYTHON_EXCEPTION_LINE = re.compile(
    r"(?:raise\s+)?(\w+(?:Error|Exception|Warning))\s*\(([^)]*)\)"
)

PYTHON_EXCEPT_BLOCK = re.compile(
    r"except\s+(\w+(?:Error|Exception)?(?:\s*,\s*\w+(?:Error|Exception)?)*)\s*(?:as\s+\w+)?\s*:"
)

JS_ERROR_PATTERN = re.compile(
    r"(?:throw new |catch\s*\(\s*\w+\s*\)\s*\{[^}]*)"
    r"(\w+Error)\s*\(([^)]*)\)",
)

LOG_ERROR_LINE = re.compile(
    r"(?:ERROR|CRITICAL|FATAL)\s*[|\]:]\s*(.+)",
    re.IGNORECASE,
)

LOG_EXCEPTION = re.compile(
    r"(\w+(?:Error|Exception|Failure))\s*:\s*(.+)",
)

HTTP_ERROR = re.compile(
    r"(?:status[_\s]?code|HTTP)\s*[=:]\s*([45]\d{2})\b.*?(?:message|detail|error)\s*[=:]\s*['\"]?([^'\"}\n]+)",
    re.IGNORECASE,
)


# ─── Models ──────────────────────────────────────────────────────────────────

class ErrorPattern(BaseModel):
    error_type: str
    message: str
    source_file: str
    module: str = ""
    function: str = ""
    line_number: int = 0
    frequency: int = 1
    severity: str = "medium"
    category: str = "runtime"
    fingerprint: str = ""

    def compute_fingerprint(self) -> str:
        """Generate a dedup fingerprint."""
        normalized_msg = re.sub(r"[\d]+", "N", self.message)
        normalized_msg = re.sub(r"['\"].*?['\"]", "STR", normalized_msg)
        normalized_msg = re.sub(r"/[\w/.-]+", "PATH", normalized_msg)
        self.fingerprint = f"{self.error_type}::{normalized_msg[:100]}"
        return self.fingerprint


class ErrorHuntResult(BaseModel):
    total_patterns_found: int = 0
    unique_patterns: int = 0
    new_templates_created: int = 0
    existing_templates_matched: int = 0
    files_scanned: int = 0
    patterns: list[ErrorPattern] = Field(default_factory=list)
    top_errors: list[dict[str, Any]] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


# ─── Error Hunter ────────────────────────────────────────────────────────────

class ErrorHunter:
    """Scan files for error patterns and submit to GS343."""

    def __init__(self, db: Any) -> None:
        self.db = db
        self._existing_templates: set[str] = set()

    async def hunt(self, scan_id: int, max_files: int = 500) -> ErrorHuntResult:
        """Run full error hunting pipeline."""
        result = ErrorHuntResult()

        # Load existing GS343 templates for dedup
        await self._load_existing_templates()

        files = self.db.list_files(scan_id=scan_id, limit=max_files * 2)
        target_files = [
            f for f in files
            if self._is_scannable(f)
        ][:max_files]

        logger.info(f"Error hunting across {len(target_files)} files from scan {scan_id}")

        all_patterns: list[ErrorPattern] = []
        for f in target_files:
            fpath = f.path if hasattr(f, "path") else f.get("path", "")
            try:
                patterns = self._scan_file(fpath)
                all_patterns.extend(patterns)
                result.files_scanned += 1
            except Exception as e:
                result.errors.append(f"{fpath}: {e}")

        # Compute fingerprints and deduplicate
        fingerprint_groups: dict[str, list[ErrorPattern]] = defaultdict(list)
        for p in all_patterns:
            p.compute_fingerprint()
            fingerprint_groups[p.fingerprint].append(p)

        deduped: list[ErrorPattern] = []
        for fp, group in fingerprint_groups.items():
            representative = group[0]
            representative.frequency = len(group)
            deduped.append(representative)

        result.total_patterns_found = len(all_patterns)
        result.unique_patterns = len(deduped)
        result.patterns = sorted(deduped, key=lambda x: x.frequency, reverse=True)

        # Check against existing GS343 templates
        new_patterns = []
        for p in deduped:
            if p.fingerprint in self._existing_templates:
                result.existing_templates_matched += 1
            else:
                new_patterns.append(p)

        # Submit new patterns to GS343
        result.new_templates_created = await self._submit_to_gs343(new_patterns)

        # Push summary to Shared Brain
        await self._push_summary(result)

        # Build top errors
        result.top_errors = [
            {
                "error_type": p.error_type,
                "message": p.message[:200],
                "frequency": p.frequency,
                "severity": p.severity,
                "source": p.source_file,
            }
            for p in result.patterns[:20]
        ]

        logger.info(
            f"Error hunt complete: {result.total_patterns_found} found, "
            f"{result.unique_patterns} unique, {result.new_templates_created} new GS343 templates"
        )
        return result

    def _is_scannable(self, f: Any) -> bool:
        """Check if file should be scanned for errors."""
        fpath = f.path if hasattr(f, "path") else f.get("path", "")
        ext = Path(fpath).suffix.lower()
        size = f.size_bytes if hasattr(f, "size_bytes") else f.get("size_bytes", 0)
        return ext in (LOG_EXTENSIONS | CODE_EXTENSIONS) and 0 < size < MAX_FILE_SIZE

    def _scan_file(self, path: str) -> list[ErrorPattern]:
        """Scan a single file for error patterns."""
        try:
            content = Path(path).read_text(encoding="utf-8", errors="replace")
        except (OSError, PermissionError):
            return []

        ext = Path(path).suffix.lower()
        patterns: list[ErrorPattern] = []

        if ext == ".py":
            patterns.extend(self._scan_python(content, path))
        elif ext in (".js", ".ts", ".tsx", ".jsx"):
            patterns.extend(self._scan_javascript(content, path))
        elif ext in LOG_EXTENSIONS:
            patterns.extend(self._scan_log(content, path))

        return patterns

    def _scan_python(self, content: str, path: str) -> list[ErrorPattern]:
        """Scan Python file for error patterns."""
        patterns: list[ErrorPattern] = []

        # Full tracebacks
        for m in PYTHON_TRACEBACK.finditer(content):
            patterns.append(ErrorPattern(
                error_type=m.group(1),
                message=m.group(2).strip()[:500],
                source_file=path,
                severity=self._classify_severity(m.group(1)),
                category="traceback",
            ))

        # Raised exceptions
        for m in PYTHON_EXCEPTION_LINE.finditer(content):
            patterns.append(ErrorPattern(
                error_type=m.group(1),
                message=m.group(2).strip().strip("'\"")[:500],
                source_file=path,
                severity=self._classify_severity(m.group(1)),
                category="raised",
            ))

        # Except blocks (what errors are being caught)
        for m in PYTHON_EXCEPT_BLOCK.finditer(content):
            for exc_type in re.split(r"\s*,\s*", m.group(1)):
                exc_type = exc_type.strip()
                if exc_type and exc_type != "Exception":
                    patterns.append(ErrorPattern(
                        error_type=exc_type,
                        message=f"Caught in {Path(path).name}",
                        source_file=path,
                        severity="low",
                        category="handled",
                    ))

        return patterns

    def _scan_javascript(self, content: str, path: str) -> list[ErrorPattern]:
        """Scan JS/TS file for error patterns."""
        patterns: list[ErrorPattern] = []

        for m in JS_ERROR_PATTERN.finditer(content):
            patterns.append(ErrorPattern(
                error_type=m.group(1),
                message=m.group(2).strip().strip("'\"")[:500],
                source_file=path,
                severity=self._classify_severity(m.group(1)),
                category="thrown",
            ))

        # Console.error calls
        for m in re.finditer(r"console\.error\s*\(\s*['\"`]([^'\"`]+)", content):
            patterns.append(ErrorPattern(
                error_type="ConsoleError",
                message=m.group(1)[:500],
                source_file=path,
                severity="low",
                category="logged",
            ))

        return patterns

    def _scan_log(self, content: str, path: str) -> list[ErrorPattern]:
        """Scan log file for error patterns."""
        patterns: list[ErrorPattern] = []

        for m in LOG_ERROR_LINE.finditer(content):
            msg = m.group(1).strip()[:500]
            exc_match = LOG_EXCEPTION.search(msg)
            if exc_match:
                patterns.append(ErrorPattern(
                    error_type=exc_match.group(1),
                    message=exc_match.group(2).strip()[:500],
                    source_file=path,
                    severity=self._classify_severity(exc_match.group(1)),
                    category="log",
                ))
            else:
                patterns.append(ErrorPattern(
                    error_type="LogError",
                    message=msg,
                    source_file=path,
                    severity="medium",
                    category="log",
                ))

        for m in HTTP_ERROR.finditer(content):
            status = int(m.group(1))
            patterns.append(ErrorPattern(
                error_type=f"HTTP{status}",
                message=m.group(2).strip()[:500],
                source_file=path,
                severity="high" if status >= 500 else "medium",
                category="http",
            ))

        return patterns

    @staticmethod
    def _classify_severity(error_type: str) -> str:
        """Classify error severity based on type name."""
        critical = {"SystemExit", "MemoryError", "RecursionError", "SystemError"}
        high = {"ConnectionError", "TimeoutError", "PermissionError", "FileNotFoundError",
                "ImportError", "ModuleNotFoundError", "DatabaseError", "IntegrityError"}
        low = {"DeprecationWarning", "FutureWarning", "UserWarning", "SyntaxWarning"}

        if error_type in critical:
            return "critical"
        if error_type in high:
            return "high"
        if error_type in low:
            return "low"
        return "medium"

    async def _load_existing_templates(self) -> None:
        """Load existing GS343 template fingerprints for deduplication."""
        if not GS343_URL:
            logger.info("GS343 sync disabled — no endpoint configured")
            return
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(f"{GS343_URL}/templates")
                if resp.status_code == 200:
                    templates = resp.json()
                    for t in templates if isinstance(templates, list) else templates.get("templates", []):
                        error_type = t.get("error_type", "")
                        message = t.get("message_pattern", t.get("message", ""))
                        normalized = re.sub(r"[\d]+", "N", message)
                        normalized = re.sub(r"['\"].*?['\"]", "STR", normalized)
                        self._existing_templates.add(f"{error_type}::{normalized[:100]}")
                    logger.info(f"Loaded {len(self._existing_templates)} existing GS343 templates")
        except Exception as e:
            logger.warning(f"Could not load GS343 templates (GS343 may be offline): {e}")

    async def _submit_to_gs343(self, patterns: list[ErrorPattern]) -> int:
        """Submit new error patterns to GS343."""
        if not GS343_URL:
            return 0
        created = 0
        async with httpx.AsyncClient(timeout=10.0) as client:
            for p in patterns[:50]:
                try:
                    payload = {
                        "error_type": p.error_type,
                        "message_pattern": p.message[:500],
                        "source_module": Path(p.source_file).stem,
                        "severity": p.severity,
                        "category": p.category,
                        "frequency": p.frequency,
                        "auto_fix": "",
                        "notes": f"Auto-discovered by scanner from {p.source_file}",
                        "discovered_at": datetime.now(timezone.utc).isoformat(),
                    }
                    resp = await client.post(f"{GS343_URL}/errors/new", json=payload)
                    if resp.status_code < 300:
                        created += 1
                        self._existing_templates.add(p.fingerprint)
                except Exception as e:
                    logger.debug(f"GS343 submit failed for {p.error_type}: {e}")
        return created

    async def _push_summary(self, result: ErrorHuntResult) -> None:
        """Push error hunt summary to Shared Brain."""
        if result.total_patterns_found == 0:
            return
        if not SHARED_BRAIN_URL:
            logger.info("Shared Brain push disabled — no endpoint configured")
            return

        top_err_parts = []
        for e in result.top_errors[:5]:
            etype = e["error_type"]
            freq = e["frequency"]
            top_err_parts.append(f"{etype}({freq}x)")
        top_err_str = "; ".join(top_err_parts)
        content = (
            f"ERROR HUNT RESULTS: Scanned {result.files_scanned} files. "
            f"Found {result.total_patterns_found} error patterns ({result.unique_patterns} unique). "
            f"Matched {result.existing_templates_matched} existing GS343 templates. "
            f"Created {result.new_templates_created} new templates. "
            f"Top errors: {top_err_str}"
        )
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                await client.post(
                    f"{SHARED_BRAIN_URL}/ingest",
                    json={
                        "instance_id": "scanner_error_hunter",
                        "role": "assistant",
                        "content": content,
                        "importance": 6,
                        "tags": ["scan", "errors", "gs343", "patterns"],
                    },
                )
        except Exception as e:
            result.errors.append(f"Brain push failed: {e}")
