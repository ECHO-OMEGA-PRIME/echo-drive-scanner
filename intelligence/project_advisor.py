"""Intelligent Drive Scanner v2.0 — Project Advisor (Stage 10).

Analyzes scanned files to generate two categories of actionable intelligence:

1. PROJECT PROPOSALS — new projects that SHOULD be built based on:
   - Data clusters with no corresponding code/tooling
   - Repeated manual processes that could be automated
   - Domain gaps (heavy data, missing engines)
   - Orphaned datasets needing pipelines
   - File patterns suggesting unmet workflow needs

2. PROGRAM RECOMMENDATIONS — programs that COULD be built based on:
   - Existing logic/code fragments that could be promoted to full tools
   - Partial implementations across multiple files
   - Duplicate logic that should be unified into a shared library
   - Scripts that have grown beyond script scope
   - APIs/integrations already implemented ad-hoc but not productized

Output: List[ProjectProposal] stored to DB + Knowledge Forge ingest.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from loguru import logger

from storage.models import FileRecord, Classification, IntelligenceScore


# ── Constants ─────────────────────────────────────────────────────────────────

CODE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".cs", ".java", ".go", ".rs",
    ".cpp", ".c", ".h", ".rb", ".php", ".ps1", ".sh", ".bat", ".lua",
    ".r", ".m", ".swift", ".kt", ".scala",
}

DATA_EXTENSIONS = {
    ".csv", ".json", ".xml", ".xlsx", ".xls", ".db", ".sqlite", ".sqlite3",
    ".parquet", ".feather", ".h5", ".hdf5", ".arrow", ".ndjson", ".jsonl",
}

DOC_EXTENSIONS = {
    ".pdf", ".docx", ".doc", ".txt", ".md", ".rst", ".pptx", ".ppt",
    ".html", ".htm",
}

CONFIG_EXTENSIONS = {
    ".yaml", ".yml", ".toml", ".ini", ".env", ".cfg", ".conf",
}

# Patterns that suggest a fragment / partial / orphaned implementation
FRAGMENT_PATTERNS = [
    r"TODO|FIXME|HACK|XXX|INCOMPLETE|WIP|STUB",
    r"def main\(\)|if __name__.*__main__",
    r"prototype|proof.of.concept|poc|scratch|draft|temp|tmp",
]

# Keywords suggesting automation opportunity
AUTOMATION_SIGNALS = [
    "manual", "copy", "paste", "export", "download", "upload",
    "monthly", "weekly", "daily", "batch", "report", "summary",
]

# Domain → engine prefix mapping for gap detection
DOMAIN_ENGINE_MAP = {
    "TAX": "TX",
    "OIL": "OFE",
    "DRILL": "DRL",
    "LEGAL": "LGL",
    "FINANCE": "FIN",
    "MEDICAL": "MED",
    "REAL_ESTATE": "RE",
    "CRYPTO": "CRY",
    "PROG": None,  # code domain — analyze differently
    "AI": "AGI",
}

# Priority scoring weights
PRIORITY_WEIGHTS = {
    "file_count": 0.25,
    "total_size": 0.15,
    "domain_match": 0.20,
    "fragment_density": 0.20,
    "data_without_code": 0.20,
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _human_size(nbytes: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(nbytes) < 1024.0:
            return f"{nbytes:.1f} {unit}"
        nbytes //= 1024
    return f"{nbytes:.1f} PB"


def _extract_logic_signatures(content: str) -> dict[str, Any]:
    """Extract logic fingerprints from source code content."""
    sigs: dict[str, Any] = {
        "functions": [],
        "classes": [],
        "imports": [],
        "api_calls": [],
        "has_main": False,
        "has_cli": False,
        "has_api": False,
        "has_db": False,
        "has_auth": False,
        "estimated_lines": content.count("\n"),
        "fragment_signals": [],
    }

    if not content:
        return sigs

    # Functions
    sigs["functions"] = re.findall(r"(?:def|function|func)\s+(\w+)\s*\(", content)[:20]

    # Classes
    sigs["classes"] = re.findall(r"(?:class)\s+(\w+)[\s:(]", content)[:10]

    # Imports
    sigs["imports"] = re.findall(r"(?:import|from|require)\s+([\w.]+)", content)[:20]

    # API patterns
    api_patterns = re.findall(
        r"https?://[\w./-]+|fetch\(|requests\.|aiohttp|axios|curl", content
    )
    sigs["api_calls"] = list(set(api_patterns))[:10]

    # Capability flags
    sigs["has_main"] = bool(re.search(r"def main\(|if __name__.*main", content))
    sigs["has_cli"] = bool(re.search(r"argparse|click|typer|sys\.argv", content))
    sigs["has_api"] = bool(re.search(r"FastAPI|Flask|Express|@app\.|router\.", content))
    sigs["has_db"] = bool(re.search(r"sqlite|postgres|mysql|mongodb|sqlalchemy|prisma", content, re.I))
    sigs["has_auth"] = bool(re.search(r"jwt|oauth|api.?key|bearer|authenticate", content, re.I))

    # Fragment signals
    for pattern in FRAGMENT_PATTERNS:
        matches = re.findall(pattern, content, re.I)
        if matches:
            sigs["fragment_signals"].extend(matches[:3])

    return sigs


def _score_priority(
    file_count: int,
    total_bytes: int,
    has_domain_match: bool,
    fragment_density: float,
    data_code_ratio: float,
) -> float:
    """Score 0-100 for project proposal priority."""
    score = 0.0

    # File count signal (more files = bigger opportunity)
    if file_count >= 100:
        score += 25
    elif file_count >= 20:
        score += 15
    elif file_count >= 5:
        score += 8
    else:
        score += 3

    # Size signal
    if total_bytes >= 1_000_000_000:  # 1GB+
        score += 15
    elif total_bytes >= 100_000_000:
        score += 10
    elif total_bytes >= 10_000_000:
        score += 5

    # Domain match (we have engines for this domain)
    if has_domain_match:
        score += 20

    # Fragment density (lots of partials = high opportunity)
    score += min(20, fragment_density * 100)

    # Data without code (unprocessed data = build a pipeline)
    score += min(20, data_code_ratio * 20)

    return min(100.0, round(score, 1))


# ── Main Advisor Class ────────────────────────────────────────────────────────


class ProjectAdvisor:
    """Stage 10 — Project and Program Intelligence Advisor."""

    def __init__(self) -> None:
        self._proposals: list[dict[str, Any]] = []

    def analyze(
        self,
        files: list[FileRecord],
        scores: dict[int, IntelligenceScore],
        classifications: dict[int, list[Classification]],
        scan_id: int,
        file_contents: dict[str, str] | None = None,
    ) -> list[dict[str, Any]]:
        """Run full project intelligence analysis.

        Args:
            files: All scanned FileRecord objects.
            scores: Intelligence scores keyed by file ID.
            classifications: Classifications keyed by file ID.
            scan_id: Current scan ID.
            file_contents: Optional dict of path → content for deep analysis.

        Returns:
            List of ProjectProposal dicts ready for DB/Knowledge Forge.
        """
        logger.info("Stage 10: Project Advisor — analyzing {} files", len(files))

        self._proposals = []
        file_contents = file_contents or {}

        # Group files by domain
        domain_groups = self._group_by_domain(files, scores, classifications)

        # Group files by directory cluster
        dir_groups = self._group_by_directory(files)

        # Analyze each domain cluster
        for domain, domain_files in domain_groups.items():
            self._analyze_domain_cluster(domain, domain_files, scan_id, file_contents)

        # Analyze directory clusters for partial implementations
        for dir_path, dir_files in dir_groups.items():
            self._analyze_directory_cluster(dir_path, dir_files, scan_id, file_contents)

        # Detect unified library opportunities (duplicate logic)
        self._detect_duplicate_logic(files, scan_id, file_contents)

        # Detect data-without-pipeline patterns
        self._detect_orphaned_data(files, scan_id)

        # Detect scripts that outgrew their scope
        self._detect_promoted_scripts(files, scan_id, file_contents)

        # Sort by priority descending
        self._proposals.sort(key=lambda p: p["priority_score"], reverse=True)

        logger.info(
            "Stage 10: Generated {} project proposals / program recommendations",
            len(self._proposals),
        )
        return self._proposals

    # ── Grouping ──────────────────────────────────────────────────────────────

    def _group_by_domain(
        self,
        files: list[FileRecord],
        scores: dict[int, IntelligenceScore],
        classifications: dict[int, list[Classification]],
    ) -> dict[str, list[FileRecord]]:
        groups: dict[str, list[FileRecord]] = defaultdict(list)
        for f in files:
            fid = f.id or 0
            score = scores.get(fid)
            domain = (score.primary_domain if score else None) or "UNKNOWN"
            groups[domain].append(f)
        return groups

    def _group_by_directory(
        self, files: list[FileRecord]
    ) -> dict[str, list[FileRecord]]:
        groups: dict[str, list[FileRecord]] = defaultdict(list)
        for f in files:
            parent = str(Path(f.path).parent)
            groups[parent].append(f)
        # Only return dirs with 3+ files
        return {k: v for k, v in groups.items() if len(v) >= 3}

    # ── Analyzers ─────────────────────────────────────────────────────────────

    def _analyze_domain_cluster(
        self,
        domain: str,
        files: list[FileRecord],
        scan_id: int,
        contents: dict[str, str],
    ) -> None:
        """Detect project opportunities within a domain cluster."""
        if len(files) < 3:
            return

        code_files = [f for f in files if f.extension in CODE_EXTENSIONS]
        data_files = [f for f in files if f.extension in DATA_EXTENSIONS]
        doc_files = [f for f in files if f.extension in DOC_EXTENSIONS]

        total_bytes = sum(f.size_bytes for f in files)
        has_engine = domain in DOMAIN_ENGINE_MAP and DOMAIN_ENGINE_MAP[domain] is not None

        # PATTERN: Heavy data domain, no code → needs pipeline
        if len(data_files) > 5 and len(code_files) == 0:
            priority = _score_priority(
                len(files), total_bytes, has_engine,
                0.0, len(data_files) / max(1, len(files))
            )
            self._proposals.append({
                "scan_id": scan_id,
                "proposal_type": "PROJECT",
                "category": "DATA_PIPELINE",
                "domain": domain,
                "title": f"Build {domain} Data Pipeline",
                "summary": (
                    f"Found {len(data_files)} {domain} data files "
                    f"({_human_size(total_bytes)}) with zero processing code. "
                    f"A dedicated ingestion + transformation pipeline would unlock "
                    f"this data for AI queries and reporting."
                ),
                "rationale": [
                    f"{len(data_files)} data files found ({', '.join(set(f.extension for f in data_files))})",
                    f"0 code files in domain — no automation exists",
                    f"Total data volume: {_human_size(total_bytes)}",
                    f"Echo Engine Runtime has {domain} engines ready to classify",
                ],
                "suggested_stack": ["Python 3.11", "Pandas/Polars", "SQLite", "Cloudflare Worker", "Echo Engine Runtime"],
                "suggested_name": f"echo-{domain.lower()}-pipeline",
                "effort_estimate": "Medium (2-4 days)",
                "priority_score": priority,
                "source_files": [f.path for f in data_files[:10]],
                "file_count": len(files),
                "total_bytes": total_bytes,
                "created_at": _now_iso(),
            })

        # PATTERN: Domain docs + data, no API integration
        if len(doc_files) > 10 and len(data_files) > 3 and len(code_files) < 3:
            priority = _score_priority(len(files), total_bytes, has_engine, 0.1, 0.5)
            self._proposals.append({
                "scan_id": scan_id,
                "proposal_type": "PROJECT",
                "category": "KNOWLEDGE_API",
                "domain": domain,
                "title": f"Build {domain} Knowledge API",
                "summary": (
                    f"Large {domain} document library ({len(doc_files)} docs + "
                    f"{len(data_files)} data files) has no query interface. "
                    f"A RAG-backed knowledge API would make this searchable and AI-accessible."
                ),
                "rationale": [
                    f"{len(doc_files)} documents in {domain} domain",
                    f"{len(data_files)} structured data files",
                    "No REST API or query layer found",
                    "Echo Knowledge Forge + Graph RAG infrastructure already available",
                ],
                "suggested_stack": ["FastAPI", "ChromaDB", "Echo Knowledge Forge", "Echo Graph RAG"],
                "suggested_name": f"echo-{domain.lower()}-knowledge-api",
                "effort_estimate": "Small (1-2 days)",
                "priority_score": priority,
                "source_files": [f.path for f in (doc_files + data_files)[:10]],
                "file_count": len(files),
                "total_bytes": total_bytes,
                "created_at": _now_iso(),
            })

    def _analyze_directory_cluster(
        self,
        dir_path: str,
        files: list[FileRecord],
        scan_id: int,
        contents: dict[str, str],
    ) -> None:
        """Detect partial implementations in a directory cluster."""
        code_files = [f for f in files if f.extension in CODE_EXTENSIONS]
        if len(code_files) < 2:
            return

        total_bytes = sum(f.size_bytes for f in files)
        fragment_count = 0
        logic_sigs: list[dict[str, Any]] = []
        all_functions: list[str] = []
        all_classes: list[str] = []
        capability_flags: dict[str, bool] = {
            "has_main": False, "has_cli": False, "has_api": False,
            "has_db": False, "has_auth": False,
        }

        for f in code_files:
            content = contents.get(f.path, "")
            if content:
                sigs = _extract_logic_signatures(content)
                logic_sigs.append(sigs)
                all_functions.extend(sigs["functions"])
                all_classes.extend(sigs["classes"])
                if sigs["fragment_signals"]:
                    fragment_count += 1
                for flag in capability_flags:
                    if sigs.get(flag):
                        capability_flags[flag] = True

        fragment_density = fragment_count / max(1, len(code_files))

        # PATTERN: Partial implementation with real capability flags
        if fragment_density > 0.3 and (
            capability_flags["has_main"] or capability_flags["has_cli"] or capability_flags["has_api"]
        ):
            capabilities = [k.replace("has_", "") for k, v in capability_flags.items() if v]
            dir_name = Path(dir_path).name

            self._proposals.append({
                "scan_id": scan_id,
                "proposal_type": "PROGRAM",
                "category": "PROMOTE_PARTIAL",
                "domain": "CODE",
                "title": f"Promote '{dir_name}' to Full Application",
                "summary": (
                    f"Directory '{dir_path}' contains {len(code_files)} code files "
                    f"with {int(fragment_density * 100)}% fragment density. "
                    f"Detected capabilities: {', '.join(capabilities)}. "
                    f"This partial implementation has enough structure to become a "
                    f"production application with cleanup and completion."
                ),
                "rationale": [
                    f"{len(code_files)} code files with existing logic",
                    f"{int(fragment_density * 100)}% contain TODO/WIP/incomplete markers",
                    f"Detected: {', '.join(capabilities)}",
                    f"{len(set(all_functions))} unique functions already implemented",
                    f"{len(set(all_classes))} classes defined",
                ],
                "suggested_stack": self._infer_stack(logic_sigs),
                "suggested_name": dir_name.lower().replace(" ", "-"),
                "effort_estimate": self._estimate_effort(len(code_files), fragment_density),
                "priority_score": _score_priority(
                    len(files), total_bytes, False, fragment_density, 0.0
                ),
                "source_files": [f.path for f in code_files[:10]],
                "existing_functions": list(set(all_functions))[:20],
                "existing_classes": list(set(all_classes))[:10],
                "capabilities": capabilities,
                "file_count": len(files),
                "total_bytes": total_bytes,
                "created_at": _now_iso(),
            })

    def _detect_duplicate_logic(
        self,
        files: list[FileRecord],
        scan_id: int,
        contents: dict[str, str],
    ) -> None:
        """Find duplicate function names across separate files — unify into shared lib."""
        code_files = [f for f in files if f.extension in CODE_EXTENSIONS and f.path in contents]
        if len(code_files) < 5:
            return

        func_to_files: dict[str, list[str]] = defaultdict(list)
        for f in code_files:
            content = contents.get(f.path, "")
            funcs = re.findall(r"(?:def|function|func)\s+(\w+)\s*\(", content)
            for fn in set(funcs):
                if len(fn) > 4:  # skip trivial names
                    func_to_files[fn].append(f.path)

        # Functions appearing in 3+ files
        duplicated = {fn: paths for fn, paths in func_to_files.items() if len(paths) >= 3}

        if len(duplicated) >= 5:
            total_bytes = sum(f.size_bytes for f in code_files)
            self._proposals.append({
                "scan_id": scan_id,
                "proposal_type": "PROGRAM",
                "category": "SHARED_LIBRARY",
                "domain": "CODE",
                "title": "Build Shared Utility Library",
                "summary": (
                    f"Found {len(duplicated)} functions duplicated across 3+ files. "
                    f"Consolidating into a shared library would reduce maintenance "
                    f"burden and create a single source of truth for core logic."
                ),
                "rationale": [
                    f"{len(duplicated)} duplicate functions detected across {len(code_files)} files",
                    "Top duplicates: " + ", ".join(list(duplicated.keys())[:8]),
                    "Shared library would enable single import across all projects",
                ],
                "suggested_stack": ["Python 3.11", "setuptools", "PyPI (private)"],
                "suggested_name": "echo-shared-utils",
                "effort_estimate": "Small-Medium (1-3 days)",
                "priority_score": min(100.0, 40.0 + len(duplicated) * 1.5),
                "duplicate_functions": list(duplicated.keys())[:30],
                "source_files": list({p for paths in list(duplicated.values())[:10] for p in paths})[:15],
                "file_count": len(code_files),
                "total_bytes": total_bytes,
                "created_at": _now_iso(),
            })

    def _detect_orphaned_data(
        self,
        files: list[FileRecord],
        scan_id: int,
    ) -> None:
        """Find large data files with no nearby code — build a viewer/processor."""
        # Group data files by parent directory
        data_by_dir: dict[str, list[FileRecord]] = defaultdict(list)
        code_dirs: set[str] = set()

        for f in files:
            parent = str(Path(f.path).parent)
            if f.extension in DATA_EXTENSIONS:
                data_by_dir[parent].append(f)
            elif f.extension in CODE_EXTENSIONS:
                code_dirs.add(parent)

        for dir_path, data_files in data_by_dir.items():
            if dir_path in code_dirs:
                continue  # has code nearby
            total_bytes = sum(f.size_bytes for f in data_files)
            if total_bytes < 1_000_000:  # skip tiny data
                continue

            extensions = list(set(f.extension for f in data_files))
            dir_name = Path(dir_path).name

            self._proposals.append({
                "scan_id": scan_id,
                "proposal_type": "PROGRAM",
                "category": "DATA_VIEWER",
                "domain": "DATA",
                "title": f"Build Data Processor for '{dir_name}'",
                "summary": (
                    f"{len(data_files)} data files ({_human_size(total_bytes)}) in "
                    f"'{dir_path}' have no processing code in the same directory. "
                    f"Build a processor/viewer to make this data actionable."
                ),
                "rationale": [
                    f"{len(data_files)} data files: {', '.join(extensions)}",
                    f"Total size: {_human_size(total_bytes)}",
                    "No code files found in same directory",
                    "Data is currently read-only, inaccessible to AI systems",
                ],
                "suggested_stack": self._suggest_stack_for_extensions(extensions),
                "suggested_name": f"{dir_name.lower().replace(' ', '-')}-processor",
                "effort_estimate": "Small (0.5-1 day)",
                "priority_score": _score_priority(
                    len(data_files), total_bytes, False, 0.0, 1.0
                ),
                "source_files": [f.path for f in data_files[:10]],
                "file_count": len(data_files),
                "total_bytes": total_bytes,
                "created_at": _now_iso(),
            })

    def _detect_promoted_scripts(
        self,
        files: list[FileRecord],
        scan_id: int,
        contents: dict[str, str],
    ) -> None:
        """Detect scripts that have grown into application scope."""
        large_scripts = [
            f for f in files
            if f.extension in {".py", ".js", ".ts", ".ps1"}
            and f.size_bytes > 15_000  # 15KB+ single-file script
        ]

        for f in large_scripts:
            content = contents.get(f.path, "")
            sigs = _extract_logic_signatures(content)

            capability_count = sum([
                sigs["has_main"], sigs["has_cli"], sigs["has_api"],
                sigs["has_db"], sigs["has_auth"],
            ])
            func_count = len(set(sigs["functions"]))
            class_count = len(set(sigs["classes"]))

            # Big script with multiple capabilities = promote to proper package
            if capability_count >= 3 or (func_count >= 15 and class_count >= 2):
                fname = Path(f.path).stem
                self._proposals.append({
                    "scan_id": scan_id,
                    "proposal_type": "PROGRAM",
                    "category": "PROMOTE_SCRIPT",
                    "domain": "CODE",
                    "title": f"Promote '{f.filename}' to Package",
                    "summary": (
                        f"'{f.filename}' ({_human_size(f.size_bytes)}) is a monolithic script "
                        f"with {func_count} functions, {class_count} classes, and "
                        f"{capability_count} capability types. It has grown beyond script scope "
                        f"and should be refactored into a proper package with CLI, tests, and docs."
                    ),
                    "rationale": [
                        f"{func_count} functions, {class_count} classes in single file",
                        f"File size: {_human_size(f.size_bytes)} (exceeds script threshold)",
                        f"Capabilities: {[k for k,v in {'CLI': sigs['has_cli'], 'API': sigs['has_api'], 'DB': sigs['has_db'], 'Auth': sigs['has_auth']}.items() if v]}",
                        "Refactoring would improve maintainability and testability",
                    ],
                    "suggested_stack": self._infer_stack([sigs]),
                    "suggested_name": fname.lower().replace("_", "-"),
                    "effort_estimate": "Medium (2-3 days refactor)",
                    "priority_score": min(100.0, 35.0 + func_count * 0.8 + capability_count * 5),
                    "source_files": [f.path],
                    "existing_functions": sigs["functions"][:20],
                    "existing_classes": sigs["classes"][:10],
                    "capabilities": [k for k, v in {
                        "cli": sigs["has_cli"], "api": sigs["has_api"],
                        "db": sigs["has_db"], "auth": sigs["has_auth"],
                    }.items() if v],
                    "file_count": 1,
                    "total_bytes": f.size_bytes,
                    "created_at": _now_iso(),
                })

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _infer_stack(self, logic_sigs: list[dict[str, Any]]) -> list[str]:
        """Infer likely tech stack from logic signatures."""
        stack: list[str] = []
        all_imports: list[str] = []
        for s in logic_sigs:
            all_imports.extend(s.get("imports", []))

        import_str = " ".join(all_imports).lower()

        if "fastapi" in import_str or any(s.get("has_api") for s in logic_sigs):
            stack.append("FastAPI")
        if "flask" in import_str:
            stack.append("Flask")
        if "react" in import_str or "jsx" in import_str:
            stack.append("React")
        if "sqlite" in import_str or any(s.get("has_db") for s in logic_sigs):
            stack.append("SQLite")
        if "aiohttp" in import_str or "asyncio" in import_str:
            stack.append("asyncio")
        if "pandas" in import_str:
            stack.append("Pandas")
        if "torch" in import_str or "tensorflow" in import_str:
            stack.append("PyTorch/TF")
        if "loguru" in import_str:
            stack.append("loguru")
        if "pydantic" in import_str:
            stack.append("Pydantic")
        if "click" in import_str or any(s.get("has_cli") for s in logic_sigs):
            stack.append("Click/Typer")

        if not stack:
            stack.append("Python 3.11")

        return stack[:6]

    def _suggest_stack_for_extensions(self, extensions: list[str]) -> list[str]:
        """Suggest processing stack based on data file types."""
        stack: list[str] = []
        ext_set = set(extensions)
        if ".csv" in ext_set or ".xlsx" in ext_set or ".xls" in ext_set:
            stack.extend(["Pandas", "openpyxl"])
        if ".json" in ext_set or ".jsonl" in ext_set or ".ndjson" in ext_set:
            stack.append("orjson")
        if ".parquet" in ext_set or ".arrow" in ext_set or ".feather" in ext_set:
            stack.extend(["PyArrow", "Polars"])
        if ".db" in ext_set or ".sqlite" in ext_set or ".sqlite3" in ext_set:
            stack.append("SQLite/SQLAlchemy")
        if ".pdf" in ext_set:
            stack.extend(["pdfplumber", "pypdf2"])
        if not stack:
            stack.append("Python 3.11")
        return stack[:5]

    def _estimate_effort(self, file_count: int, fragment_density: float) -> str:
        if fragment_density > 0.7:
            return "Large (5-10 days — heavy rework needed)"
        elif file_count > 20:
            return "Medium-Large (3-5 days)"
        elif file_count > 10:
            return "Medium (2-3 days)"
        else:
            return "Small-Medium (1-2 days)"


# ── Knowledge Forge Integration ───────────────────────────────────────────────


def format_proposals_for_knowledge_forge(
    proposals: list[dict[str, Any]],
    scan_id: int,
    scan_paths: list[str],
) -> dict[str, Any]:
    """Format all proposals into a Knowledge Forge ingest payload."""
    projects = [p for p in proposals if p["proposal_type"] == "PROJECT"]
    programs = [p for p in proposals if p["proposal_type"] == "PROGRAM"]

    content_lines = [
        f"# Project Advisor Report — Scan #{scan_id}",
        f"**Scan Paths:** {', '.join(scan_paths)}",
        f"**Generated:** {_now_iso()}",
        f"**Total Proposals:** {len(proposals)} ({len(projects)} projects, {len(programs)} programs)",
        "",
        "---",
        "",
        "## 🏗️ PROJECT PROPOSALS (New Builds)",
        "",
    ]

    for i, p in enumerate(projects, 1):
        content_lines += [
            f"### {i}. {p['title']}",
            f"**Priority:** {p['priority_score']:.0f}/100 | **Domain:** {p['domain']} | **Effort:** {p['effort_estimate']}",
            f"**Category:** {p['category']}",
            "",
            p["summary"],
            "",
            "**Rationale:**",
        ]
        for r in p.get("rationale", []):
            content_lines.append(f"- {r}")
        stack = p.get("suggested_stack", [])
        if stack:
            content_lines.append(f"\n**Suggested Stack:** {', '.join(stack)}")
        name = p.get("suggested_name", "")
        if name:
            content_lines.append(f"**Suggested Name:** `{name}`")
        content_lines.append("")

    content_lines += [
        "---",
        "",
        "## 💡 PROGRAM RECOMMENDATIONS (From Existing Logic)",
        "",
    ]

    for i, p in enumerate(programs, 1):
        content_lines += [
            f"### {i}. {p['title']}",
            f"**Priority:** {p['priority_score']:.0f}/100 | **Category:** {p['category']} | **Effort:** {p['effort_estimate']}",
            "",
            p["summary"],
            "",
            "**Rationale:**",
        ]
        for r in p.get("rationale", []):
            content_lines.append(f"- {r}")

        if p.get("existing_functions"):
            funcs = p["existing_functions"][:10]
            content_lines.append(f"\n**Existing Functions:** {', '.join(funcs)}")
        if p.get("capabilities"):
            content_lines.append(f"**Detected Capabilities:** {', '.join(p['capabilities'])}")
        stack = p.get("suggested_stack", [])
        if stack:
            content_lines.append(f"**Stack:** {', '.join(stack)}")
        content_lines.append("")

    return {
        "title": f"Project Advisor Report — Scan #{scan_id}",
        "content": "\n".join(content_lines),
        "category": "SYSTEM_ARCHITECTURE",
        "doc_type": "project_advisor_report",
        "tags": ["project-advisor", "stage10", f"scan-{scan_id}", "recommendations", "programs"],
    }


# ── DB Storage Helpers ────────────────────────────────────────────────────────


def store_proposals_to_db(db_path: str, proposals: list[dict[str, Any]]) -> int:
    """Store proposals to SQLite. Returns count stored."""
    import sqlite3
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS project_proposals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            proposal_type TEXT NOT NULL,
            category TEXT NOT NULL,
            domain TEXT,
            title TEXT NOT NULL,
            summary TEXT,
            rationale TEXT,
            suggested_stack TEXT,
            suggested_name TEXT,
            effort_estimate TEXT,
            priority_score REAL DEFAULT 0,
            source_files TEXT,
            existing_functions TEXT,
            existing_classes TEXT,
            capabilities TEXT,
            duplicate_functions TEXT,
            file_count INTEGER DEFAULT 0,
            total_bytes INTEGER DEFAULT 0,
            created_at TEXT
        )
    """)

    count = 0
    for p in proposals:
        cur.execute("""
            INSERT INTO project_proposals (
                scan_id, proposal_type, category, domain, title, summary,
                rationale, suggested_stack, suggested_name, effort_estimate,
                priority_score, source_files, existing_functions, existing_classes,
                capabilities, duplicate_functions, file_count, total_bytes, created_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            p.get("scan_id"), p.get("proposal_type"), p.get("category"),
            p.get("domain"), p.get("title"), p.get("summary"),
            json.dumps(p.get("rationale", [])),
            json.dumps(p.get("suggested_stack", [])),
            p.get("suggested_name"), p.get("effort_estimate"),
            p.get("priority_score", 0),
            json.dumps(p.get("source_files", [])),
            json.dumps(p.get("existing_functions", [])),
            json.dumps(p.get("existing_classes", [])),
            json.dumps(p.get("capabilities", [])),
            json.dumps(p.get("duplicate_functions", [])),
            p.get("file_count", 0), p.get("total_bytes", 0),
            p.get("created_at"),
        ))
        count += 1

    conn.commit()
    conn.close()
    return count
