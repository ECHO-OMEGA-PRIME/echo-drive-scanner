"""
EKM Generator — Generate Echo Knowledge Memories from intelligent scan results.
=================================================================================
Groups classified files by domain, finds incomplete projects, suggests new projects
from gap analysis, and pushes EKMs to Shared Brain / Memory Prime / Knowledge Forge.
"""

from __future__ import annotations

import asyncio
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
# Endpoints come from env; empty means "not configured" → pushes are skipped.

import os

SHARED_BRAIN_URL = os.environ.get("DRIVESCAN_SHARED_BRAIN_URL", "")
MEMORY_PRIME_URL = os.environ.get("DRIVESCAN_MEMORY_PRIME_URL", "")
KNOWLEDGE_FORGE_URL = os.environ.get("DRIVESCAN_KNOWLEDGE_FORGE_URL", "")

# Minimum file patterns that indicate a "complete" project
PROJECT_COMPLETENESS_PATTERNS: dict[str, list[str]] = {
    "python_package": ["__init__.py", "*.py", "requirements.txt"],
    "python_app": ["*.py", "requirements.txt"],
    "fastapi_service": ["*.py", "requirements.txt"],
    "nextjs_app": ["package.json", "next.config.*", "app/page.tsx", "app/layout.tsx"],
    "cloudflare_worker": ["wrangler.toml", "src/index.ts", "package.json"],
    "node_project": ["package.json", "*.js"],
    "documentation": ["README.md"],
}

# Known engine tier prefixes (from build plan v7.1)
ENGINE_TIERS = [
    "LG", "LM", "TX", "PRB", "REG", "ENT", "SYN", "WAT", "GEO", "INT",
    "ET", "GS", "GOV", "DRL", "MECH", "AUTO", "AERO", "ENRG", "MED",
    "OFE", "RAIL", "FRAC", "PROD", "CHEM", "MARINE", "INS", "RE", "ACCT",
    "SCM", "TELE", "MINE", "FOOD", "VET", "FOREN", "LING", "MUSIC",
    "ARCH", "EE", "HVAC", "WELD", "NUC", "RENEW", "CRYPTO", "SPORT",
    "WEATHER", "ASTRO", "CYBER", "PROG", "FIN", "ENV",
]


# ─── Models ──────────────────────────────────────────────────────────────────

class DomainSummaryEKM(BaseModel):
    domain: str
    domain_label: str = ""
    file_count: int = 0
    total_size_bytes: int = 0
    avg_quality_score: float = 0.0
    avg_importance_score: float = 0.0
    top_files: list[dict[str, Any]] = Field(default_factory=list)
    key_topics: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)


class IncompleteProject(BaseModel):
    path: str
    name: str
    project_type: str
    present_files: list[str] = Field(default_factory=list)
    missing_patterns: list[str] = Field(default_factory=list)
    completeness_pct: float = 0.0
    suggestion: str = ""


class ProjectSuggestion(BaseModel):
    title: str
    description: str
    rationale: str
    related_domains: list[str] = Field(default_factory=list)
    related_files: int = 0
    priority: str = "medium"


class EKMGenerationResult(BaseModel):
    domain_summaries: list[DomainSummaryEKM] = Field(default_factory=list)
    incomplete_projects: list[IncompleteProject] = Field(default_factory=list)
    project_suggestions: list[ProjectSuggestion] = Field(default_factory=list)
    ekms_pushed: int = 0
    errors: list[str] = Field(default_factory=list)


# ─── EKM Generator ──────────────────────────────────────────────────────────

class EKMGenerator:
    """Generate EKMs from intelligent scan results and push to cloud memory."""

    def __init__(self, db: Any) -> None:
        self.db = db

    async def generate(self, scan_id: int) -> EKMGenerationResult:
        """Run full EKM generation pipeline."""
        result = EKMGenerationResult()

        # Phase 1: Domain summaries
        domain_stats = self.db.get_domain_stats(scan_id)
        for ds in domain_stats:
            summary = self._build_domain_summary(scan_id, ds)
            result.domain_summaries.append(summary)

        # Phase 2: Find incomplete projects
        files = self.db.list_files(scan_id=scan_id, limit=50000)
        result.incomplete_projects = self._find_incomplete_projects(files)

        # Phase 3: Gap analysis → project suggestions
        result.project_suggestions = self._suggest_projects(
            result.domain_summaries, result.incomplete_projects, files
        )

        # Phase 4: Push to cloud
        pushed = await self._push_to_cloud(result)
        result.ekms_pushed = pushed

        logger.info(
            f"EKM generation complete: {len(result.domain_summaries)} domain summaries, "
            f"{len(result.incomplete_projects)} incomplete projects, "
            f"{len(result.project_suggestions)} suggestions, "
            f"{pushed} EKMs pushed to cloud"
        )
        return result

    def _build_domain_summary(self, scan_id: int, ds: Any) -> DomainSummaryEKM:
        """Build a domain summary EKM from domain stats."""
        top_scores = self.db.get_top_scores("overall_score", limit=10)
        domain_top = [
            s for s in top_scores
            if s.get("primary_domain") == ds.domain
        ][:5]

        recs = self.db.get_recommendations(scan_id=scan_id, limit=100)
        domain_recs = []
        for r in recs:
            try:
                affected = json.loads(r.affected_files) if isinstance(r.affected_files, str) else r.affected_files
                if affected and isinstance(affected, list):
                    domain_recs.append(r.title)
            except (json.JSONDecodeError, AttributeError):
                pass

        topics = []
        if hasattr(ds, "top_topics") and ds.top_topics:
            try:
                topics = json.loads(ds.top_topics) if isinstance(ds.top_topics, str) else ds.top_topics
            except (json.JSONDecodeError, TypeError):
                pass

        return DomainSummaryEKM(
            domain=ds.domain,
            domain_label=getattr(ds, "domain_label", None) or ds.domain,
            file_count=ds.file_count,
            total_size_bytes=ds.total_size_bytes,
            avg_quality_score=getattr(ds, "avg_score", 0.0) or 0.0,
            avg_importance_score=0.0,
            top_files=[{"path": f.get("path", ""), "score": f.get("overall_score", 0)} for f in domain_top],
            key_topics=topics[:10] if isinstance(topics, list) else [],
            recommendations=domain_recs[:5],
        )

    def _find_incomplete_projects(self, files: list[Any]) -> list[IncompleteProject]:
        """Scan directories for incomplete project structures."""
        incomplete = []
        dir_files: dict[str, list[str]] = defaultdict(list)

        for f in files:
            parent = str(Path(f.path).parent) if hasattr(f, "path") else str(Path(f.get("path", "")).parent)
            name = Path(f.path).name if hasattr(f, "path") else Path(f.get("path", "")).name
            dir_files[parent].append(name)

        for dir_path, filenames in dir_files.items():
            if len(filenames) < 2:
                continue

            for proj_type, patterns in PROJECT_COMPLETENESS_PATTERNS.items():
                present = []
                missing = []
                for pattern in patterns:
                    if pattern.startswith("*"):
                        ext = pattern[1:]
                        if any(fn.endswith(ext) for fn in filenames):
                            present.append(pattern)
                        else:
                            missing.append(pattern)
                    elif "/" in pattern:
                        subpath = Path(dir_path) / pattern.split("/")[0]
                        subfile = pattern.split("/")[-1]
                        if subpath.exists():
                            sub_files = dir_files.get(str(subpath), [])
                            if any(fn == subfile or (subfile.startswith("*") and fn.endswith(subfile[1:])) for fn in sub_files):
                                present.append(pattern)
                            else:
                                missing.append(pattern)
                        else:
                            missing.append(pattern)
                    else:
                        if pattern in filenames:
                            present.append(pattern)
                        else:
                            missing.append(pattern)

                total = len(patterns)
                found = len(present)
                if 0 < found < total and found >= 1:
                    pct = round(found / total * 100, 1)
                    if pct < 90:
                        incomplete.append(IncompleteProject(
                            path=dir_path,
                            name=Path(dir_path).name,
                            project_type=proj_type,
                            present_files=present,
                            missing_patterns=missing,
                            completeness_pct=pct,
                            suggestion=f"Add {', '.join(missing)} to complete {proj_type} structure",
                        ))
                        break

        incomplete.sort(key=lambda x: x.completeness_pct, reverse=True)
        return incomplete[:100]

    def _suggest_projects(
        self,
        summaries: list[DomainSummaryEKM],
        incomplete: list[IncompleteProject],
        files: list[Any],
    ) -> list[ProjectSuggestion]:
        """Suggest new projects based on gap analysis."""
        suggestions: list[ProjectSuggestion] = []

        # Check which domains have many files but no dedicated engine/dashboard
        for s in summaries:
            if s.file_count > 50 and s.domain not in ("PROG", "UNKNOWN"):
                suggestions.append(ProjectSuggestion(
                    title=f"{s.domain} Dashboard",
                    description=f"Build a web dashboard for {s.domain_label or s.domain} domain ({s.file_count} files detected)",
                    rationale=f"High file count ({s.file_count}) in {s.domain} domain suggests dedicated UI would improve workflow",
                    related_domains=[s.domain],
                    related_files=s.file_count,
                    priority="high" if s.file_count > 200 else "medium",
                ))

        # Check for domains with high-quality files but no engine tier
        for s in summaries:
            if s.avg_quality_score > 0.7 and s.domain not in ENGINE_TIERS:
                suggestions.append(ProjectSuggestion(
                    title=f"{s.domain} Intelligence Engine",
                    description=f"Create TIE-grade engine for {s.domain_label or s.domain} domain",
                    rationale=f"High-quality files (avg {s.avg_quality_score:.1%}) in unindexed domain",
                    related_domains=[s.domain],
                    related_files=s.file_count,
                    priority="medium",
                ))

        # Check for many incomplete projects in a domain → consolidation tool
        domain_incomplete: dict[str, int] = defaultdict(int)
        for proj in incomplete:
            for s in summaries:
                proj_lower = proj.path.lower()
                if s.domain.lower() in proj_lower:
                    domain_incomplete[s.domain] += 1
                    break

        for domain, count in domain_incomplete.items():
            if count >= 3:
                suggestions.append(ProjectSuggestion(
                    title=f"{domain} Project Consolidator",
                    description=f"Tool to merge/complete {count} incomplete {domain} projects",
                    rationale=f"{count} incomplete projects detected in {domain} domain",
                    related_domains=[domain],
                    related_files=count,
                    priority="low",
                ))

        # Check for TODO/FIXME density
        todo_count = sum(
            1 for f in files
            if hasattr(f, "content_sample") and f.content_sample
            and re.search(r"(?i)\b(TODO|FIXME|HACK|XXX)\b", f.content_sample or "")
        )
        if todo_count > 20:
            suggestions.append(ProjectSuggestion(
                title="Technical Debt Tracker",
                description=f"Build a TODO/FIXME tracker for {todo_count} occurrences found",
                rationale=f"High TODO density ({todo_count} files) indicates unfinished work",
                related_domains=["PROG"],
                related_files=todo_count,
                priority="medium",
            ))

        suggestions.sort(key=lambda x: {"high": 0, "medium": 1, "low": 2}[x.priority])
        return suggestions[:20]

    async def _push_to_cloud(self, result: EKMGenerationResult) -> int:
        """Push generated EKMs to Shared Brain, Memory Prime, and Knowledge Forge."""
        if not (SHARED_BRAIN_URL or MEMORY_PRIME_URL or KNOWLEDGE_FORGE_URL):
            logger.info("EKM push disabled — no endpoints configured")
            return 0
        pushed = 0
        async with httpx.AsyncClient(timeout=15.0) as client:
            # Push domain summaries
            for summary in (result.domain_summaries if SHARED_BRAIN_URL else []):
                content = (
                    f"DOMAIN SCAN SUMMARY [{summary.domain}]: {summary.file_count} files, "
                    f"{summary.total_size_bytes / (1024*1024):.1f} MB, "
                    f"quality={summary.avg_quality_score:.1%}. "
                    f"Topics: {', '.join(summary.key_topics[:5])}. "
                    f"Recommendations: {'; '.join(summary.recommendations[:3])}"
                )
                try:
                    resp = await client.post(
                        f"{SHARED_BRAIN_URL}/ingest",
                        json={
                            "instance_id": "scanner_ekm_generator",
                            "role": "assistant",
                            "content": content,
                            "importance": 6,
                            "tags": ["scan", "domain", summary.domain, "ekm"],
                        },
                    )
                    if resp.status_code < 300:
                        pushed += 1
                except Exception as e:
                    result.errors.append(f"Brain push failed for {summary.domain}: {e}")
                    logger.warning(f"Shared Brain push failed: {e}")

            # Push incomplete projects as a batch
            if result.incomplete_projects and SHARED_BRAIN_URL:
                incomplete_text = "INCOMPLETE PROJECTS DETECTED:\n" + "\n".join(
                    f"- {p.name} ({p.project_type}) at {p.path}: {p.completeness_pct}% complete, missing {', '.join(p.missing_patterns)}"
                    for p in result.incomplete_projects[:20]
                )
                try:
                    resp = await client.post(
                        f"{SHARED_BRAIN_URL}/ingest",
                        json={
                            "instance_id": "scanner_ekm_generator",
                            "role": "assistant",
                            "content": incomplete_text,
                            "importance": 7,
                            "tags": ["scan", "incomplete", "projects", "ekm"],
                        },
                    )
                    if resp.status_code < 300:
                        pushed += 1
                except Exception as e:
                    result.errors.append(f"Incomplete projects push failed: {e}")

            # Push project suggestions
            if result.project_suggestions and SHARED_BRAIN_URL:
                suggestions_text = "PROJECT SUGGESTIONS FROM SCAN:\n" + "\n".join(
                    f"- [{s.priority.upper()}] {s.title}: {s.description} ({s.rationale})"
                    for s in result.project_suggestions[:10]
                )
                try:
                    resp = await client.post(
                        f"{SHARED_BRAIN_URL}/ingest",
                        json={
                            "instance_id": "scanner_ekm_generator",
                            "role": "assistant",
                            "content": suggestions_text,
                            "importance": 7,
                            "tags": ["scan", "suggestions", "projects", "ekm"],
                        },
                    )
                    if resp.status_code < 300:
                        pushed += 1
                except Exception as e:
                    result.errors.append(f"Suggestions push failed: {e}")

            # Push to Memory Prime as structured data
            if MEMORY_PRIME_URL:
                try:
                    resp = await client.post(
                        f"{MEMORY_PRIME_URL}/store",
                        json={
                            "category": "scan_intelligence",
                            "content": json.dumps({
                                "domains": len(result.domain_summaries),
                                "incomplete_projects": len(result.incomplete_projects),
                                "suggestions": len(result.project_suggestions),
                                "top_domains": [
                                    {"domain": s.domain, "files": s.file_count}
                                    for s in sorted(result.domain_summaries, key=lambda x: x.file_count, reverse=True)[:10]
                                ],
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                            }),
                            "tags": ["scan", "ekm", "intelligence"],
                        },
                    )
                    if resp.status_code < 300:
                        pushed += 1
                except Exception as e:
                    result.errors.append(f"Memory Prime push failed: {e}")

            # Push domain summaries to Knowledge Forge as individual documents
            for summary in (result.domain_summaries if KNOWLEDGE_FORGE_URL else []):
                try:
                    forge_content = (
                        f"DOMAIN EKM [{summary.domain}]: {summary.file_count} files, "
                        f"{summary.total_size_bytes / (1024*1024):.1f} MB, "
                        f"quality={summary.avg_quality_score:.1%}. "
                        f"Topics: {', '.join(summary.key_topics[:5])}. "
                        f"Top files: {'; '.join(f.get('path', '')[-60:] for f in summary.top_files[:3])}. "
                        f"Recommendations: {'; '.join(summary.recommendations[:3])}"
                    )
                    resp = await client.post(
                        f"{KNOWLEDGE_FORGE_URL}/ingest",
                        json={
                            "title": f"Domain EKM: {summary.domain_label or summary.domain}",
                            "content": forge_content,
                            "category": "ekm",
                            "tags": ["ekm", "domain", summary.domain, "scan"],
                            "metadata": {
                                "domain": summary.domain,
                                "file_count": summary.file_count,
                                "quality": summary.avg_quality_score,
                                "size_mb": round(summary.total_size_bytes / (1024 * 1024), 1),
                            },
                        },
                    )
                    if resp.status_code < 300:
                        pushed += 1
                except Exception as e:
                    result.errors.append(f"Knowledge Forge push failed for {summary.domain}: {e}")

            # Push project suggestions to Knowledge Forge
            if result.project_suggestions and KNOWLEDGE_FORGE_URL:
                try:
                    suggestions_forge = "PROJECT SUGGESTIONS FROM INTELLIGENCE SCAN:\n" + "\n".join(
                        f"[{s.priority.upper()}] {s.title}: {s.description}\n  Rationale: {s.rationale}\n  Domains: {', '.join(s.related_domains)}"
                        for s in result.project_suggestions[:15]
                    )
                    resp = await client.post(
                        f"{KNOWLEDGE_FORGE_URL}/ingest",
                        json={
                            "title": "Intelligence Scan Project Suggestions",
                            "content": suggestions_forge,
                            "category": "recommendation",
                            "tags": ["ekm", "suggestions", "projects", "scan"],
                            "metadata": {
                                "suggestion_count": len(result.project_suggestions),
                                "high_priority": sum(1 for s in result.project_suggestions if s.priority == "high"),
                            },
                        },
                    )
                    if resp.status_code < 300:
                        pushed += 1
                except Exception as e:
                    result.errors.append(f"Knowledge Forge suggestions push failed: {e}")

            # Push incomplete projects to Knowledge Forge
            if result.incomplete_projects and KNOWLEDGE_FORGE_URL:
                try:
                    incomplete_forge = "INCOMPLETE PROJECTS FROM INTELLIGENCE SCAN:\n" + "\n".join(
                        f"- {p.name} ({p.project_type}) at {p.path}: {p.completeness_pct}% complete\n  Present: {', '.join(p.present_files)}\n  Missing: {', '.join(p.missing_patterns)}"
                        for p in result.incomplete_projects[:20]
                    )
                    resp = await client.post(
                        f"{KNOWLEDGE_FORGE_URL}/ingest",
                        json={
                            "title": "Incomplete Projects Detected",
                            "content": incomplete_forge,
                            "category": "audit",
                            "tags": ["ekm", "incomplete", "projects", "scan"],
                            "metadata": {
                                "project_count": len(result.incomplete_projects),
                                "avg_completeness": round(
                                    sum(p.completeness_pct for p in result.incomplete_projects) / max(len(result.incomplete_projects), 1), 1
                                ),
                            },
                        },
                    )
                    if resp.status_code < 300:
                        pushed += 1
                except Exception as e:
                    result.errors.append(f"Knowledge Forge incomplete push failed: {e}")

        return pushed
