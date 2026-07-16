"""Intelligent Drive Scanner v2.0 — Multi-Engine Classification Pipeline.

Routes each file through the optimal engine(s) based on a 3-tier strategy:
  Tier 1 (Fast, 90%): Single engine query in FAST mode (~130ms)
  Tier 2 (Explore, 8%): Cross-domain + top 3 targeted queries (~287ms×3)
  Tier 3 (Deep, 2%): MEMO mode + AI Orchestrator deep analysis
"""

from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime
from typing import Any

from loguru import logger

from config import (
    BATCH_SIZE,
    BINARY_EXTENSIONS,
    CONCURRENT_BATCHES,
    EXECUTABLE_EXTENSIONS,
    TIER1_CONCURRENCY,
    TIER2_CONCURRENCY,
    TIER2_CONFIDENCE_THRESHOLD,
    TIER3_CONCURRENCY,
    TIER3_SIZE_THRESHOLD,
)
from storage.models import (
    Classification,
    ClassificationResult,
    ClassificationTier,
    EngineResult,
    FileRecord,
    FileSample,
    QueryMode,
)


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


# ── Priority Scoring ─────────────────────────────────────────────────────────

PRIORITY_EXTENSIONS: dict[str, int] = {
    **{ext: 100 for ext in EXECUTABLE_EXTENSIONS},
    ".xlsx": 80,
    ".xls": 80,
    ".csv": 70,
    ".pdf": 75,
    ".docx": 70,
    ".doc": 70,
    ".py": 60,
    ".js": 55,
    ".ts": 55,
    ".go": 55,
    ".rs": 55,
    ".sol": 90,
    ".asm": 85,
    ".sql": 65,
    ".db": 60,
    ".sqlite": 60,
    ".env": 95,
    ".pem": 95,
    ".key": 95,
    ".json": 50,
    ".yaml": 50,
    ".yml": 50,
    ".toml": 50,
}

PRIORITY_PATH_KEYWORDS: dict[str, int] = {
    "secret": 100,
    "credential": 100,
    "password": 100,
    "private": 95,
    "finance": 85,
    "accounting": 85,
    "legal": 80,
    "contract": 80,
    "security": 90,
    "cyber": 90,
    "malware": 95,
    "medical": 85,
    "patient": 90,
    "hipaa": 90,
    "tax": 80,
    "irs": 80,
}

FINANCIAL_KEYWORDS = {
    "invoice",
    "revenue",
    "balance",
    "ledger",
    "audit",
    "expense",
    "depreciat",
    "asset",
    "liability",
    "equity",
}
LEGAL_KEYWORDS = {
    "contract",
    "agreement",
    "clause",
    "indemnif",
    "warranty",
    "litigation",
    "settlement",
    "arbitrat",
    "damages",
}
SECURITY_KEYWORDS = {
    "vulnerability",
    "exploit",
    "malware",
    "trojan",
    "backdoor",
    "privilege",
    "escalat",
    "inject",
    "overflow",
    "payload",
}


def compute_file_priority(file: FileRecord | FileSample) -> int:
    """Compute classification priority for queue ordering (higher = process first)."""
    priority = 0

    ext = file.extension.lower() if file.extension else ""
    priority += PRIORITY_EXTENSIONS.get(ext, 0)

    path_lower = file.path.lower() if hasattr(file, "path") else ""
    for keyword, score in PRIORITY_PATH_KEYWORDS.items():
        if keyword in path_lower:
            priority += score
            break

    if file.size_bytes > TIER3_SIZE_THRESHOLD:
        priority += 20

    return priority


def determine_tier(sample: FileSample, file: FileRecord | None = None) -> ClassificationTier:
    """Determine which classification tier a file should use."""
    ext = sample.extension.lower()

    if ext in BINARY_EXTENSIONS and ext not in EXECUTABLE_EXTENSIONS:
        return ClassificationTier.TIER1_FAST

    if ext in EXECUTABLE_EXTENSIONS:
        return ClassificationTier.TIER3_DEEP

    if ext in {".env", ".pem", ".key", ".p12", ".pfx"}:
        return ClassificationTier.TIER3_DEEP

    if (
        sample.detected_domain != "UNKNOWN"
        and sample.domain_confidence >= TIER2_CONFIDENCE_THRESHOLD
    ):
        is_large_text = sample.size_bytes > TIER3_SIZE_THRESHOLD and not sample.is_binary
        has_financial = any(
            kw in (sample.content_sample or "").lower() for kw in FINANCIAL_KEYWORDS
        )
        has_legal = any(kw in (sample.content_sample or "").lower() for kw in LEGAL_KEYWORDS)
        has_security = any(kw in (sample.content_sample or "").lower() for kw in SECURITY_KEYWORDS)

        if is_large_text and (has_financial or has_legal or has_security):
            return ClassificationTier.TIER3_DEEP
        return ClassificationTier.TIER1_FAST

    if sample.detected_domain == "UNKNOWN" or sample.domain_confidence < TIER2_CONFIDENCE_THRESHOLD:
        if sample.size_bytes > TIER3_SIZE_THRESHOLD and not sample.is_binary:
            return ClassificationTier.TIER3_DEEP
        return ClassificationTier.TIER2_EXPLORE

    return ClassificationTier.TIER1_FAST


def _build_query_from_sample(sample: FileSample) -> str:
    """Build a query string from a file sample for engine queries."""
    parts: list[str] = []

    if sample.content_sample:
        text = sample.content_sample[:500]
        parts.append(text)

    if sample.keywords:
        parts.append(" ".join(sample.keywords[:20]))

    if not parts:
        parts.append(f"{sample.filename} {sample.extension} file analysis")

    return " ".join(parts)[:1000]


def _engine_result_to_classification(
    result: EngineResult,
    file_id: int,
    scan_id: int,
) -> Classification:
    """Convert an EngineResult to a Classification record."""
    return Classification(
        file_id=file_id,
        scan_id=scan_id,
        engine_id=result.engine_id,
        domain=result.domain,
        domain_label=result.domain_label,
        topic=result.topic,
        conclusion=result.conclusion,
        confidence=result.confidence,
        authority_weight=result.authority_weight,
        score=result.score,
        mode=result.mode,
        response_ms=result.response_ms,
        determinism_hash=result.determinism_hash,
        classified_at=_now_iso(),
    )


class ClassificationPipeline:
    """Multi-engine classification pipeline with 3-tier strategy.

    Manages the flow: File → Sample → Tier Selection → Engine Queries → Results.
    Uses an EngineClient for all API calls.
    """

    def __init__(self, engine_client: Any) -> None:
        self.client = engine_client
        self.stats = {
            "tier1_count": 0,
            "tier2_count": 0,
            "tier3_count": 0,
            "total_classified": 0,
            "total_api_calls": 0,
            "total_errors": 0,
            "total_ms": 0,
        }

    async def classify_file(
        self,
        sample: FileSample,
        file_id: int,
        scan_id: int,
    ) -> ClassificationResult:
        """Classify a single file through the appropriate tier."""
        tier = determine_tier(sample)
        query = _build_query_from_sample(sample)
        start = time.monotonic()

        try:
            if tier == ClassificationTier.TIER1_FAST:
                result = await self._tier1_classify(sample, query, file_id, scan_id)
            elif tier == ClassificationTier.TIER2_EXPLORE:
                result = await self._tier2_classify(sample, query, file_id, scan_id)
            else:
                result = await self._tier3_classify(sample, query, file_id, scan_id)
        except Exception as exc:
            logger.warning("Classification failed for {}: {}", sample.path, exc)
            self.stats["total_errors"] += 1
            result = ClassificationResult(
                file_path=sample.path,
                tier=tier,
                classifications=[],
                primary_domain=sample.detected_domain,
            )

        elapsed_ms = int((time.monotonic() - start) * 1000)
        result.total_ms = elapsed_ms
        self.stats["total_ms"] += elapsed_ms
        self.stats["total_classified"] += 1
        return result

    async def _tier1_classify(
        self,
        sample: FileSample,
        query: str,
        file_id: int,
        scan_id: int,
    ) -> ClassificationResult:
        """Tier 1: Single domain query in FAST mode."""
        self.stats["tier1_count"] += 1
        self.stats["total_api_calls"] += 1

        domain = sample.detected_domain if sample.detected_domain != "UNKNOWN" else "PROG"
        domain_result = await self.client.query_domain(domain, query, mode="FAST")

        classifications: list[Classification] = []
        domain_dist: dict[str, float] = {}

        for er in domain_result.results[:3]:
            cls = _engine_result_to_classification(er, file_id, scan_id)
            classifications.append(cls)
            domain_dist[er.domain] = domain_dist.get(er.domain, 0) + er.score

        primary_domain = domain
        primary_engine = ""
        if classifications:
            best = max(classifications, key=lambda c: c.score)
            primary_domain = best.domain
            primary_engine = best.engine_id

        return ClassificationResult(
            file_path=sample.path,
            tier=ClassificationTier.TIER1_FAST,
            classifications=classifications,
            primary_domain=primary_domain,
            primary_engine=primary_engine,
            domain_distribution=domain_dist,
        )

    async def _tier2_classify(
        self,
        sample: FileSample,
        query: str,
        file_id: int,
        scan_id: int,
    ) -> ClassificationResult:
        """Tier 2: Cross-domain discovery + targeted queries to top 3 domains."""
        self.stats["tier2_count"] += 1
        self.stats["total_api_calls"] += 1

        cross_result = await self.client.cross_domain_query(query, limit=5)

        domain_scores: dict[str, float] = {}
        for er in cross_result.results:
            domain_scores[er.domain] = domain_scores.get(er.domain, 0) + er.score

        top_domains = sorted(domain_scores.keys(), key=lambda d: domain_scores[d], reverse=True)[:3]

        classifications: list[Classification] = []
        domain_dist: dict[str, float] = {}

        for er in cross_result.results:
            cls = _engine_result_to_classification(er, file_id, scan_id)
            classifications.append(cls)
            domain_dist[er.domain] = domain_dist.get(er.domain, 0) + er.score

        tasks = []
        for domain in top_domains:
            tasks.append(self.client.query_domain(domain, query, mode="DEFENSE"))
            self.stats["total_api_calls"] += 1

        if tasks:
            domain_results = await asyncio.gather(*tasks, return_exceptions=True)
            for dr in domain_results:
                if isinstance(dr, Exception):
                    logger.warning("Tier 2 domain query failed: {}", dr)
                    continue
                for er in dr.results[:2]:
                    cls = _engine_result_to_classification(er, file_id, scan_id)
                    classifications.append(cls)
                    domain_dist[er.domain] = domain_dist.get(er.domain, 0) + er.score

        primary_domain = "UNKNOWN"
        primary_engine = ""
        if classifications:
            best = max(classifications, key=lambda c: c.score)
            primary_domain = best.domain
            primary_engine = best.engine_id

        return ClassificationResult(
            file_path=sample.path,
            tier=ClassificationTier.TIER2_EXPLORE,
            classifications=classifications,
            primary_domain=primary_domain,
            primary_engine=primary_engine,
            domain_distribution=domain_dist,
        )

    async def _tier3_classify(
        self,
        sample: FileSample,
        query: str,
        file_id: int,
        scan_id: int,
    ) -> ClassificationResult:
        """Tier 3: Deep analysis with MEMO mode + full reasoning."""
        self.stats["tier3_count"] += 1
        self.stats["total_api_calls"] += 1

        cross_result = await self.client.cross_domain_query(query, limit=5)

        domain_scores: dict[str, float] = {}
        for er in cross_result.results:
            domain_scores[er.domain] = domain_scores.get(er.domain, 0) + er.score

        top_domains = sorted(domain_scores.keys(), key=lambda d: domain_scores[d], reverse=True)[:2]

        classifications: list[Classification] = []
        domain_dist: dict[str, float] = {}

        for er in cross_result.results:
            cls = _engine_result_to_classification(er, file_id, scan_id)
            classifications.append(cls)
            domain_dist[er.domain] = domain_dist.get(er.domain, 0) + er.score

        tasks = []
        for domain in top_domains:
            tasks.append(self.client.query_domain(domain, query, mode="MEMO"))
            self.stats["total_api_calls"] += 1

        if tasks:
            memo_results = await asyncio.gather(*tasks, return_exceptions=True)
            for dr in memo_results:
                if isinstance(dr, Exception):
                    logger.warning("Tier 3 MEMO query failed: {}", dr)
                    continue
                for er in dr.results[:3]:
                    cls = _engine_result_to_classification(er, file_id, scan_id)
                    cls.mode = QueryMode.MEMO.value
                    classifications.append(cls)
                    domain_dist[er.domain] = domain_dist.get(er.domain, 0) + er.score

        primary_domain = "UNKNOWN"
        primary_engine = ""
        if classifications:
            best = max(classifications, key=lambda c: c.score)
            primary_domain = best.domain
            primary_engine = best.engine_id

        return ClassificationResult(
            file_path=sample.path,
            tier=ClassificationTier.TIER3_DEEP,
            classifications=classifications,
            primary_domain=primary_domain,
            primary_engine=primary_engine,
            domain_distribution=domain_dist,
        )

    async def classify_batch(
        self,
        samples: list[tuple[FileSample, int]],
        scan_id: int,
    ) -> list[ClassificationResult]:
        """Classify a batch of files with tiered concurrency.

        Args:
            samples: List of (FileSample, file_id) tuples.
            scan_id: Current scan ID.

        Returns:
            List of ClassificationResult, one per file.
        """
        tier1_items: list[tuple[FileSample, int]] = []
        tier2_items: list[tuple[FileSample, int]] = []
        tier3_items: list[tuple[FileSample, int]] = []

        for sample, file_id in samples:
            tier = determine_tier(sample)
            if tier == ClassificationTier.TIER1_FAST:
                tier1_items.append((sample, file_id))
            elif tier == ClassificationTier.TIER2_EXPLORE:
                tier2_items.append((sample, file_id))
            else:
                tier3_items.append((sample, file_id))

        logger.info(
            "Batch classification: {} Tier1, {} Tier2, {} Tier3",
            len(tier1_items),
            len(tier2_items),
            len(tier3_items),
        )

        results: list[ClassificationResult] = []

        sem1 = asyncio.Semaphore(TIER1_CONCURRENCY)
        sem2 = asyncio.Semaphore(TIER2_CONCURRENCY)
        sem3 = asyncio.Semaphore(TIER3_CONCURRENCY)

        async def _classify_with_sem(
            sem: asyncio.Semaphore,
            sample: FileSample,
            file_id: int,
        ) -> ClassificationResult:
            async with sem:
                return await self.classify_file(sample, file_id, scan_id)

        tier1_tasks = [_classify_with_sem(sem1, s, fid) for s, fid in tier1_items]
        tier2_tasks = [_classify_with_sem(sem2, s, fid) for s, fid in tier2_items]
        tier3_tasks = [_classify_with_sem(sem3, s, fid) for s, fid in tier3_items]

        all_tasks = tier1_tasks + tier2_tasks + tier3_tasks

        for chunk_start in range(0, len(all_tasks), BATCH_SIZE * CONCURRENT_BATCHES):
            chunk = all_tasks[chunk_start : chunk_start + BATCH_SIZE * CONCURRENT_BATCHES]
            chunk_results = await asyncio.gather(*chunk, return_exceptions=True)
            for cr in chunk_results:
                if isinstance(cr, Exception):
                    logger.error("Classification task failed: {}", cr)
                    self.stats["total_errors"] += 1
                else:
                    results.append(cr)

        return results

    async def classify_batch_sorted(
        self,
        samples: list[tuple[FileSample, int]],
        scan_id: int,
    ) -> list[ClassificationResult]:
        """Classify a batch sorted by priority (highest priority first)."""
        sorted_samples = sorted(
            samples,
            key=lambda item: compute_file_priority(item[0]),
            reverse=True,
        )
        return await self.classify_batch(sorted_samples, scan_id)

    def get_stats(self) -> dict[str, Any]:
        """Return classification pipeline statistics."""
        total = self.stats["total_classified"]
        return {
            "total_classified": total,
            "tier1_count": self.stats["tier1_count"],
            "tier2_count": self.stats["tier2_count"],
            "tier3_count": self.stats["tier3_count"],
            "tier1_pct": round(self.stats["tier1_count"] / max(total, 1) * 100, 1),
            "tier2_pct": round(self.stats["tier2_count"] / max(total, 1) * 100, 1),
            "tier3_pct": round(self.stats["tier3_count"] / max(total, 1) * 100, 1),
            "total_api_calls": self.stats["total_api_calls"],
            "total_errors": self.stats["total_errors"],
            "error_rate_pct": round(self.stats["total_errors"] / max(total, 1) * 100, 2),
            "avg_ms": round(self.stats["total_ms"] / max(total, 1), 1),
        }

    def reset_stats(self) -> None:
        """Reset pipeline statistics."""
        for key in self.stats:
            self.stats[key] = 0
