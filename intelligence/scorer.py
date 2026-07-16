"""Intelligent Drive Scanner v2.0 — File Intelligence Scoring.

Every file receives a composite intelligence score across 6 dimensions (0-100):
  1. Quality — Content completeness and richness
  2. Importance — Business criticality
  3. Sensitivity — PII/PHI/financial/classified content
  4. Staleness — How outdated (0=fresh, 100=ancient)
  5. Uniqueness — How unique vs duplicates (100=unique, 0=many copies)
  6. Risk — Composite security/compliance risk
"""

from __future__ import annotations

import json
import math
import re
from datetime import UTC, datetime

from loguru import logger

from config import (
    DOMAIN_CRITICALITY,
    DOMAIN_SENSITIVITY,
    EXECUTABLE_EXTENSIONS,
    IMPORTANCE_WEIGHTS,
    OVERALL_WEIGHTS,
    QUALITY_WEIGHTS,
    SENSITIVITY_PATTERNS,
)
from storage.models import (
    Classification,
    DuplicateCluster,
    FileRecord,
    IntelligenceScore,
)


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _days_since(iso_str: str | None) -> int:
    """Calculate days since an ISO-8601 timestamp."""
    if not iso_str:
        return 9999
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        delta = datetime.now(UTC) - dt
        return max(0, delta.days)
    except (ValueError, TypeError):
        return 9999


# ── Shared Location Detection ────────────────────────────────────────────────

SHARED_PATH_PATTERNS = [
    r"\\\\",  # UNC paths
    r"[/\\]public[/\\]",
    r"[/\\]shared[/\\]",
    r"[/\\]common[/\\]",
    r"[/\\]everyone[/\\]",
    r"[/\\]downloads[/\\]",
    r"[/\\]desktop[/\\]",
]

ENCRYPTED_PATH_PATTERNS = [
    r"[/\\]vault[/\\]",
    r"[/\\]secure[/\\]",
    r"[/\\]encrypted[/\\]",
    r"[/\\]prometheus[/\\]",
    r"[/\\]private[/\\]",
]


def _is_shared_location(path: str) -> bool:
    path_lower = path.lower()
    return any(re.search(pat, path_lower) for pat in SHARED_PATH_PATTERNS)


def _is_encrypted_location(path: str) -> bool:
    path_lower = path.lower()
    return any(re.search(pat, path_lower) for pat in ENCRYPTED_PATH_PATTERNS)


# ── Quality Score ────────────────────────────────────────────────────────────


def calculate_quality(
    file: FileRecord,
    classifications: list[Classification],
) -> float:
    """Calculate content quality score (0-100).

    Factors: content length, keyword density, structure, engine match count/score.
    """
    factors: dict[str, float] = {}

    # Content length (log scale, max at ~100KB)
    if file.size_bytes > 0:
        log_size = math.log10(max(file.size_bytes, 1))
        factors["content_length"] = min(100.0, log_size / 5.0 * 100.0)
    else:
        factors["content_length"] = 0.0

    # Keyword density from content sample
    sample = file.content_sample or ""
    words = sample.split()
    word_count = len(words)
    if word_count > 0:
        unique_words = len(set(w.lower() for w in words if len(w) > 2))
        keyword_ratio = unique_words / word_count
        factors["keyword_density"] = min(100.0, keyword_ratio * 200.0)
    else:
        factors["keyword_density"] = 0.0

    # Structure score (headers, sections, formatting)
    structure_score = 0.0
    if sample:
        has_headers = bool(re.search(r"^#{1,6}\s|^[A-Z][A-Z\s]{5,}$", sample, re.MULTILINE))
        has_sections = sample.count("\n\n") > 2
        has_lists = bool(re.search(r"^\s*[-*]\s|^\s*\d+\.\s", sample, re.MULTILINE))
        has_code = bool(re.search(r"```|def\s|class\s|function\s|import\s", sample))
        structure_score = sum(
            [
                30.0 if has_headers else 0.0,
                25.0 if has_sections else 0.0,
                25.0 if has_lists else 0.0,
                20.0 if has_code else 0.0,
            ]
        )
    factors["structure_score"] = structure_score

    # Engine match count
    match_count = len(classifications)
    factors["engine_match_count"] = min(100.0, match_count * 20.0)

    # Engine match score (average)
    if classifications:
        avg_score = sum(c.score for c in classifications) / len(classifications)
        factors["engine_match_score"] = min(100.0, avg_score)
    else:
        factors["engine_match_score"] = 0.0

    # Completeness (files with both content and classifications are more complete)
    completeness = 0.0
    if file.content_sample:
        completeness += 30.0
    if file.sha256:
        completeness += 20.0
    if classifications:
        completeness += 30.0
    if file.mime_type:
        completeness += 20.0
    factors["completeness"] = completeness

    # Weighted sum
    total = sum(factors.get(k, 0.0) * w for k, w in QUALITY_WEIGHTS.items())
    return round(min(100.0, max(0.0, total)), 1)


# ── Importance Score ─────────────────────────────────────────────────────────


def calculate_importance(
    file: FileRecord,
    classifications: list[Classification],
    reference_count: int = 0,
    duplicate_count: int = 0,
) -> float:
    """Calculate business importance score (0-100).

    Factors: domain criticality, authority weight, recency, references, uniqueness, depth.
    """
    factors: dict[str, float] = {}

    # Domain criticality
    if classifications:
        domains = [c.domain for c in classifications]
        best_crit = max(DOMAIN_CRITICALITY.get(d, 30) for d in domains)
        factors["domain_criticality"] = best_crit
    else:
        factors["domain_criticality"] = 20.0

    # Authority weight from engine results
    if classifications:
        max_weight = max(c.authority_weight for c in classifications)
        factors["authority_weight"] = min(100.0, max_weight)
    else:
        factors["authority_weight"] = 0.0

    # Access recency
    days_accessed = _days_since(file.accessed_at)
    if days_accessed < 7:
        factors["access_recency"] = 100.0
    elif days_accessed < 30:
        factors["access_recency"] = 80.0
    elif days_accessed < 90:
        factors["access_recency"] = 60.0
    elif days_accessed < 365:
        factors["access_recency"] = 40.0
    elif days_accessed < 730:
        factors["access_recency"] = 20.0
    else:
        factors["access_recency"] = 5.0

    # Reference count (how many other files reference this one)
    factors["reference_count"] = min(100.0, reference_count * 15.0)

    # Uniqueness (no duplicates = more important)
    if duplicate_count == 0:
        factors["uniqueness"] = 100.0
    elif duplicate_count == 1:
        factors["uniqueness"] = 60.0
    elif duplicate_count <= 3:
        factors["uniqueness"] = 35.0
    else:
        factors["uniqueness"] = 10.0

    # Path depth (shallow = more visible = more important)
    if file.depth <= 2:
        factors["path_depth"] = 100.0
    elif file.depth <= 4:
        factors["path_depth"] = 70.0
    elif file.depth <= 6:
        factors["path_depth"] = 40.0
    else:
        factors["path_depth"] = 15.0

    total = sum(factors.get(k, 0.0) * w for k, w in IMPORTANCE_WEIGHTS.items())
    return round(min(100.0, max(0.0, total)), 1)


# ── Sensitivity Score ────────────────────────────────────────────────────────


def calculate_sensitivity(
    file: FileRecord,
    classifications: list[Classification],
) -> float:
    """Calculate sensitivity score (0-100).

    Detects PII, PHI, financial data, API keys, passwords, classified markings.
    """
    score = 0.0
    content = file.content_sample or ""

    # Pattern-based detection
    matches_found: list[str] = []
    for name, (pattern, weight) in SENSITIVITY_PATTERNS.items():
        if re.search(pattern, content):
            matches_found.append(name)
            score = max(score, weight)

    # Domain-based sensitivity boost
    for cls in classifications:
        domain_boost = DOMAIN_SENSITIVITY.get(cls.domain, 0)
        if domain_boost > 0:
            score = max(score, score + domain_boost * 0.5)

    # Extension-based sensitivity
    ext = (file.extension or "").lower()
    if ext in {".env", ".pem", ".key", ".p12", ".pfx", ".jks", ".keystore"}:
        score = max(score, 90.0)
    elif ext in {".bak", ".backup", ".dump", ".sql"}:
        score = max(score, 40.0)

    # Filename patterns
    filename_lower = (file.filename or "").lower()
    if any(
        kw in filename_lower for kw in ["password", "secret", "credential", "private_key", "token"]
    ):
        score = max(score, 85.0)
    elif any(kw in filename_lower for kw in ["ssn", "social_security", "tax_return", "w2", "1099"]):
        score = max(score, 80.0)

    if matches_found:
        logger.debug("Sensitivity patterns in {}: {}", file.path, matches_found)

    return round(min(100.0, max(0.0, score)), 1)


# ── Staleness Score ──────────────────────────────────────────────────────────


def calculate_staleness(file: FileRecord) -> float:
    """Calculate staleness score (0=fresh, 100=ancient and forgotten)."""
    days_modified = _days_since(file.modified_at)
    days_accessed = _days_since(file.accessed_at)

    if days_modified < 7:
        base = 0.0
    elif days_modified < 30:
        base = 10.0
    elif days_modified < 90:
        base = 25.0
    elif days_modified < 365:
        base = 50.0
    elif days_modified < 730:
        base = 75.0
    else:
        base = 90.0

    # Boost staleness if never accessed either
    if days_accessed > 730 and base > 50:
        base = min(100.0, base + 10.0)

    # Reduce staleness if recently accessed despite old modification
    if days_accessed < 30 and base > 50:
        base = base * 0.6

    return round(min(100.0, max(0.0, base)), 1)


# ── Uniqueness Score ─────────────────────────────────────────────────────────


def calculate_uniqueness(
    file: FileRecord,
    cluster: DuplicateCluster | None = None,
    duplicate_count: int = 0,
) -> float:
    """Calculate uniqueness score (100=unique, 0=many exact duplicates)."""
    count = duplicate_count
    if cluster is not None:
        count = max(count, cluster.file_count)

    if count <= 1:
        return 100.0
    if count == 2:
        return 50.0
    if count <= 5:
        return 25.0
    return round(max(5.0, 100.0 / count), 1)


# ── Risk Score ───────────────────────────────────────────────────────────────


def calculate_risk(
    file: FileRecord,
    classifications: list[Classification],
    sensitivity: float,
) -> float:
    """Calculate security/compliance risk score (0=safe, 100=critical risk)."""
    risk = 0.0
    ext = (file.extension or "").lower()
    path_lower = (file.path or "").lower()

    # High sensitivity + not in encrypted location
    if sensitivity > 70 and not _is_encrypted_location(file.path):
        risk += 40.0

    # Executable in unexpected location
    if ext in EXECUTABLE_EXTENSIONS:
        if any(kw in path_lower for kw in ["temp", "tmp", "download", "appdata"]):
            risk += 60.0
        elif any(kw in path_lower for kw in ["desktop", "public"]):
            risk += 40.0

    # CYBER engine matches
    cyber_matches = [c for c in classifications if c.domain == "CYBER"]
    if cyber_matches:
        max_cyber_score = max(c.score for c in cyber_matches)
        risk += min(50.0, max_cyber_score)

    # Sensitive data in shared/public folders
    if sensitivity > 50 and _is_shared_location(file.path):
        risk += 30.0

    # Known risky extensions without CYBER classification
    if ext in {".bat", ".cmd", ".vbs", ".ps1", ".hta"} and not cyber_matches:
        risk += 20.0

    # Config/env files in non-secure locations
    if (
        ext in {".env", ".cfg", ".ini", ".conf"}
        and "password" in (file.content_sample or "").lower()
    ):
        risk += 35.0

    return round(min(100.0, max(0.0, risk)), 1)


# ── Overall Score ────────────────────────────────────────────────────────────


def calculate_overall(
    quality: float,
    importance: float,
    sensitivity: float,
    staleness: float,
    uniqueness: float,
    risk: float,
) -> float:
    """Calculate the overall intelligence score from all 6 dimensions.

    Note: staleness and risk have NEGATIVE weights (they reduce the score).
    """
    scores = {
        "quality": quality,
        "importance": importance,
        "sensitivity": sensitivity,
        "staleness": staleness,
        "uniqueness": uniqueness,
        "risk": risk,
    }

    total = 0.0
    for dim, weight in OVERALL_WEIGHTS.items():
        value = scores.get(dim, 0.0)
        if weight < 0:
            # Negative weight: higher value reduces overall score
            total += abs(weight) * (100.0 - value)
        else:
            total += weight * value

    return round(min(100.0, max(0.0, total)), 1)


# ── Scorer Class ─────────────────────────────────────────────────────────────


class IntelligenceScorer:
    """Scores files across all 6 dimensions and produces IntelligenceScore records."""

    def __init__(self) -> None:
        self.scored_count = 0

    def score_file(
        self,
        file: FileRecord,
        classifications: list[Classification],
        scan_id: int,
        cluster: DuplicateCluster | None = None,
        reference_count: int = 0,
        duplicate_count: int = 0,
    ) -> IntelligenceScore:
        """Score a single file across all 6 dimensions."""
        quality = calculate_quality(file, classifications)
        importance = calculate_importance(file, classifications, reference_count, duplicate_count)
        sensitivity = calculate_sensitivity(file, classifications)
        staleness = calculate_staleness(file)
        uniqueness = calculate_uniqueness(file, cluster, duplicate_count)
        risk = calculate_risk(file, classifications, sensitivity)
        overall = calculate_overall(quality, importance, sensitivity, staleness, uniqueness, risk)

        # Determine primary domain from classifications
        primary_domain = "UNKNOWN"
        primary_engine = ""
        domain_dist: dict[str, float] = {}
        if classifications:
            for cls in classifications:
                domain_dist[cls.domain] = domain_dist.get(cls.domain, 0) + cls.score
            best = max(classifications, key=lambda c: c.score)
            primary_domain = best.domain
            primary_engine = best.engine_id

        self.scored_count += 1

        return IntelligenceScore(
            file_id=file.id or 0,
            scan_id=scan_id,
            overall_score=overall,
            quality_score=quality,
            importance_score=importance,
            sensitivity_score=sensitivity,
            staleness_score=staleness,
            uniqueness_score=uniqueness,
            risk_score=risk,
            primary_domain=primary_domain,
            primary_engine=primary_engine,
            domain_distribution=json.dumps(domain_dist),
            classification_count=len(classifications),
            scored_at=_now_iso(),
        )

    def score_batch(
        self,
        items: list[tuple[FileRecord, list[Classification]]],
        scan_id: int,
        clusters: dict[int, DuplicateCluster] | None = None,
        reference_counts: dict[int, int] | None = None,
        duplicate_counts: dict[int, int] | None = None,
    ) -> list[IntelligenceScore]:
        """Score a batch of files."""
        results: list[IntelligenceScore] = []
        clusters = clusters or {}
        reference_counts = reference_counts or {}
        duplicate_counts = duplicate_counts or {}

        for file, classifications in items:
            file_id = file.id or 0
            cluster = clusters.get(file_id)
            ref_count = reference_counts.get(file_id, 0)
            dup_count = duplicate_counts.get(file_id, 0)

            score = self.score_file(
                file,
                classifications,
                scan_id,
                cluster=cluster,
                reference_count=ref_count,
                duplicate_count=dup_count,
            )
            results.append(score)

        logger.info("Scored {} files", len(results))
        return results
