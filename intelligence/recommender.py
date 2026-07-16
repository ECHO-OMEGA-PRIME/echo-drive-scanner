"""Intelligent Drive Scanner v2.0 — Actionable Recommendations Engine.

Generates actionable recommendations based on intelligence scores,
relationships, duplicate clusters, and classifications.

Categories: archive, delete, secure, backup, deduplicate, organize,
review, alert, encrypt, update.
"""

from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from loguru import logger

from config import (
    RECOMMENDATION_THRESHOLDS,
)
from storage.models import (
    Classification,
    DuplicateCluster,
    FileRecord,
    IntelligenceScore,
    Recommendation,
    RecommendationCategory,
    Relationship,
    RelationshipType,
    Severity,
)


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _human_size(nbytes: int) -> str:
    """Format byte count as human-readable string."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(nbytes) < 1024.0:
            return f"{nbytes:.1f} {unit}"
        nbytes /= 1024.0  # type: ignore[assignment]
    return f"{nbytes:.1f} PB"


# ── Recommendation Generators ────────────────────────────────────────────────


def _gen_archive_recommendations(
    files: list[FileRecord],
    scores: dict[int, IntelligenceScore],
    scan_id: int,
    thresholds: dict[str, Any],
) -> list[Recommendation]:
    """Archive stale files with low importance."""
    recs: list[Recommendation] = []
    stale_threshold = thresholds.get("archive_staleness_min", 80)
    importance_max = thresholds.get("archive_importance_max", 30)

    candidates: list[FileRecord] = []
    total_bytes = 0

    for f in files:
        fid = f.id or 0
        score = scores.get(fid)
        if not score:
            continue
        if score.staleness_score >= stale_threshold and score.importance_score <= importance_max:
            candidates.append(f)
            total_bytes += f.size_bytes

    if candidates:
        affected_ids = [str(f.id or 0) for f in candidates[:500]]
        recs.append(
            Recommendation(
                scan_id=scan_id,
                category=RecommendationCategory.ARCHIVE.value,
                severity=Severity.LOW.value,
                title=f"Archive {len(candidates)} stale files ({_human_size(total_bytes)})",
                description=(
                    f"Found {len(candidates)} files with staleness score >= {stale_threshold} "
                    f"and importance <= {importance_max}. These files haven't been accessed "
                    f"or modified in a long time and have low business value. Archiving them "
                    f"to cold storage would recover {_human_size(total_bytes)} of active disk space."
                ),
                affected_files=json.dumps(affected_ids),
                affected_count=len(candidates),
                estimated_impact=f"Recover {_human_size(total_bytes)} disk space",
                action_command=f"python scanner.py --execute-recommendation archive --scan-id {scan_id}",
                auto_executable=True,
                requires_review=False,
                created_at=_now_iso(),
            )
        )
    return recs


def _gen_delete_recommendations(
    files: list[FileRecord],
    scores: dict[int, IntelligenceScore],
    clusters: list[DuplicateCluster],
    scan_id: int,
    thresholds: dict[str, Any],
) -> list[Recommendation]:
    """Delete exact duplicates that are stale and unimportant."""
    recs: list[Recommendation] = []
    total_wasted = sum(c.total_wasted_bytes for c in clusters)

    if clusters:
        total_files = sum(max(0, c.file_count - 1) for c in clusters)
        recs.append(
            Recommendation(
                scan_id=scan_id,
                category=RecommendationCategory.DELETE.value,
                severity=Severity.MEDIUM.value,
                title=f"Delete {total_files} exact duplicates (saving {_human_size(total_wasted)})",
                description=(
                    f"Found {len(clusters)} duplicate clusters containing "
                    f"{total_files} redundant copies. Each cluster has one recommended "
                    f"keeper (highest quality score). Deleting redundant copies would "
                    f"recover {_human_size(total_wasted)} of disk space."
                ),
                affected_files=json.dumps([str(c.id or 0) for c in clusters[:200]]),
                affected_count=total_files,
                estimated_impact=f"Recover {_human_size(total_wasted)} disk space",
                action_command=f"python scanner.py --execute-recommendation deduplicate --scan-id {scan_id}",
                auto_executable=False,
                requires_review=True,
                created_at=_now_iso(),
            )
        )
    return recs


def _gen_secure_recommendations(
    files: list[FileRecord],
    scores: dict[int, IntelligenceScore],
    scan_id: int,
    thresholds: dict[str, Any],
) -> list[Recommendation]:
    """Secure sensitive files not in encrypted locations."""
    recs: list[Recommendation] = []
    sensitivity_threshold = thresholds.get("secure_sensitivity_min", 70)

    candidates: list[FileRecord] = []
    for f in files:
        fid = f.id or 0
        score = scores.get(fid)
        if not score:
            continue
        if score.sensitivity_score >= sensitivity_threshold:
            path_lower = f.path.lower()
            in_secure = any(
                kw in path_lower for kw in ("vault", "secure", "encrypted", "prometheus", "private")
            )
            if not in_secure:
                candidates.append(f)

    if candidates:
        recs.append(
            Recommendation(
                scan_id=scan_id,
                category=RecommendationCategory.SECURE.value,
                severity=Severity.HIGH.value,
                title=f"{len(candidates)} files contain PII/PHI — move to encrypted vault",
                description=(
                    f"Found {len(candidates)} files with sensitivity score >= "
                    f"{sensitivity_threshold} that are NOT in an encrypted or secure "
                    f"location. These files may contain SSNs, credit card numbers, "
                    f"API keys, medical records, or other sensitive data. Move them "
                    f"to the encrypted vault or apply file-level encryption."
                ),
                affected_files=json.dumps([str(f.id or 0) for f in candidates[:500]]),
                affected_count=len(candidates),
                estimated_impact=f"Protect {len(candidates)} sensitive files from exposure",
                action_command=f"python scanner.py --execute-recommendation secure --scan-id {scan_id}",
                auto_executable=False,
                requires_review=True,
                created_at=_now_iso(),
            )
        )
    return recs


def _gen_backup_recommendations(
    files: list[FileRecord],
    scores: dict[int, IntelligenceScore],
    relationships: list[Relationship],
    scan_id: int,
    thresholds: dict[str, Any],
) -> list[Recommendation]:
    """Backup critical files with no duplicates."""
    recs: list[Recommendation] = []
    importance_threshold = thresholds.get("backup_importance_min", 80)

    # Files that have duplicates (they already have a backup of sorts)
    has_duplicate: set[int] = set()
    for rel in relationships:
        if rel.relationship_type == RelationshipType.DUPLICATES.value:
            has_duplicate.add(rel.source_file_id)
            has_duplicate.add(rel.target_file_id)

    candidates: list[FileRecord] = []
    for f in files:
        fid = f.id or 0
        score = scores.get(fid)
        if not score:
            continue
        if score.importance_score >= importance_threshold and fid not in has_duplicate:
            candidates.append(f)

    if candidates:
        total_bytes = sum(f.size_bytes for f in candidates)
        recs.append(
            Recommendation(
                scan_id=scan_id,
                category=RecommendationCategory.BACKUP.value,
                severity=Severity.HIGH.value,
                title=f"{len(candidates)} critical files have no backup — sync to R2",
                description=(
                    f"Found {len(candidates)} files with importance score >= "
                    f"{importance_threshold} that exist in only one location. "
                    f"These are critical business files with no redundancy. "
                    f"Sync them to R2 cloud storage for disaster recovery."
                ),
                affected_files=json.dumps([str(f.id or 0) for f in candidates[:500]]),
                affected_count=len(candidates),
                estimated_impact=f"Protect {_human_size(total_bytes)} of critical data",
                action_command=f"python scanner.py --execute-recommendation backup --scan-id {scan_id}",
                auto_executable=True,
                requires_review=False,
                created_at=_now_iso(),
            )
        )
    return recs


def _gen_review_recommendations(
    files: list[FileRecord],
    scores: dict[int, IntelligenceScore],
    scan_id: int,
    thresholds: dict[str, Any],
) -> list[Recommendation]:
    """Flag high-risk files for review."""
    recs: list[Recommendation] = []
    risk_threshold = thresholds.get("review_risk_min", 70)

    candidates: list[FileRecord] = []
    for f in files:
        fid = f.id or 0
        score = scores.get(fid)
        if not score:
            continue
        if score.risk_score >= risk_threshold:
            candidates.append(f)

    if candidates:
        recs.append(
            Recommendation(
                scan_id=scan_id,
                category=RecommendationCategory.REVIEW.value,
                severity=Severity.HIGH.value,
                title=f"Review {len(candidates)} high-risk files",
                description=(
                    f"Found {len(candidates)} files with risk score >= {risk_threshold}. "
                    f"These may include executables in temp directories, exposed API keys, "
                    f"sensitive data in shared folders, or files matching security threat "
                    f"patterns. Manual review is recommended."
                ),
                affected_files=json.dumps([str(f.id or 0) for f in candidates[:500]]),
                affected_count=len(candidates),
                estimated_impact=f"Mitigate security risk for {len(candidates)} files",
                action_command=f"python scanner.py --execute-recommendation review --scan-id {scan_id}",
                auto_executable=False,
                requires_review=True,
                created_at=_now_iso(),
            )
        )
    return recs


def _gen_alert_recommendations(
    files: list[FileRecord],
    classifications: dict[int, list[Classification]],
    scan_id: int,
    thresholds: dict[str, Any],
) -> list[Recommendation]:
    """Alert on CYBER-classified files with high confidence."""
    recs: list[Recommendation] = []
    alert_score_min = thresholds.get("alert_cyber_score_min", 70)

    candidates: list[FileRecord] = []
    for f in files:
        fid = f.id or 0
        clss = classifications.get(fid, [])
        cyber = [c for c in clss if c.domain == "CYBER" and c.score >= alert_score_min]
        if cyber:
            candidates.append(f)

    if candidates:
        recs.append(
            Recommendation(
                scan_id=scan_id,
                category=RecommendationCategory.ALERT.value,
                severity=Severity.CRITICAL.value,
                title=f"{len(candidates)} files match security threat patterns — investigate",
                description=(
                    f"Found {len(candidates)} files classified by CYBER engines "
                    f"with score >= {alert_score_min}. These may match malware "
                    f"persistence patterns, exploit kits, suspicious scripts, "
                    f"or unauthorized access tools. Immediate investigation recommended."
                ),
                affected_files=json.dumps([str(f.id or 0) for f in candidates[:500]]),
                affected_count=len(candidates),
                estimated_impact="Potential security breach — immediate investigation needed",
                action_command=f"python scanner.py --execute-recommendation alert --scan-id {scan_id}",
                auto_executable=False,
                requires_review=True,
                created_at=_now_iso(),
            )
        )
    return recs


def _gen_encrypt_recommendations(
    files: list[FileRecord],
    scores: dict[int, IntelligenceScore],
    scan_id: int,
    thresholds: dict[str, Any],
) -> list[Recommendation]:
    """Recommend encryption for highly sensitive unencrypted files."""
    recs: list[Recommendation] = []
    sensitivity_threshold = thresholds.get("encrypt_sensitivity_min", 80)

    candidates: list[FileRecord] = []
    for f in files:
        fid = f.id or 0
        score = scores.get(fid)
        if not score:
            continue
        if score.sensitivity_score >= sensitivity_threshold:
            ext = (f.extension or "").lower()
            # Already encrypted formats
            if ext in (".gpg", ".pgp", ".aes", ".enc", ".vault"):
                continue
            candidates.append(f)

    if candidates:
        recs.append(
            Recommendation(
                scan_id=scan_id,
                category=RecommendationCategory.ENCRYPT.value,
                severity=Severity.HIGH.value,
                title=f"Encrypt {len(candidates)} highly sensitive files",
                description=(
                    f"Found {len(candidates)} files with sensitivity score >= "
                    f"{sensitivity_threshold} that are not encrypted. These contain "
                    f"highly sensitive data (financial records, credentials, PII) "
                    f"and should be encrypted at rest."
                ),
                affected_files=json.dumps([str(f.id or 0) for f in candidates[:500]]),
                affected_count=len(candidates),
                estimated_impact=f"Protect {len(candidates)} files with encryption",
                action_command=f"python scanner.py --execute-recommendation encrypt --scan-id {scan_id}",
                auto_executable=False,
                requires_review=True,
                created_at=_now_iso(),
            )
        )
    return recs


def _gen_organize_recommendations(
    files: list[FileRecord],
    scores: dict[int, IntelligenceScore],
    classifications: dict[int, list[Classification]],
    scan_id: int,
    thresholds: dict[str, Any],
) -> list[Recommendation]:
    """Suggest organizing misplaced files into proper domain folders."""
    recs: list[Recommendation] = []
    misplaced: list[tuple[FileRecord, str]] = []

    domain_folder_map = {
        "TAX": "TAX_KNOWLEDGE",
        "FIN": "FINANCE",
        "LG": "LEGAL",
        "CYBER": "SECURITY",
        "MED": "MEDICAL",
        "PROG": "CODE",
        "LM": "LANDMAN",
        "OIL": "OILFIELD",
    }

    for f in files:
        fid = f.id or 0
        score = scores.get(fid)
        if not score or not score.primary_domain:
            continue
        domain = score.primary_domain
        expected_folder = domain_folder_map.get(domain)
        if not expected_folder:
            continue
        path_lower = f.path.lower()
        # Check if file is in a "wrong" location (downloads, desktop, temp)
        wrong_locations = ("downloads", "desktop", "temp", "tmp", "appdata")
        if any(loc in path_lower for loc in wrong_locations):
            misplaced.append((f, domain))

    if misplaced:
        domain_counts: dict[str, int] = defaultdict(int)
        for _, domain in misplaced:
            domain_counts[domain] += 1
        detail_parts = [
            f"{count} {domain}"
            for domain, count in sorted(domain_counts.items(), key=lambda x: -x[1])[:5]
        ]
        detail = ", ".join(detail_parts)

        recs.append(
            Recommendation(
                scan_id=scan_id,
                category=RecommendationCategory.ORGANIZE.value,
                severity=Severity.LOW.value,
                title=f"Move {len(misplaced)} files from temporary locations to proper folders",
                description=(
                    f"Found {len(misplaced)} classified files in Downloads, Desktop, or "
                    f"Temp directories. These should be moved to their proper domain "
                    f"folders for better organization. Breakdown: {detail}."
                ),
                affected_files=json.dumps([str(f.id or 0) for f, _ in misplaced[:500]]),
                affected_count=len(misplaced),
                estimated_impact=f"Organize {len(misplaced)} files into correct locations",
                action_command=f"python scanner.py --execute-recommendation organize --scan-id {scan_id}",
                auto_executable=False,
                requires_review=True,
                created_at=_now_iso(),
            )
        )
    return recs


def _gen_update_recommendations(
    files: list[FileRecord],
    scores: dict[int, IntelligenceScore],
    scan_id: int,
    thresholds: dict[str, Any],
) -> list[Recommendation]:
    """Flag important files that are getting stale."""
    recs: list[Recommendation] = []
    staleness_min = thresholds.get("update_staleness_min", 50)
    importance_min = thresholds.get("update_importance_min", 60)

    candidates: list[FileRecord] = []
    for f in files:
        fid = f.id or 0
        score = scores.get(fid)
        if not score:
            continue
        if score.staleness_score >= staleness_min and score.importance_score >= importance_min:
            candidates.append(f)

    if candidates:
        recs.append(
            Recommendation(
                scan_id=scan_id,
                category=RecommendationCategory.UPDATE.value,
                severity=Severity.MEDIUM.value,
                title=f"{len(candidates)} important documents need updating",
                description=(
                    f"Found {len(candidates)} files with importance >= {importance_min} "
                    f"and staleness >= {staleness_min}. These are business-critical "
                    f"documents that haven't been updated in a while and may contain "
                    f"outdated information."
                ),
                affected_files=json.dumps([str(f.id or 0) for f in candidates[:500]]),
                affected_count=len(candidates),
                estimated_impact=f"Keep {len(candidates)} critical documents current",
                action_command=f"python scanner.py --execute-recommendation update --scan-id {scan_id}",
                auto_executable=False,
                requires_review=True,
                created_at=_now_iso(),
            )
        )
    return recs


# ── Main Recommender Class ───────────────────────────────────────────────────


class RecommendationEngine:
    """Generates actionable recommendations from intelligence analysis.

    Analyzes scores, relationships, classifications, and duplicate clusters
    to produce prioritized, actionable recommendations across 10 categories.
    """

    def __init__(self, thresholds: dict[str, Any] | None = None) -> None:
        self.thresholds = thresholds or RECOMMENDATION_THRESHOLDS
        self.recommendations: list[Recommendation] = []

    def generate_all(
        self,
        files: list[FileRecord],
        scores: dict[int, IntelligenceScore],
        classifications: dict[int, list[Classification]],
        relationships: list[Relationship],
        clusters: list[DuplicateCluster],
        scan_id: int,
    ) -> list[Recommendation]:
        """Generate all recommendation categories.

        Args:
            files: All file records from scan.
            scores: Map of file_id → IntelligenceScore.
            classifications: Map of file_id → classifications.
            relationships: All detected relationships.
            clusters: Duplicate file clusters.
            scan_id: Current scan ID.

        Returns:
            Prioritized list of recommendations.
        """
        self.recommendations = []
        logger.info("Generating recommendations for {} files", len(files))

        generators: list[tuple[str, Callable[..., list[Recommendation]], tuple[Any, ...]]] = [
            (
                "alert",
                _gen_alert_recommendations,
                (files, classifications, scan_id, self.thresholds),
            ),
            ("secure", _gen_secure_recommendations, (files, scores, scan_id, self.thresholds)),
            ("encrypt", _gen_encrypt_recommendations, (files, scores, scan_id, self.thresholds)),
            ("review", _gen_review_recommendations, (files, scores, scan_id, self.thresholds)),
            (
                "delete",
                _gen_delete_recommendations,
                (files, scores, clusters, scan_id, self.thresholds),
            ),
            (
                "backup",
                _gen_backup_recommendations,
                (files, scores, relationships, scan_id, self.thresholds),
            ),
            ("archive", _gen_archive_recommendations, (files, scores, scan_id, self.thresholds)),
            (
                "organize",
                _gen_organize_recommendations,
                (files, scores, classifications, scan_id, self.thresholds),
            ),
            ("update", _gen_update_recommendations, (files, scores, scan_id, self.thresholds)),
        ]

        for name, gen_func, args in generators:
            try:
                recs = gen_func(*args)
                self.recommendations.extend(recs)
                if recs:
                    logger.info("Generated {} {} recommendation(s)", len(recs), name)
            except Exception as e:
                logger.error("Failed to generate {} recommendations: {}", name, e)

        # Sort by severity priority
        severity_order = {
            Severity.CRITICAL.value: 0,
            Severity.HIGH.value: 1,
            Severity.MEDIUM.value: 2,
            Severity.LOW.value: 3,
            Severity.INFO.value: 4,
        }
        self.recommendations.sort(key=lambda r: severity_order.get(r.severity, 5))

        logger.info(
            "Generated {} total recommendations across {} categories",
            len(self.recommendations),
            len({r.category for r in self.recommendations}),
        )
        return self.recommendations

    def get_stats(self) -> dict[str, Any]:
        """Return recommendation generation statistics."""
        by_category: dict[str, int] = defaultdict(int)
        by_severity: dict[str, int] = defaultdict(int)
        total_affected = 0

        for rec in self.recommendations:
            by_category[rec.category] += 1
            by_severity[rec.severity] += 1
            total_affected += rec.affected_count

        return {
            "total_recommendations": len(self.recommendations),
            "by_category": dict(by_category),
            "by_severity": dict(by_severity),
            "total_affected_files": total_affected,
            "auto_executable": sum(1 for r in self.recommendations if r.auto_executable),
            "requires_review": sum(1 for r in self.recommendations if r.requires_review),
        }
