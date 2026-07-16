"""Intelligent Drive Scanner v2.0 — Content-Aware Deduplication.

Three levels of deduplication:
  1. Exact Duplicates — SHA-256 match (100% identical)
  2. Near Duplicates — Normalized text hash (same content, different formatting)
  3. Semantic Duplicates — Same classifications + >0.8 keyword overlap

Each duplicate cluster selects a "keeper" using configurable strategies.
"""

from __future__ import annotations

import re
from collections import defaultdict
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any

from loguru import logger

from storage.models import (
    Classification,
    DuplicateCluster,
    DuplicateMember,
    FileRecord,
    IntelligenceScore,
    KeeperStrategy,
)


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


# ── Text Normalization ───────────────────────────────────────────────────────

_WHITESPACE_RE = re.compile(r"\s+")
_NON_ALNUM_RE = re.compile(r"[^a-z0-9 ]")


def normalize_text(text: str) -> str:
    """Normalize text for near-duplicate detection.

    Lowercases, strips punctuation, collapses whitespace, removes formatting.
    Two documents with the same normalized text are near-duplicates.
    """
    text = text.lower()
    text = _NON_ALNUM_RE.sub(" ", text)
    text = _WHITESPACE_RE.sub(" ", text).strip()
    return text


def normalized_hash(text: str) -> str:
    """SHA-256 hash of normalized text content."""
    normed = normalize_text(text)
    return sha256(normed.encode("utf-8", errors="replace")).hexdigest()


# ── Keyword Overlap ──────────────────────────────────────────────────────────


def keyword_overlap(words_a: set[str], words_b: set[str]) -> float:
    """Jaccard similarity between two keyword sets."""
    if not words_a or not words_b:
        return 0.0
    intersection = words_a & words_b
    union = words_a | words_b
    return len(intersection) / len(union)


def extract_keywords(text: str, min_len: int = 3) -> set[str]:
    """Extract unique lowercase words from text."""
    words = text.lower().split()
    return {w for w in words if len(w) >= min_len and w.isalpha()}


# ── Keeper Selection Strategies ──────────────────────────────────────────────


def _select_keeper_newest(members: list[tuple[FileRecord, IntelligenceScore | None]]) -> int:
    """Keep the most recently modified file."""
    best = max(members, key=lambda x: x[0].modified_at or "")
    return best[0].id or 0


def _select_keeper_largest(members: list[tuple[FileRecord, IntelligenceScore | None]]) -> int:
    """Keep the largest file."""
    best = max(members, key=lambda x: x[0].size_bytes)
    return best[0].id or 0


def _select_keeper_shallowest(members: list[tuple[FileRecord, IntelligenceScore | None]]) -> int:
    """Keep the file with the shallowest path depth."""
    best = min(members, key=lambda x: x[0].depth)
    return best[0].id or 0


def _select_keeper_most_accessed(members: list[tuple[FileRecord, IntelligenceScore | None]]) -> int:
    """Keep the most recently accessed file."""
    best = max(members, key=lambda x: x[0].accessed_at or "")
    return best[0].id or 0


def _select_keeper_highest_quality(
    members: list[tuple[FileRecord, IntelligenceScore | None]],
) -> int:
    """Keep the file with the highest quality score."""
    scored = [(f, s) for f, s in members if s is not None]
    if not scored:
        return _select_keeper_newest(members)
    best = max(scored, key=lambda x: x[1].quality_score)
    return best[0].id or 0


def _select_keeper_domain_folder(members: list[tuple[FileRecord, IntelligenceScore | None]]) -> int:
    """Keep the file in its domain-appropriate folder."""
    for f, s in members:
        if s and s.primary_domain:
            domain_lower = s.primary_domain.lower()
            path_lower = f.path.lower()
            if domain_lower in path_lower:
                return f.id or 0
    # Fallback to highest quality
    return _select_keeper_highest_quality(members)


KEEPER_FUNCTIONS = {
    KeeperStrategy.KEEP_NEWEST.value: _select_keeper_newest,
    KeeperStrategy.KEEP_LARGEST.value: _select_keeper_largest,
    KeeperStrategy.KEEP_SHALLOWEST.value: _select_keeper_shallowest,
    KeeperStrategy.KEEP_MOST_ACCESSED.value: _select_keeper_most_accessed,
    KeeperStrategy.KEEP_HIGHEST_QUALITY.value: _select_keeper_highest_quality,
    KeeperStrategy.KEEP_IN_DOMAIN_FOLDER.value: _select_keeper_domain_folder,
}


# ── Deduplicator Class ──────────────────────────────────────────────────────


class Deduplicator:
    """Content-aware deduplication engine.

    Detects exact, near, and semantic duplicates.
    Selects keepers using configurable strategies.
    """

    def __init__(
        self,
        strategy: str = KeeperStrategy.KEEP_HIGHEST_QUALITY.value,
        near_dup_enabled: bool = True,
        semantic_dup_enabled: bool = True,
        semantic_overlap_threshold: float = 0.8,
    ) -> None:
        self.strategy = strategy
        self.near_dup_enabled = near_dup_enabled
        self.semantic_dup_enabled = semantic_dup_enabled
        self.semantic_overlap_threshold = semantic_overlap_threshold
        self.clusters: list[DuplicateCluster] = []
        self.stats: dict[str, int] = {
            "exact_clusters": 0,
            "near_clusters": 0,
            "semantic_clusters": 0,
            "total_duplicates": 0,
            "total_wasted_bytes": 0,
        }

    def find_duplicates(
        self,
        files: list[FileRecord],
        scores: dict[int, IntelligenceScore] | None = None,
        classifications: dict[int, list[Classification]] | None = None,
    ) -> list[DuplicateCluster]:
        """Find all duplicate clusters across files.

        Args:
            files: All scanned file records.
            scores: Optional intelligence scores for keeper selection.
            classifications: Optional classifications for semantic dedup.

        Returns:
            List of duplicate clusters with keeper assignments.
        """
        self.clusters = []
        scores = scores or {}
        classifications = classifications or {}

        logger.info("Finding duplicates across {} files", len(files))

        # Phase 1: Exact duplicates (SHA-256)
        exact = self._find_exact_duplicates(files, scores)
        self.clusters.extend(exact)
        self.stats["exact_clusters"] = len(exact)

        # Track which files are already in exact clusters
        exact_file_ids: set[int] = set()
        for cluster in exact:
            for member in cluster.members:
                exact_file_ids.add(member.file_id)

        # Phase 2: Near duplicates (normalized text hash)
        if self.near_dup_enabled:
            remaining = [f for f in files if (f.id or 0) not in exact_file_ids]
            near = self._find_near_duplicates(remaining, scores)
            self.clusters.extend(near)
            self.stats["near_clusters"] = len(near)

            for cluster in near:
                for member in cluster.members:
                    exact_file_ids.add(member.file_id)

        # Phase 3: Semantic duplicates (classification + keyword overlap)
        if self.semantic_dup_enabled and classifications:
            remaining = [f for f in files if (f.id or 0) not in exact_file_ids]
            semantic = self._find_semantic_duplicates(remaining, classifications, scores)
            self.clusters.extend(semantic)
            self.stats["semantic_clusters"] = len(semantic)

        # Calculate totals
        self.stats["total_duplicates"] = sum(max(0, c.file_count - 1) for c in self.clusters)
        self.stats["total_wasted_bytes"] = sum(c.total_wasted_bytes for c in self.clusters)

        logger.info(
            "Found {} duplicate clusters ({} exact, {} near, {} semantic), "
            "{} redundant files, {} wasted bytes",
            len(self.clusters),
            self.stats["exact_clusters"],
            self.stats["near_clusters"],
            self.stats["semantic_clusters"],
            self.stats["total_duplicates"],
            self.stats["total_wasted_bytes"],
        )
        return self.clusters

    def _find_exact_duplicates(
        self,
        files: list[FileRecord],
        scores: dict[int, IntelligenceScore],
    ) -> list[DuplicateCluster]:
        """Find files with identical SHA-256 hashes."""
        by_hash: dict[str, list[FileRecord]] = defaultdict(list)
        for f in files:
            if f.sha256:
                by_hash[f.sha256].append(f)

        clusters: list[DuplicateCluster] = []
        for sha, group in by_hash.items():
            if len(group) < 2:
                continue

            members_with_scores = [(f, scores.get(f.id or 0)) for f in group]
            keeper_id = self._select_keeper(members_with_scores)
            next((f.size_bytes for f in group if f.id == keeper_id), 0)
            wasted = sum(f.size_bytes for f in group if f.id != keeper_id)

            members = []
            for f in group:
                members.append(
                    DuplicateMember(
                        file_id=f.id or 0,
                        is_keeper=1 if f.id == keeper_id else 0,
                        file_path=f.path,
                        size_bytes=f.size_bytes,
                    )
                )

            cluster = DuplicateCluster(
                cluster_hash=sha,
                file_count=len(group),
                total_wasted_bytes=wasted,
                best_file_id=keeper_id,
                strategy=self.strategy,
                created_at=_now_iso(),
                members=members,
            )
            clusters.append(cluster)

        return clusters

    def _find_near_duplicates(
        self,
        files: list[FileRecord],
        scores: dict[int, IntelligenceScore],
    ) -> list[DuplicateCluster]:
        """Find files with same normalized text content."""
        by_norm_hash: dict[str, list[FileRecord]] = defaultdict(list)
        for f in files:
            if not f.content_sample or f.is_binary:
                continue
            norm_h = normalized_hash(f.content_sample)
            by_norm_hash[norm_h].append(f)

        clusters: list[DuplicateCluster] = []
        for norm_h, group in by_norm_hash.items():
            if len(group) < 2:
                continue
            # Skip if all files have same SHA-256 (already caught by exact dedup)
            shas = {f.sha256 for f in group if f.sha256}
            if len(shas) <= 1:
                continue

            members_with_scores = [(f, scores.get(f.id or 0)) for f in group]
            keeper_id = self._select_keeper(members_with_scores)
            wasted = sum(f.size_bytes for f in group if f.id != keeper_id)

            members = []
            for f in group:
                members.append(
                    DuplicateMember(
                        file_id=f.id or 0,
                        is_keeper=1 if f.id == keeper_id else 0,
                        file_path=f.path,
                        size_bytes=f.size_bytes,
                    )
                )

            cluster = DuplicateCluster(
                cluster_hash=f"near:{norm_h[:32]}",
                file_count=len(group),
                total_wasted_bytes=wasted,
                best_file_id=keeper_id,
                strategy=self.strategy,
                created_at=_now_iso(),
                members=members,
            )
            clusters.append(cluster)

        return clusters

    def _find_semantic_duplicates(
        self,
        files: list[FileRecord],
        classifications: dict[int, list[Classification]],
        scores: dict[int, IntelligenceScore],
    ) -> list[DuplicateCluster]:
        """Find files with same engine classifications and high keyword overlap."""
        # Group by primary domain + primary topic
        topic_groups: dict[str, list[FileRecord]] = defaultdict(list)
        for f in files:
            fid = f.id or 0
            clss = classifications.get(fid, [])
            if not clss:
                continue
            primary = max(clss, key=lambda c: c.score)
            key = f"{primary.domain}:{primary.topic}"
            topic_groups[key].append(f)

        clusters: list[DuplicateCluster] = []
        for topic_key, group in topic_groups.items():
            if len(group) < 2:
                continue

            # Check keyword overlap between pairs
            keywords_cache: dict[int, set[str]] = {}
            for f in group:
                fid = f.id or 0
                if fid not in keywords_cache:
                    keywords_cache[fid] = extract_keywords(f.content_sample or "")

            # Find subgroups with high overlap
            visited: set[int] = set()
            for i, f1 in enumerate(group):
                fid1 = f1.id or 0
                if fid1 in visited:
                    continue
                sub_group = [f1]
                kw1 = keywords_cache.get(fid1, set())
                if not kw1:
                    continue

                for f2 in group[i + 1 :]:
                    fid2 = f2.id or 0
                    if fid2 in visited:
                        continue
                    kw2 = keywords_cache.get(fid2, set())
                    if not kw2:
                        continue
                    overlap = keyword_overlap(kw1, kw2)
                    if overlap >= self.semantic_overlap_threshold:
                        sub_group.append(f2)
                        visited.add(fid2)

                if len(sub_group) >= 2:
                    visited.add(fid1)
                    members_with_scores = [(f, scores.get(f.id or 0)) for f in sub_group]
                    keeper_id = self._select_keeper(members_with_scores)
                    wasted = sum(f.size_bytes for f in sub_group if f.id != keeper_id)

                    members = []
                    for f in sub_group:
                        members.append(
                            DuplicateMember(
                                file_id=f.id or 0,
                                is_keeper=1 if f.id == keeper_id else 0,
                                file_path=f.path,
                                size_bytes=f.size_bytes,
                            )
                        )

                    cluster = DuplicateCluster(
                        cluster_hash=f"sem:{topic_key}:{fid1}",
                        file_count=len(sub_group),
                        total_wasted_bytes=wasted,
                        best_file_id=keeper_id,
                        strategy=self.strategy,
                        created_at=_now_iso(),
                        members=members,
                    )
                    clusters.append(cluster)

        return clusters

    def _select_keeper(
        self,
        members: list[tuple[FileRecord, IntelligenceScore | None]],
    ) -> int:
        """Select the keeper file from a group of duplicates.

        Uses the configured strategy, falling back through a cascade:
        highest_quality → newest → shallowest.
        """
        if not members:
            return 0

        select_fn = KEEPER_FUNCTIONS.get(self.strategy)
        if select_fn:
            try:
                return select_fn(members)
            except Exception:
                pass

        # Fallback cascade
        for fallback in (
            _select_keeper_highest_quality,
            _select_keeper_newest,
            _select_keeper_shallowest,
        ):
            try:
                return fallback(members)
            except Exception:
                continue

        return members[0][0].id or 0

    def get_stats(self) -> dict[str, Any]:
        """Return deduplication statistics."""
        return {
            "total_clusters": len(self.clusters),
            **self.stats,
        }
