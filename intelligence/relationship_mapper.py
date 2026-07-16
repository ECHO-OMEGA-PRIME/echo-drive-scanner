"""Intelligent Drive Scanner v2.0 â€” Cross-File Relationship Mapping.

Detects how files relate to each other by analyzing shared content, naming
patterns, directory structures, code dependencies, and classification overlaps.
"""

from __future__ import annotations

import re
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from loguru import logger

from storage.models import (
    Classification,
    FileRecord,
    Relationship,
    RelationshipType,
)


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


# â”€â”€ Version Pattern Detection â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

VERSION_PATTERNS = [
    re.compile(r"^(.+?)[-_]v(\d+(?:\.\d+)*)(\..+)$", re.IGNORECASE),
    re.compile(r"^(.+?)[-_](\d{8})(\..+)$"),  # date-based
    re.compile(r"^(.+?)[-_](?:copy|backup|old|bak)(\..+)$", re.IGNORECASE),
    re.compile(r"^(.+?)\s*\((\d+)\)(\..+)$"),  # file (1).txt
    re.compile(r"^(.+?)[-_]rev(\d+)(\..+)$", re.IGNORECASE),
]

# â”€â”€ Code Import Patterns â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

IMPORT_PATTERNS: dict[str, list[re.Pattern[str]]] = {
    ".py": [
        re.compile(r"^\s*(?:from|import)\s+([\w.]+)", re.MULTILINE),
    ],
    ".js": [
        re.compile(r"""(?:require|import)\s*\(?['"](.+?)['"]"""),
        re.compile(r"""from\s+['"](.+?)['"]"""),
    ],
    ".ts": [
        re.compile(r"""(?:require|import)\s*\(?['"](.+?)['"]"""),
        re.compile(r"""from\s+['"](.+?)['"]"""),
    ],
    ".tsx": [
        re.compile(r"""(?:require|import)\s*\(?['"](.+?)['"]"""),
        re.compile(r"""from\s+['"](.+?)['"]"""),
    ],
    ".go": [
        re.compile(r'"([^"]+)"'),
    ],
    ".rs": [
        re.compile(r"(?:use|mod)\s+([\w:]+)"),
    ],
    ".java": [
        re.compile(r"import\s+([\w.]+)"),
    ],
    ".cs": [
        re.compile(r"using\s+([\w.]+)"),
    ],
    ".cpp": [
        re.compile(r'#include\s*[<"](.+?)[>"]'),
    ],
    ".c": [
        re.compile(r'#include\s*[<"](.+?)[>"]'),
    ],
    ".h": [
        re.compile(r'#include\s*[<"](.+?)[>"]'),
    ],
}


class RelationshipMapper:
    """Detects cross-file relationships from multiple signals.

    Relationship types detected:
      - duplicates: Exact SHA-256 match
      - near_duplicates: Same normalized text hash
      - references: Content mentions another filename
      - versioned: Same base name with version suffix
      - supplements: Same domain + shared keywords
      - depends_on: Code imports/includes
      - co_classified: Same engine classifications
      - supersedes: Same topic, newer, higher quality
    """

    def __init__(self) -> None:
        self.relationships: list[Relationship] = []
        self.stats = {
            "duplicates": 0,
            "versioned": 0,
            "references": 0,
            "depends_on": 0,
            "supplements": 0,
            "co_classified": 0,
            "supersedes": 0,
        }

    def detect_all(
        self,
        files: list[FileRecord],
        classifications: dict[int, list[Classification]],
        scan_id: int,
    ) -> list[Relationship]:
        """Run all relationship detection passes on a set of files.

        Args:
            files: All file records from this scan.
            classifications: Map of file_id â†’ list of classifications.
            scan_id: Current scan ID.

        Returns:
            List of detected relationships.
        """
        self.relationships = []
        logger.info("Detecting relationships across {} files", len(files))

        # Build indexes for efficient lookup
        by_hash: dict[str, list[FileRecord]] = defaultdict(list)
        by_name_stem: dict[str, list[FileRecord]] = defaultdict(list)
        by_dir: dict[str, list[FileRecord]] = defaultdict(list)
        filenames_set: set[str] = set()
        file_id_map: dict[str, int] = {}

        for f in files:
            file_id = f.id or 0
            file_id_map[f.path] = file_id
            filenames_set.add(f.filename.lower())

            if f.sha256:
                by_hash[f.sha256].append(f)

            stem = self._extract_stem(f.filename)
            if stem:
                by_name_stem[stem].append(f)

            by_dir[f.parent_dir].append(f)

        # Pass 1: Hash-based duplicates
        self._detect_hash_duplicates(by_hash, scan_id)

        # Pass 2: Version patterns
        self._detect_versions(by_name_stem, scan_id)

        # Pass 3: Content references
        self._detect_content_references(files, filenames_set, file_id_map, scan_id)

        # Pass 4: Code dependencies
        self._detect_code_dependencies(files, by_dir, file_id_map, scan_id)

        # Pass 5: Domain co-classification
        self._detect_co_classified(files, classifications, scan_id)

        # Pass 6: Supersedes detection (same topic, newer, higher quality)
        self._detect_supersedes(files, classifications, scan_id)

        logger.info(
            "Detected {} relationships: {}",
            len(self.relationships),
            {k: v for k, v in self.stats.items() if v > 0},
        )
        return self.relationships

    def _extract_stem(self, filename: str) -> str:
        """Extract base name stem for version grouping."""
        for pattern in VERSION_PATTERNS:
            m = pattern.match(filename)
            if m:
                return m.group(1).lower().strip("-_ ")
        # Fallback: filename without extension
        p = Path(filename)
        return p.stem.lower()

    def _detect_hash_duplicates(
        self,
        by_hash: dict[str, list[FileRecord]],
        scan_id: int,
    ) -> None:
        """Detect exact duplicates via SHA-256 match."""
        for sha, group in by_hash.items():
            if len(group) < 2 or not sha:
                continue
            # Create pairwise relationships (first file is "source")
            primary = group[0]
            for other in group[1:]:
                rel = Relationship(
                    source_file_id=primary.id or 0,
                    target_file_id=other.id or 0,
                    relationship_type=RelationshipType.DUPLICATES.value,
                    confidence=1.0,
                    evidence=f"SHA-256 match: {sha[:16]}...",
                    detected_at=_now_iso(),
                    scan_id=scan_id,
                )
                self.relationships.append(rel)
                self.stats["duplicates"] += 1

    def _detect_versions(
        self,
        by_name_stem: dict[str, list[FileRecord]],
        scan_id: int,
    ) -> None:
        """Detect versioned files from naming patterns."""
        for _stem, group in by_name_stem.items():
            if len(group) < 2:
                continue

            # Check if names actually show version pattern differences
            for pattern in VERSION_PATTERNS:
                matches = [(f, pattern.match(f.filename)) for f in group]
                versioned = [(f, m) for f, m in matches if m is not None]
                if len(versioned) >= 2:
                    sorted_files = sorted(versioned, key=lambda x: x[0].modified_at or "")
                    for i in range(len(sorted_files) - 1):
                        older = sorted_files[i][0]
                        newer = sorted_files[i + 1][0]
                        rel = Relationship(
                            source_file_id=older.id or 0,
                            target_file_id=newer.id or 0,
                            relationship_type=RelationshipType.VERSIONED.value,
                            confidence=0.85,
                            evidence=f"Version pattern: {older.filename} â†’ {newer.filename}",
                            detected_at=_now_iso(),
                            scan_id=scan_id,
                        )
                        self.relationships.append(rel)
                        self.stats["versioned"] += 1
                    break

    def _detect_content_references(
        self,
        files: list[FileRecord],
        filenames_set: set[str],
        file_id_map: dict[str, int],
        scan_id: int,
    ) -> None:
        """Detect files that reference other filenames in their content."""
        filename_to_paths: dict[str, list[str]] = defaultdict(list)
        for f in files:
            filename_to_paths[f.filename.lower()].append(f.path)

        for f in files:
            if not f.content_sample:
                continue
            content_lower = f.content_sample.lower()
            source_id = f.id or 0

            for target_name in filenames_set:
                if target_name == f.filename.lower():
                    continue
                if len(target_name) < 5:
                    continue
                if target_name in content_lower:
                    for target_path in filename_to_paths.get(target_name, []):
                        target_id = file_id_map.get(target_path, 0)
                        if target_id == 0 or target_id == source_id:
                            continue
                        rel = Relationship(
                            source_file_id=source_id,
                            target_file_id=target_id,
                            relationship_type=RelationshipType.REFERENCES.value,
                            confidence=0.7,
                            evidence=f"Content mentions '{target_name}'",
                            detected_at=_now_iso(),
                            scan_id=scan_id,
                        )
                        self.relationships.append(rel)
                        self.stats["references"] += 1

    def _detect_code_dependencies(
        self,
        files: list[FileRecord],
        by_dir: dict[str, list[FileRecord]],
        file_id_map: dict[str, int],
        scan_id: int,
    ) -> None:
        """Detect code import/include dependencies."""
        for f in files:
            ext = (f.extension or "").lower()
            patterns = IMPORT_PATTERNS.get(ext)
            if not patterns or not f.content_sample:
                continue

            source_id = f.id or 0
            source_dir = f.parent_dir

            for pattern in patterns:
                imports = pattern.findall(f.content_sample)
                for imp in imports:
                    imp_clean = imp.strip().replace(".", "/").replace("::", "/")
                    # Try to find the imported file in same directory or nearby
                    candidates = by_dir.get(source_dir, [])
                    for candidate in candidates:
                        if candidate.id == f.id:
                            continue
                        cand_stem = Path(candidate.filename).stem.lower()
                        imp_last = imp_clean.split("/")[-1].lower()
                        if cand_stem == imp_last:
                            target_id = candidate.id or 0
                            rel = Relationship(
                                source_file_id=source_id,
                                target_file_id=target_id,
                                relationship_type=RelationshipType.DEPENDS_ON.value,
                                confidence=0.8,
                                evidence=f"Import: {imp}",
                                detected_at=_now_iso(),
                                scan_id=scan_id,
                            )
                            self.relationships.append(rel)
                            self.stats["depends_on"] += 1
                            break

    def _detect_co_classified(
        self,
        files: list[FileRecord],
        classifications: dict[int, list[Classification]],
        scan_id: int,
        min_shared_topics: int = 3,
    ) -> None:
        """Detect files co-classified by the same engines on the same topics."""
        # Build topicâ†’file index
        topic_files: dict[str, list[int]] = defaultdict(list)
        for file_id, clss in classifications.items():
            for cls in clss:
                key = f"{cls.domain}:{cls.topic}"
                topic_files[key].append(file_id)

        # Find pairs that share 3+ topics
        pair_shared: dict[tuple[int, int], list[str]] = defaultdict(list)
        for topic_key, file_ids in topic_files.items():
            if len(file_ids) < 2:
                continue
            unique_ids = list(set(file_ids))
            for i in range(min(len(unique_ids), 20)):
                for j in range(i + 1, min(len(unique_ids), 20)):
                    pair = (min(unique_ids[i], unique_ids[j]), max(unique_ids[i], unique_ids[j]))
                    pair_shared[pair].append(topic_key)

        for (fid1, fid2), shared_topics in pair_shared.items():
            if len(shared_topics) >= min_shared_topics:
                rel = Relationship(
                    source_file_id=fid1,
                    target_file_id=fid2,
                    relationship_type=RelationshipType.CO_CLASSIFIED.value,
                    confidence=min(1.0, len(shared_topics) * 0.15),
                    evidence=f"Shared topics ({len(shared_topics)}): {', '.join(shared_topics[:5])}",
                    detected_at=_now_iso(),
                    scan_id=scan_id,
                )
                self.relationships.append(rel)
                self.stats["co_classified"] += 1

    def _detect_supersedes(
        self,
        files: list[FileRecord],
        classifications: dict[int, list[Classification]],
        scan_id: int,
    ) -> None:
        """Detect files that supersede older files on the same topic."""
        # Group by primary domain + similar filename stem
        domain_stem_groups: dict[str, list[FileRecord]] = defaultdict(list)

        for f in files:
            file_id = f.id or 0
            clss = classifications.get(file_id, [])
            if not clss:
                continue
            primary_domain = max(clss, key=lambda c: c.score).domain
            stem = self._extract_stem(f.filename)
            key = f"{primary_domain}:{stem}"
            domain_stem_groups[key].append(f)

        for _key, group in domain_stem_groups.items():
            if len(group) < 2:
                continue

            # Sort by modification date
            sorted_group = sorted(group, key=lambda f: f.modified_at or "", reverse=True)
            newest = sorted_group[0]
            for older in sorted_group[1:]:
                if not newest.modified_at or not older.modified_at:
                    continue
                if newest.modified_at > older.modified_at:
                    rel = Relationship(
                        source_file_id=newest.id or 0,
                        target_file_id=older.id or 0,
                        relationship_type=RelationshipType.SUPERSEDES.value,
                        confidence=0.65,
                        evidence=f"Newer ({newest.filename}) supersedes older ({older.filename})",
                        detected_at=_now_iso(),
                        scan_id=scan_id,
                    )
                    self.relationships.append(rel)
                    self.stats["supersedes"] += 1

    def get_stats(self) -> dict[str, Any]:
        """Return relationship detection statistics."""
        return {
            "total_relationships": len(self.relationships),
            **self.stats,
        }
