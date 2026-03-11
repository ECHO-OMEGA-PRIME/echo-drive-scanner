"""Intelligent Drive Scanner v2.0 — Main Scan Orchestrator.

Coordinates the full intelligence scanning pipeline:
  1. File discovery (walk filesystem)
  2. Content sampling (extract samples, hashes, MIME types)
  3. Classification (3-tier engine pipeline)
  4. Scoring (6-dimension intelligence scores)
  5. Relationship mapping (cross-file analysis)
  6. Deduplication (exact, near, semantic)
  7. Recommendations (actionable intelligence)
  8. Cloud sync (upload results to Cloudflare Worker)
  9. Dashboard (optional live analytics)

Usage:
    python scanner.py --profile INTELLIGENCE --drives O: I: F:
    python scanner.py --intelligence --path "O:\\TAX_KNOWLEDGE" --dashboard
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import aiohttp
from loguru import logger

from config import (
    DRIVE_INTELLIGENCE_URL,
    WORKER_SYNC_ENABLED,
    WORKER_PUSH_BATCH_SIZE,
    DB_PATH,
    LOG_DIR,
    SCAN_PROFILES,
    ScanConfig,
)
from intelligence.classifier import ClassificationPipeline
from intelligence.content_sampler import ContentSampler
from intelligence.deduplicator import Deduplicator
from intelligence.engine_client import EngineClient
from intelligence.recommender import RecommendationEngine
from intelligence.relationship_mapper import RelationshipMapper
from intelligence.scorer import IntelligenceScorer
from storage.db import IntelligenceDB
from storage.models import (
    Classification,
    DomainStats,
    FileRecord,
    IntelligenceScore,
    ScanProgress,
    ScanStatus,
)
from intelligence.project_advisor import ProjectAdvisor, format_proposals_for_knowledge_forge, store_proposals_to_db
from intelligence.function_library import extract_all as extract_libraries
from intelligence.checkpoint import ScanLock, ScanCheckpoint, check_disk_space


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── File Discovery ───────────────────────────────────────────────────────────


def discover_files(
    paths: list[str],
    config: ScanConfig,
) -> list[Path]:
    """Walk filesystem paths and collect file entries.

    Applies extension filtering, size limits, and skip patterns.

    Args:
        paths: List of root paths (drives, folders) to scan.
        config: Scan configuration with filters.

    Returns:
        List of discovered file paths.
    """
    discovered: list[Path] = []
    skip_dirs = {
        ".git", "__pycache__", "node_modules", ".venv", "venv",
        ".hf_cache", ".playwright-mcp", "$Recycle.Bin",
        "System Volume Information", "Windows",
    }

    for root_path_str in paths:
        root_path = Path(root_path_str)
        if not root_path.exists():
            logger.warning("Path does not exist: {}", root_path)
            continue

        logger.info("Discovering files in: {}", root_path)

        if root_path.is_file():
            discovered.append(root_path)
            continue

        for dirpath, dirnames, filenames in os.walk(root_path, topdown=True):
            # Prune skip directories
            dirnames[:] = [
                d for d in dirnames
                if d not in skip_dirs
                and not d.startswith(".")
            ]

            depth = len(Path(dirpath).parts) - len(root_path.parts)
            if config.max_depth and depth > config.max_depth:
                dirnames.clear()
                continue

            for filename in filenames:
                try:
                    filepath = Path(dirpath) / filename
                    # Quick stat to check size
                    try:
                        stat = filepath.stat()
                    except (OSError, PermissionError):
                        continue

                    if stat.st_size == 0:
                        continue
                    if config.max_file_size and stat.st_size > config.max_file_size:
                        continue

                    # Extension filter
                    ext = filepath.suffix.lower()
                    if config.include_extensions and ext not in config.include_extensions:
                        continue
                    if config.exclude_extensions and ext in config.exclude_extensions:
                        continue

                    discovered.append(filepath)
                except Exception as e:
                    logger.debug("Error checking file {}: {}", filename, e)

    logger.info("Discovered {} files across {} paths", len(discovered), len(paths))
    return discovered


def discover_files_streaming(
    paths: list[str],
    config: ScanConfig,
):
    """Generator version of discover_files — yields one Path at a time.
    Never holds the full file list in RAM. Use for large drives."""
    skip_dirs = {
        ".git", "__pycache__", "node_modules", ".venv", "venv",
        ".hf_cache", ".playwright-mcp", "$Recycle.Bin",
        "System Volume Information", "Windows",
    }

    for root_path_str in paths:
        root_path = Path(root_path_str)
        if not root_path.exists():
            logger.warning("Path does not exist: {}", root_path)
            continue
        for dirpath, dirnames, filenames in os.walk(root_path, followlinks=False):
            # Prune skip dirs in-place
            dirnames[:] = [
                d for d in dirnames
                if d not in skip_dirs and not d.startswith(".")
            ]
            for filename in filenames:
                file_path = Path(dirpath) / filename
                try:
                    if config.max_file_size_mb and file_path.stat().st_size > config.max_file_size_mb * 1024 * 1024:
                        continue
                    if config.extensions and file_path.suffix.lower() not in config.extensions:
                        continue
                    yield file_path
                except (PermissionError, OSError):
                    continue


def build_file_records(
    file_paths: list[Path],
    scan_id: int,
) -> list[FileRecord]:
    """Convert discovered paths to FileRecord objects with filesystem metadata.

    Args:
        file_paths: Discovered file paths.
        scan_id: Current scan ID.

    Returns:
        List of FileRecord objects.
    """
    records: list[FileRecord] = []

    for fp in file_paths:
        try:
            stat = fp.stat()
            records.append(FileRecord(
                path=str(fp),
                filename=fp.name,
                extension=fp.suffix.lower(),
                size_bytes=stat.st_size,
                created_at=datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc).isoformat(),
                modified_at=datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
                accessed_at=datetime.fromtimestamp(stat.st_atime, tz=timezone.utc).isoformat(),
                drive=fp.drive or str(fp.parts[0]) if fp.parts else "",
                parent_dir=str(fp.parent),
                depth=len(fp.parts),
                scan_id=scan_id,
            ))
        except (OSError, PermissionError) as e:
            logger.debug("Cannot stat {}: {}", fp, e)

    return records


# ── Main Scanner Orchestrator ────────────────────────────────────────────────


class IntelligenceScanOrchestrator:
    """Orchestrates the full intelligence scanning pipeline.

    Coordinates discovery, sampling, classification, scoring, relationships,
    deduplication, and recommendation generation.
    """

    def __init__(self, config: ScanConfig | None = None) -> None:
        self.config = config or ScanConfig()
        self.db = IntelligenceDB(DB_PATH)
        self.sampler = ContentSampler()
        self.scorer = IntelligenceScorer()
        self.mapper = RelationshipMapper()
        self.deduplicator = Deduplicator()
        self.recommender = RecommendationEngine()
        self.progress = ScanProgress(scan_id=0)
        self._progress_callbacks: list[Any] = []

    def add_progress_callback(self, callback: Any) -> None:
        """Register a callback for progress updates (e.g., WebSocket)."""
        self._progress_callbacks.append(callback)

    def _update_progress(self, **kwargs: Any) -> None:
        """Update and broadcast scan progress."""
        for key, value in kwargs.items():
            if hasattr(self.progress, key):
                setattr(self.progress, key, value)
        for cb in self._progress_callbacks:
            try:
                cb(self.progress)
            except Exception:
                pass

    async def run_scan(
        self,
        paths: list[str],
        profile: str = "INTELLIGENCE",
    ) -> int:
        """Execute a full intelligence scan.

        Args:
            paths: Root paths to scan.
            profile: Scan profile name.

        Returns:
            Scan ID.
        """
        start_time = time.time()
        logger.info("Starting intelligence scan: paths={}, profile={}", paths, profile)

        # Initialize database
        self.db.initialize()

        # Create scan record
        scan_id = self.db.create_scan(
            drives=paths,
            profile=profile,
        )
        self.progress.scan_id = scan_id
        self._update_progress(phase="discovering")

        try:
            # Pre-flight checks
            db_ok, free_gb = check_disk_space(self.db.db_path)
            if not free_gb:
                logger.error("Insufficient disk space for scan DB — aborting")
                self.db.complete_scan(scan_id, 0, 0, 0, 0, 0.0)
                return scan_id
            logger.info("Disk preflight OK: {:.1f}GB free", free_gb)

            # Phase 1: Discovery (streaming — never holds full list in RAM)
            logger.info("Phase 1: File Discovery")
            self._update_progress(phase="discovering")

            BATCH_SIZE = 2000  # files per batch — tune up/down for speed vs memory
            total_discovered = 0
            total_size = 0
            all_stored_ids: list[int] = []
            path_to_id_partial: dict[str, int] = {}

            # Stream discovery + sample + store in rolling batches
            logger.info("Phase 2: Streaming batch sample + store (batch_size={})", BATCH_SIZE)
            self._update_progress(phase="sampling")

            batch_paths: list[Path] = []
            total_skipped = [0]  # mutable counter for closure

            async def flush_batch(batch: list[Path]) -> list[int]:
                """Parallel sample + library extract + change detection + store."""
                # Change detection — skip unchanged files
                changed = []
                for p in batch:
                    try:
                        stat = p.stat()
                        mtime = str(stat.st_mtime)
                        if not self.db.file_unchanged(str(p), mtime, stat.st_size):
                            changed.append(p)
                        else:
                            # Still update last_seen
                            total_skipped[0] += 1
                    except OSError:
                        pass

                if not changed:
                    return []

                # Parallel sampling — all files at once via ThreadPoolExecutor
                samples = await self.sampler.sample_files_parallel(changed, max_workers=32)

                records = build_file_records(changed, scan_id)
                sampled = []
                for record, sample in zip(records, samples):
                    if sample:
                        record.sha256 = sample.sha256
                        record.xxhash = sample.xxhash
                        record.mime_type = sample.mime_type
                        record.content_sample = sample.content_sample
                        record.file_signature = sample.file_signature
                        record.is_binary = 1 if sample.is_binary else 0
                        # Update change detection hash
                        try:
                            stat = Path(record.path).stat()
                            self.db.update_file_hash(
                                record.path, sample.sha256, sample.xxhash,
                                stat.st_size, str(stat.st_mtime), scan_id
                            )
                        except OSError:
                            pass
                        # Library extraction — code files only
                        ext = Path(record.path).suffix.lower()
                        if ext in ('.py', '.js', '.ts', '.jsx', '.tsx') and sample.content_sample:
                            try:
                                extractions = extract_libraries(Path(record.path), sample.content_sample)
                                lib_counts = self.db.store_library_batch(scan_id, extractions)
                                if extractions.get('secrets'):
                                    logger.warning("🔴 SENSITIVE: {} secrets in {}",
                                        len(extractions['secrets']), record.path)
                            except Exception as le:
                                logger.debug("Library extract failed {}: {}", record.path, le)
                    sampled.append(record)

                ids = self.db.upsert_files_batch(sampled)
                for rec, fid in zip(sampled, ids):
                    path_to_id_partial[rec.path] = fid
                return ids

            # Priority sort: scan high-value dirs first
            PRIORITY_DIRS = ['ECHO_OMEGA_PRIME', 'SYSTEMS', 'WORKERS', 'CORE', '_CLAUDE']
            def _priority_key(p):
                s = str(p)
                for i, d in enumerate(PRIORITY_DIRS):
                    if d in s:
                        return i
                return len(PRIORITY_DIRS)

            for file_path in discover_files_streaming(paths, self.config):
                batch_paths.append(file_path)
                total_discovered += 1
                if len(batch_paths) >= BATCH_SIZE:
                    ids = await flush_batch(batch_paths)
                    all_stored_ids.extend(ids)
                    total_size += sum(p.stat().st_size for p in batch_paths if p.exists())
                    self._update_progress(processed_files=total_discovered, current_file=str(batch_paths[-1].name))
                    logger.info("Batch committed: {} files processed ({} total)", len(batch_paths), total_discovered)
                    batch_paths = []  # release memory

            # Final partial batch
            if batch_paths:
                ids = await flush_batch(batch_paths)
                all_stored_ids.extend(ids)
                total_size += sum(p.stat().st_size for p in batch_paths if p.exists())

            self._update_progress(total_files=total_discovered, processed_files=total_discovered)

            if total_discovered == 0:
                logger.warning("No files discovered. Completing scan.")
                self.db.complete_scan(scan_id, 0, 0, 0, 0, 0.0)
                return scan_id

            logger.info("Phase 2 complete: {} files stored in DB", total_discovered)
            stored_ids = all_stored_ids
            # Update IDs from database — returned IDs correspond 1:1 with sampled_records
            path_to_id: dict[str, int] = {}
            path_to_id = path_to_id_partial  # already built during streaming flush

            # Phase 2b: Deduplication
            logger.info("Phase 2b: Deduplication")
            try:
                dedup = Deduplicator(self.db)
                dedup_results = dedup.find_duplicates(scan_id)
                logger.info("Dedup complete: {} clusters, {} wasted bytes",
                    dedup_results.get('clusters', 0),
                    dedup_results.get('wasted_bytes', 0))
            except Exception as de:
                logger.warning("Dedup failed: {}", de)

            # Phase 2c: Library stats
            lib_stats = self.db.get_library_stats()
            logger.info("Library totals — functions:{} patterns:{} schemas:{} endpoints:{} secrets:{}",
                lib_stats.get('lib_functions', 0),
                lib_stats.get('lib_patterns', 0),
                lib_stats.get('lib_schemas', 0),
                lib_stats.get('lib_endpoints', 0),
                lib_stats.get('sensitive_findings', 0))

            # Phase 3: Classification
            logger.info("Phase 3: Engine Classification")
            self._update_progress(phase="classifying")

            all_classifications: dict[int, list[Classification]] = {}
            engine_client = EngineClient()

            async with aiohttp.ClientSession() as session:
                engine_client.session = session
                pipeline = ClassificationPipeline(engine_client)

                # Build file samples for classification as (FileSample, file_id) tuples
                from storage.models import FileSample
                sample_tuples: list[tuple[FileSample, int]] = []
                for rec in sampled_records:
                    if rec.content_sample or not rec.is_binary:
                        fs = FileSample(
                            path=rec.path,
                            filename=rec.filename,
                            extension=rec.extension,
                            size_bytes=rec.size_bytes,
                            mime_type=rec.mime_type or "",
                            file_signature=rec.file_signature or "",
                            content_sample=rec.content_sample,
                            is_binary=bool(rec.is_binary),
                            sha256=rec.sha256 or "",
                            xxhash=rec.xxhash or "",
                        )
                        sample_tuples.append((fs, rec.id or 0))

                # Classify in batches
                batch_size = 100
                api_calls = 0
                cache_hits = 0
                for batch_start in range(0, len(sample_tuples), batch_size):
                    batch = sample_tuples[batch_start:batch_start + batch_size]
                    results = await pipeline.classify_batch_sorted(batch, scan_id)

                    for result in results:
                        file_id = path_to_id.get(result.file_path, 0)
                        if file_id and result.classifications:
                            all_classifications[file_id] = result.classifications
                            self.db.insert_classifications_batch(result.classifications)
                            api_calls += len(result.classifications)

                    classified = min(batch_start + len(batch), len(sample_tuples))
                    self._update_progress(
                        classified_files=classified,
                        api_calls=api_calls,
                        cache_hits=cache_hits,
                        throughput_files_per_min=(
                            classified / max(1, (time.time() - start_time) / 60)
                        ),
                    )

            # Phase 4: Intelligence Scoring
            logger.info("Phase 4: Intelligence Scoring")
            self._update_progress(phase="scoring")

            scores: dict[int, IntelligenceScore] = {}
            for rec in sampled_records:
                fid = rec.id or 0
                clss = all_classifications.get(fid, [])
                score = self.scorer.score_file(rec, clss, scan_id)
                scores[fid] = score
                self.db.upsert_score(score)

            # Phase 5: Relationship Mapping
            logger.info("Phase 5: Relationship Mapping")
            self._update_progress(phase="mapping_relationships")

            relationships = self.mapper.detect_all(
                sampled_records, all_classifications, scan_id,
            )
            if relationships:
                self.db.insert_relationships_batch(relationships)

            # Phase 6: Deduplication
            logger.info("Phase 6: Deduplication")
            self._update_progress(phase="deduplicating")

            clusters = self.deduplicator.find_duplicates(
                sampled_records, scores, all_classifications,
            )
            for cluster in clusters:
                self.db.insert_duplicate_cluster(cluster)

            # Phase 7: Recommendations
            logger.info("Phase 7: Generating Recommendations")
            self._update_progress(phase="recommending")

            recommendations = self.recommender.generate_all(
                sampled_records, scores, all_classifications,
                relationships, clusters, scan_id,
            )
            if recommendations:
                self.db.insert_recommendations_batch(recommendations)

            
            # Stage 10: Project Advisor — Project & Program Intelligence
            logger.info("Stage 10: Project Advisor — Generating Project & Program Proposals")
            self._update_progress(phase="advising")
            try:
                advisor_contents: dict[str, str] = {}
                code_exts = {".py", ".js", ".ts", ".jsx", ".tsx", ".ps1", ".sh"}
                for rec in sampled_records:
                    if rec.extension in code_exts and rec.size_bytes < 200_000:
                        try:
                            advisor_contents[rec.path] = Path(rec.path).read_text(encoding="utf-8", errors="ignore")
                        except Exception:
                            pass
                advisor = ProjectAdvisor()
                proposals = advisor.analyze(
                    files=sampled_records, scores=scores,
                    classifications=all_classifications,
                    scan_id=scan_id, file_contents=advisor_contents,
                )
                if proposals:
                    db_path = str(Path(__file__).parent / "intelligence.db")
                    store_proposals_to_db(db_path, proposals)
                    logger.info("Stage 10: {} proposals stored", len(proposals))
                    kf_payload = format_proposals_for_knowledge_forge(proposals, scan_id, paths)
                    try:
                        import aiohttp as _ah
                        async with _ah.ClientSession() as _s:
                            async with _s.post(
                                "https://echo-knowledge-forge.bmcii1976.workers.dev/ingest",
                                json=kf_payload,
                                headers={"X-Echo-API-Key": "Pr0m3th3us!Prime2025"},
                                timeout=_ah.ClientTimeout(total=30),
                            ) as _r:
                                logger.info("Stage 10: Knowledge Forge -> {}", _r.status)
                    except Exception as _kfe:
                        logger.warning("Stage 10: KF ingest failed: {}", _kfe)
            except Exception as _ae:
                logger.warning("Stage 10 failed (non-fatal): {}", _ae)

            # Phase 9: Domain Statistics
            logger.info("Phase 8: Computing Domain Statistics")
            self._update_progress(phase="computing_stats")

            domain_file_counts: dict[str, int] = defaultdict(int)
            domain_size_totals: dict[str, int] = defaultdict(int)
            domain_score_sums: dict[str, float] = defaultdict(float)

            for fid, score in scores.items():
                domain = score.primary_domain or "UNKNOWN"
                domain_file_counts[domain] += 1
                rec = next((r for r in sampled_records if r.id == fid), None)
                if rec:
                    domain_size_totals[domain] += rec.size_bytes
                domain_score_sums[domain] += score.overall_score

            for domain in domain_file_counts:
                count = domain_file_counts[domain]
                avg = domain_score_sums[domain] / max(1, count)
                ds = DomainStats(
                    scan_id=scan_id,
                    domain=domain,
                    file_count=count,
                    total_size_bytes=domain_size_totals[domain],
                    avg_score=round(avg, 1),
                )
                self.db.upsert_domain_stats(ds)

            # Complete scan
            elapsed = time.time() - start_time
            skipped = len(sampled_records) - len(all_classifications)
            self.db.complete_scan(
                scan_id, len(sampled_records), total_size,
                len(all_classifications), skipped, elapsed,
            )

            self._update_progress(
                phase="completed",
                elapsed_seconds=elapsed,
            )

            # Log summary
            logger.info(
                "Scan {} complete: {} files, {} classified, {} relationships, "
                "{} duplicate clusters, {} recommendations, {:.1f}s",
                scan_id,
                len(sampled_records),
                len(all_classifications),
                len(relationships),
                len(clusters),
                len(recommendations),
                elapsed,
            )

            # Phase 10: Worker Sync — push results to echo-drive-intelligence
            if WORKER_SYNC_ENABLED:
                logger.info("Phase 10: Pushing to echo-drive-intelligence worker")
                pushed = await self.upload_to_cloud(scan_id)
                if pushed:
                    logger.info("Phase 10: Worker push complete ✅")
                else:
                    logger.warning("Phase 10: Worker push failed — results remain in local DB")
            else:
                logger.debug("Worker sync disabled (WORKER_SYNC_ENABLED=False)")

            return scan_id

        except Exception as e:
            logger.error("Scan {} failed: {}", scan_id, e)
            self.db.fail_scan(scan_id)
            raise

    async def upload_to_cloud(self, scan_id: int) -> bool:
        """Push completed scan results to echo-drive-intelligence Cloudflare Worker.

        Maps local SQLite schema → Worker D1 ScanInput interface and streams
        files in batches to stay under CF Worker request size limits.

        Args:
            scan_id: ID of the completed scan to push.

        Returns:
            True if all batches uploaded successfully.
        """
        if not DRIVE_INTELLIGENCE_URL:
            logger.warning("DRIVE_INTELLIGENCE_URL not set, skipping worker push")
            return False

        # Resolve API key: env first, then vault
        # Key: echo-omega-prime-forge-x-2026 (confirmed working on drive-intelligence worker)
        api_key = os.environ.get("ECHO_API_KEY", "echo-omega-prime-forge-x-2026")
        if not api_key:
            try:
                import aiohttp as _ah2
                async with _ah2.ClientSession() as _vs:
                    async with _vs.get(
                        "https://echo-vault-api.bmcii1976.workers.dev/get",
                        params={"service": "echo-drive-intelligence"},
                        headers={"X-Echo-API-Key": "echo-vault-master-2024"},
                        timeout=_ah2.ClientTimeout(total=5),
                    ) as _vr:
                        if _vr.status == 200:
                            vd = await _vr.json()
                            api_key = vd.get("api_key") or vd.get("value", "echo-omega-prime-forge-x-2026")
            except Exception:
                api_key = "echo-omega-prime-forge-x-2026"

        headers = {
            "Content-Type": "application/json",
            "X-Echo-API-Key": api_key,
        }

        # ── Fetch all data from local DB ───────────────────────────────────
        scan = self.db.get_scan(scan_id)
        if not scan:
            logger.error("Scan {} not found in local DB", scan_id)
            return False

        files = self.db.list_files(scan_id=scan_id, limit=500_000)
        scores_raw = self.db.get_top_scores(dimension="overall_score", limit=500_000)
        recs = self.db.get_recommendations(scan_id=scan_id, limit=10_000)
        domain_stats = self.db.get_domain_stats(scan_id)
        dup_clusters = self.db.get_duplicate_clusters(scan_id=scan_id)

        logger.info(
            "Worker push: scan={} files={} scores={} recs={} domains={} dupes={}",
            scan_id, len(files), len(scores_raw), len(recs),
            len(domain_stats), len(dup_clusters),
        )

        # ── Map files → FileInput ──────────────────────────────────────────
        # Worker uses file_index (position in files array) to link scores
        file_inputs = []
        file_index_map: dict[int, int] = {}  # local file_id -> batch index
        for idx, f in enumerate(files):
            fid = f.id if hasattr(f, "id") else (f.get("id") if isinstance(f, dict) else idx)
            file_index_map[fid] = idx
            rec = f if isinstance(f, dict) else f.model_dump() if hasattr(f, "model_dump") else vars(f)
            file_inputs.append({
                "path":             rec.get("path", ""),
                "filename":         rec.get("filename", ""),
                "extension":        rec.get("extension", ""),
                "size_bytes":       rec.get("size_bytes", 0),
                "modified_at":      rec.get("modified_at"),
                "created_at":       rec.get("created_at"),
                "content_hash":     rec.get("sha256") or rec.get("xxhash") or "",
                "domain":           rec.get("domain", "UNKNOWN"),
                "domain_label":     rec.get("domain_label", ""),
                "domain_confidence": rec.get("domain_confidence", 0.0),
            })

        # ── Map scores → ScoreInput ────────────────────────────────────────
        score_inputs = []
        for s in scores_raw:
            sd = s if isinstance(s, dict) else (s.model_dump() if hasattr(s, "model_dump") else vars(s))
            fid = sd.get("file_id", 0)
            score_inputs.append({
                "file_index":        file_index_map.get(fid, 0),
                "overall_score":     sd.get("overall_score", 0.0),
                "quality_score":     sd.get("quality_score", 0.0),
                "importance_score":  sd.get("importance_score", 0.0),
                "sensitivity_score": sd.get("sensitivity_score", 0.0),
                "staleness_score":   sd.get("staleness_score", 0.0),
                "uniqueness_score":  sd.get("uniqueness_score", 0.0),
                "risk_score":        sd.get("risk_score", 0.0),
                "scored_at":         sd.get("scored_at", _now_iso()),
            })

        # ── Map domain_stats → DomainInput ────────────────────────────────
        domain_inputs = []
        for d in domain_stats:
            dd = d if isinstance(d, dict) else (d.model_dump() if hasattr(d, "model_dump") else vars(d))
            domain_inputs.append({
                "domain":           dd.get("domain", "UNKNOWN"),
                "domain_label":     dd.get("domain_label", ""),
                "file_count":       dd.get("file_count", 0),
                "total_size_bytes": dd.get("total_size_bytes", 0),
                "avg_score":        dd.get("avg_score", 0.0),
            })

        # ── Map duplicate clusters → DuplicateInput ───────────────────────
        dupe_inputs = []
        for c in dup_clusters:
            cd = c if isinstance(c, dict) else (c.model_dump() if hasattr(c, "model_dump") else vars(c))
            dupe_inputs.append({
                "cluster_hash": cd.get("cluster_hash", ""),
                "file_count":   cd.get("file_count", 0),
                "wasted_bytes": cd.get("total_wasted_bytes", 0),
                "file_paths":   cd.get("file_paths", []),
            })

        # ── Map recommendations → RecommendationInput ─────────────────────
        rec_inputs = []
        for r in recs:
            rd = r if isinstance(r, dict) else (r.model_dump() if hasattr(r, "model_dump") else vars(r))
            rec_inputs.append({
                "title":            rd.get("title", ""),
                "description":      rd.get("description", ""),
                "category":         rd.get("category", "general"),
                "severity":         rd.get("severity", "medium"),
                "affected_files":   rd.get("affected_files", []),
                "estimated_impact": rd.get("estimated_impact", ""),
            })

        # ── Build ScanInput payload ────────────────────────────────────────
        sd = scan if isinstance(scan, dict) else (scan.model_dump() if hasattr(scan, "model_dump") else vars(scan))
        BATCH = WORKER_PUSH_BATCH_SIZE  # default 500

        # Send first batch with full scan metadata + first BATCH files
        first_files  = file_inputs[:BATCH]
        first_scores = [s for s in score_inputs if s["file_index"] < BATCH]

        payload: dict = {
            "node":              os.environ.get("COMPUTERNAME", "ALPHA"),
            "started_at":        sd.get("started_at", _now_iso()),
            "completed_at":      sd.get("completed_at", _now_iso()),
            "profile":           sd.get("profile", "INTELLIGENCE"),
            "paths":             json.loads(sd.get("drives", "[]")) if isinstance(sd.get("drives"), str) else sd.get("drives", []),
            "total_files":       sd.get("total_files", len(files)),
            "total_size_bytes":  sd.get("total_size_bytes", 0),
            "duration_seconds":  sd.get("duration_seconds", 0.0),
            "status":            "complete",
            "files":             first_files,
            "scores":            first_scores,
            "domains":           domain_inputs,
            "duplicates":        dupe_inputs,
            "recommendations":   rec_inputs,
        }

        try:
            async with aiohttp.ClientSession() as session:
                # POST scan + first batch
                async with session.post(
                    f"{DRIVE_INTELLIGENCE_URL}/ingest/scan",
                    json=payload,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=120),
                ) as resp:
                    if resp.status not in (200, 201):
                        logger.error("Worker /ingest/scan failed: {} {}", resp.status, await resp.text())
                        return False
                    result = await resp.json()
                    worker_scan_id = result.get("scan_id") or result.get("id")
                    logger.info("Worker scan created: id={} counts={}", worker_scan_id, result.get("counts", {}))

                # Push remaining file batches via /ingest/files
                remaining = file_inputs[BATCH:]
                batch_num = 1
                for i in range(0, len(remaining), BATCH):
                    chunk_files = remaining[i:i + BATCH]
                    offset = BATCH + i
                    chunk_scores = [
                        {**s, "file_index": s["file_index"] - offset}
                        for s in score_inputs
                        if offset <= s["file_index"] < offset + BATCH
                    ]
                    batch_payload = {
                        "scan_id": worker_scan_id,
                        "files":   chunk_files,
                        "scores":  chunk_scores,
                    }
                    async with session.post(
                        f"{DRIVE_INTELLIGENCE_URL}/ingest/files",
                        json=batch_payload,
                        headers=headers,
                        timeout=aiohttp.ClientTimeout(total=60),
                    ) as br:
                        if br.status not in (200, 201):
                            logger.warning("Batch {} failed: {}", batch_num, await br.text())
                        else:
                            logger.debug("Batch {}: {} files pushed", batch_num, len(chunk_files))
                    batch_num += 1

                total_batches = 1 + max(0, (len(file_inputs) - BATCH + BATCH - 1) // BATCH)
                logger.info(
                    "Worker push complete: scan_id={} {} files in {} batches",
                    worker_scan_id, len(file_inputs), total_batches,
                )
                return True

        except Exception as e:
            logger.error("Worker push error: {}", e)
            return False

    def get_scan_summary(self, scan_id: int) -> dict[str, Any] | None:
        """Get scan summary for display."""
        summary = self.db.get_scan_summary(scan_id)
        if summary:
            return summary.model_dump()
        return None
