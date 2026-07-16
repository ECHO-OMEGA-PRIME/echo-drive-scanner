"""Intelligent Drive Scanner v2.0 — SQLite Intelligence Database Manager.

Manages the local SQLite database storing all file records, classifications,
intelligence scores, relationships, duplicate clusters, and recommendations.
All queries use parameterized statements. Thread-safe via WAL mode.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from loguru import logger

from storage.models import (
    Classification,
    DomainStats,
    DuplicateCluster,
    FileRecord,
    IntelligenceScore,
    Recommendation,
    Relationship,
    ScanRecord,
    ScanSummary,
)

# ── Schema ───────────────────────────────────────────────────────────────────

SCHEMA_VERSION = "2.0.0"

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS schema_info (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    drives TEXT NOT NULL,
    profile TEXT NOT NULL,
    total_files INTEGER DEFAULT 0,
    total_size_bytes INTEGER DEFAULT 0,
    files_classified INTEGER DEFAULT 0,
    files_skipped INTEGER DEFAULT 0,
    duration_seconds REAL,
    status TEXT DEFAULT 'running',
    config TEXT
);

CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    path TEXT NOT NULL UNIQUE,
    filename TEXT NOT NULL,
    extension TEXT,
    size_bytes INTEGER NOT NULL,
    created_at TEXT,
    modified_at TEXT,
    accessed_at TEXT,
    sha256 TEXT,
    xxhash TEXT,
    mime_type TEXT,
    drive TEXT NOT NULL,
    parent_dir TEXT NOT NULL,
    depth INTEGER NOT NULL,
    is_binary INTEGER DEFAULT 0,
    content_sample TEXT,
    file_signature TEXT,
    scan_id INTEGER NOT NULL,
    first_seen_scan_id INTEGER,
    last_modified_scan_id INTEGER,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS classifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id INTEGER NOT NULL,
    scan_id INTEGER NOT NULL,
    engine_id TEXT NOT NULL,
    domain TEXT NOT NULL,
    domain_label TEXT,
    topic TEXT NOT NULL,
    conclusion TEXT,
    confidence TEXT NOT NULL,
    authority_weight INTEGER DEFAULT 0,
    score REAL NOT NULL,
    mode TEXT DEFAULT 'FAST',
    response_ms INTEGER,
    determinism_hash TEXT,
    classified_at TEXT NOT NULL,
    FOREIGN KEY (file_id) REFERENCES files(id),
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS intelligence_scores (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id INTEGER NOT NULL UNIQUE,
    scan_id INTEGER NOT NULL,
    overall_score REAL NOT NULL DEFAULT 0,
    quality_score REAL DEFAULT 0,
    importance_score REAL DEFAULT 0,
    sensitivity_score REAL DEFAULT 0,
    staleness_score REAL DEFAULT 0,
    uniqueness_score REAL DEFAULT 0,
    risk_score REAL DEFAULT 0,
    primary_domain TEXT,
    primary_engine TEXT,
    domain_distribution TEXT,
    classification_count INTEGER DEFAULT 0,
    scored_at TEXT NOT NULL,
    score_version TEXT DEFAULT '2.0',
    FOREIGN KEY (file_id) REFERENCES files(id),
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS relationships (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_file_id INTEGER NOT NULL,
    target_file_id INTEGER NOT NULL,
    relationship_type TEXT NOT NULL,
    confidence REAL NOT NULL,
    evidence TEXT,
    detected_at TEXT NOT NULL,
    scan_id INTEGER NOT NULL,
    FOREIGN KEY (source_file_id) REFERENCES files(id),
    FOREIGN KEY (target_file_id) REFERENCES files(id),
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS duplicate_clusters (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cluster_hash TEXT NOT NULL,
    file_count INTEGER NOT NULL,
    total_wasted_bytes INTEGER,
    best_file_id INTEGER,
    strategy TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (best_file_id) REFERENCES files(id)
);

CREATE TABLE IF NOT EXISTS duplicate_members (
    cluster_id INTEGER NOT NULL,
    file_id INTEGER NOT NULL,
    is_keeper INTEGER DEFAULT 0,
    PRIMARY KEY (cluster_id, file_id),
    FOREIGN KEY (cluster_id) REFERENCES duplicate_clusters(id),
    FOREIGN KEY (file_id) REFERENCES files(id)
);

CREATE TABLE IF NOT EXISTS recommendations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    affected_files TEXT,
    affected_count INTEGER DEFAULT 1,
    estimated_impact TEXT,
    action_command TEXT,
    status TEXT DEFAULT 'pending',
    created_at TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS domain_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    domain TEXT NOT NULL,
    domain_label TEXT,
    file_count INTEGER NOT NULL,
    total_size_bytes INTEGER,
    avg_score REAL,
    avg_confidence TEXT,
    top_topics TEXT,
    UNIQUE(scan_id, domain),
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

-- ── Project Advisor Proposals (Stage 10) ───────────────────────────────────
-- Build/program proposals: projects that need completion (TODO/WIP/STUB) and
-- new builds/programs that should be built. Written by
-- intelligence.project_advisor.store_proposals_to_db (kept in sync here so the
-- table always exists for read queries even before a Stage-10 scan has run).
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
);

-- ── Echo Function Library ──────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS lib_functions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    language TEXT NOT NULL,
    signature TEXT NOT NULL,
    docstring TEXT,
    body TEXT,
    body_hash TEXT NOT NULL,
    file_path TEXT NOT NULL,
    line_number INTEGER,
    is_async INTEGER DEFAULT 0,
    quality_score INTEGER DEFAULT 0,
    patterns TEXT,
    arg_count INTEGER DEFAULT 0,
    copy_count INTEGER DEFAULT 1,
    first_seen_scan INTEGER,
    last_seen_scan INTEGER,
    UNIQUE(body_hash, file_path)
);

-- ── Echo Pattern Library ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS lib_patterns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern TEXT NOT NULL,
    language TEXT NOT NULL,
    file_path TEXT NOT NULL,
    scan_id INTEGER,
    UNIQUE(pattern, file_path)
);

-- ── Echo Schema Library ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS lib_schemas (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    schema_type TEXT NOT NULL,
    language TEXT,
    file_path TEXT NOT NULL,
    definition TEXT,
    scan_id INTEGER,
    UNIQUE(name, file_path)
);

-- ── Echo API Library ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS lib_endpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    language TEXT,
    file_path TEXT NOT NULL,
    scan_id INTEGER,
    UNIQUE(method, path, file_path)
);

-- ── Echo Prompt Library ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS lib_prompts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    prompt_type TEXT NOT NULL,
    content TEXT NOT NULL,
    length INTEGER DEFAULT 0,
    file_path TEXT NOT NULL,
    quality_score INTEGER DEFAULT 0,
    scan_id INTEGER,
    content_hash TEXT,
    UNIQUE(content_hash, file_path)
);

-- ── Echo Config Library ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS lib_configs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL,
    value_preview TEXT,
    language TEXT,
    file_path TEXT NOT NULL,
    scan_id INTEGER,
    UNIQUE(key, file_path)
);

-- ── Echo Error Library ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS lib_errors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    exception_type TEXT NOT NULL,
    handler_body TEXT,
    language TEXT,
    file_path TEXT NOT NULL,
    quality_score INTEGER DEFAULT 0,
    scan_id INTEGER,
    UNIQUE(exception_type, file_path)
);

-- ── Echo Credential Map ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS lib_credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    credential_key TEXT NOT NULL,
    file_path TEXT NOT NULL,
    scan_id INTEGER,
    UNIQUE(credential_key, file_path)
);

-- ── Sensitive File Findings ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS sensitive_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_path TEXT NOT NULL,
    secret_type TEXT NOT NULL,
    line_number INTEGER,
    match_preview TEXT,
    scan_id INTEGER,
    severity TEXT DEFAULT 'HIGH',
    resolved INTEGER DEFAULT 0,
    found_at TEXT DEFAULT (datetime('now'))
);

-- ── Scan Checkpoints ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scan_stages (
    scan_id INTEGER NOT NULL,
    stage TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TEXT,
    completed_at TEXT,
    detail TEXT,
    warning_count INTEGER DEFAULT 0,
    PRIMARY KEY (scan_id, stage),
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS scan_file_observations (
    scan_id INTEGER NOT NULL,
    file_id INTEGER NOT NULL,
    path TEXT NOT NULL,
    filename TEXT NOT NULL,
    extension TEXT,
    size_bytes INTEGER NOT NULL,
    created_at TEXT,
    modified_at TEXT,
    accessed_at TEXT,
    sha256 TEXT,
    xxhash TEXT,
    mime_type TEXT,
    drive TEXT NOT NULL,
    parent_dir TEXT NOT NULL,
    depth INTEGER NOT NULL,
    is_binary INTEGER DEFAULT 0,
    observed_at TEXT NOT NULL,
    PRIMARY KEY (scan_id, file_id),
    FOREIGN KEY (scan_id) REFERENCES scans(id),
    FOREIGN KEY (file_id) REFERENCES files(id)
);

CREATE TRIGGER IF NOT EXISTS trg_scan_observations_no_update
BEFORE UPDATE ON scan_file_observations
BEGIN SELECT RAISE(ABORT, 'scan observations are immutable'); END;

CREATE TRIGGER IF NOT EXISTS trg_scan_observations_no_delete
BEFORE DELETE ON scan_file_observations
BEGIN SELECT RAISE(ABORT, 'scan observations are immutable'); END;

CREATE TABLE IF NOT EXISTS scan_score_observations (
    scan_id INTEGER NOT NULL,
    file_id INTEGER NOT NULL,
    overall_score REAL NOT NULL DEFAULT 0,
    quality_score REAL DEFAULT 0,
    importance_score REAL DEFAULT 0,
    sensitivity_score REAL DEFAULT 0,
    staleness_score REAL DEFAULT 0,
    uniqueness_score REAL DEFAULT 0,
    risk_score REAL DEFAULT 0,
    primary_domain TEXT,
    primary_engine TEXT,
    domain_distribution TEXT,
    classification_count INTEGER DEFAULT 0,
    scored_at TEXT NOT NULL,
    score_version TEXT DEFAULT '2.0',
    PRIMARY KEY (scan_id, file_id),
    FOREIGN KEY (scan_id) REFERENCES scans(id),
    FOREIGN KEY (file_id) REFERENCES files(id)
);

CREATE TRIGGER IF NOT EXISTS trg_scan_scores_no_update
BEFORE UPDATE ON scan_score_observations
BEGIN SELECT RAISE(ABORT, 'scan score observations are immutable'); END;

CREATE TRIGGER IF NOT EXISTS trg_scan_scores_no_delete
BEFORE DELETE ON scan_score_observations
BEGIN SELECT RAISE(ABORT, 'scan score observations are immutable'); END;

CREATE TABLE IF NOT EXISTS scan_checkpoints (
    scan_id INTEGER NOT NULL,
    drive TEXT NOT NULL,
    last_path TEXT,
    files_processed INTEGER DEFAULT 0,
    batches_committed INTEGER DEFAULT 0,
    updated_at TEXT,
    PRIMARY KEY (scan_id, drive)
);

-- ── Change Detection ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS file_hashes (
    path TEXT PRIMARY KEY,
    sha256 TEXT,
    xxhash TEXT,
    size_bytes INTEGER,
    modified_at TEXT,
    last_scan_id INTEGER,
    last_seen TEXT DEFAULT (datetime('now'))
);
"""

INDEX_SQL = """
CREATE INDEX IF NOT EXISTS idx_files_path ON files(path);
CREATE INDEX IF NOT EXISTS idx_files_drive ON files(drive);
CREATE INDEX IF NOT EXISTS idx_files_extension ON files(extension);
CREATE INDEX IF NOT EXISTS idx_files_sha256 ON files(sha256);
CREATE INDEX IF NOT EXISTS idx_files_scan ON files(scan_id);
CREATE INDEX IF NOT EXISTS idx_files_parent ON files(parent_dir);
CREATE INDEX IF NOT EXISTS idx_class_file ON classifications(file_id);
CREATE INDEX IF NOT EXISTS idx_class_domain ON classifications(domain);
CREATE INDEX IF NOT EXISTS idx_class_engine ON classifications(engine_id);
CREATE INDEX IF NOT EXISTS idx_class_scan ON classifications(scan_id);
CREATE INDEX IF NOT EXISTS idx_scores_file ON intelligence_scores(file_id);
CREATE INDEX IF NOT EXISTS idx_scores_domain ON intelligence_scores(primary_domain);
CREATE INDEX IF NOT EXISTS idx_scores_overall ON intelligence_scores(overall_score DESC);
CREATE INDEX IF NOT EXISTS idx_rels_source ON relationships(source_file_id);
CREATE INDEX IF NOT EXISTS idx_rels_target ON relationships(target_file_id);
CREATE INDEX IF NOT EXISTS idx_recs_category ON recommendations(category);
CREATE INDEX IF NOT EXISTS idx_recs_severity ON recommendations(severity);
CREATE INDEX IF NOT EXISTS idx_domain_stats_scan ON domain_stats(scan_id);
CREATE INDEX IF NOT EXISTS idx_proposals_scan ON project_proposals(scan_id);
CREATE INDEX IF NOT EXISTS idx_proposals_priority ON project_proposals(priority_score DESC);
CREATE INDEX IF NOT EXISTS idx_proposals_category ON project_proposals(category);


CREATE INDEX IF NOT EXISTS idx_lib_funcs_name ON lib_functions(name);
CREATE INDEX IF NOT EXISTS idx_lib_funcs_lang ON lib_functions(language);
CREATE INDEX IF NOT EXISTS idx_lib_funcs_hash ON lib_functions(body_hash);
CREATE INDEX IF NOT EXISTS idx_lib_funcs_quality ON lib_functions(quality_score);
CREATE INDEX IF NOT EXISTS idx_lib_patterns ON lib_patterns(pattern);
CREATE INDEX IF NOT EXISTS idx_lib_endpoints ON lib_endpoints(method, path);
CREATE INDEX IF NOT EXISTS idx_lib_prompts ON lib_prompts(prompt_type);
CREATE INDEX IF NOT EXISTS idx_lib_creds ON lib_credentials(credential_key);
CREATE INDEX IF NOT EXISTS idx_sensitive ON sensitive_findings(secret_type);
CREATE INDEX IF NOT EXISTS idx_file_hashes ON file_hashes(sha256);
CREATE INDEX IF NOT EXISTS idx_scan_stages_scan ON scan_stages(scan_id);
CREATE INDEX IF NOT EXISTS idx_scan_observations_scan ON scan_file_observations(scan_id);
CREATE INDEX IF NOT EXISTS idx_scan_observations_path ON scan_file_observations(path);
CREATE INDEX IF NOT EXISTS idx_scan_scores_scan ON scan_score_observations(scan_id);
CREATE INDEX IF NOT EXISTS idx_scan_scores_domain ON scan_score_observations(primary_domain);
"""


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


class IntelligenceDB:
    """SQLite intelligence database manager.

    Thread-safe via WAL mode, parameterized queries, context-manager connections.
    """

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self._ensure_schema()

    def initialize(self) -> None:
        """Ensure database schema is up to date. Safe to call multiple times."""
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        """Create tables and indexes if they don't exist."""
        with self._connect() as conn:
            conn.executescript(SCHEMA_SQL)
            conn.executescript(INDEX_SQL)
            # Backward-compatible migrations for databases created by v2.0.
            duplicate_columns = {
                row[1] for row in conn.execute("PRAGMA table_info(duplicate_clusters)")
            }
            if "scan_id" not in duplicate_columns:
                conn.execute("ALTER TABLE duplicate_clusters ADD COLUMN scan_id INTEGER")
            conn.execute(
                "INSERT OR REPLACE INTO schema_info (key, value) VALUES (?, ?)",
                ("version", SCHEMA_VERSION),
            )
            conn.commit()
        logger.info("Intelligence DB ready at {}", self.db_path)

    @contextmanager
    def _connect(self) -> Generator[sqlite3.Connection, None, None]:
        """Yield a WAL-mode connection with row_factory."""
        conn = sqlite3.connect(str(self.db_path), timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA cache_size=-64000")  # 64MB cache
        conn.execute("PRAGMA temp_store=MEMORY")
        try:
            yield conn
        finally:
            conn.close()

    # ── Scan Operations ──────────────────────────────────────────────────────

    def create_scan(
        self, drives: list[str], profile: str, config: dict[str, Any] | None = None
    ) -> int:
        """Create a new scan record and return its ID."""
        with self._connect() as conn:
            cursor = conn.execute(
                """INSERT INTO scans (started_at, drives, profile, status, config)
                   VALUES (?, ?, ?, 'running', ?)""",
                (_now_iso(), json.dumps(drives), profile, json.dumps(config) if config else None),
            )
            conn.commit()
            scan_id = cursor.lastrowid
            if scan_id is None:
                raise RuntimeError("SQLite did not return a scan id after insert")
            logger.info("Created scan #{} profile={} drives={}", scan_id, profile, drives)
            return int(scan_id)

    def complete_scan(
        self,
        scan_id: int,
        total_files: int,
        total_size: int,
        classified: int,
        skipped: int,
        duration: float,
        status: str = "completed",
    ) -> None:
        """Mark a scan terminal with an explicit truthful status."""
        allowed = {"completed", "completed_with_warnings", "degraded"}
        if status not in allowed:
            raise ValueError(f"invalid completion status: {status}")
        with self._connect() as conn:
            conn.execute(
                """UPDATE scans SET completed_at=?, total_files=?, total_size_bytes=?,
                   files_classified=?, files_skipped=?, duration_seconds=?, status=?
                   WHERE id=?""",
                (
                    _now_iso(),
                    total_files,
                    total_size,
                    classified,
                    skipped,
                    duration,
                    status,
                    scan_id,
                ),
            )
            conn.commit()

    def cancel_scan(self, scan_id: int) -> None:
        """Mark one owned scan canceled."""
        with self._connect() as conn:
            conn.execute(
                "UPDATE scans SET completed_at=?, status='cancelled' WHERE id=? AND status='running'",
                (_now_iso(), scan_id),
            )
            conn.commit()

    def fail_scan(self, scan_id: int) -> None:
        """Mark a scan as failed."""
        with self._connect() as conn:
            conn.execute(
                "UPDATE scans SET completed_at=?, status='failed' WHERE id=?",
                (_now_iso(), scan_id),
            )
            conn.commit()

    def get_scan(self, scan_id: int) -> ScanRecord | None:
        """Get a scan record by ID."""
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
            if not row:
                return None
            return ScanRecord(**dict(row))

    def list_scans(self, limit: int = 20) -> list[ScanRecord]:
        """List recent scans."""
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
            return [ScanRecord(**dict(r)) for r in rows]

    def count_scans(self) -> int:
        """Return the exact number of persisted scan rows."""
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) AS count FROM scans").fetchone()
            return int(row["count"] if row else 0)

    def latest_completed_scan(self) -> ScanRecord | None:
        """Return the newest terminal scan, preferring completed evidence."""
        with self._connect() as conn:
            row = conn.execute(
                """SELECT * FROM scans
                   WHERE status IN ('completed','completed_with_warnings','degraded')
                   ORDER BY id DESC LIMIT 1"""
            ).fetchone()
            return ScanRecord(**dict(row)) if row else None

    def record_stage(
        self,
        scan_id: int,
        stage: str,
        status: str,
        detail: str = "",
        warning_count: int = 0,
    ) -> None:
        """Upsert the observable state of one pipeline stage."""
        terminal = status in {"passed", "failed", "degraded", "skipped", "cancelled"}
        now = _now_iso()
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO scan_stages
                   (scan_id, stage, status, started_at, completed_at, detail, warning_count)
                   VALUES (?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(scan_id, stage) DO UPDATE SET
                     status=excluded.status,
                     completed_at=excluded.completed_at,
                     detail=excluded.detail,
                     warning_count=excluded.warning_count""",
                (
                    scan_id,
                    stage,
                    status,
                    now,
                    now if terminal else None,
                    detail[:1000],
                    warning_count,
                ),
            )
            conn.commit()

    def get_scan_stages(self, scan_id: int) -> list[dict[str, Any]]:
        """Return ordered stage outcomes for one scan."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM scan_stages WHERE scan_id=? ORDER BY rowid",
                (scan_id,),
            ).fetchall()
            return [dict(row) for row in rows]

    def _record_observation(self, conn: sqlite3.Connection, file: FileRecord, file_id: int) -> None:
        """Persist an immutable per-scan file snapshot."""
        conn.execute(
            """INSERT OR IGNORE INTO scan_file_observations
               (scan_id, file_id, path, filename, extension, size_bytes, created_at,
                modified_at, accessed_at, sha256, xxhash, mime_type, drive,
                parent_dir, depth, is_binary, observed_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                file.scan_id,
                file_id,
                file.path,
                file.filename,
                file.extension,
                file.size_bytes,
                file.created_at,
                file.modified_at,
                file.accessed_at,
                file.sha256,
                file.xxhash,
                file.mime_type,
                file.drive,
                file.parent_dir,
                file.depth,
                file.is_binary,
                _now_iso(),
            ),
        )

    # ── File Operations ──────────────────────────────────────────────────────

    def upsert_file(self, file: FileRecord) -> int:
        """Insert or update a file record. Returns the file ID."""
        with self._connect() as conn:
            existing = conn.execute(
                "SELECT id, modified_at FROM files WHERE path=?", (file.path,)
            ).fetchone()

            if existing:
                file_id = existing["id"]
                old_modified = existing["modified_at"]
                conn.execute(
                    """UPDATE files SET filename=?, extension=?, size_bytes=?,
                       created_at=?, modified_at=?, accessed_at=?, sha256=?, xxhash=?,
                       mime_type=?, drive=?, parent_dir=?, depth=?, is_binary=?,
                       content_sample=?, file_signature=?, scan_id=?,
                       last_modified_scan_id=CASE WHEN ?!=? THEN ? ELSE last_modified_scan_id END
                       WHERE id=?""",
                    (
                        file.filename,
                        file.extension,
                        file.size_bytes,
                        file.created_at,
                        file.modified_at,
                        file.accessed_at,
                        file.sha256,
                        file.xxhash,
                        file.mime_type,
                        file.drive,
                        file.parent_dir,
                        file.depth,
                        file.is_binary,
                        file.content_sample,
                        file.file_signature,
                        file.scan_id,
                        file.modified_at,
                        old_modified,
                        file.scan_id,
                        file_id,
                    ),
                )
            else:
                cursor = conn.execute(
                    """INSERT INTO files (path, filename, extension, size_bytes,
                       created_at, modified_at, accessed_at, sha256, xxhash,
                       mime_type, drive, parent_dir, depth, is_binary,
                       content_sample, file_signature, scan_id, first_seen_scan_id)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        file.path,
                        file.filename,
                        file.extension,
                        file.size_bytes,
                        file.created_at,
                        file.modified_at,
                        file.accessed_at,
                        file.sha256,
                        file.xxhash,
                        file.mime_type,
                        file.drive,
                        file.parent_dir,
                        file.depth,
                        file.is_binary,
                        file.content_sample,
                        file.file_signature,
                        file.scan_id,
                        file.scan_id,
                    ),
                )
                file_id = cursor.lastrowid
            self._record_observation(conn, file, int(file_id))
            conn.commit()
            return file_id

    def upsert_files_batch(self, files: list[FileRecord]) -> list[int]:
        """Batch upsert files. Returns list of file IDs."""
        ids: list[int] = []
        with self._connect() as conn:
            for f in files:
                existing = conn.execute("SELECT id FROM files WHERE path=?", (f.path,)).fetchone()
                if existing:
                    file_id = existing["id"]
                    conn.execute(
                        """UPDATE files SET filename=?, extension=?, size_bytes=?,
                           modified_at=?, sha256=?, xxhash=?, mime_type=?,
                           content_sample=?, file_signature=?, scan_id=?
                           WHERE id=?""",
                        (
                            f.filename,
                            f.extension,
                            f.size_bytes,
                            f.modified_at,
                            f.sha256,
                            f.xxhash,
                            f.mime_type,
                            f.content_sample,
                            f.file_signature,
                            f.scan_id,
                            file_id,
                        ),
                    )
                else:
                    cursor = conn.execute(
                        """INSERT INTO files (path, filename, extension, size_bytes,
                           created_at, modified_at, accessed_at, sha256, xxhash,
                           mime_type, drive, parent_dir, depth, is_binary,
                           content_sample, file_signature, scan_id, first_seen_scan_id)
                           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (
                            f.path,
                            f.filename,
                            f.extension,
                            f.size_bytes,
                            f.created_at,
                            f.modified_at,
                            f.accessed_at,
                            f.sha256,
                            f.xxhash,
                            f.mime_type,
                            f.drive,
                            f.parent_dir,
                            f.depth,
                            f.is_binary,
                            f.content_sample,
                            f.file_signature,
                            f.scan_id,
                            f.scan_id,
                        ),
                    )
                    file_id = cursor.lastrowid
                ids.append(file_id)
                self._record_observation(conn, f, int(file_id))
            conn.commit()
        return ids

    def get_file(self, file_id: int) -> FileRecord | None:
        """Get a file record by ID."""
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM files WHERE id=?", (file_id,)).fetchone()
            if not row:
                return None
            return FileRecord(**dict(row))

    def get_file_by_path(self, path: str) -> FileRecord | None:
        """Get a file record by path."""
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM files WHERE path=?", (path,)).fetchone()
            if not row:
                return None
            return FileRecord(**dict(row))

    def list_files(
        self,
        scan_id: int | None = None,
        drive: str | None = None,
        extension: str | None = None,
        domain: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[FileRecord]:
        """List files; scan-scoped reads use immutable observation snapshots."""
        clauses: list[str] = []
        params: list[Any] = []
        if scan_id is not None:
            base = "scan_file_observations f"
            clauses.append("f.scan_id=?")
            params.append(scan_id)
        else:
            base = "files f"
        if drive is not None:
            clauses.append("f.drive=?")
            params.append(drive)
        if extension is not None:
            clauses.append("f.extension=?")
            params.append(extension)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        if domain is not None:
            sql = f"""SELECT DISTINCT f.* FROM {base}
                      JOIN scan_score_observations s ON s.file_id=f.file_id AND s.scan_id=f.scan_id
                      {where}{" AND" if clauses else " WHERE"} s.primary_domain=?
                      ORDER BY f.file_id LIMIT ? OFFSET ?"""
            params.extend([domain, limit, offset])
        else:
            id_column = "file_id" if scan_id is not None else "id"
            sql = f"SELECT * FROM {base} {where} ORDER BY {id_column} LIMIT ? OFFSET ?"
            params.extend([limit, offset])
        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
            records: list[FileRecord] = []
            for row in rows:
                data = dict(row)
                if scan_id is not None:
                    data["id"] = data.pop("file_id")
                    data.pop("observed_at", None)
                records.append(FileRecord(**data))
            return records

    def count_files(self, scan_id: int | None = None) -> int:
        """Count total files."""
        with self._connect() as conn:
            if scan_id is not None:
                row = conn.execute(
                    "SELECT COUNT(*) as cnt FROM files WHERE scan_id=?", (scan_id,)
                ).fetchone()
            else:
                row = conn.execute("SELECT COUNT(*) as cnt FROM files").fetchone()
            return row["cnt"] if row else 0

    def get_files_needing_classification(self, scan_id: int, limit: int = 500) -> list[FileRecord]:
        """Get files that haven't been classified in this scan."""
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT f.* FROM files f
                   LEFT JOIN classifications c ON c.file_id=f.id AND c.scan_id=?
                   WHERE f.scan_id=? AND c.id IS NULL
                   ORDER BY f.size_bytes DESC
                   LIMIT ?""",
                (scan_id, scan_id, limit),
            ).fetchall()
            return [FileRecord(**dict(r)) for r in rows]

    # ── Classification Operations ────────────────────────────────────────────

    def insert_classification(self, cls: Classification) -> int:
        """Insert a classification result."""
        with self._connect() as conn:
            cursor = conn.execute(
                """INSERT INTO classifications (file_id, scan_id, engine_id, domain,
                   domain_label, topic, conclusion, confidence, authority_weight,
                   score, mode, response_ms, determinism_hash, classified_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    cls.file_id,
                    cls.scan_id,
                    cls.engine_id,
                    cls.domain,
                    cls.domain_label,
                    cls.topic,
                    cls.conclusion,
                    cls.confidence,
                    cls.authority_weight,
                    cls.score,
                    cls.mode,
                    cls.response_ms,
                    cls.determinism_hash,
                    cls.classified_at or _now_iso(),
                ),
            )
            conn.commit()
            row_id = cursor.lastrowid
            if row_id is None:
                raise RuntimeError("SQLite did not return an id after insert")
            return int(row_id)

    def insert_classifications_batch(self, classifications: list[Classification]) -> int:
        """Batch insert classifications. Returns count inserted."""
        with self._connect() as conn:
            conn.executemany(
                """INSERT INTO classifications (file_id, scan_id, engine_id, domain,
                   domain_label, topic, conclusion, confidence, authority_weight,
                   score, mode, response_ms, determinism_hash, classified_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                [
                    (
                        c.file_id,
                        c.scan_id,
                        c.engine_id,
                        c.domain,
                        c.domain_label,
                        c.topic,
                        c.conclusion,
                        c.confidence,
                        c.authority_weight,
                        c.score,
                        c.mode,
                        c.response_ms,
                        c.determinism_hash,
                        c.classified_at or _now_iso(),
                    )
                    for c in classifications
                ],
            )
            conn.commit()
            return len(classifications)

    def get_classifications(self, file_id: int) -> list[Classification]:
        """Get all classifications for a file."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM classifications WHERE file_id=? ORDER BY score DESC",
                (file_id,),
            ).fetchall()
            return [Classification(**dict(r)) for r in rows]

    def get_classifications_by_domain(self, scan_id: int, domain: str) -> list[Classification]:
        """Get all classifications for a domain in a scan."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM classifications WHERE scan_id=? AND domain=? ORDER BY score DESC",
                (scan_id, domain),
            ).fetchall()
            return [Classification(**dict(r)) for r in rows]

    # ── Score Operations ─────────────────────────────────────────────────────

    def upsert_score(self, score: IntelligenceScore) -> int:
        """Insert or update an intelligence score."""
        with self._connect() as conn:
            existing = conn.execute(
                "SELECT id FROM intelligence_scores WHERE file_id=?", (score.file_id,)
            ).fetchone()
            if existing:
                conn.execute(
                    """UPDATE intelligence_scores SET scan_id=?, overall_score=?,
                       quality_score=?, importance_score=?, sensitivity_score=?,
                       staleness_score=?, uniqueness_score=?, risk_score=?,
                       primary_domain=?, primary_engine=?, domain_distribution=?,
                       classification_count=?, scored_at=?, score_version=?
                       WHERE file_id=?""",
                    (
                        score.scan_id,
                        score.overall_score,
                        score.quality_score,
                        score.importance_score,
                        score.sensitivity_score,
                        score.staleness_score,
                        score.uniqueness_score,
                        score.risk_score,
                        score.primary_domain,
                        score.primary_engine,
                        score.domain_distribution,
                        score.classification_count,
                        score.scored_at or _now_iso(),
                        score.score_version,
                        score.file_id,
                    ),
                )
                score_id = existing["id"]
            else:
                cursor = conn.execute(
                    """INSERT INTO intelligence_scores (file_id, scan_id, overall_score,
                       quality_score, importance_score, sensitivity_score,
                       staleness_score, uniqueness_score, risk_score,
                       primary_domain, primary_engine, domain_distribution,
                       classification_count, scored_at, score_version)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        score.file_id,
                        score.scan_id,
                        score.overall_score,
                        score.quality_score,
                        score.importance_score,
                        score.sensitivity_score,
                        score.staleness_score,
                        score.uniqueness_score,
                        score.risk_score,
                        score.primary_domain,
                        score.primary_engine,
                        score.domain_distribution,
                        score.classification_count,
                        score.scored_at or _now_iso(),
                        score.score_version,
                    ),
                )
                score_id = cursor.lastrowid
            conn.execute(
                """INSERT OR IGNORE INTO scan_score_observations
                   (scan_id, file_id, overall_score, quality_score, importance_score,
                    sensitivity_score, staleness_score, uniqueness_score, risk_score,
                    primary_domain, primary_engine, domain_distribution,
                    classification_count, scored_at, score_version)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    score.scan_id,
                    score.file_id,
                    score.overall_score,
                    score.quality_score,
                    score.importance_score,
                    score.sensitivity_score,
                    score.staleness_score,
                    score.uniqueness_score,
                    score.risk_score,
                    score.primary_domain,
                    score.primary_engine,
                    score.domain_distribution,
                    score.classification_count,
                    score.scored_at or _now_iso(),
                    score.score_version,
                ),
            )
            conn.commit()
            return score_id

    def get_score(
        self,
        file_id: int,
        scan_id: int | None = None,
    ) -> IntelligenceScore | None:
        """Get the latest score or an immutable scan-specific score."""
        with self._connect() as conn:
            if scan_id is None:
                row = conn.execute(
                    "SELECT * FROM intelligence_scores WHERE file_id=?", (file_id,)
                ).fetchone()
            else:
                row = conn.execute(
                    "SELECT * FROM scan_score_observations WHERE file_id=? AND scan_id=?",
                    (file_id, scan_id),
                ).fetchone()
            if not row:
                return None
            data = dict(row)
            data.pop("id", None)
            return IntelligenceScore(**data)

    def get_top_scores(
        self,
        dimension: str = "overall_score",
        limit: int = 50,
        scan_id: int | None = None,
    ) -> list[dict[str, Any]]:
        """Get top files from immutable per-scan scores when scoped."""
        valid = {
            "overall_score",
            "quality_score",
            "importance_score",
            "sensitivity_score",
            "risk_score",
            "uniqueness_score",
        }
        if dimension not in valid:
            dimension = "overall_score"
        if scan_id is None:
            source = "intelligence_scores s"
            where = ""
            params: list[Any] = [limit]
            join = "JOIN files f ON f.id=s.file_id"
        else:
            source = "scan_score_observations s"
            where = "WHERE s.scan_id=?"
            params = [scan_id, limit]
            join = "JOIN scan_file_observations f ON f.file_id=s.file_id AND f.scan_id=s.scan_id"
        with self._connect() as conn:
            rows = conn.execute(
                f"""SELECT s.*, f.path, f.filename, f.extension, f.size_bytes
                    FROM {source}
                    {join}
                    {where}
                    ORDER BY s.{dimension} DESC LIMIT ?""",
                params,
            ).fetchall()
            return [dict(row) for row in rows]

    def get_high_risk_files(
        self,
        threshold: float = 70.0,
        limit: int = 100,
        scan_id: int | None = None,
    ) -> list[dict[str, Any]]:
        """Get files with risk score above threshold, optionally scoped to a scan."""
        if scan_id is None:
            source = "intelligence_scores s"
            join = "JOIN files f ON f.id=s.file_id"
            scan_clause = ""
            params: list[Any] = [threshold, limit]
        else:
            source = "scan_score_observations s"
            join = "JOIN scan_file_observations f ON f.file_id=s.file_id AND f.scan_id=s.scan_id"
            scan_clause = "AND s.scan_id=?"
            params = [threshold, scan_id, limit]
        with self._connect() as conn:
            rows = conn.execute(
                f"""SELECT s.*, f.path, f.filename, f.extension
                   FROM {source}
                   {join}
                   WHERE s.risk_score >= ? {scan_clause}
                   ORDER BY s.risk_score DESC LIMIT ?""",
                params,
            ).fetchall()
            return [dict(r) for r in rows]

    # ── Relationship Operations ──────────────────────────────────────────────

    def insert_relationship(self, rel: Relationship) -> int:
        """Insert a relationship."""
        with self._connect() as conn:
            cursor = conn.execute(
                """INSERT INTO relationships (source_file_id, target_file_id,
                   relationship_type, confidence, evidence, detected_at, scan_id)
                   VALUES (?,?,?,?,?,?,?)""",
                (
                    rel.source_file_id,
                    rel.target_file_id,
                    rel.relationship_type,
                    rel.confidence,
                    rel.evidence,
                    rel.detected_at or _now_iso(),
                    rel.scan_id,
                ),
            )
            conn.commit()
            row_id = cursor.lastrowid
            if row_id is None:
                raise RuntimeError("SQLite did not return an id after insert")
            return int(row_id)

    def insert_relationships_batch(self, rels: list[Relationship]) -> int:
        """Batch insert relationships."""
        with self._connect() as conn:
            conn.executemany(
                """INSERT INTO relationships (source_file_id, target_file_id,
                   relationship_type, confidence, evidence, detected_at, scan_id)
                   VALUES (?,?,?,?,?,?,?)""",
                [
                    (
                        r.source_file_id,
                        r.target_file_id,
                        r.relationship_type,
                        r.confidence,
                        r.evidence,
                        r.detected_at or _now_iso(),
                        r.scan_id,
                    )
                    for r in rels
                ],
            )
            conn.commit()
            return len(rels)

    def get_file_relationships(self, file_id: int) -> list[Relationship]:
        """Get all relationships for a file (as source or target)."""
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT * FROM relationships
                   WHERE source_file_id=? OR target_file_id=?
                   ORDER BY confidence DESC""",
                (file_id, file_id),
            ).fetchall()
            return [Relationship(**dict(r)) for r in rows]

    # ── Duplicate Operations ─────────────────────────────────────────────────

    def insert_duplicate_cluster(
        self,
        cluster: DuplicateCluster,
        scan_id: int | None = None,
    ) -> int:
        """Insert a duplicate cluster with explicit scan ownership."""
        with self._connect() as conn:
            cursor = conn.execute(
                """INSERT INTO duplicate_clusters (cluster_hash, file_count,
                   total_wasted_bytes, best_file_id, strategy, created_at, scan_id)
                   VALUES (?,?,?,?,?,?,?)""",
                (
                    cluster.cluster_hash,
                    cluster.file_count,
                    cluster.total_wasted_bytes,
                    cluster.best_file_id,
                    cluster.strategy,
                    cluster.created_at or _now_iso(),
                    scan_id,
                ),
            )
            cluster_id = cursor.lastrowid
            if cluster_id is None:
                raise RuntimeError("SQLite did not return a duplicate-cluster id after insert")
            for member in cluster.members:
                conn.execute(
                    "INSERT INTO duplicate_members (cluster_id, file_id, is_keeper) VALUES (?,?,?)",
                    (cluster_id, member.file_id, member.is_keeper),
                )
            conn.commit()
            return int(cluster_id)

    def get_duplicate_clusters(
        self,
        min_count: int = 2,
        limit: int = 100,
        scan_id: int | None = None,
    ) -> list[dict[str, Any]]:
        """Get duplicate clusters with at least min_count members.

        When scan_id is given, only clusters containing at least one file
        from that scan are returned.
        """
        scan_clause = (
            "AND (dc.scan_id=? OR (dc.scan_id IS NULL AND EXISTS "
            "(SELECT 1 FROM duplicate_members dm2 JOIN scan_file_observations o "
            "ON o.file_id=dm2.file_id WHERE dm2.cluster_id=dc.id AND o.scan_id=?)))"
            if scan_id is not None
            else ""
        )
        params: list[Any] = [min_count]
        if scan_id is not None:
            params.extend([scan_id, scan_id])
        params.append(limit)
        with self._connect() as conn:
            rows = conn.execute(
                f"""SELECT dc.*, GROUP_CONCAT(dm.file_id) as member_ids
                   FROM duplicate_clusters dc
                   JOIN duplicate_members dm ON dm.cluster_id=dc.id
                   WHERE dc.file_count >= ? {scan_clause}
                   GROUP BY dc.id
                   ORDER BY dc.total_wasted_bytes DESC
                   LIMIT ?""",
                params,
            ).fetchall()
            return [dict(r) for r in rows]

    # ── Recommendation Operations ────────────────────────────────────────────

    def insert_recommendation(self, rec: Recommendation) -> int:
        """Insert a recommendation."""
        with self._connect() as conn:
            cursor = conn.execute(
                """INSERT INTO recommendations (scan_id, category, severity, title,
                   description, affected_files, affected_count, estimated_impact,
                   action_command, status, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    rec.scan_id,
                    rec.category,
                    rec.severity,
                    rec.title,
                    rec.description,
                    rec.affected_files,
                    rec.affected_count,
                    rec.estimated_impact,
                    rec.action_command,
                    rec.status or "pending",
                    rec.created_at or _now_iso(),
                ),
            )
            conn.commit()
            row_id = cursor.lastrowid
            if row_id is None:
                raise RuntimeError("SQLite did not return an id after insert")
            return int(row_id)

    def insert_recommendations_batch(self, recs: list[Recommendation]) -> int:
        """Batch insert recommendations."""
        with self._connect() as conn:
            conn.executemany(
                """INSERT INTO recommendations (scan_id, category, severity, title,
                   description, affected_files, affected_count, estimated_impact,
                   action_command, status, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                [
                    (
                        r.scan_id,
                        r.category,
                        r.severity,
                        r.title,
                        r.description,
                        r.affected_files,
                        r.affected_count,
                        r.estimated_impact,
                        r.action_command,
                        r.status or "pending",
                        r.created_at or _now_iso(),
                    )
                    for r in recs
                ],
            )
            conn.commit()
            return len(recs)

    def get_recommendations(
        self,
        scan_id: int | None = None,
        category: str | None = None,
        severity: str | None = None,
        status: str | None = None,
        limit: int = 100,
    ) -> list[Recommendation]:
        """Get recommendations with optional filters."""
        clauses: list[str] = []
        params: list[Any] = []
        if scan_id is not None:
            clauses.append("scan_id=?")
            params.append(scan_id)
        if category is not None:
            clauses.append("category=?")
            params.append(category)
        if severity is not None:
            clauses.append("severity=?")
            params.append(severity)
        if status is not None:
            clauses.append("status=?")
            params.append(status)

        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM recommendations {where} ORDER BY id DESC LIMIT ?",
                [*params, limit],
            ).fetchall()
            return [Recommendation(**dict(r)) for r in rows]

    def get_recommendation(self, rec_id: int) -> Recommendation | None:
        """Get a single recommendation by ID."""
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM recommendations WHERE id=?", (rec_id,)).fetchone()
            return Recommendation(**dict(row)) if row else None

    def update_recommendation_status(self, rec_id: int, status: str) -> None:
        """Update a recommendation's status."""
        with self._connect() as conn:
            conn.execute("UPDATE recommendations SET status=? WHERE id=?", (status, rec_id))
            conn.commit()

    # ── Project Advisor Proposal Operations (Stage 10) ───────────────────────

    # Categories emitted by intelligence.project_advisor. The two high-level
    # "kinds" queryable from the API map onto these categories:
    #   completion → an existing project/script that needs finishing/refactor
    #   new_build  → a brand-new build/program that should be created
    _COMPLETION_CATEGORIES = ("PROMOTE_PARTIAL", "PROMOTE_SCRIPT")
    _PROPOSAL_JSON_FIELDS = (
        "rationale",
        "suggested_stack",
        "source_files",
        "existing_functions",
        "existing_classes",
        "capabilities",
        "duplicate_functions",
    )

    @classmethod
    def _proposal_kind(cls, category: str | None) -> str:
        """Map a proposal category to its high-level kind (completion|new_build)."""
        return "completion" if (category or "") in cls._COMPLETION_CATEGORIES else "new_build"

    def get_proposals(
        self,
        scan_id: int | None = None,
        kind: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Get Project Advisor proposals ordered by priority (desc).

        Args:
            scan_id: Restrict to one scan; None returns across all scans.
            kind: 'completion' (projects needing finishing — TODO/WIP/STUB) or
                  'new_build' (new builds/programs). Also accepts a raw category
                  (e.g. 'DATA_PIPELINE') or proposal_type ('PROJECT'/'PROGRAM').
            limit: Max rows to return.

        Returns:
            List of proposal dicts with JSON columns parsed back to lists and a
            derived 'kind' field. Empty list if the table is absent.
        """
        clauses: list[str] = []
        params: list[Any] = []
        if scan_id is not None:
            clauses.append("scan_id=?")
            params.append(scan_id)

        if kind:
            k = kind.strip().lower().replace("-", "_")
            completion_ph = ",".join("?" for _ in self._COMPLETION_CATEGORIES)
            if k == "completion":
                clauses.append(f"category IN ({completion_ph})")
                params.extend(self._COMPLETION_CATEGORIES)
            elif k in ("new_build", "newbuild", "new"):
                clauses.append(f"category NOT IN ({completion_ph})")
                params.extend(self._COMPLETION_CATEGORIES)
            elif k in ("project", "program"):
                clauses.append("UPPER(proposal_type)=?")
                params.append(k.upper())
            else:
                # Treat as a raw category filter (case-insensitive)
                clauses.append("UPPER(category)=?")
                params.append(kind.strip().upper())

        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = (
            f"SELECT * FROM project_proposals {where} ORDER BY priority_score DESC, id DESC LIMIT ?"
        )
        with self._connect() as conn:
            try:
                rows = conn.execute(sql, [*params, limit]).fetchall()
            except sqlite3.OperationalError:
                # Table not created yet (no Stage-10 scan has run on this db)
                return []

        proposals: list[dict[str, Any]] = []
        for r in rows:
            p = dict(r)
            for field in self._PROPOSAL_JSON_FIELDS:
                raw = p.get(field)
                if raw:
                    try:
                        p[field] = json.loads(raw)
                    except (json.JSONDecodeError, TypeError):
                        p[field] = []
                else:
                    p[field] = []
            p["kind"] = self._proposal_kind(p.get("category"))
            proposals.append(p)
        return proposals

    def count_proposals(self, scan_id: int | None = None) -> int:
        """Count stored proposals, optionally scoped to a scan."""
        with self._connect() as conn:
            try:
                if scan_id is not None:
                    row = conn.execute(
                        "SELECT COUNT(*) AS cnt FROM project_proposals WHERE scan_id=?",
                        (scan_id,),
                    ).fetchone()
                else:
                    row = conn.execute("SELECT COUNT(*) AS cnt FROM project_proposals").fetchone()
            except sqlite3.OperationalError:
                return 0
            return row["cnt"] if row else 0

    # ── Domain Stats Operations ──────────────────────────────────────────────

    def upsert_domain_stats(self, stats: DomainStats) -> None:
        """Insert or update domain statistics."""
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO domain_stats (scan_id, domain, domain_label,
                   file_count, total_size_bytes, avg_score, avg_confidence, top_topics)
                   VALUES (?,?,?,?,?,?,?,?)
                   ON CONFLICT(scan_id, domain) DO UPDATE SET
                   domain_label=excluded.domain_label, file_count=excluded.file_count,
                   total_size_bytes=excluded.total_size_bytes, avg_score=excluded.avg_score,
                   avg_confidence=excluded.avg_confidence, top_topics=excluded.top_topics""",
                (
                    stats.scan_id,
                    stats.domain,
                    stats.domain_label,
                    stats.file_count,
                    stats.total_size_bytes,
                    stats.avg_score,
                    stats.avg_confidence,
                    stats.top_topics,
                ),
            )
            conn.commit()

    def get_domain_stats(self, scan_id: int) -> list[DomainStats]:
        """Get domain statistics for a scan."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM domain_stats WHERE scan_id=? ORDER BY file_count DESC",
                (scan_id,),
            ).fetchall()
            return [DomainStats(**dict(r)) for r in rows]

    # ── Aggregation / Summary ────────────────────────────────────────────────

    def get_scan_summary(self, scan_id: int) -> ScanSummary | None:
        """Build a complete scan summary."""
        scan = self.get_scan(scan_id)
        if not scan:
            return None

        with self._connect() as conn:
            # Domain distribution
            domain_rows = conn.execute(
                """SELECT domain, COUNT(*) as cnt FROM classifications
                   WHERE scan_id=? GROUP BY domain ORDER BY cnt DESC""",
                (scan_id,),
            ).fetchall()
            domain_dist = {r["domain"]: r["cnt"] for r in domain_rows}

            # Duplicate stats
            dup_row = conn.execute(
                """SELECT COUNT(*) as clusters, COALESCE(SUM(total_wasted_bytes), 0) as wasted
                   FROM duplicate_clusters dc
                   WHERE EXISTS (SELECT 1 FROM duplicate_members dm
                                 JOIN files f ON f.id=dm.file_id
                                 WHERE dm.cluster_id=dc.id AND f.scan_id=?)""",
                (scan_id,),
            ).fetchone()

            # Score averages
            avg_row = conn.execute(
                """SELECT AVG(quality_score) as avg_q, AVG(importance_score) as avg_i,
                   SUM(CASE WHEN risk_score >= 70 THEN 1 ELSE 0 END) as high_risk,
                   SUM(CASE WHEN sensitivity_score >= 70 THEN 1 ELSE 0 END) as sensitive
                   FROM intelligence_scores WHERE scan_id=?""",
                (scan_id,),
            ).fetchone()

            # Recommendation count
            rec_row = conn.execute(
                "SELECT COUNT(*) as cnt FROM recommendations WHERE scan_id=?",
                (scan_id,),
            ).fetchone()

            return ScanSummary(
                scan_id=scan_id,
                status=scan.status,
                total_files=scan.total_files,
                total_size_bytes=scan.total_size_bytes,
                files_classified=scan.files_classified,
                duration_seconds=scan.duration_seconds or 0.0,
                domain_distribution=domain_dist,
                top_domains=self.get_domain_stats(scan_id)[:10],
                recommendation_count=rec_row["cnt"] if rec_row else 0,
                duplicate_clusters=dup_row["clusters"] if dup_row else 0,
                wasted_bytes=dup_row["wasted"] if dup_row else 0,
                avg_quality=round(avg_row["avg_q"] or 0.0, 1) if avg_row else 0.0,
                avg_importance=round(avg_row["avg_i"] or 0.0, 1) if avg_row else 0.0,
                high_risk_count=avg_row["high_risk"] if avg_row else 0,
                sensitive_count=avg_row["sensitive"] if avg_row else 0,
            )

    def search_files(self, query: str, limit: int = 50) -> list[dict[str, Any]]:
        """Full-text search across filenames and content samples."""
        pattern = f"%{query}%"
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT f.*, s.overall_score, s.primary_domain
                   FROM files f
                   LEFT JOIN intelligence_scores s ON s.file_id=f.id
                   WHERE f.filename LIKE ? OR f.path LIKE ? OR f.content_sample LIKE ?
                   ORDER BY COALESCE(s.overall_score, 0) DESC
                   LIMIT ?""",
                (pattern, pattern, pattern, limit),
            ).fetchall()
            return [dict(r) for r in rows]

    def get_score_distribution(
        self,
        dimension: str = "overall_score",
        buckets: int = 20,
        scan_id: int | None = None,
    ) -> list[dict[str, Any]]:
        """Get score distribution as histogram buckets, optionally scoped to a scan."""
        valid = {
            "overall_score",
            "quality_score",
            "importance_score",
            "sensitivity_score",
            "risk_score",
            "staleness_score",
            "uniqueness_score",
        }
        if dimension not in valid:
            dimension = "overall_score"

        bucket_size = 100.0 / buckets
        where = "WHERE scan_id=?" if scan_id is not None else ""
        params: list[Any] = [bucket_size, bucket_size, bucket_size, bucket_size, bucket_size]
        if scan_id is not None:
            params.append(scan_id)
        params.append(bucket_size)
        with self._connect() as conn:
            rows = conn.execute(
                f"""SELECT
                    CAST({dimension} / ? AS INTEGER) * ? as bucket_start,
                    CAST({dimension} / ? AS INTEGER) * ? + ? as bucket_end,
                    COUNT(*) as count
                    FROM intelligence_scores
                    {where}
                    GROUP BY CAST({dimension} / ? AS INTEGER)
                    ORDER BY bucket_start""",
                params,
            ).fetchall()
            return [dict(r) for r in rows]

    # ── Library Store Methods ──────────────────────────────────────────────

    def store_library_batch(self, scan_id: int, extractions: dict) -> dict:
        """Store all library extractions from one file in a single transaction."""
        counts = {}
        with self._connect() as conn:
            # Functions
            funcs = extractions.get("functions", [])
            for f in funcs:
                import json as _j

                try:
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO lib_functions
                        (name, language, signature, docstring, body, body_hash,
                         file_path, line_number, is_async, quality_score, patterns,
                         arg_count, first_seen_scan, last_seen_scan)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                        (
                            f["name"],
                            f["language"],
                            f["signature"],
                            f.get("docstring", ""),
                            f.get("body", ""),
                            f["body_hash"],
                            f["file_path"],
                            f.get("line_number"),
                            1 if f.get("is_async") else 0,
                            f.get("quality_score", 0),
                            _j.dumps(f.get("patterns", [])),
                            f.get("arg_count", 0),
                            scan_id,
                            scan_id,
                        ),
                    )
                    # Increment copy count if already exists
                    conn.execute(
                        """
                        UPDATE lib_functions SET copy_count = copy_count + 1,
                        last_seen_scan = ? WHERE body_hash = ? AND file_path != ?
                    """,
                        (scan_id, f["body_hash"], f["file_path"]),
                    )
                except Exception:
                    pass
            counts["functions"] = len(funcs)

            # Patterns
            pats = extractions.get("patterns", [])
            for p in pats:
                try:
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO lib_patterns (pattern, language, file_path, scan_id)
                        VALUES (?,?,?,?)
                    """,
                        (p["pattern"], p["language"], p["file_path"], scan_id),
                    )
                except Exception:
                    pass
            counts["patterns"] = len(pats)

            # Schemas
            schemas = extractions.get("schemas", [])
            for s in schemas:
                try:
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO lib_schemas
                        (name, schema_type, language, file_path, definition, scan_id)
                        VALUES (?,?,?,?,?,?)
                    """,
                        (
                            s["name"],
                            s["schema_type"],
                            s.get("language", ""),
                            s["file_path"],
                            s.get("definition", "")[:500],
                            scan_id,
                        ),
                    )
                except Exception:
                    pass
            counts["schemas"] = len(schemas)

            # Endpoints
            endpoints = extractions.get("endpoints", [])
            for e in endpoints:
                try:
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO lib_endpoints
                        (method, path, language, file_path, scan_id)
                        VALUES (?,?,?,?,?)
                    """,
                        (e["method"], e["path"], e.get("language", ""), e["file_path"], scan_id),
                    )
                except Exception:
                    pass
            counts["endpoints"] = len(endpoints)

            # Prompts
            import hashlib

            prompts = extractions.get("prompts", [])
            for p in prompts:
                h = hashlib.md5(p["content"].encode()).hexdigest()[:16]
                try:
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO lib_prompts
                        (prompt_type, content, length, file_path, scan_id, content_hash)
                        VALUES (?,?,?,?,?,?)
                    """,
                        (
                            p["prompt_type"],
                            p["content"],
                            p.get("length", 0),
                            p["file_path"],
                            scan_id,
                            h,
                        ),
                    )
                except Exception:
                    pass
            counts["prompts"] = len(prompts)

            # Configs
            configs = extractions.get("configs", [])
            for c in configs:
                try:
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO lib_configs
                        (key, value_preview, language, file_path, scan_id)
                        VALUES (?,?,?,?,?)
                    """,
                        (
                            c["key"],
                            c.get("value_preview", ""),
                            c.get("language", ""),
                            c["file_path"],
                            scan_id,
                        ),
                    )
                except Exception:
                    pass
            counts["configs"] = len(configs)

            # Errors
            errors = extractions.get("errors", [])
            for e in errors:
                try:
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO lib_errors
                        (exception_type, handler_body, language, file_path, scan_id)
                        VALUES (?,?,?,?,?)
                    """,
                        (
                            e["exception_type"],
                            e.get("handler_body", ""),
                            e.get("language", ""),
                            e["file_path"],
                            scan_id,
                        ),
                    )
                except Exception:
                    pass
            counts["errors"] = len(errors)

            # Credentials
            creds = extractions.get("credentials", [])
            for c in creds:
                try:
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO lib_credentials
                        (credential_key, file_path, scan_id)
                        VALUES (?,?,?)
                    """,
                        (c["credential_key"], c["file_path"], scan_id),
                    )
                except Exception:
                    pass
            counts["credentials"] = len(creds)

            # Sensitive findings
            secrets = extractions.get("secrets", [])
            for s in secrets:
                try:
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO sensitive_findings
                        (file_path, secret_type, line_number, match_preview, scan_id)
                        VALUES (?,?,?,?,?)
                    """,
                        (
                            s["file_path"],
                            s["secret_type"],
                            s.get("line_number"),
                            s.get("match_preview", ""),
                            scan_id,
                        ),
                    )
                except Exception:
                    pass
            counts["secrets"] = len(secrets)

            conn.commit()
        return counts

    def update_file_hash(
        self, path: str, sha256: str, xxhash: str, size_bytes: int, modified_at: str, scan_id: int
    ):
        """Update change detection hash for a file."""
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO file_hashes
                (path, sha256, xxhash, size_bytes, modified_at, last_scan_id, last_seen)
                VALUES (?,?,?,?,?,?,datetime('now'))
            """,
                (path, sha256, xxhash, size_bytes, modified_at, scan_id),
            )
            conn.commit()

    def file_unchanged(self, path: str, modified_at: str, size_bytes: int) -> bool:
        """Return True if file hash record matches current mtime+size (skip re-scan)."""
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT modified_at, size_bytes FROM file_hashes WHERE path=?
            """,
                (path,),
            ).fetchone()
        if not row:
            return False
        return row[0] == modified_at and row[1] == size_bytes

    def get_library_stats(self) -> dict:
        """Return counts across all library tables."""
        stats = {}
        tables = [
            "lib_functions",
            "lib_patterns",
            "lib_schemas",
            "lib_endpoints",
            "lib_prompts",
            "lib_configs",
            "lib_errors",
            "lib_credentials",
            "sensitive_findings",
        ]
        with self._connect() as conn:
            for t in tables:
                try:
                    row = conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()
                    stats[t] = row[0] if row else 0
                except Exception:
                    stats[t] = 0
            # Top duplicated functions
            try:
                rows = conn.execute("""
                    SELECT name, language, copy_count, quality_score
                    FROM lib_functions WHERE copy_count > 1
                    ORDER BY copy_count DESC LIMIT 10
                """).fetchall()
                stats["top_duplicates"] = [
                    {"name": r[0], "lang": r[1], "copies": r[2], "quality": r[3]} for r in rows
                ]
            except Exception:
                stats["top_duplicates"] = []
        return stats
