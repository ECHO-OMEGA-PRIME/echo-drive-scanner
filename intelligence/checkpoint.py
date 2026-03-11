"""
Echo Scanner Checkpoint — Resume interrupted scans from last position.
Stores progress per scan_id in SQLite. On restart, skips already-processed files.
"""
from __future__ import annotations
import sqlite3, time, json, os
from pathlib import Path
from loguru import logger

LOCK_DIR = Path(__file__).parent.parent / 'locks'
LOCK_DIR.mkdir(exist_ok=True)


class ScanLock:
    """File-based lock to prevent two processes scanning same drive."""

    def __init__(self, drive: str):
        safe = drive.replace(':', '').replace('\\', '').replace('/', '')
        self.lock_file = LOCK_DIR / f'scan_{safe}.lock'

    def acquire(self) -> bool:
        if self.lock_file.exists():
            try:
                data = json.loads(self.lock_file.read_text())
                pid = data.get('pid', 0)
                # Check if that process is still alive
                try:
                    os.kill(pid, 0)
                    logger.warning("Drive already being scanned by PID {}", pid)
                    return False
                except (OSError, ProcessLookupError):
                    # Process dead — stale lock
                    logger.info("Removing stale lock from PID {}", pid)
            except Exception:
                pass
        self.lock_file.write_text(json.dumps({'pid': os.getpid(), 'ts': time.time()}))
        return True

    def release(self):
        try:
            self.lock_file.unlink(missing_ok=True)
        except Exception:
            pass

    def __enter__(self):
        if not self.acquire():
            raise RuntimeError(f"Drive locked: {self.lock_file}")
        return self

    def __exit__(self, *_):
        self.release()


class ScanCheckpoint:
    """Persist scan progress so interrupted scans resume from last position."""

    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._ensure_table()

    def _ensure_table(self):
        conn = sqlite3.connect(str(self.db_path))
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_checkpoints (
                scan_id INTEGER NOT NULL,
                drive TEXT NOT NULL,
                last_path TEXT,
                files_processed INTEGER DEFAULT 0,
                batches_committed INTEGER DEFAULT 0,
                updated_at TEXT,
                PRIMARY KEY (scan_id, drive)
            )
        """)
        conn.commit()
        conn.close()

    def save(self, scan_id: int, drive: str, last_path: str, files_processed: int, batches: int):
        conn = sqlite3.connect(str(self.db_path))
        conn.execute("""
            INSERT OR REPLACE INTO scan_checkpoints
            (scan_id, drive, last_path, files_processed, batches_committed, updated_at)
            VALUES (?, ?, ?, ?, ?, datetime('now'))
        """, (scan_id, drive, last_path, files_processed, batches))
        conn.commit()
        conn.close()

    def load(self, scan_id: int, drive: str) -> dict | None:
        conn = sqlite3.connect(str(self.db_path))
        row = conn.execute("""
            SELECT last_path, files_processed, batches_committed
            FROM scan_checkpoints WHERE scan_id=? AND drive=?
        """, (scan_id, drive)).fetchone()
        conn.close()
        if row:
            return {'last_path': row[0], 'files_processed': row[1], 'batches': row[2]}
        return None

    def clear(self, scan_id: int):
        conn = sqlite3.connect(str(self.db_path))
        conn.execute("DELETE FROM scan_checkpoints WHERE scan_id=?", (scan_id,))
        conn.commit()
        conn.close()


def check_disk_space(db_path: Path, min_gb: float = 5.0) -> tuple[bool, float]:
    """Check free space on the drive hosting the DB. Returns (ok, free_gb)."""
    import shutil
    stat = shutil.disk_usage(str(db_path.parent))
    free_gb = stat.free / (1024 ** 3)
    if free_gb < min_gb:
        logger.warning("Low disk space on DB drive: {:.1f}GB free (minimum {:.1f}GB)", free_gb, min_gb)
        return False, free_gb
    return True, free_gb
