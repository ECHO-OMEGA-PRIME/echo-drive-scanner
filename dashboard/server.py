"""Intelligent Drive Scanner v2.0 — FastAPI Dashboard Server.

Real-time analytics dashboard with WebSocket scan progress,
RESTful API for file intelligence, and Jinja2 HTML templates.

Port: 8460
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import Body, FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from loguru import logger
from starlette.requests import Request

from config import DASHBOARD_PORT, LOG_DIR, PROJECT_ROOT, ScanConfig, validate_scan_path
from storage.db import IntelligenceDB
from storage.models import Recommendation, ScanProgress

DASHBOARD_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = DASHBOARD_DIR / "templates"
STATIC_DIR = DASHBOARD_DIR / "static"

# The dashboard page needs d3 from d3js.org, its own static assets, and uses
# inline <style> / style="" attributes (hence 'unsafe-inline' for styles only).
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "script-src 'self' https://d3js.org; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "connect-src 'self' ws: wss:; "
    "font-src 'self'; "
    "object-src 'none'; "
    "frame-ancestors 'none'; "
    "base-uri 'self'"
)

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": CONTENT_SECURITY_POLICY,
}

AUDIT_LOG_PATH = LOG_DIR / "actions_audit.jsonl"
QUARANTINE_DIR = PROJECT_ROOT / "quarantine"


def _audit_action(
    rec_id: int, category: str | None, decision: str, reason: str, path_count: int
) -> None:
    """Append one line to the file-action audit log.

    Must never contain file contents or matched pattern values.
    """
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "rec_id": rec_id,
        "category": category,
        "decision": decision,
        "reason": reason,
        "path_count": path_count,
    }
    try:
        AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
    except OSError as e:
        logger.error("Failed to write action audit entry: {}", e)


def _affected_paths(db: IntelligenceDB, rec: Recommendation) -> list[str]:
    """Resolve a recommendation's affected file IDs (JSON list) to paths."""
    if not rec.affected_files:
        return []
    try:
        ids = json.loads(rec.affected_files)
    except (json.JSONDecodeError, TypeError):
        return []
    paths: list[str] = []
    for fid in ids:
        try:
            file = db.get_file(int(fid))
        except (TypeError, ValueError):
            file = None
        if file and file.path:
            paths.append(file.path)
    return paths


def _quarantine_files(paths: list[str], scan_id: int) -> list[dict[str, str]]:
    """Move files into ./quarantine/<scan_id>/ instead of deleting them."""
    qdir = QUARANTINE_DIR / str(scan_id)
    qdir.mkdir(parents=True, exist_ok=True)
    moved: list[dict[str, str]] = []
    for p in paths:
        src = Path(p)
        if not src.is_file():
            continue
        dest = qdir / src.name
        n = 1
        while dest.exists():
            dest = qdir / f"{src.stem}_{n}{src.suffix}"
            n += 1
        try:
            shutil.move(str(src), str(dest))
        except OSError as e:
            logger.error("Quarantine move failed for a file: {}", e)
            continue
        moved.append({"original": str(src), "quarantined": str(dest)})
    if moved:
        with open(qdir / "manifest.jsonl", "a", encoding="utf-8") as fh:
            for m in moved:
                fh.write(json.dumps(m) + "\n")
    return moved


# ── WebSocket Manager ────────────────────────────────────────────────────────


class ConnectionManager:
    """Manage WebSocket connections for real-time scan updates."""

    def __init__(self) -> None:
        self.active: list[WebSocket] = []

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self.active.append(ws)
        logger.debug("WebSocket connected, total: {}", len(self.active))

    def disconnect(self, ws: WebSocket) -> None:
        if ws in self.active:
            self.active.remove(ws)
        logger.debug("WebSocket disconnected, total: {}", len(self.active))

    async def broadcast(self, data: dict[str, Any]) -> None:
        dead: list[WebSocket] = []
        for ws in self.active:
            try:
                await ws.send_json(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


ws_manager = ConnectionManager()


# ── App Factory ──────────────────────────────────────────────────────────────


def create_app(db_path: str | Path | None = None) -> FastAPI:
    """Create the FastAPI dashboard application.

    Args:
        db_path: Path to SQLite database. Uses default if None.

    Returns:
        Configured FastAPI application.
    """
    from config import DB_PATH
    db = IntelligenceDB(db_path or DB_PATH)

    app = FastAPI(
        title="Intelligent Drive Scanner",
        version="2.0.0",
        description="AI-powered file intelligence with 2,632 domain engines",
    )

    # Mount static files
    STATIC_DIR.mkdir(parents=True, exist_ok=True)
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

    # ── Middleware ───────────────────────────────────────────────────────

    @app.middleware("http")
    async def observability_and_security_headers(
        request: Request, call_next: Any
    ) -> Any:
        """Log one line per request and attach security headers."""
        start = time.perf_counter()
        response = await call_next(request)
        duration_ms = (time.perf_counter() - start) * 1000.0
        client_host = request.client.host if request.client else "-"
        level = "WARNING" if duration_ms > 2000 else "INFO"
        logger.log(
            level,
            "{} {} -> {} ({:.1f}ms) client={}",
            request.method,
            request.url.path,
            response.status_code,
            duration_ms,
            client_host,
        )
        for header, value in SECURITY_HEADERS.items():
            response.headers[header] = value
        return response

    # ── Exception Handling ───────────────────────────────────────────────
    # HTTPException is deliberately not intercepted: FastAPI's normal 4xx
    # handling stands. Only truly unhandled errors land here.

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.opt(exception=exc).error(
            "Unhandled error on {} {}", request.method, request.url.path
        )
        response = JSONResponse(
            status_code=500,
            content={"error": "internal_error", "detail": "An internal error occurred."},
        )
        # This response bypasses the middleware stack, so attach headers here too.
        for header, value in SECURITY_HEADERS.items():
            response.headers[header] = value
        return response

    # ── HTML Routes ──────────────────────────────────────────────────────

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request) -> HTMLResponse:
        """Main dashboard page."""
        return templates.TemplateResponse("index.html", {"request": request})

    # ── Scan API ─────────────────────────────────────────────────────────

    @app.post("/api/scan/start")
    async def start_scan(body: dict[str, Any]) -> JSONResponse:
        """Start a new intelligence scan."""
        paths = body.get("paths", [])
        profile = body.get("profile", "INTELLIGENCE")
        if not paths:
            raise HTTPException(400, "paths required")

        for p in paths:
            ok, reason = validate_scan_path(p)
            if not ok:
                logger.warning("Scan start rejected: {}", reason)
                return JSONResponse(
                    status_code=400,
                    content={"error": "path_rejected", "path": str(p), "reason": reason},
                )

        # Run scan in background
        from scanner import IntelligenceScanOrchestrator
        config = ScanConfig()
        orchestrator = IntelligenceScanOrchestrator(config)

        def progress_cb(progress: ScanProgress) -> None:
            asyncio.create_task(ws_manager.broadcast(progress.model_dump()))

        orchestrator.add_progress_callback(progress_cb)

        async def run() -> None:
            try:
                await orchestrator.run_scan(paths, profile)
            except Exception as e:
                logger.error("Background scan failed: {}", e)
                await ws_manager.broadcast({"phase": "failed", "error": str(e)})

        asyncio.create_task(run())
        return JSONResponse({"status": "started", "message": "Scan started in background"})

    @app.get("/api/scan/status")
    async def scan_status() -> JSONResponse:
        """Get current scan status."""
        scans = db.list_scans(limit=1)
        if not scans:
            return JSONResponse({"status": "no_scans"})
        scan = scans[0]
        return JSONResponse(scan.model_dump())

    @app.get("/api/scan/{scan_id}/results")
    async def scan_results(scan_id: int) -> JSONResponse:
        """Get scan results summary."""
        summary = db.get_scan_summary(scan_id)
        if not summary:
            raise HTTPException(404, "Scan not found")
        return JSONResponse(summary.model_dump())

    # ── File API ─────────────────────────────────────────────────────────

    @app.get("/api/files")
    async def list_files(
        scan_id: int | None = None,
        domain: str | None = None,
        extension: str | None = None,
        min_score: float | None = None,
        search: str | None = None,
        limit: int = Query(default=100, le=1000),
        offset: int = 0,
    ) -> JSONResponse:
        """List files with optional filters."""
        if search:
            rows = db.search_files(search, limit=limit)
            return JSONResponse({"files": [{"file": r, "score": None} for r in rows],
                                 "count": len(rows)})
        files = db.list_files(
            scan_id=scan_id,
            extension=extension,
            domain=domain,
            limit=limit,
            offset=offset,
        )

        results = []
        for f in files:
            score = db.get_score(f.id or 0)
            results.append({
                "file": f.model_dump(),
                "score": score.model_dump() if score else None,
            })
        return JSONResponse({"files": results, "count": len(results)})

    @app.get("/api/files/{file_id}")
    async def get_file_detail(file_id: int) -> JSONResponse:
        """Get full file detail with classifications and scores."""
        file = db.get_file(file_id)
        if not file:
            raise HTTPException(404, "File not found")

        score = db.get_score(file_id)
        classifications = db.get_classifications(file_id)
        relationships = db.get_file_relationships(file_id)

        return JSONResponse({
            "file": file.model_dump(),
            "score": score.model_dump() if score else None,
            "classifications": [c.model_dump() for c in classifications],
            "relationships": [r.model_dump() for r in relationships],
        })

    # ── Domain API ───────────────────────────────────────────────────────

    @app.get("/api/domains")
    async def list_domains(scan_id: int | None = None) -> JSONResponse:
        """Get domain distribution statistics."""
        sid = scan_id
        if not sid:
            scans = db.list_scans(limit=1)
            if scans:
                sid = scans[0].id or 0
        if not sid:
            return JSONResponse({"domains": []})

        stats = db.get_domain_stats(sid)
        return JSONResponse({
            "domains": [s.model_dump() for s in stats],
            "total_domains": len(stats),
        })

    # ── Duplicate API ────────────────────────────────────────────────────

    @app.get("/api/duplicates")
    async def list_duplicates(scan_id: int | None = None) -> JSONResponse:
        """Get duplicate file clusters."""
        clusters = db.get_duplicate_clusters(scan_id=scan_id)
        return JSONResponse({
            "clusters": clusters,
            "total_clusters": len(clusters),
            "total_wasted_bytes": sum(c.get("total_wasted_bytes") or 0 for c in clusters),
        })

    # ── Recommendation API ───────────────────────────────────────────────

    @app.get("/api/recommendations")
    async def list_recommendations(scan_id: int | None = None) -> JSONResponse:
        """Get all recommendations."""
        sid = scan_id
        if not sid:
            scans = db.list_scans(limit=1)
            if scans:
                sid = scans[0].id or 0
        if not sid:
            return JSONResponse({"recommendations": []})

        recs = db.get_recommendations(sid)
        return JSONResponse({
            "recommendations": [r.model_dump() for r in recs],
            "total": len(recs),
        })

    @app.post("/api/recommendations/{rec_id}/execute")
    async def execute_recommendation(
        rec_id: int, body: dict[str, Any] | None = Body(default=None)
    ) -> JSONResponse:
        """Execute a recommendation — gated, non-destructive, audited.

        Requires DRIVESCAN_ALLOW_FILE_ACTIONS=1 in the environment plus a
        {"confirm": <rec_id>} body. "delete" recommendations quarantine files
        under ./quarantine/<scan_id>/ instead of removing them.
        """
        body = body or {}

        def refuse(reason: str, category: str | None = None, path_count: int = 0) -> JSONResponse:
            _audit_action(rec_id, category, "refused", reason, path_count)
            return JSONResponse(
                status_code=403,
                content={"error": "action_disabled", "reason": reason},
            )

        if os.environ.get("DRIVESCAN_ALLOW_FILE_ACTIONS") != "1":
            return refuse(
                "file actions are disabled (set DRIVESCAN_ALLOW_FILE_ACTIONS=1 to enable)"
            )

        confirm = body.get("confirm")
        if confirm is None or str(confirm) != str(rec_id):
            return refuse("missing or mismatched 'confirm' value in request body")

        rec = db.get_recommendation(rec_id)
        if rec is None:
            _audit_action(rec_id, None, "refused", "recommendation not found", 0)
            raise HTTPException(404, "Recommendation not found")

        paths = _affected_paths(db, rec)
        for p in paths:
            ok, reason = validate_scan_path(p)
            if not ok:
                return refuse(
                    f"affected path rejected: {reason}", rec.category, len(paths)
                )

        if rec.category == "delete":
            moved = _quarantine_files(paths, rec.scan_id)
            db.update_recommendation_status(rec_id, "executed")
            _audit_action(
                rec_id, rec.category, "executed",
                f"quarantined {len(moved)} of {len(paths)} file(s)", len(paths),
            )
            return JSONResponse(
                {"status": "executed", "id": rec_id, "quarantined": len(moved)}
            )

        db.update_recommendation_status(rec_id, "executed")
        _audit_action(rec_id, rec.category, "executed", "status updated", len(paths))
        return JSONResponse({"status": "executed", "id": rec_id})

    # ── Score API ────────────────────────────────────────────────────────

    @app.get("/api/scores/distribution")
    async def score_distribution(
        scan_id: int | None = None,
        dimension: str = "overall_score",
    ) -> JSONResponse:
        """Get score distribution histogram."""
        sid = scan_id
        if not sid:
            scans = db.list_scans(limit=1)
            if scans:
                sid = scans[0].id or 0
        if not sid:
            return JSONResponse({"distribution": []})

        dist = db.get_score_distribution(dimension=dimension, scan_id=sid)
        return JSONResponse({"dimension": dimension, "buckets": dist})

    @app.get("/api/scores/top")
    async def top_scores(
        scan_id: int | None = None,
        dimension: str = "overall_score",
        limit: int = 20,
    ) -> JSONResponse:
        """Get top-scoring files."""
        sid = scan_id
        if not sid:
            scans = db.list_scans(limit=1)
            if scans:
                sid = scans[0].id or 0
        if not sid:
            return JSONResponse({"files": []})

        top = db.get_top_scores(dimension=dimension, limit=limit, scan_id=sid)
        return JSONResponse({"files": top})

    @app.get("/api/scores/risk")
    async def high_risk_files(
        scan_id: int | None = None,
        min_risk: float = 50.0,
    ) -> JSONResponse:
        """Get high-risk files."""
        sid = scan_id
        if not sid:
            scans = db.list_scans(limit=1)
            if scans:
                sid = scans[0].id or 0
        if not sid:
            return JSONResponse({"files": []})

        risk_files = db.get_high_risk_files(threshold=min_risk, scan_id=sid)
        return JSONResponse({"files": risk_files})

    # ── Export ───────────────────────────────────────────────────────────

    @app.get("/api/export/report")
    async def export_report(scan_id: int | None = None) -> JSONResponse:
        """Export full intelligence report as JSON."""
        sid = scan_id
        if not sid:
            scans = db.list_scans(limit=1)
            if scans:
                sid = scans[0].id or 0
        if not sid:
            raise HTTPException(404, "No scans found")

        summary = db.get_scan_summary(sid)
        domains = db.get_domain_stats(sid)
        recs = db.get_recommendations(sid)
        risk = db.get_high_risk_files(scan_id=sid)

        return JSONResponse({
            "report_version": "2.0",
            "scan_summary": summary.model_dump() if summary else None,
            "domain_stats": [d.model_dump() for d in domains],
            "recommendations": [r.model_dump() for r in recs],
            "high_risk_files": risk,
        })

    # ── Timeline ─────────────────────────────────────────────────────────

    @app.get("/api/timeline")
    async def timeline() -> JSONResponse:
        """Get scan history for timeline view."""
        scans = db.list_scans(limit=20)
        return JSONResponse({
            "scans": [s.model_dump() for s in scans],
        })

    # ── Health ───────────────────────────────────────────────────────────

    @app.get("/health")
    async def health() -> JSONResponse:
        """Health check. Reports degraded (still 200) on db errors."""
        try:
            scans = db.list_scans(limit=1)
        except Exception as e:
            logger.opt(exception=e).error("Health check db access failed")
            return JSONResponse({
                "status": "degraded",
                "error": f"{type(e).__name__}: {str(e)[:120]}",
            })
        return JSONResponse({
            "status": "healthy",
            "version": "2.0.0",
            "db_path": str(db.db_path),
            "total_scans": len(scans),
            "latest_scan": scans[0].model_dump() if scans else None,
        })

    # ── WebSocket ────────────────────────────────────────────────────────

    @app.websocket("/api/ws/scan")
    async def ws_scan_progress(ws: WebSocket) -> None:
        """WebSocket for real-time scan progress updates."""
        await ws_manager.connect(ws)
        try:
            while True:
                # Keep connection alive, receive any client messages
                data = await ws.receive_text()
                if data == "ping":
                    await ws.send_json({"type": "pong"})
        except WebSocketDisconnect:
            ws_manager.disconnect(ws)

    return app


# ASGI entry point: `uvicorn dashboard.server:app --port 8460`.
# Import-time work is limited to building the app and opening the sqlite db.
app = create_app()
