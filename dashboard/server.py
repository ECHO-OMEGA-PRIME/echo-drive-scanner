"""Intelligent Drive Scanner v2.1 — governed dashboard and API service."""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import Body, FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from loguru import logger
from pydantic import ValidationError
from starlette.requests import Request

from config import LOG_DIR, PROJECT_ROOT, ScanConfig, validate_scan_path
from dashboard.api_models import (
    RecommendationExecuteRequest,
    ScanCancelRequest,
    ScanStartRequest,
)
from dashboard.security import (
    API_VERSION,
    authorized_client,
    max_request_bytes,
    public_file_record,
    public_proposal,
)
from storage.db import IntelligenceDB
from storage.models import Recommendation, ScanProgress

DASHBOARD_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = DASHBOARD_DIR / "templates"
STATIC_DIR = DASHBOARD_DIR / "static"

CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "script-src 'self' https://d3js.org; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "connect-src 'self' ws: wss:; "
    "font-src 'self'; "
    "object-src 'none'; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "form-action 'self'"
)

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": CONTENT_SECURITY_POLICY,
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cross-Origin-Opener-Policy": "same-origin",
}

AUDIT_LOG_PATH = LOG_DIR / "actions_audit.jsonl"
QUARANTINE_DIR = PROJECT_ROOT / "quarantine"


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _json(payload: dict[str, Any], status_code: int = 200) -> JSONResponse:
    """Return a versioned JSON response without mutating the source payload."""
    body = {"api_version": API_VERSION, **payload}
    return JSONResponse(body, status_code=status_code)


def _token_from_headers(headers: Any) -> str:
    direct = headers.get("x-drivescan-token", "")
    if direct:
        return direct
    authorization = headers.get("authorization", "")
    if authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return ""


def _audit_action(
    rec_id: int,
    category: str | None,
    decision: str,
    reason: str,
    path_count: int,
) -> None:
    """Append a content-free action audit record."""
    entry = {
        "ts": _now_iso(),
        "rec_id": rec_id,
        "category": category,
        "decision": decision,
        "reason": reason[:500],
        "path_count": path_count,
    }
    try:
        AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with AUDIT_LOG_PATH.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, sort_keys=True) + "\n")
    except OSError as exc:
        logger.error("Failed to write action audit entry: {}", exc)


def _affected_paths(db: IntelligenceDB, rec: Recommendation) -> list[str]:
    if not rec.affected_files:
        return []
    try:
        ids = json.loads(rec.affected_files)
    except (json.JSONDecodeError, TypeError):
        return []
    paths: list[str] = []
    for file_id in ids:
        try:
            file = db.get_file(int(file_id))
        except (TypeError, ValueError):
            file = None
        if file and file.path:
            paths.append(file.path)
    return paths


def _quarantine_files(paths: list[str], scan_id: int) -> list[dict[str, str]]:
    """Move files to a reversible quarantine journal; never delete."""
    qdir = QUARANTINE_DIR / str(scan_id)
    qdir.mkdir(parents=True, exist_ok=True)
    moved: list[dict[str, str]] = []
    for raw_path in paths:
        src = Path(raw_path)
        if not src.is_file():
            continue
        dest = qdir / src.name
        suffix = 1
        while dest.exists():
            dest = qdir / f"{src.stem}_{suffix}{src.suffix}"
            suffix += 1
        try:
            shutil.move(str(src), str(dest))
        except OSError as exc:
            logger.error("Quarantine move failed for path_id={}: {}", src.name, exc)
            continue
        moved.append({"original": str(src), "quarantined": str(dest)})
    if moved:
        with (qdir / "manifest.jsonl").open("a", encoding="utf-8") as handle:
            for item in moved:
                handle.write(json.dumps(item, sort_keys=True) + "\n")
    return moved


class ConnectionManager:
    """Manage scan-progress WebSocket clients."""

    def __init__(self) -> None:
        self.active: list[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active.append(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        if websocket in self.active:
            self.active.remove(websocket)

    async def broadcast(self, data: dict[str, Any]) -> None:
        dead: list[WebSocket] = []
        for websocket in self.active:
            try:
                await websocket.send_json({"api_version": API_VERSION, **data})
            except Exception:
                dead.append(websocket)
        for websocket in dead:
            self.disconnect(websocket)


ws_manager = ConnectionManager()


def create_app(
    db_path: str | Path | None = None,
    *,
    enforce_access: bool | None = None,
) -> FastAPI:
    """Create the governed scanner API.

    Custom database instances default to access enforcement off for isolated
    tests. The production singleton always enables it.
    """
    from config import DB_PATH

    db = IntelligenceDB(Path(db_path or DB_PATH))
    enforce = (db_path is None) if enforce_access is None else enforce_access
    active_tasks: dict[int, asyncio.Task[None]] = {}

    app = FastAPI(
        title="Intelligent Drive Scanner",
        version="2.2.0",
        description="Governed filesystem intelligence and build proposals",
    )
    app.state.db = db
    app.state.active_tasks = active_tasks
    app.state.enforce_access = enforce

    STATIC_DIR.mkdir(parents=True, exist_ok=True)
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

    def resolve_scan_id(scan_id: int | None, *, allow_running: bool = False) -> int | None:
        if scan_id is not None:
            return scan_id
        scan = db.latest_completed_scan()
        if scan:
            return scan.id
        if allow_running:
            scans = db.list_scans(limit=1)
            return scans[0].id if scans else None
        return None

    @app.middleware("http")
    async def boundary_and_observability(request: Request, call_next: Any) -> Any:
        request_id = request.headers.get("x-request-id") or str(uuid.uuid4())
        start = time.perf_counter()
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                if int(content_length) > max_request_bytes():
                    return _json(
                        {"error": "request_too_large", "detail": "request body exceeds policy"},
                        413,
                    )
            except ValueError:
                return _json({"error": "invalid_content_length", "detail": "invalid header"}, 400)

        if enforce and not authorized_client(
            request.client.host if request.client else None,
            _token_from_headers(request.headers),
        ):
            logger.warning(
                "Denied scanner request {} {} request_id={}",
                request.method,
                request.url.path,
                request_id,
            )
            response = _json(
                {
                    "error": "access_denied",
                    "detail": "scanner service access denied",
                    "request_id": request_id,
                },
                403,
            )
        else:
            response = await call_next(request)

        duration_ms = (time.perf_counter() - start) * 1000.0
        logger.log(
            "WARNING" if duration_ms > 2000 else "INFO",
            "{} {} -> {} ({:.1f}ms) client={} request_id={}",
            request.method,
            request.url.path,
            response.status_code,
            duration_ms,
            request.client.host if request.client else "-",
            request_id,
        )
        response.headers["X-Request-ID"] = request_id
        for header, value in SECURITY_HEADERS.items():
            response.headers[header] = value
        return response

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.opt(exception=exc).error(
            "Unhandled error on {} {}", request.method, request.url.path
        )
        response = _json({"error": "internal_error", "detail": "An internal error occurred."}, 500)
        for header, value in SECURITY_HEADERS.items():
            response.headers[header] = value
        return response

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(request=request, name="index.html")

    @app.post("/api/scan/start", status_code=202)
    async def start_scan(body: ScanStartRequest) -> JSONResponse:
        for path in body.paths:
            ok, reason = validate_scan_path(path)
            if not ok:
                return _json(
                    {"error": "path_rejected", "path_id": "redacted", "reason": reason}, 400
                )

        running = [scan_id for scan_id, task in active_tasks.items() if not task.done()]
        if running:
            return _json(
                {
                    "error": "scan_already_running",
                    "detail": "only one active scan is allowed",
                    "scan_id": running[0],
                },
                409,
            )

        scan_id = db.create_scan(drives=body.paths, profile=body.profile)
        orchestrator = __import__("scanner").IntelligenceScanOrchestrator(ScanConfig(), db=db)
        loop = asyncio.get_running_loop()

        def progress_callback(progress: ScanProgress) -> None:
            loop.create_task(ws_manager.broadcast(progress.model_dump()))

        orchestrator.add_progress_callback(progress_callback)

        async def run_owned_scan() -> None:
            try:
                await orchestrator.run_scan(body.paths, body.profile, scan_id=scan_id)
            finally:
                active_tasks.pop(scan_id, None)

        active_tasks[scan_id] = asyncio.create_task(run_owned_scan(), name=f"drivescan-{scan_id}")
        return _json(
            {
                "status": "accepted",
                "scan_id": scan_id,
                "run_id": f"drivescan-{scan_id}",
                "profile": body.profile,
                "normalized_roots": [Path(path).anchor or Path(path).name for path in body.paths],
                "status_url": f"/api/scans/{scan_id}/status",
                "stages_url": f"/api/scans/{scan_id}/stages",
                "accepted_at": _now_iso(),
            },
            202,
        )

    @app.get("/api/scan/status")
    async def scan_status() -> JSONResponse:
        scans = db.list_scans(limit=1)
        if not scans:
            return _json({"status": "no_scans"})
        return _json(scans[0].model_dump())

    @app.get("/api/scans/latest")
    async def latest_scan() -> JSONResponse:
        scan = db.latest_completed_scan()
        if not scan:
            raise HTTPException(404, "No completed scans found")
        return _json(scan.model_dump())

    @app.get("/api/scans/{scan_id}/status")
    async def specific_scan_status(scan_id: int) -> JSONResponse:
        scan = db.get_scan(scan_id)
        if not scan:
            raise HTTPException(404, "Scan not found")
        return _json({**scan.model_dump(), "stages": db.get_scan_stages(scan_id)})

    @app.get("/api/scans/{scan_id}/stages")
    async def scan_stages(scan_id: int) -> JSONResponse:
        if not db.get_scan(scan_id):
            raise HTTPException(404, "Scan not found")
        return _json({"scan_id": scan_id, "stages": db.get_scan_stages(scan_id)})

    @app.post("/api/scans/{scan_id}/cancel")
    async def cancel_scan(scan_id: int, body: ScanCancelRequest) -> JSONResponse:
        task = active_tasks.get(scan_id)
        if task is None or task.done():
            return _json({"error": "scan_not_active", "detail": "scan is not active"}, 409)
        task.cancel(body.reason)
        db.cancel_scan(scan_id)
        _audit_action(scan_id, "scan", "cancelled", body.reason, 0)
        return _json({"status": "cancellation_requested", "scan_id": scan_id})

    @app.get("/api/scan/{scan_id}/results")
    async def scan_results(scan_id: int) -> JSONResponse:
        summary = db.get_scan_summary(scan_id)
        if not summary:
            raise HTTPException(404, "Scan not found")
        return _json({**summary.model_dump(), "stages": db.get_scan_stages(scan_id)})

    @app.get("/api/files")
    async def list_files(
        scan_id: int | None = None,
        domain: str | None = None,
        extension: str | None = None,
        min_score: float | None = None,
        search: str | None = None,
        limit: int = Query(default=100, ge=1, le=1000),
        offset: int = Query(default=0, ge=0),
    ) -> JSONResponse:
        del min_score  # reserved for a versioned score-filter contract
        sid = resolve_scan_id(scan_id)
        if sid is None:
            return _json({"scan_id": None, "files": [], "count": 0})
        if search:
            rows = db.search_files(search, limit=limit)
            items = []
            for row in rows:
                record = db.get_file(int(row.get("id", 0))) if isinstance(row, dict) else None
                if record and record.scan_id == sid:
                    items.append({"file": public_file_record(record), "score": None})
        else:
            files = db.list_files(
                scan_id=sid, extension=extension, domain=domain, limit=limit, offset=offset
            )
            items = []
            for file in files:
                score = db.get_score(file.id or 0, sid)
                items.append(
                    {
                        "file": public_file_record(file),
                        "score": score.model_dump() if score and score.scan_id == sid else None,
                    }
                )
        return _json({"scan_id": sid, "files": items, "count": len(items)})

    @app.get("/api/files/{file_id}")
    async def get_file_detail(file_id: int, scan_id: int | None = None) -> JSONResponse:
        sid = resolve_scan_id(scan_id)
        file = db.get_file(file_id)
        if not file or sid is None:
            raise HTTPException(404, "File not found")
        observed_ids = {item.id for item in db.list_files(scan_id=sid, limit=100000)}
        if file_id not in observed_ids:
            raise HTTPException(404, "File not found")
        score = db.get_score(file_id, sid)
        return _json(
            {
                "scan_id": sid,
                "file": public_file_record(file),
                "score": score.model_dump() if score and score.scan_id == sid else None,
                "classifications": [
                    c.model_dump() for c in db.get_classifications(file_id) if c.scan_id == sid
                ],
                "relationships": [
                    r.model_dump() for r in db.get_file_relationships(file_id) if r.scan_id == sid
                ],
            }
        )

    @app.get("/api/domains")
    async def list_domains(scan_id: int | None = None) -> JSONResponse:
        sid = resolve_scan_id(scan_id)
        stats = db.get_domain_stats(sid) if sid else []
        return _json(
            {
                "scan_id": sid,
                "domains": [item.model_dump() for item in stats],
                "total_domains": len(stats),
            }
        )

    @app.get("/api/duplicates")
    async def list_duplicates(scan_id: int | None = None) -> JSONResponse:
        sid = resolve_scan_id(scan_id)
        clusters = db.get_duplicate_clusters(scan_id=sid) if sid else []
        return _json(
            {
                "scan_id": sid,
                "clusters": clusters,
                "total_clusters": len(clusters),
                "total_wasted_bytes": sum(item.get("total_wasted_bytes") or 0 for item in clusters),
            }
        )

    @app.get("/api/recommendations")
    async def list_recommendations(scan_id: int | None = None) -> JSONResponse:
        sid = resolve_scan_id(scan_id)
        recs = db.get_recommendations(sid) if sid else []
        return _json(
            {
                "scan_id": sid,
                "recommendations": [rec.model_dump() for rec in recs],
                "total": len(recs),
            }
        )

    @app.post("/api/recommendations/{rec_id}/execute")
    async def execute_recommendation(
        rec_id: int,
        body: dict[str, Any] | None = Body(default=None),
    ) -> JSONResponse:
        def refuse(reason: str, category: str | None = None, path_count: int = 0) -> JSONResponse:
            _audit_action(rec_id, category, "refused", reason, path_count)
            return _json({"error": "action_disabled", "reason": reason}, 403)

        if os.environ.get("DRIVESCAN_ALLOW_FILE_ACTIONS") != "1":
            return refuse("file actions are disabled by policy")
        try:
            confirmation = RecommendationExecuteRequest.model_validate(body or {})
        except ValidationError:
            return refuse("missing, invalid, or unexpected confirmation fields")
        if confirmation.confirm != rec_id:
            return refuse("confirmation does not match recommendation")
        rec = db.get_recommendation(rec_id)
        if rec is None:
            raise HTTPException(404, "Recommendation not found")
        paths = _affected_paths(db, rec)
        for path in paths:
            ok, reason = validate_scan_path(path)
            if not ok:
                return refuse(f"affected path rejected: {reason}", rec.category, len(paths))
        if rec.category == "delete":
            moved = _quarantine_files(paths, rec.scan_id)
            if len(moved) != len(paths) or not moved:
                _audit_action(
                    rec_id, rec.category, "partial_failure", "quarantine incomplete", len(paths)
                )
                return _json(
                    {"error": "quarantine_incomplete", "moved": len(moved), "expected": len(paths)},
                    409,
                )
            db.update_recommendation_status(rec_id, "executed")
            _audit_action(rec_id, rec.category, "executed", "all files quarantined", len(paths))
            return _json({"status": "executed", "id": rec_id, "quarantined": len(moved)})
        db.update_recommendation_status(rec_id, "executed")
        _audit_action(rec_id, rec.category, "executed", "status updated", len(paths))
        return _json({"status": "executed", "id": rec_id})

    @app.get("/api/proposals")
    async def list_proposals(
        request: Request,
        scan_id: int | None = None,
        kind: str | None = Query(default=None, pattern="^(completion|new_build)$"),
        limit: int = Query(default=100, ge=1, le=1000),
    ) -> JSONResponse:
        allowed_query = {"scan_id", "kind", "limit"}
        unknown_query = set(request.query_params) - allowed_query
        if unknown_query:
            return _json(
                {
                    "error": "unknown_query_parameter",
                    "detail": f"unsupported query parameters: {', '.join(sorted(unknown_query))}",
                },
                400,
            )
        sid = resolve_scan_id(scan_id)
        proposals = db.get_proposals(scan_id=sid, kind=kind, limit=limit) if sid else []
        public = [public_proposal(item) for item in proposals]
        return _json(
            {
                "scan_id": sid,
                "kind": kind,
                "proposals": public,
                "count": len(public),
                "completion": sum(1 for item in public if item.get("kind") == "completion"),
                "new_build": sum(1 for item in public if item.get("kind") == "new_build"),
                "queue_supported": False,
            }
        )

    @app.get("/api/scan/{scan_id}/proposals")
    async def scan_proposals(
        scan_id: int,
        kind: str | None = Query(default=None, pattern="^(completion|new_build)$"),
        limit: int = Query(default=100, ge=1, le=1000),
    ) -> JSONResponse:
        proposals = [
            public_proposal(item)
            for item in db.get_proposals(scan_id=scan_id, kind=kind, limit=limit)
        ]
        return _json(
            {
                "scan_id": scan_id,
                "proposals": proposals,
                "count": len(proposals),
                "completion": sum(1 for item in proposals if item.get("kind") == "completion"),
                "new_build": sum(1 for item in proposals if item.get("kind") == "new_build"),
            }
        )

    @app.get("/api/storage/summary")
    async def storage_summary(scan_id: int | None = None) -> JSONResponse:
        sid = resolve_scan_id(scan_id)
        scan = db.get_scan(sid) if sid else None
        if not scan:
            return _json({"scan_id": None, "drives": [], "health_source": "filesystem_only"})
        try:
            roots = json.loads(scan.drives) if isinstance(scan.drives, str) else scan.drives
        except json.JSONDecodeError:
            roots = []
        seen: set[str] = set()
        drives: list[dict[str, Any]] = []
        for raw_root in roots:
            anchor = Path(str(raw_root)).anchor or str(raw_root)
            key = anchor.casefold()
            if key in seen:
                continue
            seen.add(key)
            try:
                usage = shutil.disk_usage(anchor)
            except OSError:
                drives.append({"drive": anchor, "state": "unavailable", "health": "unknown"})
                continue
            used_percent = round((usage.used / usage.total) * 100, 1) if usage.total else 0.0
            state = (
                "critical"
                if used_percent >= 95
                else "warning"
                if used_percent >= 85
                else "available"
            )
            drives.append(
                {
                    "drive": anchor,
                    "total_bytes": usage.total,
                    "used_bytes": usage.used,
                    "free_bytes": usage.free,
                    "used_percent": used_percent,
                    "state": state,
                    "health": "unknown",
                    "health_reason": "SMART/device health is not collected by this service",
                }
            )
        return _json({"scan_id": sid, "drives": drives, "health_source": "filesystem_capacity"})

    @app.get("/api/scores/distribution")
    async def score_distribution(
        scan_id: int | None = None, dimension: str = "overall_score"
    ) -> JSONResponse:
        sid = resolve_scan_id(scan_id)
        return _json(
            {
                "scan_id": sid,
                "dimension": dimension,
                "buckets": db.get_score_distribution(dimension=dimension, scan_id=sid)
                if sid
                else [],
            }
        )

    @app.get("/api/scores/top")
    async def top_scores(
        scan_id: int | None = None,
        dimension: str = "overall_score",
        limit: int = Query(default=20, ge=1, le=1000),
    ) -> JSONResponse:
        sid = resolve_scan_id(scan_id)
        rows = db.get_top_scores(dimension=dimension, limit=limit, scan_id=sid) if sid else []
        for row in rows:
            if "path" in row:
                row.update(public_file_record(row))
                row.pop("path", None)
        return _json({"scan_id": sid, "files": rows})

    @app.get("/api/scores/risk")
    async def high_risk_files(scan_id: int | None = None, min_risk: float = 50.0) -> JSONResponse:
        sid = resolve_scan_id(scan_id)
        rows = db.get_high_risk_files(threshold=min_risk, scan_id=sid) if sid else []
        for row in rows:
            if "path" in row:
                row.update(public_file_record(row))
                row.pop("path", None)
        return _json({"scan_id": sid, "files": rows})

    @app.get("/api/export/report")
    async def export_report(scan_id: int | None = None) -> JSONResponse:
        sid = resolve_scan_id(scan_id)
        if not sid:
            raise HTTPException(404, "No completed scans found")
        summary = db.get_scan_summary(sid)
        return _json(
            {
                "report_version": "2.1",
                "scan_summary": summary.model_dump() if summary else None,
                "domain_stats": [item.model_dump() for item in db.get_domain_stats(sid)],
                "recommendations": [item.model_dump() for item in db.get_recommendations(sid)],
                "high_risk_files": [],
                "stages": db.get_scan_stages(sid),
            }
        )

    @app.get("/api/timeline")
    async def timeline() -> JSONResponse:
        return _json({"scans": [scan.model_dump() for scan in db.list_scans(limit=20)]})

    @app.get("/health")
    async def health() -> JSONResponse:
        try:
            scans = db.list_scans(limit=1)
            total_scans = db.count_scans()
            latest = scans[0] if scans else None
            database_state = "healthy"
        except Exception as exc:
            logger.opt(exception=exc).error("Health check database access failed")
            return _json(
                {
                    "status": "degraded",
                    "version": "2.2.0",
                    "subsystems": {"database": "failed", "api": "healthy"},
                    "error": "database_unavailable",
                }
            )
        active = [scan_id for scan_id, task in active_tasks.items() if not task.done()]
        latest_status = latest.status if latest else "none"
        status = "degraded" if latest_status in {"failed", "degraded"} else "healthy"
        return _json(
            {
                "status": status,
                "version": "2.2.0",
                "database": db.db_path.name,
                "total_scans": total_scans,
                "latest_scan": latest.model_dump() if latest else None,
                "active_scan_ids": active,
                "subsystems": {
                    "api": "healthy",
                    "database": database_state,
                    "scanner": "busy" if active else "idle",
                    "classification_engine": "configured"
                    if os.environ.get("DRIVESCAN_ENGINE_URL")
                    else "not_configured",
                    "file_actions": "enabled"
                    if os.environ.get("DRIVESCAN_ALLOW_FILE_ACTIONS") == "1"
                    else "disabled",
                },
            }
        )

    @app.websocket("/api/ws/scan")
    async def ws_scan_progress(websocket: WebSocket) -> None:
        if enforce and not authorized_client(
            websocket.client.host if websocket.client else None,
            _token_from_headers(websocket.headers),
        ):
            await websocket.close(code=4403, reason="access denied")
            return
        await ws_manager.connect(websocket)
        try:
            while True:
                data = await websocket.receive_text()
                if data == "ping":
                    await websocket.send_json({"api_version": API_VERSION, "type": "pong"})
        except WebSocketDisconnect:
            ws_manager.disconnect(websocket)

    return app


app = create_app()
