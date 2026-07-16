#!/usr/bin/env python
"""smoke_live.py — live deploy gate for the Intelligent Drive Scanner dashboard.

Runs one real scan against a temp folder into a temp sqlite db, boots the
dashboard app on a staging port as a subprocess, exercises the HTTP surface
(including negative cases), and audits production essentials (security
headers). Exits 0 only if every hard check passes.

Usage: python smoke_live.py
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent


def _pick_staging_port(preferred: int = 8399) -> int:
    """Prefer the canonical staging port; fall back to a free ephemeral one
    (Windows sometimes reserves whole port ranges, e.g. for Hyper-V)."""
    for port in (preferred, 0):
        s = socket.socket()
        try:
            s.bind(("127.0.0.1", port))
            return s.getsockname()[1]
        except OSError:
            continue
        finally:
            s.close()
    raise RuntimeError("no bindable staging port found")


STAGING_PORT = _pick_staging_port()
BASE_URL = f"http://127.0.0.1:{STAGING_PORT}"
HEALTH_TIMEOUT_S = 60

REQUIRED_SECURITY_HEADERS = [
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "Cross-Origin-Resource-Policy",
    "Cross-Origin-Opener-Policy",
]

PROTECTED_PROBE = r"C:\Windows\Temp" if os.name == "nt" else "/etc/ssh"

RESULTS: list[tuple[str, bool, str]] = []


def check(name: str, passed: bool, detail: str = "") -> bool:
    RESULTS.append((name, passed, detail))
    print(f"  [{'PASS' if passed else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))
    return passed


def http(method: str, path: str, body: dict | None = None, timeout: int = 15):
    """Return (status_code, headers, parsed_json_or_None, raw_text)."""
    data = None
    headers = {}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(BASE_URL + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", "replace")
            status, hdrs = resp.status, resp.headers
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        status, hdrs = e.code, e.headers
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        parsed = None
    return status, hdrs, parsed, raw


def make_sample_files(sample_dir: Path) -> None:
    sample_dir.mkdir(parents=True, exist_ok=True)
    (sample_dir / "report_notes.txt").write_text(
        "Quarterly production report notes for the drilling program.\n" * 25,
        encoding="utf-8",
    )
    (sample_dir / "helper_script.py").write_text(
        "def add(a, b):\n    return a + b\n\n\nif __name__ == '__main__':\n    print(add(2, 3))\n",
        encoding="utf-8",
    )
    (sample_dir / "config_sample.json").write_text(
        json.dumps({"name": "smoke", "retries": 3, "enabled": True}, indent=2),
        encoding="utf-8",
    )
    dup_payload = "identical payload content used for duplicate detection\n" * 60
    (sample_dir / "dup_copy_a.txt").write_text(dup_payload, encoding="utf-8")
    (sample_dir / "dup_copy_b.txt").write_text(dup_payload, encoding="utf-8")


def run_scan(sample_dir: Path) -> int:
    sys.path.insert(0, str(PROJECT_ROOT))
    from scanner import IntelligenceScanOrchestrator  # noqa: PLC0415

    orchestrator = IntelligenceScanOrchestrator()
    return asyncio.run(orchestrator.run_scan([str(sample_dir)], "INTEL_FAST"))


def wait_for_health(proc: subprocess.Popen) -> bool:
    deadline = time.time() + HEALTH_TIMEOUT_S
    while time.time() < deadline:
        if proc.poll() is not None:
            return False
        try:
            status, _, _, _ = http("GET", "/health", timeout=3)
            if status == 200:
                return True
        except (urllib.error.URLError, OSError, TimeoutError):
            pass
        time.sleep(0.5)
    return False


def run_checks(sample_dir: Path) -> None:
    # ── Health + security-header audit ──────────────────────────────────
    status, headers, payload, _ = http("GET", "/health")
    check("GET /health returns 200", status == 200, f"status={status}")
    check(
        "/health reports healthy",
        bool(payload) and payload.get("status") == "healthy",
        f"body_status={payload.get('status') if payload else None}",
    )
    check(
        "/health exposes versioned v2.1 contract",
        bool(payload) and payload.get("api_version") == "2.1" and payload.get("version") == "2.1.0",
        f"api_version={payload.get('api_version') if payload else None}",
    )
    check(
        "/health reports exact scan count",
        bool(payload) and payload.get("total_scans") == 1,
        f"total_scans={payload.get('total_scans') if payload else None}",
    )
    check(
        "/health does not expose the database filesystem path",
        bool(payload) and str(PROJECT_ROOT) not in json.dumps(payload),
    )
    missing = [h for h in REQUIRED_SECURITY_HEADERS if not headers.get(h)]
    check(
        "all required security headers present on 200 response",
        not missing,
        f"missing={missing}" if missing else "",
    )

    # ── Positive surface across input variations ────────────────────────
    status, _, payload, _ = http("GET", "/api/scan/status")
    check("GET /api/scan/status returns 200", status == 200, f"status={status}")
    scan_id = payload.get("id") if payload else None
    check("scan status returns a durable scan id", isinstance(scan_id, int) and scan_id > 0)

    status, _, stage_payload, _ = http("GET", f"/api/scans/{scan_id}/stages")
    stage_names = (
        {stage.get("stage") for stage in stage_payload.get("stages", [])}
        if stage_payload
        else set()
    )
    check(
        "run-specific stage outcomes are observable",
        status == 200 and {"preflight", "classification", "finalization"}.issubset(stage_names),
        f"stages={sorted(stage_names)}",
    )

    status, _, storage_payload, _ = http("GET", f"/api/storage/summary?scan_id={scan_id}")
    check(
        "storage summary reports capacity without fabricating SMART health",
        status == 200
        and bool(storage_payload)
        and storage_payload.get("health_source") == "filesystem_capacity"
        and all(drive.get("health") == "unknown" for drive in storage_payload.get("drives", [])),
    )

    status, _, payload, raw_files = http("GET", f"/api/files?scan_id={scan_id}")
    count = payload.get("count", 0) if payload else 0
    check(
        "GET /api/files (no filter) 200 with files",
        status == 200 and count >= 1,
        f"status={status} count={count}",
    )

    status, _, payload, _ = http("GET", "/api/files?search=dup")
    check("GET /api/files?search=dup returns 200", status == 200, f"status={status}")

    status, _, payload, _ = http("GET", "/api/files?extension=.nomatch")
    empty_count = payload.get("count", -1) if payload else -1
    check(
        "GET /api/files with empty-result filter 200 and count 0",
        status == 200 and empty_count == 0,
        f"status={status} count={empty_count}",
    )

    for path in (
        "/api/domains",
        "/api/duplicates",
        "/api/recommendations",
        "/api/scores/top",
        "/api/scores/risk",
        "/api/scores/distribution",
        "/api/export/report",
        "/api/timeline",
    ):
        status, _, _, _ = http("GET", path)
        check(f"GET {path} returns 200", status == 200, f"status={status}")

    status, _, payload, _ = http("GET", "/api/duplicates")
    clusters = payload.get("total_clusters", 0) if payload else 0
    print(f"  [info] duplicate clusters detected: {clusters}")

    # ── Negative cases ───────────────────────────────────────────────────
    status, _, payload, _ = http("POST", "/api/scan/start", body={"paths": [PROTECTED_PROBE]})
    check(
        "POST /api/scan/start with protected path returns 400 path_rejected",
        status == 400 and bool(payload) and payload.get("error") == "path_rejected",
        f"status={status} error={payload.get('error') if payload else None}",
    )

    status, _, payload, _ = http("POST", "/api/recommendations/1/execute")
    check(
        "POST /api/recommendations/1/execute unconfirmed returns 403 action_disabled",
        status == 403 and bool(payload) and payload.get("error") == "action_disabled",
        f"status={status} error={payload.get('error') if payload else None}",
    )

    status, _, payload, _ = http("GET", f"/api/proposals?scan_id={scan_id}&queue=true")
    check(
        "proposal endpoint rejects legacy queue mutation parameter",
        status == 400 and bool(payload) and payload.get("error") == "unknown_query_parameter",
        f"status={status}",
    )

    status, _, _, _ = http("GET", "/api/definitely-not-a-route")
    check("GET unknown route returns 404", status == 404, f"status={status}")


def main() -> int:
    tmp_root = Path(tempfile.mkdtemp(prefix="drivescan_smoke_"))
    db_path = tmp_root / "smoke.db"
    sample_dir = tmp_root / "samples"

    os.environ["DRIVESCAN_DB_PATH"] = str(db_path)
    os.environ.pop("DRIVESCAN_ALLOW_FILE_ACTIONS", None)

    proc: subprocess.Popen | None = None
    try:
        print(f"[1/4] Creating sample files in {sample_dir}")
        make_sample_files(sample_dir)

        print("[2/4] Running real INTEL_FAST scan into temp db...")
        scan_id = run_scan(sample_dir)
        print(f"      scan complete (scan_id={scan_id})")

        print(f"[3/4] Launching staging server on port {STAGING_PORT}...")
        proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "uvicorn",
                "dashboard.server:app",
                "--host",
                "127.0.0.1",
                "--port",
                str(STAGING_PORT),
                "--log-level",
                "warning",
            ],
            cwd=str(PROJECT_ROOT),
            env={**os.environ, "DRIVESCAN_DB_PATH": str(db_path)},
        )
        if not wait_for_health(proc):
            check(
                "staging server became healthy", False, f"no /health 200 within {HEALTH_TIMEOUT_S}s"
            )
        else:
            print("[4/4] Server healthy — running checks:\n")
            run_checks(sample_dir)
    finally:
        if proc is not None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=10)
        # sqlite handles on Windows can linger briefly after process exit
        for _ in range(5):
            shutil.rmtree(tmp_root, ignore_errors=True)
            if not tmp_root.exists():
                break
            time.sleep(0.5)

    # ── Summary ──────────────────────────────────────────────────────────
    print("\n" + "=" * 72)
    print(f"{'CHECK':<58} RESULT")
    print("-" * 72)
    for name, passed, _ in RESULTS:
        print(f"{name:<58} {'PASS' if passed else 'FAIL'}")
    print("-" * 72)
    failed = [r for r in RESULTS if not r[1]]
    print(
        f"TOTAL: {len(RESULTS)} checks, {len(RESULTS) - len(failed)} passed, {len(failed)} failed"
    )
    if failed:
        print("SMOKE RESULT: FAIL")
        return 1
    print("SMOKE RESULT: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
