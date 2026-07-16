"""Intelligent Drive Scanner v2.0 — CLI Interface.

Command-line interface for running intelligence scans, viewing results,
executing recommendations, and managing the dashboard.

Usage:
    python cli.py --profile INTELLIGENCE --drives O: I: F:
    python cli.py --intelligence --path "O:\\TAX_KNOWLEDGE" --dashboard
    python cli.py --recommendations --scan-id 1
    python cli.py --dashboard --port 8460
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from typing import Any

from loguru import logger

from config import DASHBOARD_PORT, DB_PATH, LOG_DIR, SCAN_PROFILES, ScanConfig
from scanner import IntelligenceScanOrchestrator
from storage.db import IntelligenceDB


def setup_logging(verbose: bool = False) -> None:
    """Configure loguru logging."""
    logger.remove()
    level = "DEBUG" if verbose else "INFO"
    logger.add(
        sys.stderr,
        level=level,
        format=(
            "<green>{time:HH:mm:ss}</green> | "
            "<level>{level: <8}</level> | "
            "<cyan>{name}</cyan>:<cyan>{function}</cyan> | "
            "<level>{message}</level>"
        ),
    )
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    logger.add(
        LOG_DIR / "scanner_{time}.log",
        rotation="50 MB",
        retention="7 days",
        level="DEBUG",
    )


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="Intelligent Drive Scanner",
        description="AI-powered file intelligence scanner with 2,632 domain engines.",
    )

    # Scan mode
    scan_group = parser.add_argument_group("Scan Options")
    scan_group.add_argument(
        "--drives",
        nargs="+",
        metavar="DRIVE",
        help="Drives to scan (e.g., O: I: F:)",
    )
    scan_group.add_argument(
        "--path",
        type=str,
        help="Specific folder path to scan",
    )
    scan_group.add_argument(
        "--profile",
        type=str,
        default="INTELLIGENCE",
        choices=list(SCAN_PROFILES.keys()),
        help="Scan profile (default: INTELLIGENCE)",
    )
    scan_group.add_argument(
        "--intelligence",
        action="store_true",
        help="Enable intelligence classification (shorthand for --profile INTELLIGENCE)",
    )
    scan_group.add_argument(
        "--domains",
        type=str,
        help="Comma-separated list of domains to focus on (e.g., CYBER,FIN,LG)",
    )
    scan_group.add_argument(
        "--max-files",
        type=int,
        default=0,
        help="Maximum number of files to scan (0=unlimited)",
    )
    scan_group.add_argument(
        "--max-depth",
        type=int,
        default=0,
        help="Maximum directory depth (0=unlimited)",
    )

    # Results & Recommendations
    results_group = parser.add_argument_group("Results")
    results_group.add_argument(
        "--recommendations",
        action="store_true",
        help="Show recommendations from last scan",
    )
    results_group.add_argument(
        "--execute-recommendation",
        type=str,
        metavar="CATEGORY",
        help="Execute recommendations of given category (archive, delete, etc.)",
    )
    results_group.add_argument(
        "--scan-id",
        type=int,
        help="Specify scan ID for results/recommendations",
    )
    results_group.add_argument(
        "--summary",
        action="store_true",
        help="Show scan summary",
    )
    results_group.add_argument(
        "--list-scans",
        action="store_true",
        help="List all scans",
    )
    results_group.add_argument(
        "--export-report",
        action="store_true",
        help="Export full intelligence report as JSON",
    )

    # Deep Analysis
    deep_group = parser.add_argument_group("Deep Analysis")
    deep_group.add_argument(
        "--deep-analyze",
        nargs="+",
        metavar="FILE",
        help="Deep-analyze specific files",
    )

    # Dashboard
    dash_group = parser.add_argument_group("Dashboard")
    dash_group.add_argument(
        "--dashboard",
        action="store_true",
        help="Start the analytics dashboard after scan (or standalone)",
    )
    dash_group.add_argument(
        "--port",
        type=int,
        default=DASHBOARD_PORT,
        help=f"Dashboard port (default: {DASHBOARD_PORT})",
    )

    # Cloud
    cloud_group = parser.add_argument_group("Cloud")
    cloud_group.add_argument(
        "--upload-cloud",
        action="store_true",
        help="Upload scan results to cloud worker",
    )

    # General
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose logging")

    return parser


async def cmd_scan(args: argparse.Namespace) -> int:
    """Execute an intelligence scan."""
    paths: list[str] = []
    if args.path:
        paths = [args.path]
    elif args.drives:
        paths = [d if d.endswith("\\") else d + "\\" for d in args.drives]
    else:
        logger.error("Specify --drives or --path to scan")
        return 1

    profile = "INTELLIGENCE" if args.intelligence else args.profile
    raw_profile_config = SCAN_PROFILES.get(profile, {})
    profile_config: dict[str, Any] = (
        raw_profile_config if isinstance(raw_profile_config, dict) else {}
    )

    config = ScanConfig(
        max_depth=args.max_depth or profile_config.get("max_depth"),
        max_file_size=profile_config.get("max_file_size"),
        include_extensions=set(profile_config.get("include_extensions", [])) or None,
        exclude_extensions=set(profile_config.get("exclude_extensions", [])) or None,
    )

    orchestrator = IntelligenceScanOrchestrator(config)
    scan_id = await orchestrator.run_scan(paths, profile)

    # Print summary
    summary = orchestrator.get_scan_summary(scan_id)
    if summary:
        print(f"\n{'=' * 60}")
        print(f"SCAN COMPLETE — ID: {scan_id}")
        print(f"{'=' * 60}")
        print(f"  Files:        {summary.get('total_files', 0):,}")
        print(f"  Size:         {summary.get('total_size_bytes', 0) / (1024**3):.2f} GB")
        print(f"  Classified:   {summary.get('files_classified', 0):,}")
        print(f"  Duration:     {summary.get('duration_seconds', 0):.1f}s")
        print(f"  Duplicates:   {summary.get('duplicate_clusters', 0)} clusters")
        print(f"  Recs:         {summary.get('recommendation_count', 0)}")
        print(f"  High Risk:    {summary.get('high_risk_count', 0)}")
        print(f"  Sensitive:    {summary.get('sensitive_count', 0)}")
        print(f"{'=' * 60}")

    # Upload to cloud if requested
    if args.upload_cloud:
        await orchestrator.upload_to_cloud(scan_id)

    return 0


def cmd_recommendations(args: argparse.Namespace) -> int:
    """Show or execute recommendations."""
    db = IntelligenceDB(DB_PATH)

    scan_id = args.scan_id
    if not scan_id:
        scans = db.list_scans(limit=1)
        if not scans:
            logger.error("No scans found. Run a scan first.")
            return 1
        scan_id = scans[0].id or 0

    recs = db.get_recommendations(scan_id)
    if not recs:
        print(f"No recommendations for scan {scan_id}")
        return 0

    severity_colors = {
        "critical": "\033[91m",
        "high": "\033[93m",
        "medium": "\033[96m",
        "low": "\033[92m",
        "info": "\033[90m",
    }
    reset = "\033[0m"

    print(f"\nRecommendations for Scan #{scan_id}:")
    print(f"{'=' * 70}")

    for i, rec in enumerate(recs, 1):
        color = severity_colors.get(rec.severity, "")
        print(f"\n{color}[{rec.severity.upper()}]{reset} #{i}: {rec.title}")
        print(f"  Category:  {rec.category}")
        print(f"  Files:     {rec.affected_count}")
        print(f"  Impact:    {rec.estimated_impact}")
        if rec.auto_executable:
            print("  Auto-exec: YES")
        else:
            print("  Review:    Required")
        print(f"  Command:   {rec.action_command}")

    return 0


def cmd_summary(args: argparse.Namespace) -> int:
    """Show scan summary."""
    db = IntelligenceDB(DB_PATH)

    scan_id = args.scan_id
    if not scan_id:
        scans = db.list_scans(limit=1)
        if not scans:
            logger.error("No scans found")
            return 1
        scan_id = scans[0].id or 0

    summary = db.get_scan_summary(scan_id)
    if not summary:
        print(f"Scan {scan_id} not found")
        return 1

    print(f"\nScan #{summary.scan_id} Summary")
    print(f"{'=' * 50}")
    print(f"  Status:       {summary.status}")
    print(f"  Files:        {summary.total_files:,}")
    print(f"  Size:         {summary.total_size_bytes / (1024**3):.2f} GB")
    print(f"  Classified:   {summary.files_classified:,}")
    print(f"  Duration:     {summary.duration_seconds:.1f}s")
    print(f"  Avg Quality:  {summary.avg_quality:.1f}")
    print(f"  Avg Import:   {summary.avg_importance:.1f}")
    print(f"  High Risk:    {summary.high_risk_count}")
    print(f"  Sensitive:    {summary.sensitive_count}")
    print(f"  Dup Clusters: {summary.duplicate_clusters}")
    print(f"  Wasted:       {summary.wasted_bytes / (1024**3):.2f} GB")
    print(f"  Recs:         {summary.recommendation_count}")

    if summary.domain_distribution:
        print("\n  Domain Distribution:")
        sorted_domains = sorted(
            summary.domain_distribution.items(),
            key=lambda x: x[1],
            reverse=True,
        )
        for domain, count in sorted_domains[:15]:
            bar = "█" * min(40, int(count / max(1, summary.total_files) * 200))
            pct = count / max(1, summary.total_files) * 100
            print(f"    {domain:<12} {count:>6,} ({pct:5.1f}%) {bar}")

    return 0


def cmd_list_scans(args: argparse.Namespace) -> int:
    """List all scans."""
    db = IntelligenceDB(DB_PATH)
    scans = db.list_scans(limit=50)
    if not scans:
        print("No scans found.")
        return 0

    print(
        f"\n{'ID':>4}  {'Status':<10}  {'Files':>8}  {'Classified':>10}  {'Duration':>8}  {'Started'}"
    )
    print("-" * 75)
    for scan in scans:
        duration_str = f"{scan.duration_seconds:.0f}s" if scan.duration_seconds else "-"
        started = scan.started_at[:19] if scan.started_at else "-"
        print(
            f"{scan.id or 0:>4}  {scan.status:<10}  {scan.total_files:>8,}  "
            f"{scan.files_classified:>10,}  {duration_str:>8}  {started}"
        )

    return 0


async def cmd_dashboard(args: argparse.Namespace) -> int:
    """Start the analytics dashboard."""
    try:
        import uvicorn

        from dashboard.server import create_app

        app = create_app(DB_PATH)
        port = args.port or DASHBOARD_PORT
        logger.info("Starting dashboard on port {}", port)
        config = uvicorn.Config(app, host="0.0.0.0", port=port, log_level="info")
        server = uvicorn.Server(config)
        await server.serve()
    except ImportError as e:
        logger.error("Dashboard dependencies missing: {}", e)
        return 1
    return 0


def main() -> int:
    """Main entry point."""
    parser = build_parser()
    args = parser.parse_args()
    setup_logging(args.verbose)

    # Route to subcommand
    if args.list_scans:
        return cmd_list_scans(args)

    if args.summary:
        return cmd_summary(args)

    if args.recommendations or args.execute_recommendation:
        return cmd_recommendations(args)

    if args.dashboard and not (args.drives or args.path):
        return asyncio.run(cmd_dashboard(args))

    if args.drives or args.path:
        exit_code = asyncio.run(cmd_scan(args))
        if args.dashboard and exit_code == 0:
            asyncio.run(cmd_dashboard(args))
        return exit_code

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
