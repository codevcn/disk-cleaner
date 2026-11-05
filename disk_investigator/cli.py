"""
Command-line interface for disk_investigator.
Outputs clean, structured JSON by default for consumption by AI Agents like Google Antigravity.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional

from . import __version__
from .capabilities import get_doctor_report
from .cleanup import PlanGenerator, SafeExecutor
from .detectors import DeveloperDetector, DockerDetector, LargeFilesDetector
from .models import BackendKind
from .services import DrilldownService, ScanService
from .updates import BackgroundRefreshManager, UpdateCacheManager, UpdateEngine, UpdateState
from .version_checker import check_for_updates, notify_if_update_available

# Ensure UTF-8 output on Windows consoles
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass


def _json_output(data: Any, pretty: bool = True) -> None:
    """Outputs data as JSON to stdout."""
    indent = 2 if pretty else None
    json.dump(data, sys.stdout, indent=indent, ensure_ascii=False)
    sys.stdout.write("\n")
    sys.stdout.flush()


def _error_exit(msg: str, code: int = 1) -> None:
    """Outputs error envelope in JSON and terminates."""
    _json_output({"status": "error", "error": msg}, pretty=True)
    sys.exit(code)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="disk-investigator",
        description="AI-native disk investigation harness for Windows 11",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument(
        "--compact",
        action="store_true",
        help="Output compact JSON without indentation",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Command: doctor
    subparsers.add_parser(
        "doctor",
        help="Inspect host environment, runtimes, and tool capabilities",
    )

    # Command: discover-capabilities
    caps_parser = subparsers.add_parser(
        "discover-capabilities",
        aliases=["capabilities"],
        help="Discover installed applications and system ecosystem capabilities",
    )

    # Command: investigate
    inv_parser = subparsers.add_parser(
        "investigate",
        help="Comprehensive multi-domain storage investigation across system, browser, office, creator, gaming, dev, and AI/ML",
    )
    inv_parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Target directory to investigate (default: current directory)",
    )

    # Command: overview
    overview_parser = subparsers.add_parser(
        "overview",
        help="High-level disk usage overview for drives and top root consumers",
    )
    overview_parser.add_argument(
        "drive",
        nargs="?",
        default=None,
        help="Specific drive letter (e.g. C: or D:) or omit to inspect all drives",
    )
    overview_parser.add_argument(
        "--backend",
        choices=["dust", "native"],
        default=None,
        help="Force specific scanning backend",
    )
    overview_parser.add_argument(
        "--deep",
        action="store_true",
        help="Perform deep recursive scan of root directories (slower)",
    )

    # Command: scan
    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan a filesystem path with specified depth",
    )
    scan_parser.add_argument("path", help="Directory or drive path to scan")
    scan_parser.add_argument(
        "--depth",
        "-d",
        type=int,
        default=1,
        help="Depth of recursive scanning (default: 1)",
    )
    scan_parser.add_argument(
        "--max-entries",
        "-n",
        type=int,
        default=30,
        help="Max top entries to return (default: 30)",
    )
    scan_parser.add_argument(
        "--only-dir",
        "-D",
        action="store_true",
        help="Display directories only",
    )
    scan_parser.add_argument(
        "--min-size",
        type=int,
        default=None,
        help="Minimum size in bytes to include",
    )
    scan_parser.add_argument(
        "--backend",
        choices=["dust", "native"],
        default=None,
        help="Force specific scanning backend",
    )
    scan_parser.add_argument(
        "--parent-snapshot",
        type=str,
        default=None,
        help="Link this scan to a parent snapshot ID",
    )

    # Command: drilldown
    drill_parser = subparsers.add_parser(
        "drilldown",
        help="Targeted forensic drill-down into a specific directory",
    )
    drill_parser.add_argument("path", help="Directory path to drill down into")
    drill_parser.add_argument(
        "--depth",
        "-d",
        type=int,
        default=2,
        help="Exploration depth (default: 2)",
    )
    drill_parser.add_argument(
        "--parent-snapshot",
        type=str,
        default=None,
        help="Link this drilldown to an existing parent snapshot ID",
    )
    drill_parser.add_argument(
        "--backend",
        choices=["dust", "native"],
        default=None,
        help="Force specific scanning backend",
    )
    drill_parser.add_argument(
        "--only-dir",
        "-D",
        action="store_true",
        help="Drill into directories only",
    )

    # Command: detect-dev
    dev_parser = subparsers.add_parser(
        "detect-dev",
        help="Detect developer artifacts (node_modules, venvs, package caches, build artifacts)",
    )
    dev_parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Target project or parent directory to scan (default: current directory)",
    )
    dev_parser.add_argument(
        "--include-global",
        action="store_true",
        help="Also inspect global user caches (npm-cache, pip cache, gradle, cargo)",
    )
    dev_parser.add_argument(
        "--max-depth",
        type=int,
        default=4,
        help="Maximum traversal depth (default: 4)",
    )

    # Command: detect-docker
    subparsers.add_parser(
        "detect-docker",
        help="Inspect Docker storage on Windows (WSL2 VHDX backing storage & daemon breakdown)",
    )

    # Command: detect-large
    large_parser = subparsers.add_parser(
        "detect-large",
        help="Locate large files exceeding a size threshold",
    )
    large_parser.add_argument("path", help="Directory to search")
    large_parser.add_argument(
        "--min-size-mb",
        type=int,
        default=100,
        help="Minimum file size in megabytes (default: 100)",
    )
    large_parser.add_argument(
        "--max-results",
        type=int,
        default=30,
        help="Maximum results to return (default: 30)",
    )

    # Command: cleanup-plan
    plan_parser = subparsers.add_parser(
        "cleanup-plan",
        help="Generate a structured CleanupPlan for developer or cache candidates without deleting",
    )
    plan_parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Target directory to discover cleanup candidates",
    )
    plan_parser.add_argument(
        "--include-global",
        action="store_true",
        help="Include global developer caches in the plan",
    )

    # Command: execute-plan
    exec_parser = subparsers.add_parser(
        "execute-plan",
        help="Execute specific approved items from a cleanup plan (dry-run by default)",
    )
    exec_parser.add_argument("plan_id", help="Plan ID to execute (e.g. plan_abc12345)")
    exec_parser.add_argument(
        "--items",
        required=True,
        help="Comma-separated item IDs to execute (e.g. '1,2,5')",
    )
    exec_parser.add_argument(
        "--apply",
        action="store_true",
        help="Explicitly apply the execution (without --apply, runs in DRY-RUN mode)",
    )

    # Command: check-update
    check_update_parser = subparsers.add_parser(
        "check-update",
        help="Check GitHub for newer versions of disk_investigator",
    )
    check_update_parser.add_argument(
        "--force",
        action="store_true",
        help="Bypass cache and query GitHub immediately",
    )

    # Command: update
    update_parser = subparsers.add_parser(
        "update",
        help="Download and install the latest official release of disk_investigator",
    )
    update_parser.add_argument(
        "--yes", "-y",
        action="store_true",
        help="Skip interactive confirmation prompt (unattended upgrade)",
    )
    update_parser.add_argument(
        "--status",
        action="store_true",
        help="Inspect the receipt of the last completed or attempted update",
    )

    # Hidden Command: _refresh-update-cache
    subparsers.add_parser(
        "_refresh-update-cache",
        help=argparse.SUPPRESS,
    )

    return parser


def main(args: Optional[List[str]] = None) -> int:
    parser = build_parser()
    parsed = parser.parse_args(args)

    if not parsed.command:
        parser.print_help(sys.stderr)
        return 1

    pretty = not parsed.compact

    # Hidden worker path: must run detached worker without emitting advisories
    if parsed.command == "_refresh-update-cache":
        mgr = BackgroundRefreshManager()
        mgr.run_worker(__version__)
        return 0

    # Background / unobtrusive update notification to stderr (100% network-free on foreground)
    notify_if_update_available(__version__)

    try:
        if parsed.command == "doctor":
            report = get_doctor_report()
            report["update_check"] = check_for_updates(__version__)
            _json_output({"status": "success", "doctor": report}, pretty=pretty)
            return 0

        if parsed.command in ("discover-capabilities", "capabilities"):
            from .discovery.capability_discovery import CapabilityDiscovery
            discovery = CapabilityDiscovery()
            caps = discovery.discover_all()
            _json_output({
                "status": "success",
                "capabilities": {k: v.to_dict() for k, v in caps.items() if v.detected},
            }, pretty=pretty)
            return 0

        if parsed.command == "investigate":
            from .path_policy import canonicalize_path
            from .services.investigation_service import InvestigationService
            svc = InvestigationService()
            target_p = canonicalize_path(parsed.path)
            res = svc.investigate(target_path=target_p)
            _json_output({"status": "success", "investigation": res.to_dict()}, pretty=pretty)
            return 0

        if parsed.command == "check-update":
            info = check_for_updates(__version__, force=parsed.force)
            _json_output({"status": "success", "update_info": info}, pretty=pretty)
            return 0

        if parsed.command == "update":
            cache_mgr = UpdateCacheManager()
            if parsed.status:
                receipt = cache_mgr.read_receipt()
                if not receipt:
                    _json_output({
                        "status": "success",
                        "last_update": None,
                        "message": "No previous update receipt found.",
                    }, pretty=pretty)
                    return 0
                _json_output({
                    "status": "success",
                    "last_update": receipt.to_dict(),
                }, pretty=pretty)
                return 0

            engine = UpdateEngine(cache_mgr)
            current_ver = os.environ.get("DISK_INVESTIGATOR_CURRENT_VERSION_OVERRIDE", __version__)
            update_res = engine.execute_update(current_version=current_ver, yes=parsed.yes)
            is_ok = update_res.state in (UpdateState.UP_TO_DATE, UpdateState.HANDOFF_STARTED)
            _json_output({
                "status": "success" if is_ok else "failed",
                "update": update_res.to_dict(),
            }, pretty=pretty)

            if update_res.state in (UpdateState.HANDOFF_STARTED, UpdateState.UP_TO_DATE):
                return 0
            elif update_res.state == UpdateState.CANCELLED:
                return 2
            else:
                return 1

        # Initialize services
        scan_service = ScanService()
        preferred_backend = BackendKind(parsed.backend) if getattr(parsed, "backend", None) else None

        if parsed.command == "overview":
            overviews = scan_service.drive_overview(
                drive_letter_or_path=parsed.drive,
                preferred_backend=preferred_backend,
                deep=getattr(parsed, "deep", False),
            )
            data = [o.to_dict() for o in overviews]
            _json_output({"status": "success", "drives": data}, pretty=pretty)
            return 0

        elif parsed.command == "scan":
            snapshot = scan_service.scan_path(
                path=parsed.path,
                depth=parsed.depth,
                max_entries=parsed.max_entries,
                only_dir=parsed.only_dir,
                min_size_bytes=parsed.min_size,
                preferred_backend=preferred_backend,
                parent_snapshot_id=parsed.parent_snapshot,
            )
            _json_output({"status": "success", "snapshot": snapshot.to_dict()}, pretty=pretty)
            return 0

        elif parsed.command == "drilldown":
            drill_service = DrilldownService(scan_service)
            result = drill_service.drilldown(
                target_path=parsed.path,
                depth=parsed.depth,
                parent_snapshot_id=parsed.parent_snapshot,
                only_dir=parsed.only_dir,
                preferred_backend=preferred_backend,
            )
            _json_output({"status": "success", "drilldown": result}, pretty=pretty)
            return 0

        elif parsed.command == "detect-dev":
            detector = DeveloperDetector()
            artifacts = detector.scan_project_tree(parsed.path, max_depth=parsed.max_depth)
            if parsed.include_global:
                global_artifacts = detector.detect_known_global_caches()
                artifacts.extend(global_artifacts)

            total_bytes = sum(a.logical_bytes for a in artifacts)
            _json_output({
                "status": "success",
                "target_path": parsed.path,
                "artifacts_count": len(artifacts),
                "total_bytes": total_bytes,
                "artifacts": [a.to_dict() for a in artifacts],
            }, pretty=pretty)
            return 0

        elif parsed.command == "detect-docker":
            detector = DockerDetector()
            report = detector.inspect()
            _json_output({"status": "success", "docker": report}, pretty=pretty)
            return 0

        elif parsed.command == "detect-large":
            detector = LargeFilesDetector()
            min_bytes = parsed.min_size_mb * 1024 * 1024
            items = detector.find_large_files(
                root_path=parsed.path,
                min_size_bytes=min_bytes,
                max_results=parsed.max_results,
            )
            total_bytes = sum(i.size_bytes for i in items)
            _json_output({
                "status": "success",
                "root_path": parsed.path,
                "min_size_mb": parsed.min_size_mb,
                "files_count": len(items),
                "total_bytes": total_bytes,
                "large_files": [i.to_dict() for i in items],
            }, pretty=pretty)
            return 0

        elif parsed.command == "cleanup-plan":
            from .path_policy import canonicalize_path
            from .services.investigation_service import InvestigationService
            target_p = canonicalize_path(parsed.path)
            svc = InvestigationService()
            inv_res = svc.investigate(target_path=target_p)

            candidates: List[Any] = list(inv_res.artifacts)

            # Also include legacy global dev caches if requested
            if getattr(parsed, "include_global", False):
                dev_det = DeveloperDetector()
                candidates.extend(dev_det.detect_known_global_caches())

            planner = PlanGenerator()
            plan = planner.generate_plan(target_root=target_p, candidates=candidates)
            _json_output({"status": "success", "plan": plan.to_dict()}, pretty=pretty)
            return 0

        elif parsed.command == "execute-plan":
            planner = PlanGenerator()
            plan = planner.load_plan(parsed.plan_id)
            if not plan:
                _error_exit(f"Plan ID '{parsed.plan_id}' not found in cache")

            try:
                item_ids = [int(i.strip()) for i in parsed.items.split(",") if i.strip()]
            except ValueError:
                _error_exit(f"Invalid items list: '{parsed.items}'. Must be comma-separated integers like '1,2,3'")

            executor = SafeExecutor()
            dry_run = not parsed.apply
            result = executor.execute(plan=plan, item_ids=item_ids, dry_run=dry_run)
            _json_output({"status": "success", "execution": result.to_dict()}, pretty=pretty)
            return 0

    except Exception as e:
        _error_exit(str(e))

    return 0


if __name__ == "__main__":
    sys.exit(main())
