"""
version_checker.py - Thin compatibility facade for disk_investigator.updates subsystem.
Preserves backwards compatibility for existing imports and tests.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from .updates.cache import UpdateCacheManager, is_kill_switch_active
from .updates.models import parse_semver
from .updates.update_engine import UpdateEngine

GITHUB_REPO = "codevcn/disk-cleaner"
CACHE_TTL_SECONDS = 86400  # 24 hours
REQUEST_TIMEOUT_SECONDS = 5.0
CACHE_SCHEMA_VERSION = 1


def _get_cache_path() -> Path:
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        base_dir = Path(local_app_data) / "DiskInvestigator" / "updates"
    else:
        base_dir = Path(tempfile.gettempdir()) / "DiskInvestigator" / "updates"
    return base_dir / "update_status.json"


def _is_valid_cache(data: Any, expected_repo: str) -> bool:
    import time
    if not isinstance(data, dict):
        return False
    if data.get("schema_version") != CACHE_SCHEMA_VERSION:
        return False
    if data.get("repo") != expected_repo:
        return False
    checked_at = data.get("checked_at")
    if not isinstance(checked_at, (int, float)):
        return False
    now = time.time()
    if checked_at <= 0 or checked_at > now + 3600:
        return False
    latest_ver = data.get("latest_version")
    if not isinstance(latest_ver, str) or not latest_ver.strip():
        return False
    return True


def check_for_updates(
    current_version: str,
    repo: str = GITHUB_REPO,
    force: bool = False,
    timeout: float = REQUEST_TIMEOUT_SECONDS,
) -> Dict[str, Any]:
    """
    Checks GitHub for the latest release/tag via official Releases API.
    If force=True, queries network and updates cache.
    If force=False, returns cached status (never blocks main thread on network).
    """
    cache_file = _get_cache_path()
    mgr = UpdateCacheManager(base_dir=cache_file.parent, repo=repo)
    mgr.cache_file = cache_file
    engine = UpdateEngine(mgr)
    return engine.check_update_status(current_version=current_version, force_network=force)


def notify_if_update_available(current_version: str, repo: str = GITHUB_REPO) -> None:
    """
    Checks for updates and outputs an unobtrusive notification to stderr if found.
    Never prints to stdout to prevent JSON corruption.
    Foreground execution is 100% network-free.
    """
    engine = UpdateEngine(UpdateCacheManager(repo=repo))
    engine.notify_if_update_available(current_version=current_version)
