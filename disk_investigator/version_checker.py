"""
version_checker.py - Automated GitHub release version checker for disk_investigator.

Enforces:
1. Fast, non-blocking check with caching (TTL: 1 hour) to avoid network latency on every CLI run.
2. Graceful fallback on network timeout or offline environments.
3. Outputs notification to sys.stderr so stdout JSON envelopes remain strictly parseable.
"""

from __future__ import annotations

import json
import os
import re
import sys
import tempfile
import time
import urllib.request
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

GITHUB_REPO = "codevcn/disk-cleaner"
CACHE_TTL_SECONDS = 3600  # Check at most once per hour unless forced
REQUEST_TIMEOUT_SECONDS = 2.0


def parse_semver(ver_str: str) -> Tuple[int, ...]:
    """Extracts numeric semver tuple from string like 'v2.0.3' -> (2, 0, 3)."""
    cleaned = re.sub(r"^[^\d]*", "", str(ver_str).strip())
    numbers = []
    for part in cleaned.split("."):
        try:
            match = re.match(r"^\d+", part)
            if match:
                numbers.append(int(match.group(0)))
            else:
                numbers.append(0)
        except Exception:
            numbers.append(0)
    while len(numbers) < 3:
        numbers.append(0)
    return tuple(numbers[:3])


def _get_cache_path() -> Path:
    """
    Returns path to cached update status in %LOCALAPPDATA%\\DiskInvestigator\\updates.
    Never creates cache files in the current working directory to preserve read-only scans.
    """
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        base_dir = Path(local_app_data) / "DiskInvestigator" / "updates"
    else:
        base_dir = Path(tempfile.gettempdir()) / "DiskInvestigator" / "updates"
    return base_dir / "update_status.json"


def _is_valid_cache(data: Any, expected_repo: str) -> bool:
    """Validates structure, provenance, and timestamp sanity of cache payload."""
    if not isinstance(data, dict):
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
    Uses cached result if available, valid, and fresh.
    Fails safely without raising exceptions on network errors.
    """
    cache_file = _get_cache_path()
    now = time.time()

    # 1. Try reading from cache unless forced
    if not force and cache_file.exists():
        try:
            with open(cache_file, "r", encoding="utf-8") as f:
                cached_data = json.load(f)
                if _is_valid_cache(cached_data, repo):
                    checked_at = cached_data["checked_at"]
                    if now - checked_at < CACHE_TTL_SECONDS:
                        return cached_data
        except Exception:
            pass

    result: Dict[str, Any] = {
        "status": "checked",
        "update_available": False,
        "current_version": current_version,
        "latest_version": current_version,
        "repo": repo,
        "checked_at": now,
        "release_url": f"https://github.com/{repo}/releases/latest",
        "message": "You are on the latest version.",
    }

    try:
        # Step 1: Query GitHub Releases API (Immutable release provenance)
        api_url = f"https://api.github.com/repos/{repo}/releases/latest"
        req = urllib.request.Request(
            api_url,
            headers={
                "User-Agent": "disk-investigator-version-checker",
                "Accept": "application/vnd.github.v3+json",
            },
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                payload = json.loads(resp.read().decode("utf-8"))
                tag_name = payload.get("tag_name", "").strip()
                latest_ver = tag_name.lstrip("v")
                html_url = payload.get("html_url", result["release_url"])

                if latest_ver:
                    result["latest_version"] = latest_ver
                    result["release_url"] = html_url
                    result["release_name"] = payload.get("name", tag_name)
                    result["published_at"] = payload.get("published_at", "")

                    if parse_semver(latest_ver) > parse_semver(current_version):
                        result["update_available"] = True
                        result["message"] = (
                            f"Phiên bản mới v{latest_ver} đã có trên GitHub (hiện tại: v{current_version})."
                        )
                        result["update_instruction"] = (
                            f"Tải bản cài đặt mới tại: {html_url} hoặc chạy 'update.cmd' để cập nhật."
                        )
    except Exception:
        # Fail closed safely on network issues without unpinned raw fallback
        result["status"] = "offline_or_failed"
        result["message"] = "Không thể kiểm tra cập nhật (offline hoặc mạng giới hạn)."

    # Step 2: Atomic write to cache
    try:
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        tmp_file = cache_file.with_suffix(".tmp")
        with open(tmp_file, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        os.replace(str(tmp_file), str(cache_file))
    except Exception:
        pass

    return result


def notify_if_update_available(current_version: str, repo: str = GITHUB_REPO) -> None:
    """
    Checks for updates and outputs an unobtrusive notification to stderr if found.
    Never prints to stdout to prevent JSON corruption.
    """
    try:
        info = check_for_updates(current_version=current_version, repo=repo, force=False)
        if info.get("update_available"):
            latest = info.get("latest_version")
            rel_url = info.get("release_url", f"https://github.com/{repo}/releases/latest")
            msg = (
                f"\n[🔔 UPDATE AVAILABLE] Phiên bản mới v{latest} đã có trên GitHub (hiện tại: v{current_version})!\n"
                f"    -> Tải bản cài đặt mới nhất: {rel_url}\n"
                f"    -> Hoặc chạy file: update.cmd (hoặc 'python update_from_github.py')\n"
            )
            sys.stderr.write(msg)
            sys.stderr.flush()
    except Exception:
        pass
