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
import time
import urllib.request
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

GITHUB_REPO = "codevcn/disk-cleaner"
CACHE_TTL_SECONDS = 3600  # Check at most once per hour unless forced
REQUEST_TIMEOUT_SECONDS = 2.0


def parse_semver(ver_str: str) -> Tuple[int, ...]:
    """Extracts numeric semver tuple from string like 'v2.0.3' -> (2, 0, 3)."""
    cleaned = re.sub(r"^[^\d]*", "", ver_str.strip())
    numbers = []
    for part in cleaned.split("."):
        try:
            num = int(re.match(r"^\d+", part).group(0))  # type: ignore
            numbers.append(num)
        except Exception:
            numbers.append(0)
    while len(numbers) < 3:
        numbers.append(0)
    return tuple(numbers[:3])


def _get_cache_path() -> Path:
    """Returns path to cached update status."""
    cache_dir = Path.cwd() / ".investigation_cache"
    if not cache_dir.exists():
        try:
            cache_dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            # Fallback to user temp
            return Path(os.environ.get("TEMP", ".")) / "disk_investigator_update.json"
    return cache_dir / "update_status.json"


def check_for_updates(
    current_version: str,
    repo: str = GITHUB_REPO,
    force: bool = False,
    timeout: float = REQUEST_TIMEOUT_SECONDS,
) -> Dict[str, Any]:
    """
    Checks GitHub for the latest release/tag.
    Uses cached result if available and fresh.
    Fails safely without raising exceptions on network errors.
    """
    cache_file = _get_cache_path()
    now = time.time()

    # 1. Try reading from cache unless forced
    if not force and cache_file.exists():
        try:
            with open(cache_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                checked_at = data.get("checked_at", 0)
                if now - checked_at < CACHE_TTL_SECONDS:
                    return data
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
        # Step 1: Query GitHub Releases API
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
                            "Nhờ AI Agent chạy 'python update_from_github.py' hoặc chạy 'update.cmd' để cập nhật."
                        )
    except Exception as e:
        # Step 2: Fallback to raw __init__.py if release query fails
        try:
            raw_url = f"https://raw.githubusercontent.com/{repo}/main/disk_investigator/__init__.py"
            req = urllib.request.Request(raw_url, headers={"User-Agent": "disk-investigator"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status == 200:
                    text = resp.read().decode("utf-8")
                    match = re.search(r'__version__\s*=\s*["\']([^"\']+)["\']', text)
                    if match:
                        latest_ver = match.group(1).strip()
                        result["latest_version"] = latest_ver
                        if parse_semver(latest_ver) > parse_semver(current_version):
                            result["update_available"] = True
                            result["message"] = (
                                f"Phiên bản mới v{latest_ver} đã có trên GitHub (hiện tại: v{current_version})."
                            )
                            result["update_instruction"] = (
                                "Nhờ AI Agent chạy 'python update_from_github.py' hoặc chạy 'update.cmd' để cập nhật."
                            )
        except Exception:
            result["status"] = "offline_or_failed"
            result["message"] = "Không thể kiểm tra cập nhật (offline hoặc mạng giới hạn)."

    # Save to cache
    try:
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        with open(cache_file, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
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
            msg = (
                f"\n[🔔 UPDATE AVAILABLE] Phiên bản mới v{latest} đã có trên GitHub (hiện tại: v{current_version})!\n"
                f"    -> Nhờ AI Agent chạy: python update_from_github.py\n"
                f"    -> Hoặc chạy file: update.cmd\n"
            )
            sys.stderr.write(msg)
            sys.stderr.flush()
    except Exception:
        pass
