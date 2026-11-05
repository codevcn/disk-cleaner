"""
disk_investigator.updates.cache
Local update cache manager with 24-hour freshness TTL, 7-day max stale boundary,
kill-switch detection, and update receipt persistence.
"""

from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, Optional

from .models import CacheFreshness, UpdateCache, UpdateReceipt, parse_semver

CACHE_SCHEMA_VERSION = 1
FRESH_TTL_SECONDS = 86400        # 24 hours
MAX_STALE_SECONDS = 604800       # 7 days
KILL_SWITCH_ENV = "DISK_INVESTIGATOR_NO_UPDATE_CHECK"
ACCEPTED_KILL_SWITCH_VALUES = {"1", "true", "yes", "on"}


def is_kill_switch_active() -> bool:
    """
    Checks if automatic update checking is disabled via environment variable.
    Recognizes '1', 'true', 'yes', 'on' (case-insensitive).
    """
    val = os.environ.get(KILL_SWITCH_ENV, "").strip().lower()
    return val in ACCEPTED_KILL_SWITCH_VALUES


class UpdateCacheManager:
    """Manages update_status.json cache and last_update_result.json receipt."""

    def __init__(self, base_dir: Optional[Path] = None, repo: str = "codevcn/disk-cleaner"):
        self.repo = repo
        if base_dir:
            self.updates_dir = base_dir
        else:
            local_app_data = os.environ.get("LOCALAPPDATA")
            if local_app_data:
                self.updates_dir = Path(local_app_data) / "DiskInvestigator" / "updates"
            else:
                self.updates_dir = Path(tempfile.gettempdir()) / "DiskInvestigator" / "updates"

        self.cache_file = self.updates_dir / "update_status.json"
        self.receipt_file = self.updates_dir / "last_update_result.json"

    def read_cache(self, current_version: str) -> UpdateCache:
        """
        Reads local update status cache. Returns UpdateCache with freshness state.
        Never throws exceptions; falls back to CacheFreshness.EXPIRED on any error.
        """
        if not self.cache_file.exists():
            return UpdateCache(
                current_version=current_version,
                latest_version=current_version,
                repo=self.repo,
                freshness=CacheFreshness.EXPIRED,
            )

        try:
            with open(self.cache_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            if not isinstance(data, dict):
                return UpdateCache(current_version=current_version, freshness=CacheFreshness.EXPIRED)

            if data.get("schema_version") != CACHE_SCHEMA_VERSION:
                return UpdateCache(current_version=current_version, freshness=CacheFreshness.EXPIRED)

            if data.get("repo") != self.repo:
                return UpdateCache(current_version=current_version, freshness=CacheFreshness.EXPIRED)

            checked_at = float(data.get("checked_at", 0.0))
            now = time.time()
            if checked_at <= 0 or checked_at > now + 3600:
                return UpdateCache(current_version=current_version, freshness=CacheFreshness.EXPIRED)

            latest_ver = str(data.get("latest_version", current_version)).strip()
            release_url = str(data.get("release_url", f"https://github.com/{self.repo}/releases/latest"))
            published_at = str(data.get("published_at", ""))

            # Calculate freshness
            age = now - checked_at
            if age <= FRESH_TTL_SECONDS:
                freshness = CacheFreshness.FRESH
            elif age <= MAX_STALE_SECONDS:
                freshness = CacheFreshness.STALE
            else:
                freshness = CacheFreshness.EXPIRED

            update_avail = parse_semver(latest_ver) > parse_semver(current_version)

            return UpdateCache(
                schema_version=CACHE_SCHEMA_VERSION,
                repo=self.repo,
                current_version=current_version,
                latest_version=latest_ver,
                release_url=release_url,
                published_at=published_at,
                checked_at=checked_at,
                update_available=update_avail,
                freshness=freshness,
            )
        except Exception:
            return UpdateCache(current_version=current_version, freshness=CacheFreshness.EXPIRED)

    def write_cache(self, cache: UpdateCache) -> bool:
        """
        Atomically saves UpdateCache to update_status.json using a temporary file.
        """
        try:
            self.updates_dir.mkdir(parents=True, exist_ok=True)
            tmp_file = self.cache_file.with_suffix(f".tmp_{os.getpid()}")
            with open(tmp_file, "w", encoding="utf-8") as f:
                json.dump(cache.to_dict(), f, indent=2, ensure_ascii=False)
            os.replace(str(tmp_file), str(self.cache_file))
            return True
        except Exception:
            return False

    def clear_cache(self) -> bool:
        """Deletes cache file."""
        try:
            if self.cache_file.exists():
                self.cache_file.unlink()
            return True
        except Exception:
            return False

    def read_receipt(self) -> Optional[UpdateReceipt]:
        """Reads last_update_result.json receipt if present."""
        if not self.receipt_file.exists():
            return None
        try:
            with open(self.receipt_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            return UpdateReceipt(
                schema_version=data.get("schema_version", 1),
                status=data.get("status", "unknown"),
                from_version=data.get("from_version", ""),
                to_version=data.get("to_version", ""),
                completed_at=data.get("completed_at", ""),
                installer_exit_code=data.get("installer_exit_code", 0),
                error_message=data.get("error_message"),
                rollback_attempted=data.get("rollback_attempted", False),
            )
        except Exception:
            return None

    def write_receipt(self, receipt: UpdateReceipt) -> bool:
        """Atomically writes UpdateReceipt to last_update_result.json."""
        try:
            self.updates_dir.mkdir(parents=True, exist_ok=True)
            tmp_file = self.receipt_file.with_suffix(f".tmp_{os.getpid()}")
            with open(tmp_file, "w", encoding="utf-8") as f:
                json.dump(receipt.to_dict(), f, indent=2, ensure_ascii=False)
            os.replace(str(tmp_file), str(self.receipt_file))
            return True
        except Exception:
            return False
