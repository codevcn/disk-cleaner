"""
disk_investigator.updates.background_refresh
Single-flight lock management and detached background refresh process runner.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

from .cache import UpdateCacheManager, is_kill_switch_active
from .models import CacheFreshness, UpdateCache, parse_semver
from .release_client import GitHubReleaseClient

LOCK_TIMEOUT_SECONDS = 300.0  # 5 minutes stale lock recovery


class BackgroundRefreshManager:
    """Manages single-flight lock and schedules detached background refresh worker."""

    def __init__(self, cache_manager: Optional[UpdateCacheManager] = None):
        self.cache_mgr = cache_manager or UpdateCacheManager()
        self.lock_file = self.cache_mgr.updates_dir / "refresh.lock"

    def acquire_lock(self) -> bool:
        """
        Attempts to acquire atomic refresh lock. Recovers stale locks (>5 mins).
        Returns True if lock acquired, False if already locked.
        """
        try:
            self.cache_mgr.updates_dir.mkdir(parents=True, exist_ok=True)
            now = time.time()

            if self.lock_file.exists():
                try:
                    mtime = self.lock_file.stat().st_mtime
                    if now - mtime < LOCK_TIMEOUT_SECONDS:
                        return False  # Still valid and actively running
                    # Stale lock: remove it
                    self.lock_file.unlink(missing_ok=True)
                except Exception:
                    pass

            # Atomic creation: exclusive open
            # Using O_CREAT | O_EXCL ensures mutual exclusion
            flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
            fd = os.open(str(self.lock_file), flags)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    f.write(f"pid={os.getpid()}\ntime={now}\n")
                return True
            except Exception:
                return False
        except FileExistsError:
            return False
        except Exception:
            return False

    def release_lock(self) -> None:
        """Releases refresh lock."""
        try:
            if self.lock_file.exists():
                self.lock_file.unlink(missing_ok=True)
        except Exception:
            pass

    def schedule_refresh(self) -> bool:
        """
        Spawns a detached background child process to refresh the update cache.
        Does not block foreground execution.
        """
        if is_kill_switch_active():
            return False

        # If lock is already held and fresh, avoid spawning unnecessary process
        if self.lock_file.exists():
            try:
                if time.time() - self.lock_file.stat().st_mtime < LOCK_TIMEOUT_SECONDS:
                    return False
            except Exception:
                pass

        # Construct detached process command
        # Works whether running as raw Python (python -m disk_investigator) or packaged EXE
        cmd = [sys.executable]
        if not getattr(sys, "frozen", False):
            # When running as raw python script/module
            cmd.extend(["-m", "disk_investigator"])
        cmd.append("_refresh-update-cache")

        creationflags = 0
        if sys.platform == "win32":
            # DETACHED_PROCESS (0x00000008) + CREATE_NO_WINDOW (0x08000000)
            creationflags = 0x00000008 | 0x08000000

        try:
            subprocess.Popen(
                cmd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                creationflags=creationflags,
            )
            return True
        except Exception:
            return False

    def run_worker(self, current_version: str) -> bool:
        """
        Executed inside the detached worker process.
        Acquires lock, fetches GitHub release, saves cache, and releases lock.
        Completely silent; never prints to stdout/stderr.
        """
        if is_kill_switch_active():
            return False

        if not self.acquire_lock():
            return False

        try:
            client = GitHubReleaseClient(repo=self.cache_mgr.repo)
            rel = client.get_latest_release(timeout=10.0)

            latest_ver = rel.version
            now = time.time()
            update_avail = parse_semver(latest_ver) > parse_semver(current_version)

            new_cache = UpdateCache(
                schema_version=1,
                repo=self.cache_mgr.repo,
                current_version=current_version,
                latest_version=latest_ver,
                release_url=rel.release_url,
                published_at=rel.published_at,
                checked_at=now,
                update_available=update_avail,
                freshness=CacheFreshness.FRESH,
            )
            self.cache_mgr.write_cache(new_cache)
            return True
        except Exception:
            return False
        finally:
            self.release_lock()
