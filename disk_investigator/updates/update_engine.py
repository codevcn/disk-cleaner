"""
disk_investigator.updates.update_engine
Core orchestration engine for in-app self-update, staged lifecycle handoff,
non-blocking update notifications, and fail-closed security verification.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple

from .background_refresh import BackgroundRefreshManager
from .cache import UpdateCacheManager, is_kill_switch_active
from .checksum import parse_sha256sums_manifest, verify_sha256_checksum
from .models import CacheFreshness, ReleaseInfo, UpdateCache, UpdateResult, UpdateState, parse_semver
from .release_client import GitHubReleaseClient

UPDATE_LOCK_TIMEOUT_SECONDS = 600.0  # 10 minutes stale update lock recovery
SETUP_EXE_NAME = "disk-investigator-setup.exe"
MANIFEST_NAME = "SHA256SUMS.txt"


class UpdateEngine:
    """Orchestrates in-app updates and non-blocking advisories."""

    def __init__(self, cache_manager: Optional[UpdateCacheManager] = None):
        self.cache_mgr = cache_manager or UpdateCacheManager()
        self.refresh_mgr = BackgroundRefreshManager(self.cache_mgr)
        self.update_lock_file = self.cache_mgr.updates_dir / "update.lock"

    def acquire_update_lock(self) -> bool:
        """Acquires atomic lock for staging updates."""
        try:
            self.cache_mgr.updates_dir.mkdir(parents=True, exist_ok=True)
            now = time.time()
            if self.update_lock_file.exists():
                try:
                    if now - self.update_lock_file.stat().st_mtime < UPDATE_LOCK_TIMEOUT_SECONDS:
                        return False
                    self.update_lock_file.unlink(missing_ok=True)
                except Exception:
                    pass

            flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
            fd = os.open(str(self.update_lock_file), flags)
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

    def release_update_lock(self) -> None:
        """Releases staging update lock."""
        try:
            if self.update_lock_file.exists():
                self.update_lock_file.unlink(missing_ok=True)
        except Exception:
            pass

    def check_update_status(self, current_version: str, force_network: bool = False) -> Dict[str, Any]:
        """
        Queries update status.
        If force_network is True: makes immediate synchronous query and updates cache.
        If force_network is False: reads cache (foreground never touches network) and schedules refresh if needed.
        """
        if force_network:
            try:
                client = GitHubReleaseClient(repo=self.cache_mgr.repo)
                rel = client.get_latest_release(timeout=8.0)
                update_avail = parse_semver(rel.version) > parse_semver(current_version)
                cache_obj = UpdateCache(
                    schema_version=1,
                    repo=self.cache_mgr.repo,
                    current_version=current_version,
                    latest_version=rel.version,
                    release_url=rel.release_url,
                    published_at=rel.published_at,
                    checked_at=time.time(),
                    update_available=update_avail,
                    freshness=CacheFreshness.FRESH,
                )
                self.cache_mgr.write_cache(cache_obj)
                res = cache_obj.to_dict()
                res["status"] = "checked"
                return res
            except Exception as e:
                return {
                    "status": "offline_or_failed",
                    "error": str(e),
                    "current_version": current_version,
                    "latest_version": current_version,
                    "update_available": False,
                }

        # Non-forced check: cache only
        cache = self.cache_mgr.read_cache(current_version)
        refresh_scheduled = False

        if cache.freshness in (CacheFreshness.STALE, CacheFreshness.EXPIRED):
            if not is_kill_switch_active():
                refresh_scheduled = self.refresh_mgr.schedule_refresh()

        res = cache.to_dict()
        res["status"] = "cached"
        res["refresh_scheduled"] = refresh_scheduled
        return res

    def notify_if_update_available(self, current_version: str) -> None:
        """
        Non-blocking, foreground network-free advisory notice.
        Outputs strictly to stderr without emojis, banners, or obsolete script references.
        Never changes primary command execution or exit code.
        """
        if is_kill_switch_active():
            return

        cache = self.cache_mgr.read_cache(current_version)

        # Trigger background refresh if stale or expired
        if cache.freshness in (CacheFreshness.STALE, CacheFreshness.EXPIRED):
            self.refresh_mgr.schedule_refresh()

        # If cache is fresh or stale with known newer version, show advisory
        if cache.update_available and cache.freshness in (CacheFreshness.FRESH, CacheFreshness.STALE):
            tag = f"v{cache.latest_version}"
            rel_url = cache.release_url or f"https://github.com/{self.cache_mgr.repo}/releases/tag/{tag}"
            msg = (
                f"\n[disk-investigator] Notice: New version v{cache.latest_version} available (current: v{current_version}).\n"
                f"[disk-investigator] Run `disk_investigator update --yes` to update.\n"
                f"[disk-investigator] Release: {rel_url}\n"
            )
            try:
                sys.stderr.write(msg)
                sys.stderr.flush()
            except Exception:
                pass

    def execute_update(
        self,
        current_version: str,
        yes: bool = False,
        prompt_fn: Optional[Callable[[str], bool]] = None,
        release_client: Optional[GitHubReleaseClient] = None,
    ) -> UpdateResult:
        """
        Executes explicit in-app self-update:
        1. Queries FRESH GitHub release (never relies on stale cache).
        2. Prompts user if yes=False.
        3. Downloads SHA256SUMS.txt and disk-investigator-setup.exe.
        4. Verifies SHA-256 checksum (fail-closed).
        5. Verifies embedded setup version matches release tag.
        6. Launches installer with --wait-for-pid and exits CLI so installer can replace binary safely.
        """
        if not self.acquire_update_lock():
            return UpdateResult(
                state=UpdateState.IN_PROGRESS,
                from_version=current_version,
                target_version=current_version,
                message="Another update process is currently in progress.",
                error="Staging lock is currently held by another update process.",
            )

        try:
            client = release_client or GitHubReleaseClient(repo=self.cache_mgr.repo)
            try:
                rel = client.get_latest_release(timeout=10.0)
            except Exception as e:
                return UpdateResult(
                    state=UpdateState.FAILED,
                    from_version=current_version,
                    target_version=current_version,
                    message="Failed to query latest release from GitHub.",
                    error=str(e),
                )

            target_version = rel.version
            if parse_semver(target_version) <= parse_semver(current_version):
                return UpdateResult(
                    state=UpdateState.UP_TO_DATE,
                    from_version=current_version,
                    target_version=target_version,
                    release_url=rel.release_url,
                    message=f"Disk Investigator is already up to date (v{current_version}).",
                )

            # User confirmation gate
            if not yes:
                confirm = False
                if prompt_fn is not None:
                    confirm = prompt_fn(f"Update Disk Investigator from v{current_version} to v{target_version}? [y/N]: ")
                else:
                    try:
                        sys.stderr.write(f"\nUpdate Disk Investigator from v{current_version} to v{target_version}? [y/N]: ")
                        sys.stderr.flush()
                        ans = sys.stdin.readline().strip().lower()
                        confirm = ans in ("y", "yes")
                    except Exception:
                        confirm = False

                if not confirm:
                    return UpdateResult(
                        state=UpdateState.CANCELLED,
                        from_version=current_version,
                        target_version=target_version,
                        release_url=rel.release_url,
                        message="Update cancelled by user.",
                    )

            # Check required assets
            if SETUP_EXE_NAME not in rel.assets:
                return UpdateResult(
                    state=UpdateState.FAILED,
                    from_version=current_version,
                    target_version=target_version,
                    release_url=rel.release_url,
                    message=f"Required asset '{SETUP_EXE_NAME}' not found in release v{target_version}.",
                    error="Missing setup asset in GitHub release.",
                )

            if MANIFEST_NAME not in rel.assets:
                return UpdateResult(
                    state=UpdateState.FAILED,
                    from_version=current_version,
                    target_version=target_version,
                    release_url=rel.release_url,
                    message=f"Mandatory checksum manifest '{MANIFEST_NAME}' not found in release v{target_version}.",
                    error="Missing SHA256SUMS.txt manifest in GitHub release (Fail-Closed).",
                )

            # Staging directory
            with tempfile.TemporaryDirectory() as tmp_dir_str:
                tmp_dir = Path(tmp_dir_str)
                setup_exe_path = tmp_dir / SETUP_EXE_NAME

                # 1. Download SHA256SUMS.txt
                try:
                    manifest_text = client.download_text(rel.assets[MANIFEST_NAME].download_url, timeout=15.0)
                except Exception as e:
                    return UpdateResult(
                        state=UpdateState.FAILED,
                        from_version=current_version,
                        target_version=target_version,
                        release_url=rel.release_url,
                        message="Failed to download SHA256SUMS.txt manifest.",
                        error=str(e),
                    )

                manifest_hashes = parse_sha256sums_manifest(manifest_text)
                expected_sha = manifest_hashes.get(SETUP_EXE_NAME)
                if not expected_sha:
                    return UpdateResult(
                        state=UpdateState.FAILED,
                        from_version=current_version,
                        target_version=target_version,
                        release_url=rel.release_url,
                        message=f"Manifest does not contain valid SHA-256 for '{SETUP_EXE_NAME}'.",
                        error="Missing or invalid checksum in manifest (Fail-Closed).",
                    )

                # 2. Download setup executable
                try:
                    client.download_file(
                        url=rel.assets[SETUP_EXE_NAME].download_url,
                        destination_path=setup_exe_path,
                        timeout=60.0,
                    )
                except Exception as e:
                    return UpdateResult(
                        state=UpdateState.FAILED,
                        from_version=current_version,
                        target_version=target_version,
                        release_url=rel.release_url,
                        message=f"Failed to download '{SETUP_EXE_NAME}'.",
                        error=str(e),
                    )

                # 3. Cryptographic SHA-256 verification (MANDATORY)
                is_match, actual_sha = verify_sha256_checksum(setup_exe_path, expected_sha)
                if not is_match:
                    return UpdateResult(
                        state=UpdateState.FAILED,
                        from_version=current_version,
                        target_version=target_version,
                        release_url=rel.release_url,
                        message="Checksum verification failed! Downloaded asset may be corrupted.",
                        error=f"Checksum mismatch: expected '{expected_sha}', got '{actual_sha}'.",
                    )

                # 4. Embedded version verification: setup must match target tag
                try:
                    ver_res = subprocess.run(
                        [str(setup_exe_path), "--version"],
                        capture_output=True,
                        text=True,
                        encoding="utf-8",
                        errors="replace",
                        timeout=10,
                    )
                    combined_ver_out = (ver_res.stdout + " " + ver_res.stderr).strip()
                    if target_version not in combined_ver_out:
                        return UpdateResult(
                            state=UpdateState.FAILED,
                            from_version=current_version,
                            target_version=target_version,
                            release_url=rel.release_url,
                            message=f"Downloaded setup executable version mismatch (reports: '{combined_ver_out}').",
                            error="Setup executable version does not match release tag.",
                        )
                except Exception as e:
                    return UpdateResult(
                        state=UpdateState.FAILED,
                        from_version=current_version,
                        target_version=target_version,
                        release_url=rel.release_url,
                        message="Failed to verify downloaded setup executable version.",
                        error=str(e),
                    )

                # 5. Move setup to persistent updates staging folder before launching
                # Because tmp_dir will be deleted when context manager exits!
                staging_exe = self.cache_mgr.updates_dir / f"setup_{target_version}.exe"
                import shutil
                shutil.copy2(setup_exe_path, staging_exe)

            # 6. Launch installer detached with --wait-for-pid
            current_pid = os.getpid()
            receipt_path = self.cache_mgr.receipt_file

            launch_cmd = [
                str(staging_exe),
                "--silent",
                "--wait-for-pid",
                str(current_pid),
                "--update-result",
                str(receipt_path),
            ]

            creationflags = 0
            if sys.platform == "win32":
                creationflags = 0x00000008 | 0x08000000  # DETACHED_PROCESS | CREATE_NO_WINDOW

            try:
                proc = subprocess.Popen(
                    launch_cmd,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    close_fds=True,
                    creationflags=creationflags,
                )
            except Exception as e:
                return UpdateResult(
                    state=UpdateState.FAILED,
                    from_version=current_version,
                    target_version=target_version,
                    release_url=rel.release_url,
                    message="Failed to launch detached setup installer.",
                    error=str(e),
                )

            # 7. Update cache to record new version checked
            self.cache_mgr.write_cache(
                UpdateCache(
                    schema_version=1,
                    repo=self.cache_mgr.repo,
                    current_version=current_version,
                    latest_version=target_version,
                    release_url=rel.release_url,
                    published_at=rel.published_at,
                    checked_at=time.time(),
                    update_available=True,
                    freshness=CacheFreshness.FRESH,
                )
            )

            return UpdateResult(
                state=UpdateState.HANDOFF_STARTED,
                from_version=current_version,
                target_version=target_version,
                release_url=rel.release_url,
                installer_pid=proc.pid,
                installer_verified=True,
                message=(
                    f"Update to v{target_version} staged successfully. "
                    f"Installer process launched (PID: {proc.pid}). "
                    f"Current CLI process will now exit to allow transactional binary replacement."
                ),
            )
        finally:
            self.release_update_lock()
