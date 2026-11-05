"""
disk_investigator.tests.test_updates
Comprehensive unit, invariant, and security verification tests for Update subsystem.
Covers gates UPDATE-FINAL-01 to UPDATE-FINAL-24.
"""

import io
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from disk_investigator import __version__
from disk_investigator.cli import main as cli_main

# Allow importing installer from root
ROOT_DIR = Path(__file__).resolve().parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))
from installer import wait_for_pid_to_exit, write_update_receipt
from disk_investigator.updates import (
    BackgroundRefreshManager,
    CacheFreshness,
    GitHubReleaseClient,
    ReleaseAsset,
    ReleaseInfo,
    UpdateCache,
    UpdateCacheManager,
    UpdateEngine,
    UpdateReceipt,
    UpdateResult,
    UpdateState,
    compute_sha256,
    parse_sha256sums_manifest,
    verify_sha256_checksum,
)


class TestUpdateSubsystem(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_dir = Path(self.temp_dir.name)
        self.cache_mgr = UpdateCacheManager(base_dir=self.base_dir, repo="codevcn/disk-cleaner")
        self.engine = UpdateEngine(self.cache_mgr)

    def tearDown(self):
        self.temp_dir.cleanup()

    # --- Gate 01: Foreground Network-Free Invariant ---
    @patch("urllib.request.urlopen")
    def test_normal_command_never_calls_network(self, mock_urlopen):
        """UPDATE-FINAL-01: Foreground CLI commands never make network requests."""
        with patch("sys.stdout", new_callable=io.StringIO):
            cli_main(["overview", "C:"])
            cli_main(["doctor"])
        mock_urlopen.assert_not_called()

    # --- Gate 02, 03: Cache Freshness & SWR Refresh Scheduling ---
    def test_fresh_cache_no_background_refresh(self):
        """UPDATE-FINAL-02: Fresh cache (<24h) does not schedule background refresh."""
        now = time.time()
        fresh_cache = UpdateCache(
            schema_version=1,
            repo="codevcn/disk-cleaner",
            current_version="2.3.2",
            latest_version="2.3.2",
            checked_at=now - 3600,  # 1 hour ago
            update_available=False,
            freshness=CacheFreshness.FRESH,
        )
        self.cache_mgr.write_cache(fresh_cache)

        with patch.object(self.engine.refresh_mgr, "schedule_refresh") as mock_sched:
            res = self.engine.check_update_status(current_version="2.3.2", force_network=False)
            mock_sched.assert_not_called()
            self.assertEqual(res["freshness"], "fresh")
            self.assertFalse(res["refresh_scheduled"])

    def test_stale_cache_schedules_refresh(self):
        """UPDATE-FINAL-03: Stale cache (24h - 7d) schedules detached background refresh."""
        now = time.time()
        stale_cache = UpdateCache(
            schema_version=1,
            repo="codevcn/disk-cleaner",
            current_version="2.3.2",
            latest_version="2.3.2",
            checked_at=now - 100000,  # >24 hours ago
            update_available=False,
            freshness=CacheFreshness.STALE,
        )
        self.cache_mgr.write_cache(stale_cache)

        with patch.object(self.engine.refresh_mgr, "schedule_refresh", return_value=True) as mock_sched:
            res = self.engine.check_update_status(current_version="2.3.2", force_network=False)
            mock_sched.assert_called_once()
            self.assertEqual(res["freshness"], "stale")
            self.assertTrue(res["refresh_scheduled"])

    def test_missing_cache_schedules_refresh(self):
        """UPDATE-FINAL-03: Missing cache schedules background refresh and returns expired."""
        with patch.object(self.engine.refresh_mgr, "schedule_refresh", return_value=True) as mock_sched:
            res = self.engine.check_update_status(current_version="2.3.2", force_network=False)
            mock_sched.assert_called_once()
            self.assertEqual(res["freshness"], "expired")

    # --- Gate 04, 05: Single-Flight Refresh & Stale Lock Recovery ---
    def test_refresh_single_flight(self):
        """UPDATE-FINAL-04: Single-flight refresh lock prevents concurrent runs."""
        mgr = BackgroundRefreshManager(self.cache_mgr)
        self.assertTrue(mgr.acquire_lock())
        # Second acquire must fail
        self.assertFalse(mgr.acquire_lock())
        mgr.release_lock()
        # After release, acquire succeeds
        self.assertTrue(mgr.acquire_lock())
        mgr.release_lock()

    def test_stale_refresh_lock_recovered(self):
        """UPDATE-FINAL-04: Stale refresh lock (>5 mins) is recovered."""
        mgr = BackgroundRefreshManager(self.cache_mgr)
        mgr.cache_mgr.updates_dir.mkdir(parents=True, exist_ok=True)
        # Create lock with timestamp 10 mins in the past
        stale_time = time.time() - 600
        mgr.lock_file.write_text(f"pid=9999\ntime={stale_time}\n", encoding="utf-8")
        os.utime(str(mgr.lock_file), (stale_time, stale_time))

        self.assertTrue(mgr.acquire_lock())
        mgr.release_lock()

    # --- Gate 06, 07: Kill-Switch Semantics ---
    @patch.dict(os.environ, {"DISK_INVESTIGATOR_NO_UPDATE_CHECK": "1"})
    def test_kill_switch_disables_auto_refresh_and_advisory(self):
        """UPDATE-FINAL-06: DISK_INVESTIGATOR_NO_UPDATE_CHECK=1 disables auto-refresh and stderr advisory."""
        now = time.time()
        stale_cache = UpdateCache(
            schema_version=1,
            repo="codevcn/disk-cleaner",
            current_version="2.3.2",
            latest_version="2.4.0",
            checked_at=now - 100000,
            update_available=True,
            freshness=CacheFreshness.STALE,
        )
        self.cache_mgr.write_cache(stale_cache)

        with patch.object(self.engine.refresh_mgr, "schedule_refresh") as mock_sched, \
             patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
            self.engine.notify_if_update_available(current_version="2.3.2")
            mock_sched.assert_not_called()
            self.assertEqual(mock_stderr.getvalue(), "")

    @patch.dict(os.environ, {"DISK_INVESTIGATOR_NO_UPDATE_CHECK": "1"})
    @patch.object(GitHubReleaseClient, "get_latest_release")
    def test_explicit_check_ignores_auto_kill_switch(self, mock_get_rel):
        """UPDATE-FINAL-07: Explicit force check ignores kill-switch."""
        mock_get_rel.return_value = ReleaseInfo(
            tag="v2.4.0",
            version="2.4.0",
            release_url="https://github.com/codevcn/disk-cleaner/releases/tag/v2.4.0",
            published_at="2026-11-05T00:00:00Z",
            release_name="v2.4.0",
        )
        res = self.engine.check_update_status(current_version="2.3.2", force_network=True)
        self.assertEqual(res["status"], "checked")
        self.assertEqual(res["latest_version"], "2.4.0")

    # --- Gate 08, 09: Advisory Format & Stderr Purity ---
    def test_advisory_stderr_only_and_clean_format(self):
        """UPDATE-FINAL-08, 09: Advisory prints only to stderr, no emojis, no update.cmd."""
        now = time.time()
        fresh_update_cache = UpdateCache(
            schema_version=1,
            repo="codevcn/disk-cleaner",
            current_version="2.3.2",
            latest_version="2.4.0",
            release_url="https://github.com/codevcn/disk-cleaner/releases/tag/v2.4.0",
            checked_at=now - 60,
            update_available=True,
            freshness=CacheFreshness.FRESH,
        )
        self.cache_mgr.write_cache(fresh_update_cache)

        with patch("sys.stderr", new_callable=io.StringIO) as mock_stderr, \
             patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
            self.engine.notify_if_update_available(current_version="2.3.2")
            err = mock_stderr.getvalue()
            out = mock_stdout.getvalue()

            self.assertEqual(out, "", "stdout must remain 100% clean for JSON envelopes")
            self.assertIn("[disk-investigator] Notice: New version v2.4.0 available", err)
            self.assertIn("disk_investigator update --yes", err)
            # Must NOT contain obsolete script references or emojis
            self.assertNotIn("update.cmd", err)
            self.assertNotIn("python update_from_github.py", err)
            self.assertNotIn("🔔", err)

    # --- Gate 10: Doctor Uses Cached State Only ---
    @patch("urllib.request.urlopen")
    def test_doctor_uses_cached_update_state_only(self, mock_urlopen):
        """UPDATE-FINAL-10: Doctor subcommand reads cached update check only."""
        with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
            exit_code = cli_main(["doctor"])
            self.assertEqual(exit_code, 0)
            mock_urlopen.assert_not_called()
            data = json.loads(mock_stdout.getvalue())
            self.assertEqual(data["status"], "success")
            self.assertIn("update_check", data["doctor"])

    # --- Gate 11, 12, 13: Update CLI & Confirmation Gate ---
    def test_update_up_to_date_no_download(self):
        """UPDATE-FINAL-11: If version is already latest, returns UP_TO_DATE without downloading."""
        mock_client = MagicMock()
        mock_client.get_latest_release.return_value = ReleaseInfo(
            tag="v2.3.2",
            version="2.3.2",
            release_url="https://github.com/codevcn/disk-cleaner/releases/tag/v2.3.2",
            published_at="",
            release_name="",
        )
        res = self.engine.execute_update(current_version="2.3.2", yes=True, release_client=mock_client)
        self.assertEqual(res.state, UpdateState.UP_TO_DATE)
        mock_client.download_file.assert_not_called()

    def test_update_requires_confirmation_without_yes(self):
        """UPDATE-FINAL-13: Update without --yes prompts user; if rejected returns CANCELLED."""
        mock_client = MagicMock()
        mock_client.get_latest_release.return_value = ReleaseInfo(
            tag="v2.4.0",
            version="2.4.0",
            release_url="https://github.com/codevcn/disk-cleaner/releases/tag/v2.4.0",
            published_at="",
            release_name="",
        )
        # User answers 'n'
        res = self.engine.execute_update(
            current_version="2.3.2",
            yes=False,
            prompt_fn=lambda prompt: False,
            release_client=mock_client,
        )
        self.assertEqual(res.state, UpdateState.CANCELLED)
        mock_client.download_file.assert_not_called()

    # --- Gate 14, 15, 16: Cryptographic Verification & Fail-Closed ---
    def test_missing_checksum_manifest_aborts(self):
        """UPDATE-FINAL-15: Missing SHA256SUMS.txt aborts update with FAILED state."""
        mock_client = MagicMock()
        mock_client.get_latest_release.return_value = ReleaseInfo(
            tag="v2.4.0",
            version="2.4.0",
            release_url="https://github.com/codevcn/disk-cleaner/releases/tag/v2.4.0",
            published_at="",
            release_name="",
            assets={
                "disk-investigator-setup.exe": ReleaseAsset("disk-investigator-setup.exe", "http://example.com/setup.exe"),
                # SHA256SUMS.txt missing!
            },
        )
        res = self.engine.execute_update(current_version="2.3.2", yes=True, release_client=mock_client)
        self.assertEqual(res.state, UpdateState.FAILED)
        self.assertIn("SHA256SUMS.txt", res.message)

    def test_checksum_mismatch_aborts(self):
        """UPDATE-FINAL-15: Checksum mismatch aborts update immediately."""
        mock_client = MagicMock()
        mock_client.get_latest_release.return_value = ReleaseInfo(
            tag="v2.4.0",
            version="2.4.0",
            release_url="https://github.com/codevcn/disk-cleaner/releases/tag/v2.4.0",
            published_at="",
            release_name="",
            assets={
                "disk-investigator-setup.exe": ReleaseAsset("disk-investigator-setup.exe", "http://example.com/setup.exe"),
                "SHA256SUMS.txt": ReleaseAsset("SHA256SUMS.txt", "http://example.com/sums.txt"),
            },
        )
        # Expected fake sha
        fake_expected_sha = "0000000000000000000000000000000000000000000000000000000000000000"
        mock_client.download_text.return_value = f"{fake_expected_sha}  disk-investigator-setup.exe\n"

        def fake_download_file(url, destination_path, **kwargs):
            destination_path.write_bytes(b"ACTUAL_EXE_BYTES_DIFFERENT_HASH")

        mock_client.download_file.side_effect = fake_download_file

        res = self.engine.execute_update(current_version="2.3.2", yes=True, release_client=mock_client)
        self.assertEqual(res.state, UpdateState.FAILED)
        self.assertIn("Checksum verification failed", res.message)

    # --- Gate 17: Concurrent Update Single-Flight ---
    def test_concurrent_update_is_blocked(self):
        """UPDATE-FINAL-17: Second concurrent update is blocked with IN_PROGRESS state."""
        self.assertTrue(self.engine.acquire_update_lock())
        res = self.engine.execute_update(current_version="2.3.2", yes=True)
        self.assertEqual(res.state, UpdateState.IN_PROGRESS)
        self.engine.release_update_lock()

    # --- Gate 18, 19, 21: Staged Handoff & Popen Verification ---
    @patch("subprocess.Popen")
    @patch("subprocess.run")
    def test_update_reports_handoff_started_never_premature_success(self, mock_sub_run, mock_popen):
        """UPDATE-FINAL-21: Update reports HANDOFF_STARTED, never premature update_success."""
        mock_proc = MagicMock()
        mock_proc.pid = 98765
        mock_popen.return_value = mock_proc

        # Mock --version check on downloaded setup
        mock_ver_res = MagicMock()
        mock_ver_res.stdout = "disk-investigator-setup 2.4.0"
        mock_ver_res.stderr = ""
        mock_sub_run.return_value = mock_ver_res

        mock_client = MagicMock()
        mock_client.get_latest_release.return_value = ReleaseInfo(
            tag="v2.4.0",
            version="2.4.0",
            release_url="https://github.com/codevcn/disk-cleaner/releases/tag/v2.4.0",
            published_at="",
            release_name="",
            assets={
                "disk-investigator-setup.exe": ReleaseAsset("disk-investigator-setup.exe", "http://example.com/setup.exe"),
                "SHA256SUMS.txt": ReleaseAsset("SHA256SUMS.txt", "http://example.com/sums.txt"),
            },
        )

        test_bytes = b"VALID_EXE_PAYLOAD_FOR_TESTING"
        import hashlib
        valid_sha = hashlib.sha256(test_bytes).hexdigest()
        mock_client.download_text.return_value = f"{valid_sha}  disk-investigator-setup.exe\n"

        def fake_download_file(url, destination_path, **kwargs):
            destination_path.write_bytes(test_bytes)

        mock_client.download_file.side_effect = fake_download_file

        res = self.engine.execute_update(current_version="2.3.2", yes=True, release_client=mock_client)
        self.assertEqual(res.state, UpdateState.HANDOFF_STARTED)
        self.assertEqual(res.installer_pid, 98765)
        self.assertTrue(res.installer_verified)
        self.assertIn("staged successfully", res.message)

        # Verify installer was launched with --wait-for-pid and --update-result
        mock_popen.assert_called_once()
        args, kwargs = mock_popen.call_args
        cmd_args = args[0]
        self.assertIn("--silent", cmd_args)
        self.assertIn("--wait-for-pid", cmd_args)
        self.assertIn(str(os.getpid()), cmd_args)
        self.assertIn("--update-result", cmd_args)

    # --- Gate 22: Update Result Receipt Persistence ---
    def test_installer_update_receipt_success(self):
        """UPDATE-FINAL-22: Installer records verifiable update receipt on completion."""
        receipt_file = self.base_dir / "test_receipt.json"
        write_update_receipt(
            receipt_path=receipt_file,
            status="success",
            from_ver="2.3.2",
            to_ver="2.4.0",
            exit_code=0,
            rollback=False,
        )
        self.assertTrue(receipt_file.exists())
        data = json.loads(receipt_file.read_text(encoding="utf-8"))
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["from_version"], "2.3.2")
        self.assertEqual(data["to_version"], "2.4.0")
        self.assertEqual(data["installer_exit_code"], 0)

    # --- Gate 19, 20: Parent PID Wait and Safety ---
    def test_installer_waits_for_nonexistent_parent_pid(self):
        """UPDATE-FINAL-19: Non-existent PID exits immediately (returns True)."""
        self.assertTrue(wait_for_pid_to_exit(99999999, timeout_seconds=0.5))

    @patch("ctypes.windll.kernel32.OpenProcess")
    def test_installer_timeout_does_not_kill_parent(self, mock_open_proc):
        """UPDATE-FINAL-20: If parent does not exit within timeout, returns False without killing."""
        # Mock handle that always returns STILL_ACTIVE
        mock_open_proc.return_value = 1234
        with patch("ctypes.windll.kernel32.GetExitCodeProcess") as mock_get_code:
            def fake_get_code(handle, byref):
                byref._obj.value = 259  # STILL_ACTIVE
                return True
            mock_get_code.side_effect = fake_get_code
            with patch("ctypes.windll.kernel32.CloseHandle"):
                res = wait_for_pid_to_exit(12345, timeout_seconds=0.4)
                self.assertFalse(res, "Must return False on timeout")

    # --- Gate 16: Setup Embedded Version Verification ---
    @patch("subprocess.run")
    def test_setup_embedded_version_must_match_tag(self, mock_sub_run):
        """UPDATE-FINAL-16: Setup embedded version must strictly equal release tag."""
        mock_ver_res = MagicMock()
        mock_ver_res.stdout = "disk-investigator-setup 2.3.2"  # Outdated version!
        mock_ver_res.stderr = ""
        mock_sub_run.return_value = mock_ver_res

        mock_client = MagicMock()
        mock_client.get_latest_release.return_value = ReleaseInfo(
            tag="v2.4.0",
            version="2.4.0",
            release_url="https://github.com/codevcn/disk-cleaner/releases/tag/v2.4.0",
            published_at="",
            release_name="",
            assets={
                "disk-investigator-setup.exe": ReleaseAsset("disk-investigator-setup.exe", "http://example.com/setup.exe"),
                "SHA256SUMS.txt": ReleaseAsset("SHA256SUMS.txt", "http://example.com/sums.txt"),
            },
        )
        test_bytes = b"SETUP_BYTES_WITH_MISMATCHED_VERSION"
        import hashlib
        valid_sha = hashlib.sha256(test_bytes).hexdigest()
        mock_client.download_text.return_value = f"{valid_sha}  disk-investigator-setup.exe\n"

        def fake_download_file(url, destination_path, **kwargs):
            destination_path.write_bytes(test_bytes)

        mock_client.download_file.side_effect = fake_download_file

        res = self.engine.execute_update(current_version="2.3.2", yes=True, release_client=mock_client)
        self.assertEqual(res.state, UpdateState.FAILED)
        self.assertIn("version mismatch", res.message)

    # --- CLI update --status command ---
    def test_update_status_cli(self):
        """CLI: update --status returns receipt JSON."""
        # 1. When no receipt exists
        with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
            code = cli_main(["update", "--status"])
            self.assertEqual(code, 0)
            out = json.loads(mock_stdout.getvalue())
            self.assertEqual(out["status"], "success")

        # 2. When receipt exists
        receipt_file = UpdateCacheManager().receipt_file
        receipt_file.parent.mkdir(parents=True, exist_ok=True)
        receipt_file.write_text(json.dumps({
            "schema_version": 1,
            "status": "success",
            "from_version": "2.3.2",
            "to_version": "2.4.0",
            "completed_at": "2026-11-05T00:00:00Z",
            "installer_exit_code": 0
        }), encoding="utf-8")

        with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
            code = cli_main(["update", "--status"])
            self.assertEqual(code, 0)
            out = json.loads(mock_stdout.getvalue())
            self.assertEqual(out["status"], "success")
            self.assertEqual(out["last_update"]["to_version"], "2.4.0")


if __name__ == "__main__":
    unittest.main()
