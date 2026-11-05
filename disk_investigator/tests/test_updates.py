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
from installer import (
    wait_for_pid_to_exit,
    write_update_receipt,
    check_pid_state,
    PidWaitState,
    release_update_lock,
    install,
)
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
        mock_ver_res.returncode = 0
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
        """UPDATE-FINAL-19: Non-existent PID exits immediately (returns PidWaitState.EXITED)."""
        self.assertEqual(wait_for_pid_to_exit(99999999, timeout_seconds=0.5), PidWaitState.EXITED)

    @patch("ctypes.windll.kernel32.OpenProcess")
    def test_installer_timeout_does_not_kill_parent(self, mock_open_proc):
        """UPDATE-FINAL-20: If parent does not exit within timeout, returns PidWaitState.RUNNING without killing."""
        # Mock handle that always returns STILL_ACTIVE
        mock_open_proc.return_value = 1234
        with patch("ctypes.windll.kernel32.GetExitCodeProcess") as mock_get_code:
            def fake_get_code(handle, byref):
                byref._obj.value = 259  # STILL_ACTIVE
                return True
            mock_get_code.side_effect = fake_get_code
            with patch("ctypes.windll.kernel32.CloseHandle"):
                res = wait_for_pid_to_exit(12345, timeout_seconds=0.4)
                self.assertEqual(res, PidWaitState.RUNNING, "Must return RUNNING on timeout")

    # --- Gate 16: Setup Embedded Version Verification ---
    @patch("subprocess.run")
    def test_setup_embedded_version_must_match_tag(self, mock_sub_run):
        """UPDATE-FINAL-16: Setup embedded version must strictly equal release tag."""
        mock_ver_res = MagicMock()
        mock_ver_res.returncode = 0
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

    # --- Gate 25: Strict Checksum Manifest Security & Duplicate Rejection ---
    def test_parse_manifest_strict_rejects_separators_and_duplicates(self):
        """UPDATE-FINAL-25: Rejects filenames with path traversal/separators and rejects duplicates."""
        manifest = (
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  valid.exe\n"
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  ../bad.exe\n"
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  dir/bad.exe\n"
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  dir\\bad.exe\n"
        )
        parsed = parse_sha256sums_manifest(manifest)
        self.assertIn("valid.exe", parsed)
        self.assertEqual(len(parsed), 1)

        # Test duplicate entry rejection
        dup_manifest = (
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  valid.exe\n"
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  valid.exe\n"
        )
        with self.assertRaises(ValueError):
            parse_sha256sums_manifest(dup_manifest)

    # --- Gate 26: Strict Tag and Setup Version Regex Binding ---
    def test_strict_tag_and_setup_version_matching(self):
        """UPDATE-FINAL-26: Enforces strict semver regex on tag and setup --version output."""
        from disk_investigator.updates.update_engine import STRICT_TAG_PATTERN, SETUP_VERSION_OUTPUT_PATTERN
        self.assertIsNotNone(STRICT_TAG_PATTERN.match("v2.4.1"))
        self.assertIsNone(STRICT_TAG_PATTERN.match("2.4.1"))  # Strict requirement for leading v
        self.assertIsNone(STRICT_TAG_PATTERN.match("v2.4.1-rc1"))
        self.assertIsNone(STRICT_TAG_PATTERN.match("v2.4"))
        self.assertIsNone(STRICT_TAG_PATTERN.match("v2.4.1.0"))
        self.assertIsNone(STRICT_TAG_PATTERN.match("release-v2.4.1"))

        self.assertIsNotNone(SETUP_VERSION_OUTPUT_PATTERN.match("disk-investigator-setup 2.4.1"))
        self.assertIsNone(SETUP_VERSION_OUTPUT_PATTERN.match("disk-investigator-setup 2.4.1-beta"))
        self.assertIsNone(SETUP_VERSION_OUTPUT_PATTERN.match("other-tool 2.4.1"))
        self.assertIsNone(SETUP_VERSION_OUTPUT_PATTERN.match("disk-investigator-setup v2.4.1"))

    # --- Gate 27: Fail-Closed Tri-State PID Waiting ---
    @patch("ctypes.windll.kernel32.OpenProcess")
    @patch("ctypes.GetLastError")
    def test_tri_state_pid_wait_fail_closed(self, mock_last_err, mock_open_proc):
        """UPDATE-FINAL-27: check_pid_state returns tri-state and wait_for_pid_to_exit fails closed."""
        # 1. Invalid parameter (PID dead) -> EXITED
        mock_open_proc.return_value = 0
        mock_last_err.return_value = 87  # ERROR_INVALID_PARAMETER
        self.assertEqual(check_pid_state(12345), PidWaitState.EXITED)

        # 2. Access Denied (PID exists or unknown privilege) -> UNKNOWN (fail-closed)
        mock_last_err.return_value = 5  # ERROR_ACCESS_DENIED
        self.assertEqual(check_pid_state(12345), PidWaitState.UNKNOWN)

        # 3. wait_for_pid_to_exit immediately returns UNKNOWN if state is UNKNOWN
        self.assertEqual(wait_for_pid_to_exit(12345, timeout_seconds=1.0), PidWaitState.UNKNOWN)

        # 4. OpenProcess succeeds but GetExitCodeProcess fails -> UNKNOWN
        mock_open_proc.return_value = 9999
        with patch("ctypes.windll.kernel32.GetExitCodeProcess", return_value=0):
            with patch("ctypes.windll.kernel32.CloseHandle"):
                self.assertEqual(check_pid_state(12345), PidWaitState.UNKNOWN)

        # 5. OpenProcess succeeds and GetExitCodeProcess returns non-259 -> EXITED
        with patch("ctypes.windll.kernel32.GetExitCodeProcess") as mock_exit_code:
            def fake_get_exit(handle, byref):
                byref._obj.value = 0
                return 1
            mock_exit_code.side_effect = fake_get_exit
            with patch("ctypes.windll.kernel32.CloseHandle"):
                self.assertEqual(check_pid_state(12345), PidWaitState.EXITED)

    # --- Gate 28: Guaranteed Receipt and Lock Release on Failure Paths ---
    def test_installer_guaranteed_receipt_and_lock_release_on_all_exits(self):
        """UPDATE-FINAL-28: Installer writes receipt and releases lock even when payload is missing."""
        receipt_file = self.base_dir / "failure_receipt.json"
        updates_dir = self.base_dir / "DiskInvestigator" / "updates"
        updates_dir.mkdir(parents=True, exist_ok=True)
        lock_file = updates_dir / "update.lock"
        lock_file.write_text("active_lock", encoding="utf-8")

        with patch.dict(os.environ, {"LOCALAPPDATA": str(self.base_dir)}):
            with patch("installer.get_resource_path", return_value=Path("/nonexistent/payload.exe")):
                ok = install(silent=True, update_result=receipt_file)
                self.assertFalse(ok)
                self.assertTrue(receipt_file.exists())
                rec = json.loads(receipt_file.read_text(encoding="utf-8"))
                self.assertEqual(rec["status"], "failed")
                self.assertIn("Không tìm thấy tệp nhị phân", rec["error_message"])
                self.assertFalse(lock_file.exists(), "update.lock must be cleaned up on failure")

    # --- Gate 29: End-to-End Upgrade from Previous Version ---
    def test_upgrade_from_previous_version_e2e(self):
        """UPDATE-FINAL-29: Real E2E upgrade replaces older version and records success receipt."""
        install_dir = self.base_dir / "DiskInvestigator"
        bin_dir = install_dir / "bin"
        skill_dir = self.base_dir / "skills" / "disk-cleanup"
        skill_ref_dir = skill_dir / "references"
        bin_dir.mkdir(parents=True, exist_ok=True)
        skill_ref_dir.mkdir(parents=True, exist_ok=True)

        # 1. Simulate older installed state (v2.3.2)
        old_bin = bin_dir / "disk_investigator.exe"
        old_bin.write_bytes(b"OLD_BINARY_V232")
        old_skill = skill_dir / "SKILL.md"
        old_skill.write_text("# Old Skill", encoding="utf-8")
        manifest_file = install_dir / "install_manifest.json"
        manifest_file.write_text(json.dumps({"app_name": "Disk Investigator", "version": "2.3.2"}), encoding="utf-8")

        # 2. Prepare staging payloads for new version
        payload_dir = self.base_dir / "payload"
        payload_dir.mkdir(parents=True, exist_ok=True)
        new_bin = payload_dir / "disk_investigator.exe"
        new_bin.write_bytes(b"NEW_BINARY_V241")
        new_skill = payload_dir / "SKILL.md"
        new_skill.write_text("# New Skill v2.4.1", encoding="utf-8")
        new_readme = payload_dir / "README.md"
        new_readme.write_text("# Readme v2.4.1", encoding="utf-8")

        receipt_file = self.base_dir / "upgrade_receipt.json"

        def mock_get_resource(name):
            return payload_dir / name

        with patch.dict(os.environ, {"LOCALAPPDATA": str(self.base_dir)}):
            with patch("installer.get_target_directories", return_value=(install_dir, bin_dir, skill_dir, skill_ref_dir)):
                with patch("installer.get_resource_path", side_effect=mock_get_resource):
                    with patch("installer.add_bin_to_user_path", return_value=(True, False)):
                        with patch("installer.run_smoke_test", return_value=True):
                            with patch("installer.get_installer_version", return_value="2.4.1"):
                                ok = install(silent=True, update_result=receipt_file)
                                self.assertTrue(ok)

        # Verify files and manifest are upgraded
        self.assertEqual(old_bin.read_bytes(), b"NEW_BINARY_V241")
        self.assertEqual(old_skill.read_text(encoding="utf-8"), "# New Skill v2.4.1")
        updated_manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
        self.assertEqual(updated_manifest["version"], "2.4.1")

        # Verify receipt
        self.assertTrue(receipt_file.exists())
        receipt = json.loads(receipt_file.read_text(encoding="utf-8"))
        self.assertEqual(receipt["status"], "success")
        self.assertEqual(receipt["from_version"], "2.3.2")
        self.assertEqual(receipt["to_version"], "2.4.1")
        self.assertFalse(receipt["rollback_attempted"])

    # --- Gate 30: End-to-End Upgrade Rollback on Failure ---
    def test_failed_update_preserves_previous_version_and_records_rollback_receipt(self):
        """UPDATE-FINAL-30: Failure during installation triggers rollback, restores original files and records failure."""
        install_dir = self.base_dir / "DiskInvestigator"
        bin_dir = install_dir / "bin"
        skill_dir = self.base_dir / "skills" / "disk-cleanup"
        skill_ref_dir = skill_dir / "references"
        bin_dir.mkdir(parents=True, exist_ok=True)
        skill_ref_dir.mkdir(parents=True, exist_ok=True)

        # 1. Older installed state (v2.3.2)
        old_bin = bin_dir / "disk_investigator.exe"
        old_bin.write_bytes(b"ORIGINAL_BINARY_V232")
        old_skill = skill_dir / "SKILL.md"
        old_skill.write_text("# Original Skill v2.3.2", encoding="utf-8")
        manifest_file = install_dir / "install_manifest.json"
        manifest_file.write_text(json.dumps({"app_name": "Disk Investigator", "version": "2.3.2"}), encoding="utf-8")

        # 2. Staging payloads
        payload_dir = self.base_dir / "payload"
        payload_dir.mkdir(parents=True, exist_ok=True)
        new_bin = payload_dir / "disk_investigator.exe"
        new_bin.write_bytes(b"CORRUPT_OR_FAILING_PAYLOAD")
        new_skill = payload_dir / "SKILL.md"
        new_skill.write_text("# Corrupt Skill", encoding="utf-8")
        new_readme = payload_dir / "README.md"
        new_readme.write_text("# Readme", encoding="utf-8")

        receipt_file = self.base_dir / "rollback_receipt.json"

        def mock_get_resource(name):
            return payload_dir / name

        with patch.dict(os.environ, {"LOCALAPPDATA": str(self.base_dir)}):
            with patch("installer.get_target_directories", return_value=(install_dir, bin_dir, skill_dir, skill_ref_dir)):
                with patch("installer.get_resource_path", side_effect=mock_get_resource):
                    with patch("installer.add_bin_to_user_path", return_value=(True, False)):
                        # Force smoke test failure
                        with patch("installer.run_smoke_test", return_value=False):
                            with patch("installer.get_installer_version", return_value="2.4.1"):
                                ok = install(silent=True, update_result=receipt_file)
                                self.assertFalse(ok)

        # Verify rollback preserved original state
        self.assertEqual(old_bin.read_bytes(), b"ORIGINAL_BINARY_V232")
        self.assertEqual(old_skill.read_text(encoding="utf-8"), "# Original Skill v2.3.2")
        preserved_manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
        self.assertEqual(preserved_manifest["version"], "2.3.2")

        # Verify receipt records failure and rollback
        self.assertTrue(receipt_file.exists())
        receipt = json.loads(receipt_file.read_text(encoding="utf-8"))
        self.assertEqual(receipt["status"], "failed")
        self.assertTrue(receipt["rollback_attempted"])
        self.assertEqual(receipt["from_version"], "2.3.2")
        self.assertEqual(receipt["to_version"], "2.4.1")

    # --- Gate 31: Update Lock Transfer Fail-Closed Invariant ---
    @patch("subprocess.Popen")
    @patch("subprocess.run")
    def test_lock_transfer_failure_never_reports_handoff_started(self, mock_sub_run, mock_popen):
        """UPDATE-FINAL-31: If atomic lock transfer to installer fails, aborts child and returns FAILED."""
        mock_proc = MagicMock()
        mock_proc.pid = 98765
        mock_popen.return_value = mock_proc

        mock_ver_res = MagicMock()
        mock_ver_res.returncode = 0
        mock_ver_res.stdout = "disk-investigator-setup 2.4.2"
        mock_ver_res.stderr = ""
        mock_sub_run.return_value = mock_ver_res

        mock_client = MagicMock()
        mock_client.get_latest_release.return_value = ReleaseInfo(
            tag="v2.4.2",
            version="2.4.2",
            release_url="https://github.com/codevcn/disk-cleaner/releases/tag/v2.4.2",
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

        with patch.object(self.engine, "transfer_update_lock_to_installer", return_value=False):
            res = self.engine.execute_update(current_version="2.3.2", yes=True, release_client=mock_client)
            self.assertEqual(res.state, UpdateState.FAILED)
            self.assertIn("Failed to transfer update lock ownership", res.message)
            mock_proc.terminate.assert_called_once()
            self.assertFalse(self.engine.update_lock_file.exists(), "Staging lock must be released on abort")

    # --- Gate 32: Lock Owner Access Denied is Not Treated as Dead ---
    def test_lock_owner_access_denied_is_not_treated_as_dead(self):
        """UPDATE-FINAL-32: Unknown lock owner state (Access Denied) fails closed within active safety window."""
        self.engine.update_lock_file.parent.mkdir(parents=True, exist_ok=True)
        self.engine.update_lock_file.write_text(json.dumps({
            "owner_pid": 55555,
            "phase": "staging",
            "time": time.time() - 30,  # 30 seconds ago
        }), encoding="utf-8")

        with patch("disk_investigator.updates.update_engine.check_pid_state", return_value=PidWaitState.UNKNOWN):
            acquired = self.engine.acquire_update_lock()
            self.assertFalse(acquired, "Must not steal lock when owner state is UNKNOWN within safety window")

    # --- Gate 33: Live Installer Lock Not Recovered Only Due to Age ---
    def test_live_installer_lock_not_recovered_only_due_to_age(self):
        """UPDATE-FINAL-33: Actively running installer PID holds lock indefinitely even if age > 10m."""
        self.engine.update_lock_file.parent.mkdir(parents=True, exist_ok=True)
        self.engine.update_lock_file.write_text(json.dumps({
            "owner_pid": 77777,
            "phase": "installer",
            "time": time.time() - 1200,  # 20 minutes ago (> 10m timeout)
        }), encoding="utf-8")

        with patch("disk_investigator.updates.update_engine.check_pid_state", return_value=PidWaitState.RUNNING):
            acquired = self.engine.acquire_update_lock()
            self.assertFalse(acquired, "Live installer must NEVER lose its lock solely due to age")

    # --- Gate 34: Second Update Blocked After Handoff Until Finalizer ---
    def test_second_update_blocked_after_handoff_until_installer_finally(self):
        """UPDATE-FINAL-34: Second update process is rejected after handoff until installer releases lock."""
        # Step 1: First update acquires lock
        self.assertTrue(self.engine.acquire_update_lock())

        # Step 2: Handoff transfers lock to installer PID 88888
        self.assertTrue(self.engine.transfer_update_lock_to_installer(installer_pid=88888, target_version="2.4.2"))

        # Step 3: While installer is RUNNING, second update process tries to acquire lock
        second_engine = UpdateEngine(self.cache_mgr)
        with patch("disk_investigator.updates.update_engine.check_pid_state", return_value=PidWaitState.RUNNING):
            self.assertFalse(second_engine.acquire_update_lock(), "Second process must be blocked during installer execution")

        # Step 4: Installer completes and calls release_update_lock() in finally
        self.engine.release_update_lock()

        # Step 5: Now second update process can acquire lock
        self.assertTrue(second_engine.acquire_update_lock(), "Lock must be acquirable after installer releases it")
        second_engine.release_update_lock()

    # --- Gate 35: Lock Transfer Failure And Child Terminate Failure Keeps Lock (Fail-Closed) ---
    @patch("subprocess.Popen")
    @patch("subprocess.run")
    def test_lock_transfer_failure_and_child_terminate_failure_keeps_lock(self, mock_sub_run, mock_popen):
        """UPDATE-FINAL-35: If lock transfer fails and child installer cannot be confirmed dead, lock remains held (Fail-Closed)."""
        mock_proc = MagicMock()
        mock_proc.pid = 99991
        mock_proc.terminate.side_effect = PermissionError("Access is denied")
        mock_proc.kill.side_effect = PermissionError("Access is denied")
        mock_proc.wait.side_effect = subprocess.TimeoutExpired(cmd="setup", timeout=5.0)
        mock_popen.return_value = mock_proc

        mock_ver_res = MagicMock()
        mock_ver_res.returncode = 0
        mock_ver_res.stdout = "disk-investigator-setup 2.4.3"
        mock_ver_res.stderr = ""
        mock_sub_run.return_value = mock_ver_res

        mock_client = MagicMock()
        mock_client.get_latest_release.return_value = ReleaseInfo(
            tag="v2.4.3",
            version="2.4.3",
            release_url="https://github.com/codevcn/disk-cleaner/releases/tag/v2.4.3",
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

        with patch.object(self.engine, "transfer_update_lock_to_installer", return_value=False):
            with patch("disk_investigator.updates.update_engine.check_pid_state", return_value=PidWaitState.RUNNING):
                res = self.engine.execute_update(current_version="2.3.2", yes=True, release_client=mock_client)
                self.assertEqual(res.state, UpdateState.FAILED)
                self.assertIn("unable to verify child installer termination", res.message)
                self.assertTrue(self.engine.update_lock_file.exists(), "Lock must NOT be released if child process state is unconfirmed (Fail-Closed)")

    # --- Gate 36: Lock Transfer Failure Waits Until Child Exit Before Releasing Lock ---
    @patch("subprocess.Popen")
    @patch("subprocess.run")
    def test_lock_transfer_failure_waits_until_child_exit_before_releasing_lock(self, mock_sub_run, mock_popen):
        """UPDATE-FINAL-36: If lock transfer fails, installer is terminated and waited on before lock is released."""
        mock_proc = MagicMock()
        mock_proc.pid = 99992
        mock_proc.wait.return_value = 0
        mock_popen.return_value = mock_proc

        mock_ver_res = MagicMock()
        mock_ver_res.returncode = 0
        mock_ver_res.stdout = "disk-investigator-setup 2.4.3"
        mock_ver_res.stderr = ""
        mock_sub_run.return_value = mock_ver_res

        mock_client = MagicMock()
        mock_client.get_latest_release.return_value = ReleaseInfo(
            tag="v2.4.3",
            version="2.4.3",
            release_url="https://github.com/codevcn/disk-cleaner/releases/tag/v2.4.3",
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

        with patch.object(self.engine, "transfer_update_lock_to_installer", return_value=False):
            res = self.engine.execute_update(current_version="2.3.2", yes=True, release_client=mock_client)
            self.assertEqual(res.state, UpdateState.FAILED)
            mock_proc.terminate.assert_called_once()
            mock_proc.wait.assert_called_with(timeout=5.0)
            self.assertFalse(self.engine.update_lock_file.exists(), "Lock must be cleanly released after child process confirmed exited")

    # --- Gate 37: Installer Refuses Mutation When Update ID Or Owner Mismatches ---
    def test_installer_refuses_mutation_when_update_id_or_owner_mismatches(self):
        """UPDATE-FINAL-37: Installer validates update.lock ownership and update_id before any file mutations."""
        with tempfile.TemporaryDirectory() as tmp_env:
            env_root = Path(tmp_env)
            local_app = env_root / "LocalAppData"
            user_prof = env_root / "UserProfile"
            bin_dir = local_app / "DiskInvestigator" / "bin"
            skill_dir = user_prof / ".gemini" / "config" / "skills" / "disk-cleanup"
            bin_dir.mkdir(parents=True, exist_ok=True)
            skill_dir.mkdir(parents=True, exist_ok=True)

            target_exe = bin_dir / "disk_investigator.exe"
            target_exe.write_bytes(b"ORIGINAL_UNTOUCHED_BIN")

            updates_dir = local_app / "DiskInvestigator" / "updates"
            updates_dir.mkdir(parents=True, exist_ok=True)
            lock_file = updates_dir / "update.lock"
            receipt_file = updates_dir / "last_update_result.json"

            # Scenario: Lock belongs to a different owner / different update_id
            lock_file.write_text(json.dumps({
                "update_id": "tx_legit_id_999",
                "owner_pid": 99999,  # Not current PID
                "phase": "installer",
                "target_version": "2.4.4",
                "time": time.time(),
            }), encoding="utf-8")

            with patch.dict(os.environ, {"LOCALAPPDATA": str(local_app), "USERPROFILE": str(user_prof)}):
                with patch("installer.wait_for_pid_to_exit", return_value=PidWaitState.EXITED):
                    ok = install(
                        silent=True,
                        wait_for_pid=1234,
                        update_result=receipt_file,
                        update_id="tx_rogue_id_111",
                    )
                    self.assertFalse(ok, "Installer must reject execution when update_id / owner PID mismatches")
                    self.assertEqual(target_exe.read_bytes(), b"ORIGINAL_UNTOUCHED_BIN", "Files must not be modified (Zero Mutation)")
                    self.assertTrue(receipt_file.exists())
                    receipt = json.loads(receipt_file.read_text(encoding="utf-8"))
                    self.assertEqual(receipt["status"], "failed")
                    self.assertIn("mismatch", receipt["error_message"].lower())

    # --- Gate 38: Old Installer Cannot Delete Newer Transaction Lock ---
    def test_old_installer_cannot_delete_newer_transaction_lock(self):
        """UPDATE-FINAL-38: An installer completing or aborting cannot delete an update.lock owned by a newer transaction."""
        with tempfile.TemporaryDirectory() as tmp_env:
            local_app = Path(tmp_env) / "LocalAppData"
            updates_dir = local_app / "DiskInvestigator" / "updates"
            updates_dir.mkdir(parents=True, exist_ok=True)
            lock_file = updates_dir / "update.lock"

            # Newer transaction lock active on disk
            newer_lock_data = {
                "update_id": "tx_newer_tx_888",
                "owner_pid": 88888,
                "phase": "staging",
                "time": time.time(),
            }
            lock_file.write_text(json.dumps(newer_lock_data), encoding="utf-8")

            with patch.dict(os.environ, {"LOCALAPPDATA": str(local_app)}):
                # Old installer (with tx_older_tx_111, owner 11111) tries to release lock
                release_update_lock(expected_update_id="tx_older_tx_111", expected_owner_pid=11111)

                # Lock must NOT be deleted
                self.assertTrue(lock_file.exists(), "Newer transaction lock must survive rogue cleanup from old process")
                content = json.loads(lock_file.read_text(encoding="utf-8"))
                self.assertEqual(content["update_id"], "tx_newer_tx_888")

    # --- Gate 39: Unconfirmed Old Child And Parent Exit Cannot Overlap Second Update ---
    def test_unconfirmed_old_child_and_parent_exit_cannot_overlap_second_update(self):
        """UPDATE-FINAL-39: Even if child installer could not be killed and parent exits, second update is safe from old child."""
        with tempfile.TemporaryDirectory() as tmp_env:
            local_app = Path(tmp_env) / "LocalAppData"
            user_prof = Path(tmp_env) / "UserProfile"
            bin_dir = local_app / "DiskInvestigator" / "bin"
            updates_dir = local_app / "DiskInvestigator" / "updates"
            bin_dir.mkdir(parents=True, exist_ok=True)
            updates_dir.mkdir(parents=True, exist_ok=True)

            target_exe = bin_dir / "disk_investigator.exe"
            target_exe.write_bytes(b"EXISTING_STABLE_BINARY")

            cache_mgr = UpdateCacheManager(base_dir=updates_dir)
            engine_b = UpdateEngine(cache_mgr)

            with patch.dict(os.environ, {"LOCALAPPDATA": str(local_app), "USERPROFILE": str(user_prof)}):
                # 1. Old Updater A retained lock because child could not be confirmed dead
                old_tx_id = "tx_updater_A_111"
                old_updater_pid = 71111
                old_installer_pid = 72222
                engine_b.update_lock_file.write_text(json.dumps({
                    "update_id": old_tx_id,
                    "owner_pid": old_updater_pid,
                    "phase": "staging",
                    "time": time.time(),
                }), encoding="utf-8")

                # 2. Updater A exits (old_updater_pid becomes EXITED)
                with patch("disk_investigator.updates.update_engine.check_pid_state", return_value=PidWaitState.EXITED):
                    # 3. Second Updater B runs and acquires new lock
                    new_tx_id = "tx_updater_B_222"
                    acquired = engine_b.acquire_update_lock(update_id=new_tx_id)
                    self.assertTrue(acquired, "Updater B successfully recovers and acquires new transaction lock")

                # 4. Meanwhile, old unconfirmed child Installer A wakes up with old_tx_id
                with patch("installer.wait_for_pid_to_exit", return_value=PidWaitState.EXITED):
                    receipt_path = updates_dir / "installer_a_receipt.json"
                    success = install(
                        silent=True,
                        wait_for_pid=old_updater_pid,
                        update_result=receipt_path,
                        update_id=old_tx_id,
                    )
                    self.assertFalse(success, "Old child Installer A must abort without performing mutation")
                    self.assertEqual(target_exe.read_bytes(), b"EXISTING_STABLE_BINARY", "Target binary must remain completely untouched")

                # 5. Verify Installer A's cleanup did NOT destroy Updater B's lock
                self.assertTrue(engine_b.update_lock_file.exists(), "Updater B's active lock must remain intact")
                current_lock = json.loads(engine_b.update_lock_file.read_text(encoding="utf-8"))
                self.assertEqual(current_lock["update_id"], new_tx_id)


if __name__ == "__main__":
    unittest.main()
