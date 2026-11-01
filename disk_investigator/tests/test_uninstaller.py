#!/usr/bin/env python3
"""
test_uninstaller.py - Unit and Integration Tests for Standalone Uninstaller Engine
and UNINSTALL-FINAL-01 to UNINSTALL-FINAL-18 Acceptance Gates.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import installer
import uninstaller
from disk_investigator.lifecycle import (
    KNOWN_OWNED_FILES,
    KNOWN_OWNED_SUBDIRS,
    RELEASE_ASSETS,
    ProcessState,
    UninstallEngine,
    UninstallResult,
    UninstallStatus,
    compute_sha256,
)


class TestUninstallEngine(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.test_root = Path(self.tmp_dir.name)

        self.install_dir = self.test_root / "install"
        self.bin_dir = self.install_dir / "bin"
        self.lifecycle_dir = self.install_dir / "lifecycle"
        self.skill_dir = self.test_root / "skill"
        self.skill_ref_dir = self.skill_dir / "references"

        self.install_dir.mkdir(parents=True, exist_ok=True)
        self.bin_dir.mkdir(parents=True, exist_ok=True)
        self.lifecycle_dir.mkdir(parents=True, exist_ok=True)
        self.skill_dir.mkdir(parents=True, exist_ok=True)
        self.skill_ref_dir.mkdir(parents=True, exist_ok=True)

        self.binary_exe = self.bin_dir / "disk_investigator.exe"
        self.binary_exe.write_text("MOCK BINARY", encoding="utf-8")

        self.readme_file = self.install_dir / "README.md"
        self.readme_file.write_text("MOCK README", encoding="utf-8")

        self.skill_file = self.skill_dir / "SKILL.md"
        self.skill_file.write_text("MOCK SKILL CONTENT", encoding="utf-8")

        self.skill_ref_file = self.skill_ref_dir / "README.md"
        self.skill_ref_file.write_text("MOCK REF README", encoding="utf-8")

        self.manifest_file = self.install_dir / "install_manifest.json"
        manifest_data = {
            "app_name": "DiskInvestigator",
            "version": "2.3.0",
            "bin_file": str(self.binary_exe),
            "docs_file": str(self.readme_file),
            "skill_file": str(self.skill_file),
            "skill_sha256": compute_sha256(self.skill_file),
        }
        with open(self.manifest_file, "w", encoding="utf-8") as f:
            json.dump(manifest_data, f, indent=2)

    def tearDown(self):
        self.tmp_dir.cleanup()

    @patch("disk_investigator.lifecycle.uninstall_core.check_process_state", return_value=ProcessState.NOT_RUNNING)
    @patch("disk_investigator.lifecycle.uninstall_core.remove_bin_from_user_path", return_value=True)
    def test_uninstall_default_preserves_runtime_data(self, mock_remove_path, mock_proc):
        """UNINSTALL-FINAL-03: Default uninstall must preserve logs, cache, and state."""
        logs_dir = self.install_dir / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        log_file = logs_dir / "run_20261101.log"
        log_file.write_text("Log content", encoding="utf-8")

        cache_dir = self.install_dir / "cache"
        cache_dir.mkdir(parents=True, exist_ok=True)
        cache_file = cache_dir / "metadata.json"
        cache_file.write_text("{}", encoding="utf-8")

        plans_dir = self.install_dir / "plans"
        plans_dir.mkdir(parents=True, exist_ok=True)
        plan_file = plans_dir / "plan_abc.json"
        plan_file.write_text("{}", encoding="utf-8")

        res = UninstallEngine.execute(
            purge_data=False,
            silent=True,
            install_dir_override=self.install_dir,
            bin_dir_override=self.bin_dir,
            skill_dir_override=self.skill_dir,
        )

        self.assertEqual(res.status, UninstallStatus.SUCCESS)
        self.assertEqual(res.exit_code, 0)
        self.assertFalse(self.binary_exe.exists(), "Binary executable should be removed")
        self.assertTrue(log_file.exists(), "Runtime log file must be preserved in default uninstall")
        self.assertTrue(cache_file.exists(), "Cache file must be preserved in default uninstall")
        self.assertTrue(plan_file.exists(), "Plan file must be preserved in default uninstall")

    @patch("disk_investigator.lifecycle.uninstall_core.check_process_state", return_value=ProcessState.NOT_RUNNING)
    @patch("disk_investigator.lifecycle.uninstall_core.remove_bin_from_user_path", return_value=True)
    def test_purge_removes_known_owned_data(self, mock_remove_path, mock_proc):
        """UNINSTALL-FINAL-04: Purge removes known tool data (logs, cache, plans)."""
        logs_dir = self.install_dir / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        (logs_dir / "run.log").write_text("log", encoding="utf-8")

        cache_dir = self.install_dir / "cache"
        cache_dir.mkdir(parents=True, exist_ok=True)
        (cache_dir / "cache.db").write_text("db", encoding="utf-8")

        res = UninstallEngine.execute(
            purge_data=True,
            silent=True,
            install_dir_override=self.install_dir,
            bin_dir_override=self.bin_dir,
            skill_dir_override=self.skill_dir,
        )

        self.assertEqual(res.status, UninstallStatus.SUCCESS)
        self.assertEqual(res.exit_code, 0)
        self.assertTrue(res.runtime_data_removed)
        self.assertFalse(logs_dir.exists(), "Known logs directory must be removed on purge")
        self.assertFalse(cache_dir.exists(), "Known cache directory must be removed on purge")
        self.assertFalse(self.install_dir.exists(), "Install dir should be removed when empty")

    @patch("disk_investigator.lifecycle.uninstall_core.check_process_state", return_value=ProcessState.NOT_RUNNING)
    @patch("disk_investigator.lifecycle.uninstall_core.remove_bin_from_user_path", return_value=True)
    def test_purge_preserves_unknown_file(self, mock_remove_path, mock_proc):
        """UNINSTALL-FINAL-04: Purge MUST NEVER delete unknown user files."""
        user_notes = self.install_dir / "user_notes.txt"
        user_notes.write_text("CRITICAL USER DATA", encoding="utf-8")

        custom_folder = self.install_dir / "my_custom_plugins"
        custom_folder.mkdir(parents=True, exist_ok=True)
        custom_file = custom_folder / "plugin.py"
        custom_file.write_text("print('custom')", encoding="utf-8")

        res = UninstallEngine.execute(
            purge_data=True,
            silent=True,
            install_dir_override=self.install_dir,
            bin_dir_override=self.bin_dir,
            skill_dir_override=self.skill_dir,
        )

        self.assertEqual(res.status, UninstallStatus.SUCCESS)
        self.assertTrue(user_notes.exists(), "Unknown user file must NOT be deleted")
        self.assertTrue(custom_file.exists(), "Unknown user folder content must NOT be deleted")
        self.assertTrue(self.install_dir.exists(), "Install dir must NOT be deleted if it contains user data")
        self.assertIn(str(user_notes), res.preserved_paths)
        self.assertIn(str(custom_folder), res.preserved_paths)

    @patch("disk_investigator.lifecycle.uninstall_core.check_process_state", return_value=ProcessState.NOT_RUNNING)
    @patch("disk_investigator.lifecycle.uninstall_core.remove_bin_from_user_path", return_value=True)
    def test_modified_skill_is_preserved(self, mock_remove_path, mock_proc):
        """UNINSTALL-FINAL-05: Modified SKILL.md and user backups are preserved."""
        # Modify skill file so its hash differs from manifest
        self.skill_file.write_text("USER EDITED SKILL CONTENT", encoding="utf-8")

        # Create a user backup file
        backup_file = self.skill_dir / "SKILL.md.user-backup-20261101_100000"
        backup_file.write_text("BACKUP CONTENT", encoding="utf-8")

        res = UninstallEngine.execute(
            purge_data=False,
            silent=True,
            install_dir_override=self.install_dir,
            bin_dir_override=self.bin_dir,
            skill_dir_override=self.skill_dir,
        )

        self.assertEqual(res.status, UninstallStatus.SUCCESS)
        self.assertTrue(res.skill_preserved)
        self.assertTrue(self.skill_file.exists(), "Modified SKILL.md must be preserved")
        self.assertTrue(backup_file.exists(), "User backup file must be preserved")
        self.assertIn(str(self.skill_file), res.preserved_paths)
        self.assertIn(str(backup_file), res.preserved_paths)

    @patch("disk_investigator.lifecycle.uninstall_core.check_process_state", return_value=ProcessState.NOT_RUNNING)
    @patch("disk_investigator.lifecycle.uninstall_core.remove_bin_from_user_path", return_value=True)
    def test_unmodified_skill_is_removed(self, mock_remove_path, mock_proc):
        """UNINSTALL-FINAL-05: Unmodified SKILL.md matching manifest is removed."""
        res = UninstallEngine.execute(
            purge_data=False,
            silent=True,
            install_dir_override=self.install_dir,
            bin_dir_override=self.bin_dir,
            skill_dir_override=self.skill_dir,
        )

        self.assertEqual(res.status, UninstallStatus.SUCCESS)
        self.assertTrue(res.skill_removed)
        self.assertFalse(self.skill_file.exists(), "Unmodified SKILL.md should be safely unlinked")

    @patch("disk_investigator.lifecycle.uninstall_core.check_process_state", return_value=ProcessState.NOT_RUNNING)
    @patch("disk_investigator.lifecycle.uninstall_core.remove_bin_from_user_path", return_value=True)
    def test_missing_manifest_fails_conservatively(self, mock_remove_path, mock_proc):
        """UNINSTALL-FINAL-07: Missing manifest triggers conservative fallback."""
        if self.manifest_file.exists():
            self.manifest_file.unlink()

        # Skill has custom content not matching default
        self.skill_file.write_text("SOME UNVERIFIABLE SKILL CONTENT", encoding="utf-8")

        res = UninstallEngine.execute(
            purge_data=False,
            silent=True,
            install_dir_override=self.install_dir,
            bin_dir_override=self.bin_dir,
            skill_dir_override=self.skill_dir,
        )

        self.assertEqual(res.status, UninstallStatus.SUCCESS)
        self.assertTrue(self.skill_file.exists(), "Skill without verifiable manifest hash must be preserved")

    @patch("disk_investigator.lifecycle.uninstall_core.check_process_state", return_value=ProcessState.NOT_RUNNING)
    @patch("disk_investigator.lifecycle.uninstall_core.remove_bin_from_user_path", return_value=True)
    def test_corrupt_manifest_fails_conservatively(self, mock_remove_path, mock_proc):
        """UNINSTALL-FINAL-07: Corrupt manifest triggers conservative fallback without crash."""
        self.manifest_file.write_text("{ corrupt json: broken !!!", encoding="utf-8")

        res = UninstallEngine.execute(
            purge_data=False,
            silent=True,
            install_dir_override=self.install_dir,
            bin_dir_override=self.bin_dir,
            skill_dir_override=self.skill_dir,
        )

        self.assertIn(res.status, [UninstallStatus.SUCCESS, UninstallStatus.PARTIAL])
        self.assertTrue(any("hỏng" in w for w in res.warnings))

    def test_manifest_path_escape_is_rejected(self):
        """UNINSTALL-FINAL-06: Manifest paths outside target roots are rejected."""
        escaped_file = self.test_root / "outside_target" / "danger.txt"
        escaped_file.parent.mkdir(parents=True, exist_ok=True)
        escaped_file.write_text("TOP SECRET FILE", encoding="utf-8")

        manifest_with_escape = {
            "app_name": "DiskInvestigator",
            "version": "2.3.0",
            "bin_file": str(escaped_file),
            "docs_file": str(self.readme_file),
        }
        with open(self.manifest_file, "w", encoding="utf-8") as f:
            json.dump(manifest_with_escape, f)

        # Preflight check should flag warning
        can_proceed, status, errors, warnings = UninstallEngine.preflight_check(
            self.install_dir, self.bin_dir, self.skill_dir
        )
        self.assertTrue(any("ngoài phạm vi" in w for w in warnings))

        # Scope validation method directly
        is_safe = UninstallEngine.is_within_scope(
            escaped_file, [self.install_dir.resolve(), self.skill_dir.resolve()]
        )
        self.assertFalse(is_safe, "Escaped file path must be rejected by scope validation")
        self.assertTrue(escaped_file.exists(), "Escaped file must never be deleted")

    @patch("disk_investigator.lifecycle.uninstall_core.check_process_state", return_value=ProcessState.RUNNING)
    def test_running_cli_blocks_before_any_mutation(self, mock_proc):
        """UNINSTALL-FINAL-08 & 10: Running CLI blocks uninstallation before any mutation."""
        res = UninstallEngine.execute(
            purge_data=False,
            silent=True,
            install_dir_override=self.install_dir,
            bin_dir_override=self.bin_dir,
            skill_dir_override=self.skill_dir,
        )

        self.assertEqual(res.status, UninstallStatus.BLOCKED)
        self.assertEqual(res.exit_code, 4)
        self.assertTrue(self.binary_exe.exists(), "Binary must not be deleted when process is running")
        self.assertTrue(self.skill_file.exists(), "Skill must not be deleted when process is running")

    @patch("disk_investigator.lifecycle.uninstall_core.check_process_state", return_value=ProcessState.UNKNOWN)
    def test_unknown_process_state_blocks_before_any_mutation(self, mock_proc):
        """UNINSTALL-FINAL-09: ProcessState.UNKNOWN fails closed before mutation."""
        res = UninstallEngine.execute(
            purge_data=False,
            silent=True,
            install_dir_override=self.install_dir,
            bin_dir_override=self.bin_dir,
            skill_dir_override=self.skill_dir,
        )

        self.assertEqual(res.status, UninstallStatus.BLOCKED)
        self.assertEqual(res.exit_code, 4)
        self.assertTrue(self.binary_exe.exists(), "Binary must not be deleted if process state is UNKNOWN")

    @patch("disk_investigator.lifecycle.uninstall_core.check_process_state", return_value=ProcessState.NOT_RUNNING)
    @patch("disk_investigator.lifecycle.uninstall_core.remove_bin_from_user_path", return_value=True)
    def test_uninstaller_never_deletes_itself(self, mock_remove_path, mock_proc):
        """UNINSTALL-FINAL-11: Running executable in lifecycle is never self-deleted."""
        running_uninstaller = self.lifecycle_dir / "disk-investigator-uninstall.exe"
        running_uninstaller.write_text("MOCK RUNNING UNINSTALLER", encoding="utf-8")

        with patch("sys.executable", str(running_uninstaller)):
            res = UninstallEngine.execute(
                purge_data=False,
                silent=True,
                install_dir_override=self.install_dir,
                bin_dir_override=self.bin_dir,
                skill_dir_override=self.skill_dir,
            )

        self.assertEqual(res.status, UninstallStatus.SUCCESS)
        self.assertTrue(running_uninstaller.exists(), "Running executable must not attempt self-deletion")
        self.assertIn(str(running_uninstaller), res.preserved_paths)

    @patch("disk_investigator.lifecycle.uninstall_core.check_process_state", return_value=ProcessState.NOT_RUNNING)
    @patch("disk_investigator.lifecycle.uninstall_core.remove_bin_from_user_path", return_value=True)
    def test_uninstaller_never_deletes_itself_under_purge(self, mock_remove_path, mock_proc):
        """UNINSTALL-FINAL-11: Running executable in lifecycle is preserved even under --purge-data."""
        running_uninstaller = self.lifecycle_dir / "disk-investigator-uninstall.exe"
        running_uninstaller.write_text("RUNNING UNINSTALLER BINARY", encoding="utf-8")

        with patch("sys.executable", str(running_uninstaller)):
            res = UninstallEngine.execute(
                purge_data=True,
                silent=True,
                install_dir_override=self.install_dir,
                bin_dir_override=self.bin_dir,
                skill_dir_override=self.skill_dir,
            )

        self.assertEqual(res.status, UninstallStatus.SUCCESS)
        self.assertTrue(running_uninstaller.exists(), "Running executable must be preserved under purge")
        self.assertTrue(self.lifecycle_dir.exists(), "Directory containing running executable must be preserved")
        self.assertTrue(self.install_dir.exists(), "Install directory containing running executable must be preserved")
        self.assertIn(str(running_uninstaller), res.preserved_paths)

    @patch("disk_investigator.lifecycle.uninstall_core.check_process_state", return_value=ProcessState.NOT_RUNNING)
    @patch("disk_investigator.lifecycle.uninstall_core.remove_bin_from_user_path", return_value=True)
    def test_unknown_file_inside_known_dir_is_preserved(self, mock_remove_path, mock_proc):
        """UNINSTALL-FINAL-04: Unknown user file inside known owned directory is preserved."""
        logs_dir = self.install_dir / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        user_log_note = logs_dir / "my_custom_incident_report.txt"
        user_log_note.write_text("CRITICAL USER INCIDENT NOTE", encoding="utf-8")

        cache_dir = self.install_dir / "cache"
        cache_dir.mkdir(parents=True, exist_ok=True)
        user_cache_model = cache_dir / "custom_model.weights"
        user_cache_model.write_text("CUSTOM MODEL DATA", encoding="utf-8")

        res = UninstallEngine.execute(
            purge_data=True,
            silent=True,
            install_dir_override=self.install_dir,
            bin_dir_override=self.bin_dir,
            skill_dir_override=self.skill_dir,
        )

        self.assertEqual(res.status, UninstallStatus.SUCCESS)
        self.assertTrue(user_log_note.exists(), "Unknown user file in logs/ must be preserved")
        self.assertTrue(user_cache_model.exists(), "Unknown user file in cache/ must be preserved")
        self.assertTrue(logs_dir.exists(), "Logs dir containing unknown user file must not be removed")
        self.assertTrue(cache_dir.exists(), "Cache dir containing unknown user file must not be removed")
        self.assertIn(str(user_log_note), res.preserved_paths)
        self.assertIn(str(user_cache_model), res.preserved_paths)

    def test_manifest_reparse_escape_is_rejected(self):
        """UNINSTALL-FINAL-06: Manifest path escaping via reparse/symlink/relative escape is rejected."""
        outside_secret = self.test_root / "outside_dir" / "secret_document.docx"
        outside_secret.parent.mkdir(parents=True, exist_ok=True)
        outside_secret.write_text("CONFIDENTIAL", encoding="utf-8")

        traversal_path = self.install_dir / ".." / "outside_dir" / "secret_document.docx"
        manifest_with_escape = {
            "app_name": "DiskInvestigator",
            "version": "2.3.1",
            "bin_file": str(traversal_path),
        }
        with open(self.manifest_file, "w", encoding="utf-8") as f:
            json.dump(manifest_with_escape, f)

        can_proceed, status, errors, warnings = UninstallEngine.preflight_check(
            self.install_dir, self.bin_dir, self.skill_dir
        )
        self.assertTrue(any("ngoài phạm vi" in w for w in warnings))
        self.assertFalse(
            UninstallEngine.is_within_scope(traversal_path, [self.install_dir, self.skill_dir])
        )
        self.assertTrue(outside_secret.exists())

    @patch("disk_investigator.lifecycle.uninstall_core.check_process_state", return_value=ProcessState.NOT_RUNNING)
    @patch("disk_investigator.lifecycle.uninstall_core.remove_bin_from_user_path", return_value=False)
    def test_path_removal_failure_not_reported_as_success(self, mock_remove_path, mock_proc):
        """UNINSTALL-FINAL-13: PATH removal failure reports PARTIAL or FAILED, never SUCCESS."""
        res = UninstallEngine.execute(
            purge_data=False,
            silent=True,
            install_dir_override=self.install_dir,
            bin_dir_override=self.bin_dir,
            skill_dir_override=self.skill_dir,
        )
        self.assertNotEqual(res.status, UninstallStatus.SUCCESS)
        self.assertIn(res.status, [UninstallStatus.PARTIAL, UninstallStatus.FAILED])
        self.assertIn(res.exit_code, [1, 3])
        self.assertTrue(any("PATH" in err for err in res.errors))

    @patch("disk_investigator.lifecycle.uninstall_core.check_process_state", return_value=ProcessState.NOT_RUNNING)
    @patch("disk_investigator.lifecycle.uninstall_core.remove_bin_from_user_path", return_value=True)
    def test_binary_delete_failure_reports_partial_or_failed(self, mock_remove_path, mock_proc):
        """UNINSTALL-FINAL-13: Binary deletion failure reports PARTIAL or FAILED, never SUCCESS."""
        with patch("disk_investigator.lifecycle.uninstall_core.safe_delete_file") as mock_del:
            def fake_del(f_path, res, roots):
                if "disk_investigator.exe" in str(f_path):
                    res.errors.append("File locked by system")
                    return False
                return True
            mock_del.side_effect = fake_del

            res = UninstallEngine.execute(
                purge_data=False,
                silent=True,
                install_dir_override=self.install_dir,
                bin_dir_override=self.bin_dir,
                skill_dir_override=self.skill_dir,
            )
            self.assertNotEqual(res.status, UninstallStatus.SUCCESS)
            self.assertIn(res.status, [UninstallStatus.PARTIAL, UninstallStatus.FAILED])
            self.assertFalse(res.binary_removed)

    @patch("disk_investigator.lifecycle.uninstall_core.check_process_state", return_value=ProcessState.NOT_RUNNING)
    @patch("disk_investigator.lifecycle.uninstall_core.remove_bin_from_user_path", return_value=True)
    def test_uninstall_is_idempotent(self, mock_remove_path, mock_proc):
        """UNINSTALL-FINAL-02: Executing uninstall repeatedly succeeds idempotently."""
        res1 = UninstallEngine.execute(
            purge_data=False,
            silent=True,
            install_dir_override=self.install_dir,
            bin_dir_override=self.bin_dir,
            skill_dir_override=self.skill_dir,
        )
        self.assertEqual(res1.status, UninstallStatus.SUCCESS)

        # Second execution on already uninstalled directory
        res2 = UninstallEngine.execute(
            purge_data=False,
            silent=True,
            install_dir_override=self.install_dir,
            bin_dir_override=self.bin_dir,
            skill_dir_override=self.skill_dir,
        )
        self.assertEqual(res2.status, UninstallStatus.SUCCESS)
        self.assertEqual(res2.exit_code, 0)

    def test_uninstall_cmd_has_no_raw_recursive_fallback(self):
        """UNINSTALL-FINAL-14: uninstall.cmd has no raw destructive rd /s /q fallback."""
        cmd_path = installer.generate_uninstaller_script(
            self.install_dir, self.bin_dir, self.skill_file
        )
        self.assertTrue(cmd_path.exists())
        content = cmd_path.read_text(encoding="utf-8")

        # Crucial safety check: Ensure no "rd /s /q" exists
        self.assertNotIn("rd /s /q", content.lower(), "uninstall.cmd must NEVER contain raw rd /s /q")
        self.assertIn("disk-investigator-uninstall.exe", content)
        self.assertIn("disk-investigator-setup.exe", content)

    def test_sha_manifest_contains_uninstaller(self):
        """UNINSTALL-FINAL-15 & 17: RELEASE_ASSETS includes standalone uninstaller."""
        self.assertIn("disk_investigator.exe", RELEASE_ASSETS)
        self.assertIn("disk-investigator-setup.exe", RELEASE_ASSETS)
        self.assertIn("disk-investigator-uninstall.exe", RELEASE_ASSETS)


class TestUninstallerCLI(unittest.TestCase):
    @patch("builtins.input", return_value="n")
    def test_interactive_cancelled(self, mock_input):
        """UNINSTALL-FINAL-12 & 13: Interactive mode cancel returns code 2."""
        code = uninstaller.run_uninstaller(silent=False, no_pause=True)
        self.assertEqual(code, 2, "Interactive cancellation must return exit code 2 (CANCELLED)")

    @patch("builtins.input", return_value="y")
    @patch("disk_investigator.lifecycle.uninstall_core.UninstallEngine.execute")
    def test_interactive_confirmed(self, mock_exec, mock_input):
        """UNINSTALL-FINAL-12: Interactive confirmation invokes engine."""
        mock_result = UninstallResult(status=UninstallStatus.SUCCESS)
        mock_exec.return_value = mock_result

        code = uninstaller.run_uninstaller(silent=False, no_pause=True)
        self.assertEqual(code, 0)
        mock_exec.assert_called_once()

    @patch("disk_investigator.lifecycle.uninstall_core.UninstallEngine.execute")
    def test_silent_mode_no_prompt(self, mock_exec):
        """UNINSTALL-FINAL-12: Silent mode runs unattended."""
        mock_result = UninstallResult(status=UninstallStatus.SUCCESS)
        mock_exec.return_value = mock_result

        code = uninstaller.run_uninstaller(silent=True, purge_data=True)
        self.assertEqual(code, 0)
        mock_exec.assert_called_once_with(purge_data=True, silent=True)


if __name__ == "__main__":
    unittest.main()
