#!/usr/bin/env python3
"""
test_installer.py - Unit and Integration Tests for Installer Engine (installer.py).
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import installer


class TestInstaller(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.test_root = Path(self.tmp_dir.name)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_compute_sha256(self):
        test_file = self.test_root / "sample.txt"
        test_file.write_text("hello world 123", encoding="utf-8")
        h = installer.compute_sha256(test_file)
        self.assertEqual(len(h), 64)
        # Verify determinism
        self.assertEqual(h, installer.compute_sha256(test_file))

    def test_get_resource_path_dev_mode(self):
        # In dev mode, README.md and SKILL.md should resolve to existing files
        readme = installer.get_resource_path("README.md")
        self.assertTrue(readme.exists(), f"README.md not found at {readme}")

        skill = installer.get_resource_path("SKILL.md")
        self.assertTrue(skill.exists(), f"SKILL.md not found at {skill}")

    def test_manifest_roundtrip(self):
        install_dir = self.test_root / "DiskInvestigator"
        install_dir.mkdir(parents=True, exist_ok=True)

        sample_manifest = {
            "app_name": "DiskInvestigator",
            "version": "2.1.0",
            "bin_sha256": "abc12345",
            "skill_sha256": "def67890",
        }
        installer.write_manifest(install_dir, sample_manifest)

        loaded = installer.load_manifest(install_dir)
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded["app_name"], "DiskInvestigator")
        self.assertEqual(loaded["version"], "2.1.0")
        self.assertEqual(loaded["bin_sha256"], "abc12345")

    @patch("winreg.OpenKey")
    @patch("winreg.QueryValueEx")
    @patch("winreg.SetValueEx")
    @patch("installer.broadcast_environment_change")
    def test_add_bin_to_user_path_new_entry(
        self, mock_broadcast, mock_set_val, mock_query_val, mock_open_key
    ):
        mock_query_val.return_value = (r"C:\Tools;C:\Users\dell\bin", 2)  # 2 is REG_EXPAND_SZ
        target_bin = Path(r"C:\Users\dell\AppData\Local\DiskInvestigator\bin")

        success, changed = installer.add_bin_to_user_path(target_bin)
        self.assertTrue(success)
        self.assertTrue(changed)
        mock_set_val.assert_called_once()
        args, kwargs = mock_set_val.call_args
        # Key is args[0], ValueName is args[1], Reserved is args[2], Type is args[3], Value is args[4]
        self.assertEqual(args[1], "Path")
        self.assertIn(str(target_bin.resolve()), args[4])
        mock_broadcast.assert_called_once()

    @patch("winreg.OpenKey")
    @patch("winreg.QueryValueEx")
    @patch("winreg.SetValueEx")
    @patch("installer.broadcast_environment_change")
    def test_add_bin_to_user_path_already_present(
        self, mock_broadcast, mock_set_val, mock_query_val, mock_open_key
    ):
        target_bin = Path(r"C:\Users\dell\AppData\Local\DiskInvestigator\bin")
        mock_query_val.return_value = (
            rf"C:\Tools;{str(target_bin.resolve())};C:\Other",
            2,
        )

        success, changed = installer.add_bin_to_user_path(target_bin)
        self.assertTrue(success)
        self.assertFalse(changed)
        mock_set_val.assert_not_called()
        mock_broadcast.assert_not_called()

    @patch("winreg.OpenKey")
    @patch("winreg.QueryValueEx")
    @patch("winreg.SetValueEx")
    @patch("installer.broadcast_environment_change")
    def test_remove_bin_from_user_path(
        self, mock_broadcast, mock_set_val, mock_query_val, mock_open_key
    ):
        target_bin = Path(r"C:\Users\dell\AppData\Local\DiskInvestigator\bin")
        mock_query_val.return_value = (
            rf"C:\Tools;{str(target_bin.resolve())};C:\Other",
            2,
        )

        res = installer.remove_bin_from_user_path(target_bin)
        self.assertTrue(res)
        mock_set_val.assert_called_once()
        args, _ = mock_set_val.call_args
        self.assertNotIn(str(target_bin.resolve()), args[4])
        self.assertIn(r"C:\Tools", args[4])
        self.assertIn(r"C:\Other", args[4])
        mock_broadcast.assert_called_once()

    def test_uninstaller_script_generation(self):
        install_dir = self.test_root / "DiskInvestigator"
        bin_dir = install_dir / "bin"
        skill_path = self.test_root / "SKILL.md"
        install_dir.mkdir(parents=True, exist_ok=True)

        cmd_file = installer.generate_uninstaller_script(install_dir, bin_dir, skill_path)
        self.assertTrue(cmd_file.exists())
        content = cmd_file.read_text(encoding="utf-8")
        self.assertIn("GỠ BỎ CÀI ĐẶT", content)
        self.assertIn("DiskInvestigator", content)

    @patch("installer.get_resource_path")
    @patch("installer.get_target_directories")
    @patch("installer.add_bin_to_user_path")
    @patch("installer.run_smoke_test")
    def test_install_skill_backup_on_user_modification(
        self, mock_smoke, mock_add_path, mock_get_dirs, mock_resource
    ):
        # Setup simulated directories
        inst_dir = self.test_root / "install"
        bin_dir = inst_dir / "bin"
        skill_dir = self.test_root / "skill"
        skill_ref_dir = skill_dir / "references"
        payload_dir = self.test_root / "payload"
        payload_dir.mkdir(parents=True, exist_ok=True)

        src_exe = payload_dir / "disk_investigator.exe"
        src_exe.write_text("MOCK BINARY", encoding="utf-8")
        src_skill = payload_dir / "SKILL.md"
        src_skill.write_text("MOCK NEW SKILL", encoding="utf-8")
        src_readme = payload_dir / "README.md"
        src_readme.write_text("MOCK README", encoding="utf-8")

        def fake_resource(name):
            return payload_dir / name

        mock_resource.side_effect = fake_resource
        mock_get_dirs.return_value = (inst_dir, bin_dir, skill_dir, skill_ref_dir)
        mock_add_path.return_value = (True, True)
        mock_smoke.return_value = True

        # Pre-create an existing user-customized skill and previous manifest
        skill_dir.mkdir(parents=True, exist_ok=True)
        inst_dir.mkdir(parents=True, exist_ok=True)
        bin_dir.mkdir(parents=True, exist_ok=True)

        custom_skill = skill_dir / "SKILL.md"
        custom_skill.write_text("USER CUSTOM CONTENT THAT MUST NOT BE LOST", encoding="utf-8")

        # Previous manifest recorded a DIFFERENT hash (e.g. original default)
        prev_manifest = {
            "app_name": "DiskInvestigator",
            "version": "2.0.3",
            "skill_sha256": "original_different_hash",
        }
        installer.write_manifest(inst_dir, prev_manifest)

        # Run install
        ok = installer.install(silent=True)
        self.assertTrue(ok)

        # Check that backup file was created
        backup_files = list(skill_dir.glob("SKILL.md.user-backup-*"))
        self.assertEqual(len(backup_files), 1, "Backup file should have been generated")
        self.assertEqual(
            backup_files[0].read_text(encoding="utf-8"),
            "USER CUSTOM CONTENT THAT MUST NOT BE LOST",
        )

    @patch("installer.get_resource_path")
    @patch("installer.get_target_directories")
    @patch("installer.add_bin_to_user_path")
    @patch("installer.remove_bin_from_user_path")
    @patch("installer.run_smoke_test")
    def test_install_rollback_on_smoke_failure_path_newly_added(
        self, mock_smoke, mock_remove_path, mock_add_path, mock_get_dirs, mock_resource
    ):
        inst_dir = self.test_root / "install"
        bin_dir = inst_dir / "bin"
        skill_dir = self.test_root / "skill"
        skill_ref_dir = skill_dir / "references"
        payload_dir = self.test_root / "payload"
        payload_dir.mkdir(parents=True, exist_ok=True)

        src_exe = payload_dir / "disk_investigator.exe"
        src_exe.write_text("MOCK BINARY", encoding="utf-8")
        src_skill = payload_dir / "SKILL.md"
        src_skill.write_text("MOCK SKILL", encoding="utf-8")
        src_readme = payload_dir / "README.md"
        src_readme.write_text("MOCK README", encoding="utf-8")

        mock_resource.side_effect = lambda name: payload_dir / name
        mock_get_dirs.return_value = (inst_dir, bin_dir, skill_dir, skill_ref_dir)
        # PATH was newly added during this install (changed=True)
        mock_add_path.return_value = (True, True)
        mock_remove_path.return_value = True
        # Smoke test fails!
        mock_smoke.return_value = False

        inst_dir.mkdir(parents=True, exist_ok=True)
        bin_dir.mkdir(parents=True, exist_ok=True)
        skill_dir.mkdir(parents=True, exist_ok=True)
        skill_ref_dir.mkdir(parents=True, exist_ok=True)

        old_exe = bin_dir / "disk_investigator.exe"
        old_exe.write_text("PREVIOUS WORKING EXE", encoding="utf-8")

        # Install should fail and return False
        ok = installer.install(silent=True)
        self.assertFalse(ok, "Install must return False when smoke test fails")

        # Previous working exe must be restored by rollback
        self.assertTrue(old_exe.exists())
        self.assertEqual(old_exe.read_text(encoding="utf-8"), "PREVIOUS WORKING EXE")
        # PATH removal must have been called since path was changed during install
        mock_remove_path.assert_called_with(bin_dir)

    @patch("installer.get_resource_path")
    @patch("installer.get_target_directories")
    @patch("installer.add_bin_to_user_path")
    @patch("installer.remove_bin_from_user_path")
    @patch("installer.run_smoke_test")
    def test_install_rollback_on_smoke_failure_path_already_present(
        self, mock_smoke, mock_remove_path, mock_add_path, mock_get_dirs, mock_resource
    ):
        inst_dir = self.test_root / "install"
        bin_dir = inst_dir / "bin"
        skill_dir = self.test_root / "skill"
        skill_ref_dir = skill_dir / "references"
        payload_dir = self.test_root / "payload"
        payload_dir.mkdir(parents=True, exist_ok=True)

        src_exe = payload_dir / "disk_investigator.exe"
        src_exe.write_text("MOCK BINARY", encoding="utf-8")
        src_skill = payload_dir / "SKILL.md"
        src_skill.write_text("MOCK SKILL", encoding="utf-8")
        src_readme = payload_dir / "README.md"
        src_readme.write_text("MOCK README", encoding="utf-8")

        mock_resource.side_effect = lambda name: payload_dir / name
        mock_get_dirs.return_value = (inst_dir, bin_dir, skill_dir, skill_ref_dir)
        # PATH was ALREADY present before this install (changed=False)
        mock_add_path.return_value = (True, False)
        mock_remove_path.return_value = True
        mock_smoke.return_value = False

        inst_dir.mkdir(parents=True, exist_ok=True)
        bin_dir.mkdir(parents=True, exist_ok=True)
        skill_dir.mkdir(parents=True, exist_ok=True)
        skill_ref_dir.mkdir(parents=True, exist_ok=True)

        old_exe = bin_dir / "disk_investigator.exe"
        old_exe.write_text("PREVIOUS WORKING EXE", encoding="utf-8")

        # Install should fail and return False
        ok = installer.install(silent=True)
        self.assertFalse(ok)

        # PATH removal must NOT be called since path pre-existed!
        mock_remove_path.assert_not_called()

    @patch("installer.get_resource_path")
    @patch("installer.get_target_directories")
    @patch("installer.add_bin_to_user_path")
    @patch("installer.remove_bin_from_user_path")
    def test_install_rollback_on_path_failure(
        self, mock_remove_path, mock_add_path, mock_get_dirs, mock_resource
    ):
        inst_dir = self.test_root / "install"
        bin_dir = inst_dir / "bin"
        skill_dir = self.test_root / "skill"
        skill_ref_dir = skill_dir / "references"
        payload_dir = self.test_root / "payload"
        payload_dir.mkdir(parents=True, exist_ok=True)

        src_exe = payload_dir / "disk_investigator.exe"
        src_exe.write_text("MOCK BINARY", encoding="utf-8")
        src_skill = payload_dir / "SKILL.md"
        src_skill.write_text("MOCK SKILL", encoding="utf-8")
        src_readme = payload_dir / "README.md"
        src_readme.write_text("MOCK README", encoding="utf-8")

        mock_resource.side_effect = lambda name: payload_dir / name
        mock_get_dirs.return_value = (inst_dir, bin_dir, skill_dir, skill_ref_dir)
        # PATH configuration fails!
        mock_add_path.return_value = (False, False)

        inst_dir.mkdir(parents=True, exist_ok=True)
        bin_dir.mkdir(parents=True, exist_ok=True)
        skill_dir.mkdir(parents=True, exist_ok=True)
        skill_ref_dir.mkdir(parents=True, exist_ok=True)

        old_exe = bin_dir / "disk_investigator.exe"
        old_exe.write_text("OLD BINARY", encoding="utf-8")

        ok = installer.install(silent=True)
        self.assertFalse(ok, "Install must fail-closed if PATH configuration fails")
        # Rollback must restore old binary
        self.assertTrue(old_exe.exists())
        self.assertEqual(old_exe.read_text(encoding="utf-8"), "OLD BINARY")


if __name__ == "__main__":
    unittest.main()
