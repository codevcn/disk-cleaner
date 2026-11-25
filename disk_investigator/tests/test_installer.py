#!/usr/bin/env python3
"""
test_installer.py - Unit and Integration Tests for Installer Engine (installer.py).
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
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

    @patch("installer.get_resource_path")
    @patch("installer.get_target_directories")
    @patch("installer.add_bin_to_user_path")
    @patch("installer.run_smoke_test")
    def test_install_emits_progress_events_1_to_6(
        self, mock_smoke, mock_add_path, mock_get_dirs, mock_resource
    ):
        inst_dir = self.test_root / "install"
        bin_dir = inst_dir / "bin"
        skill_dir = self.test_root / "skill"
        skill_ref_dir = skill_dir / "references"
        payload_dir = self.test_root / "payload"
        payload_dir.mkdir(parents=True, exist_ok=True)

        (payload_dir / "disk_investigator.exe").write_text("MOCK BINARY", encoding="utf-8")
        (payload_dir / "SKILL.md").write_text("MOCK SKILL", encoding="utf-8")
        (payload_dir / "README.md").write_text("MOCK README", encoding="utf-8")

        mock_resource.side_effect = lambda name: payload_dir / name
        mock_get_dirs.return_value = (inst_dir, bin_dir, skill_dir, skill_ref_dir)

        def fake_add_path(target_bin):
            print(f"[+] Đã thêm vào User PATH: {target_bin}")
            return True, True

        mock_add_path.side_effect = fake_add_path
        mock_smoke.return_value = True

        events = []
        ok = installer.install(silent=False, on_progress=events.append)
        self.assertTrue(ok)

        step_events = [e for e in events if e.get("type") == "step"]
        self.assertEqual([e["step"] for e in step_events], [1, 2, 3, 4, 5, 6])
        self.assertTrue(all(e["total_steps"] == 6 for e in step_events))

        lock_events = [e["locked"] for e in events if e.get("type") == "lock_ui"]
        self.assertEqual(lock_events, [True, False])

        result_events = [e for e in events if e.get("type") == "result"]
        self.assertEqual(len(result_events), 1)
        res = result_events[0]
        self.assertTrue(res["success"])
        self.assertFalse(res["rollback_attempted"])
        self.assertEqual(res["target_exe"], str(bin_dir / "disk_investigator.exe"))

        log_messages = [e["message"] for e in events if e.get("type") == "log"]
        self.assertTrue(any("User PATH" in m for m in log_messages))

    @patch("installer.get_resource_path")
    @patch("installer.get_target_directories")
    @patch("installer.add_bin_to_user_path")
    @patch("installer.remove_bin_from_user_path")
    @patch("installer.run_smoke_test")
    def test_install_emits_rollback_result_on_failure(
        self, mock_smoke, mock_remove_path, mock_add_path, mock_get_dirs, mock_resource
    ):
        inst_dir = self.test_root / "install"
        bin_dir = inst_dir / "bin"
        skill_dir = self.test_root / "skill"
        skill_ref_dir = skill_dir / "references"
        payload_dir = self.test_root / "payload"
        payload_dir.mkdir(parents=True, exist_ok=True)

        (payload_dir / "disk_investigator.exe").write_text("MOCK BINARY", encoding="utf-8")
        (payload_dir / "SKILL.md").write_text("MOCK SKILL", encoding="utf-8")
        (payload_dir / "README.md").write_text("MOCK README", encoding="utf-8")

        mock_resource.side_effect = lambda name: payload_dir / name
        mock_get_dirs.return_value = (inst_dir, bin_dir, skill_dir, skill_ref_dir)
        mock_add_path.return_value = (True, True)
        mock_remove_path.return_value = True
        mock_smoke.return_value = False

        events = []
        ok = installer.install(silent=False, on_progress=events.append)
        self.assertFalse(ok)

        lock_events = [e["locked"] for e in events if e.get("type") == "lock_ui"]
        self.assertEqual(lock_events, [True, False])

        result_events = [e for e in events if e.get("type") == "result"]
        self.assertEqual(len(result_events), 1)
        res = result_events[0]
        self.assertFalse(res["success"])
        self.assertTrue(res["rollback_attempted"])
        self.assertTrue(res["rollback_succeeded"])
        self.assertIn("Smoke test", res["error"])

    def test_safe_stdio_under_noconsole_none_streams(self):
        orig_out, orig_err = sys.stdout, sys.stderr
        try:
            sys.stdout = None  # type: ignore[assignment]
            sys.stderr = None  # type: ignore[assignment]
            # Must never raise AttributeError on None stdout/stderr
            installer._safe_print("safe even when stdout is None")
            installer.configure_safe_stdio(attach_parent_console=False)
            self.assertIsNotNone(sys.stdout)
            self.assertIsNotNone(sys.stderr)
            print("safe write to fallback null stream")
            sys.stderr.write("safe stderr write\n")
            sys.stdout.flush()
        finally:
            sys.stdout = orig_out
            sys.stderr = orig_err

    def test_dual_mode_should_launch_gui(self):
        self.assertTrue(
            installer.should_launch_gui(
                argparse.Namespace(uninstall=False, silent=False, wait_for_pid=0)
            )
        )
        self.assertTrue(
            installer.should_launch_gui(
                argparse.Namespace(uninstall=False, silent=False, wait_for_pid=0, repair=True)
            )
        )
        self.assertFalse(
            installer.should_launch_gui(
                argparse.Namespace(uninstall=False, silent=True, wait_for_pid=0)
            )
        )
        self.assertFalse(
            installer.should_launch_gui(
                argparse.Namespace(uninstall=False, silent=False, wait_for_pid=1234)
            )
        )
        self.assertFalse(
            installer.should_launch_gui(
                argparse.Namespace(uninstall=True, silent=False, wait_for_pid=0)
            )
        )
        self.assertFalse(
            installer.should_launch_gui(
                argparse.Namespace(uninstall=True, silent=True, wait_for_pid=0)
            )
        )

    @patch("disk_investigator.lifecycle.installer_gui.run_installer_gui")
    @patch("installer.install", return_value=True)
    @patch("installer.UninstallEngine.execute")
    def test_main_dual_mode_dispatch(self, mock_uninstall, mock_install, mock_gui):
        mock_uninstall.return_value = MagicMock(exit_code=0)
        mock_gui.return_value = 0

        # 1. Interactive double-click (no args) -> launches GUI
        with patch.object(sys, "argv", ["disk-investigator-setup.exe"]):
            rc = installer.main()
        self.assertEqual(rc, 0)
        mock_gui.assert_called_once()
        mock_install.assert_not_called()

        # 2. --silent -> never launches GUI
        mock_gui.reset_mock()
        mock_install.reset_mock()
        with patch.object(sys, "argv", ["disk-investigator-setup.exe", "--silent"]):
            rc = installer.main()
        self.assertEqual(rc, 0)
        mock_gui.assert_not_called()
        mock_install.assert_called_once()

        # 3. --wait-for-pid -> never launches GUI
        mock_gui.reset_mock()
        mock_install.reset_mock()
        with patch.object(sys, "argv", ["disk-investigator-setup.exe", "--wait-for-pid", "4321"]):
            rc = installer.main()
        self.assertEqual(rc, 0)
        mock_gui.assert_not_called()
        mock_install.assert_called_once()

        # 4. --uninstall --silent -> never launches GUI
        mock_gui.reset_mock()
        mock_install.reset_mock()
        with patch.object(sys, "argv", ["disk-investigator-setup.exe", "--uninstall", "--silent"]):
            rc = installer.main()
        self.assertEqual(rc, 0)
        mock_gui.assert_not_called()
        mock_uninstall.assert_called_once_with(purge_data=False, silent=True)

    def test_installer_gui_queue_and_close_lock(self):
        import tkinter as tk
        from disk_investigator.lifecycle.installer_gui import InstallerWindow

        try:
            root = tk.Tk()
        except tk.TclError as exc:
            self.skipTest(f"Tkinter display unavailable: {exc}")
            return

        root.withdraw()
        try:
            win = InstallerWindow(
                root=root,
                version="2.4.4",
                app_display_name="Disk Investigator",
                install_fn=lambda **kwargs: True,
            )

            # While running/locked, close button is disabled and WM_DELETE_WINDOW must refuse closing
            self.assertEqual(str(win.close_btn.cget("state")), "disabled")
            win._on_close_requested()
            self.assertTrue(root.winfo_exists())
            self.assertIn("chờ", win.lock_hint_var.get().lower())

            # Feed simulated worker events
            win.event_queue.put({"type": "lock_ui", "locked": True})
            win.event_queue.put({"type": "step", "step": 1, "total_steps": 6, "status_text": "Kiểm tra...", "percent": 15.0})
            win.event_queue.put({"type": "log", "level": "success", "message": "[+] Bước 1 OK"})
            win.event_queue.put(
                {
                    "type": "result",
                    "success": False,
                    "error": "Smoke test vận hành thất bại.",
                    "rollback_attempted": True,
                    "rollback_succeeded": True,
                }
            )
            win.event_queue.put({"type": "lock_ui", "locked": False})
            win.event_queue.put({"type": "worker_done", "success": False})
            win.drain_events()

            self.assertFalse(win.is_running)
            self.assertFalse(win.transaction_locked)
            self.assertFalse(win.final_success)
            self.assertEqual(win.progress_var.get(), 15.0)
            self.assertIn("Rollback", win.summary_detail_var.get())
            self.assertEqual(str(win.close_btn.cget("state")), "normal")
            self.assertEqual(win.close_btn.cget("text"), "Đóng")

            # Copy logs should succeed
            win._copy_logs_to_clipboard()
            self.assertIn("[+] Bước 1 OK", root.clipboard_get())

            # Now close is unlocked and destroys root cleanly
            win._on_close_requested()
            with self.assertRaises(tk.TclError):
                root.winfo_exists()
        finally:
            try:
                root.destroy()
            except Exception:
                pass

    def test_installer_gui_worker_thread_and_after_loop(self):
        import time
        import tkinter as tk
        from disk_investigator.lifecycle.installer_gui import InstallerWindow

        try:
            root = tk.Tk()
        except tk.TclError as exc:
            self.skipTest(f"Tkinter display unavailable: {exc}")
            return

        root.withdraw()
        try:
            def fake_install(on_progress=None, **kwargs):
                on_progress({"type": "lock_ui", "locked": True})
                on_progress({"type": "step", "step": 1, "total_steps": 6, "status_text": "Bước 1", "percent": 20.0})
                on_progress({"type": "step", "step": 6, "total_steps": 6, "status_text": "Bước 6", "percent": 95.0})
                on_progress({
                    "type": "result",
                    "success": True,
                    "version": "2.4.4",
                    "error": None,
                    "rollback_attempted": False,
                    "rollback_succeeded": False,
                    "install_dir": str(self.test_root),
                    "target_exe": str(self.test_root / "disk_investigator.exe"),
                    "target_skill": str(self.test_root / "SKILL.md"),
                    "skill_backup": None,
                })
                on_progress({"type": "lock_ui", "locked": False})
                return True

            win = InstallerWindow(
                root=root,
                version="2.4.4",
                app_display_name="Disk Investigator",
                install_fn=fake_install,
            )
            win.start()

            deadline = time.time() + 5.0
            while win.is_running and time.time() < deadline:
                root.update()
                time.sleep(0.02)

            self.assertFalse(win.is_running)
            self.assertTrue(win.final_success)
            self.assertEqual(win.progress_var.get(), 100.0)
            self.assertEqual(win.close_btn.cget("text"), "Hoàn tất")
            self.assertEqual(str(win.close_btn.cget("state")), "normal")
        finally:
            try:
                root.destroy()
            except Exception:
                pass

    def test_brand_logo_and_icon_assets_resolve(self):
        for asset_name in ("logo.svg", "app_icon.ico", "app_icon.png", "logo_48.png"):
            resolved = installer.get_resource_path(asset_name)
            self.assertTrue(resolved.exists(), f"Expected brand asset missing: {resolved}")


if __name__ == "__main__":
    unittest.main()
