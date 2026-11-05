#!/usr/bin/env python3
"""
installer.py - 1-Click All-in-One Installer & Environment Setup Engine
for Disk Investigator (https://github.com/codevcn/disk-cleaner).

Delivers a single-file, zero-dependency setup executable (disk-investigator-setup.exe)
that completely sets up a Windows 11 machine for both human users and AI Agents:
1. Transactionally deploys the standalone binary (disk_investigator.exe) into
   %LOCALAPPDATA%\\DiskInvestigator\\bin\\
2. Safely configures the current user's PATH via Windows Registry (HKCU\\Environment)
   using winreg and broadcasts WM_SETTINGCHANGE (never uses setx to avoid truncation bugs).
3. Safely installs the Antigravity AI Agent Skill:
   %USERPROFILE%\\.gemini\\config\\skills\\disk-cleanup\\SKILL.md
   (with smart backup if user customized the skill file).
4. Deploys reference manuals and documentation for deep AI agent context.
5. Writes an install_manifest.json with cryptographic SHA-256 digests.
6. Generates an atomic uninstaller (uninstall.cmd and --uninstall CLI flag).
"""

from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
import datetime
import enum
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Enable UTF-8 output on Windows terminal
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

CURRENT_DIR = Path(__file__).resolve().parent
if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))

from disk_investigator.lifecycle import (
    APP_NAME,
    APP_DISPLAY_NAME,
    GITHUB_REPO,
    RELEASE_ASSETS,
    SKILL_FOLDER_NAME,
    KNOWN_OWNED_FILES,
    KNOWN_OWNED_SUBDIRS,
    ProcessState,
    UninstallEngine,
    UninstallResult,
    UninstallStatus,
    check_process_state,
    compute_sha256,
    get_app_version,
    get_resource_path,
    get_target_directories,
    load_manifest,
    write_manifest,
)
import disk_investigator.lifecycle.common as common_lifecycle


def broadcast_environment_change() -> None:
    """Broadcasts WM_SETTINGCHANGE message."""
    common_lifecycle.broadcast_environment_change()


def add_bin_to_user_path(bin_dir: Path) -> Tuple[bool, bool]:
    """Safely adds bin_dir to HKCU\\Environment\\Path using winreg."""
    return common_lifecycle.add_bin_to_user_path(
        bin_dir, broadcast_fn=broadcast_environment_change
    )


def remove_bin_from_user_path(bin_dir: Path) -> bool:
    """Safely removes bin_dir from HKCU\\Environment\\Path using winreg."""
    return common_lifecycle.remove_bin_from_user_path(
        bin_dir, broadcast_fn=broadcast_environment_change
    )


def get_installer_version() -> str:
    """Returns application version."""
    return get_app_version()


class PidWaitState(str, enum.Enum):
    EXITED = "exited"
    RUNNING = "running"
    UNKNOWN = "unknown"


def check_pid_state(pid: int) -> PidWaitState:
    """
    Checks if a PID is alive, exited, or in an unknown/inaccessible state.
    Returns PidWaitState.EXITED, RUNNING, or UNKNOWN (Fail-Closed).
    """
    if pid <= 0:
        return PidWaitState.EXITED

    if sys.platform == "win32":
        SYNCHRONIZE = 0x00100000
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        handle = ctypes.windll.kernel32.OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            err = ctypes.GetLastError()
            # ERROR_INVALID_PARAMETER (87): PID does not exist -> EXITED
            if err == 87:
                return PidWaitState.EXITED
            # If Access Denied (5) or any other API error, fail-closed -> UNKNOWN
            return PidWaitState.UNKNOWN
        try:
            exit_code = wintypes.DWORD()
            if ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                STILL_ACTIVE = 259
                if exit_code.value != STILL_ACTIVE:
                    return PidWaitState.EXITED
                return PidWaitState.RUNNING
            return PidWaitState.UNKNOWN
        finally:
            ctypes.windll.kernel32.CloseHandle(handle)
    else:
        try:
            os.kill(pid, 0)
            return PidWaitState.RUNNING
        except ProcessLookupError:
            return PidWaitState.EXITED
        except (PermissionError, OSError):
            return PidWaitState.UNKNOWN


def wait_for_pid_to_exit(pid: int, timeout_seconds: float = 30.0) -> PidWaitState:
    """
    Waits for process with PID to exit without force-killing.
    Returns PidWaitState.EXITED if process exited cleanly,
    PidWaitState.RUNNING if timed out,
    or PidWaitState.UNKNOWN if status cannot be safely determined (Fail-Closed).
    """
    if pid <= 0:
        return PidWaitState.EXITED

    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        state = check_pid_state(pid)
        if state == PidWaitState.EXITED:
            return PidWaitState.EXITED
        if state == PidWaitState.UNKNOWN:
            return PidWaitState.UNKNOWN
        time.sleep(0.2)

    return PidWaitState.RUNNING


def release_update_lock(
    expected_update_id: Optional[str] = None,
    expected_owner_pid: Optional[int] = None,
) -> None:
    """Releases the updates/update.lock only if ownership matches expected update transaction."""
    try:
        local_app_data = os.environ.get("LOCALAPPDATA")
        if local_app_data:
            lock_file = Path(local_app_data) / "DiskInvestigator" / "updates" / "update.lock"
            if not lock_file.exists():
                return
            if expected_update_id is not None or expected_owner_pid is not None:
                try:
                    data = json.loads(lock_file.read_text(encoding="utf-8"))
                    if expected_update_id is not None and data.get("update_id") != expected_update_id:
                        return
                    if expected_owner_pid is not None:
                        valid_pids = {expected_owner_pid, os.getpid()}
                        if hasattr(os, "getppid"):
                            try:
                                valid_pids.add(os.getppid())
                            except Exception:
                                pass
                        if data.get("owner_pid") not in valid_pids:
                            return
                except Exception:
                    return
            lock_file.unlink(missing_ok=True)
    except Exception:
        pass


def write_update_receipt(
    receipt_path: Optional[Path],
    status: str,
    from_ver: str,
    to_ver: str,
    exit_code: int,
    error_msg: Optional[str] = None,
    rollback: bool = False,
) -> None:
    """Writes update receipt to specified path and default updates directory."""
    receipt_data = {
        "schema_version": 1,
        "status": status,
        "from_version": from_ver,
        "to_version": to_ver,
        "completed_at": datetime.datetime.now().astimezone().isoformat(),
        "installer_exit_code": exit_code,
        "error_message": error_msg,
        "rollback_attempted": rollback,
    }
    targets = []
    if receipt_path:
        targets.append(Path(receipt_path))

    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        targets.append(Path(local_app_data) / "DiskInvestigator" / "updates" / "last_update_result.json")

    for p in targets:
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            tmp_p = p.with_suffix(f".tmp_{os.getpid()}")
            with open(tmp_p, "w", encoding="utf-8") as f:
                json.dump(receipt_data, f, indent=2, ensure_ascii=False)
            os.replace(str(tmp_p), str(p))
        except Exception:
            pass


def generate_uninstaller_script(install_dir: Path, bin_dir: Path, skill_path: Path) -> Path:
    """
    Generates a standalone uninstall.cmd script in the install directory.
    Enables one-click uninstallation from Windows Explorer or CMD.
    Never executes raw destructive recursive directory deletes (rd /s /q).
    """
    uninstaller_path = install_dir / "uninstall.cmd"
    lifecycle_dir = install_dir / "lifecycle"

    batch_content = f"""@echo off
chcp 65001 >nul
title {APP_NAME} - Gỡ cài đặt

if exist "%~dp0lifecycle\\disk-investigator-uninstall.exe" (
    "%~dp0lifecycle\\disk-investigator-uninstall.exe" %*
    exit /b %ERRORLEVEL%
)

if exist "%~dp0lifecycle\\disk-investigator-setup.exe" (
    "%~dp0lifecycle\\disk-investigator-setup.exe" --uninstall %*
    exit /b %ERRORLEVEL%
)

echo =======================================================
echo          GỠ BỎ CÀI ĐẶT {APP_NAME}
echo =======================================================
echo [!] Không tìm thấy công cụ gỡ cài đặt nội bộ trong lifecycle/
echo.
echo Vui lòng tải 'disk-investigator-uninstall.exe' chính thức từ:
echo https://github.com/{GITHUB_REPO}/releases
echo để tiến hành gỡ cài đặt sạch sẽ và an toàn.
echo =======================================================
pause
exit /b 1
"""
    with open(uninstaller_path, "w", encoding="utf-8") as f:
        f.write(batch_content)
    return uninstaller_path


def check_is_admin() -> bool:
    """Checks if current process has Administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def run_smoke_test(target_exe: Path) -> bool:
    """Executes a fast smoke test on the installed executable."""
    try:
        res_ver = subprocess.run(
            [str(target_exe), "--version"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
        )
        if res_ver.returncode != 0:
            print(f"[!] Cảnh báo smoke test --version thất bại: {res_ver.stderr.strip()}")
            return False

        ver_text = res_ver.stdout.strip() or res_ver.stderr.strip()
        expected_ver = get_installer_version()
        if expected_ver not in ver_text:
            print(f"[!] Cảnh báo smoke test: Phiên bản binary ({ver_text}) không khớp với bộ cài ({expected_ver})!")
            return False
        print(f"[+] Smoke test --version OK: {ver_text}")

        res_doc = subprocess.run(
            [str(target_exe), "doctor"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
        )
        if res_doc.returncode != 0:
            print(f"[!] Cảnh báo smoke test doctor thất bại: {res_doc.stderr.strip()}")
            return False

        print("[+] Smoke test doctor OK (Hệ thống sẵn sàng).")
        return True
    except Exception as e:
        print(f"[!] Không thể hoàn thành smoke test: {e}")
        return False


def install(
    silent: bool = False,
    repair: bool = False,
    wait_for_pid: int = 0,
    update_result: Optional[Path] = None,
    update_id: Optional[str] = None,
) -> bool:
    """
    Main 1-Click All-in-One installation procedure.
    Guarantees transactional execution, user PATH setup, skill deployment, and backup.
    """
    current_version = get_installer_version()
    install_dir, bin_dir, skill_dir, skill_ref_dir = get_target_directories()
    prev_manifest = load_manifest(install_dir)
    prev_version = prev_manifest.get("version", "unknown") if prev_manifest else "unknown"

    receipt_status = "failed"
    receipt_exit_code = 1
    receipt_error: Optional[str] = None
    receipt_rollback = False
    success = False

    try:
        print("=======================================================")
        print(f"       CÀI ĐẶT {APP_DISPLAY_NAME}")
        print("=======================================================")

        # Non-elevated recommendation check
        if check_is_admin():
            print("[!] Lưu ý: Bạn đang chạy với quyền Administrator.")
            print("[!] Disk Investigator được thiết kế cài đặt theo User-scope an toàn")
            print("[!] (%LOCALAPPDATA% và HKCU Registry). Tiếp tục cài đặt cho User hiện tại...\n")

        target_exe = bin_dir / "disk_investigator.exe"
        target_docs = install_dir / "README.md"
        target_skill = skill_dir / "SKILL.md"
        target_skill_ref_docs = skill_ref_dir / "README.md"

        # Staged lifecycle handoff: wait for parent PID to exit if requested
        if wait_for_pid > 0:
            print(f"[*] Đang chờ tiến trình cha (PID: {wait_for_pid}) kết thúc...")
            pid_state = wait_for_pid_to_exit(wait_for_pid, timeout_seconds=30.0)
            if pid_state != PidWaitState.EXITED:
                err_desc = (
                    f"Timeout waiting for parent PID {wait_for_pid} to exit"
                    if pid_state == PidWaitState.RUNNING
                    else f"Unable to safely verify parent PID {wait_for_pid} state ({pid_state.value}, Fail-Closed)"
                )
                print(f"[ERROR] {err_desc}. HỦY CÀI ĐẶT.")
                receipt_error = err_desc
                return False
            print(f"[+] Tiến trình cha PID {wait_for_pid} đã kết thúc an toàn.")

            # Validate lifecycle update.lock ownership and transaction identity (Fail-Closed)
            local_app_data = os.environ.get("LOCALAPPDATA")
            lock_file = Path(local_app_data) / "DiskInvestigator" / "updates" / "update.lock" if local_app_data else None
            if not lock_file or not lock_file.exists():
                err_desc = "Update lock does not exist prior to installer mutation (Fail-Closed)"
                print(f"[ERROR] {err_desc}. HỦY CÀI ĐẶT.")
                receipt_error = err_desc
                return False

            try:
                lock_data = json.loads(lock_file.read_text(encoding="utf-8"))
            except Exception as e:
                err_desc = f"Corrupt update lock metadata: {e} (Fail-Closed)"
                print(f"[ERROR] {err_desc}. HỦY CÀI ĐẶT.")
                receipt_error = err_desc
                return False

            if lock_data.get("phase") != "installer":
                err_desc = f"Update lock phase mismatch (expected 'installer', got '{lock_data.get('phase')}')"
                print(f"[ERROR] {err_desc}. HỦY CÀI ĐẶT.")
                receipt_error = err_desc
                return False

            valid_owner_pids = {os.getpid()}
            if hasattr(os, "getppid"):
                try:
                    valid_owner_pids.add(os.getppid())
                except Exception:
                    pass

            if lock_data.get("owner_pid") not in valid_owner_pids:
                err_desc = f"Update lock owner PID mismatch (expected {os.getpid()}, got {lock_data.get('owner_pid')})"
                print(f"[ERROR] {err_desc}. HỦY CÀI ĐẶT.")
                receipt_error = err_desc
                return False

            if update_id and lock_data.get("update_id") != update_id:
                err_desc = f"Update transaction ID mismatch (expected '{update_id}', got '{lock_data.get('update_id')}')"
                print(f"[ERROR] {err_desc}. HỦY CÀI ĐẶT.")
                receipt_error = err_desc
                return False

            if lock_data.get("target_version") and lock_data.get("target_version") != current_version:
                err_desc = f"Update target version mismatch (expected '{current_version}', got '{lock_data.get('target_version')}')"
                print(f"[ERROR] {err_desc}. HỦY CÀI ĐẶT.")
                receipt_error = err_desc
                return False

            print("[+] Xác thực bản quyền update.lock thành công (Owner PID & Transaction ID verified).")

        print(f"Thư mục cài đặt:   {install_dir}")
        print(f"Đường dẫn binary:  {target_exe}")
        print(f"Skill AI Agent:    {target_skill}")
        print(f"Tài liệu hướng dẫn:{target_docs}")
        print("=======================================================\n")

        # Step 1: Pre-flight check - destination lock & permissions
        print("[1/6] Kiểm tra quyền truy cập và tiến trình hệ thống...")
        try:
            install_dir.mkdir(parents=True, exist_ok=True)
            bin_dir.mkdir(parents=True, exist_ok=True)
            skill_dir.mkdir(parents=True, exist_ok=True)
            skill_ref_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            err_desc = f"Không thể tạo thư mục cài đặt: {e}"
            print(f"[ERROR] {err_desc}")
            receipt_error = err_desc
            return False

        if target_exe.exists():
            try:
                with open(target_exe, "a+b"):
                    pass
            except PermissionError:
                err_desc = f"File '{target_exe.name}' đang bị khóa bởi một tiến trình đang chạy."
                print(f"[ERROR] {err_desc}")
                print("[ERROR] Vui lòng tắt các cửa sổ dòng lệnh hoặc ứng dụng đang dùng tool trước khi cài đặt lại.")
                receipt_error = err_desc
                return False
            except Exception as e:
                err_desc = f"Kiểm tra ghi file thất bại: {e}"
                print(f"[ERROR] {err_desc}")
                receipt_error = err_desc
                return False

        # Step 2: Locate source payload
        print("[2/6] Trích xuất tài nguyên cài đặt (Payload)...")
        src_exe = get_resource_path("disk_investigator.exe")
        src_skill = get_resource_path("SKILL.md")
        src_readme = get_resource_path("README.md")

        if not src_exe.exists():
            err_desc = f"Không tìm thấy tệp nhị phân nguồn: {src_exe}"
            print(f"[ERROR] {err_desc}")
            receipt_error = err_desc
            return False
        if not src_skill.exists():
            err_desc = f"Không tìm thấy tệp Skill AI nguồn: {src_skill}"
            print(f"[ERROR] {err_desc}")
            receipt_error = err_desc
            return False
        if not src_readme.exists():
            err_desc = f"Không tìm thấy tệp hướng dẫn nguồn: {src_readme}"
            print(f"[ERROR] {err_desc}")
            receipt_error = err_desc
            return False

        # Step 3: Skill upgrade & backup policy
        print("[3/6] Cấu hình và đồng bộ Skill cho Google Antigravity...")
        prev_manifest = load_manifest(install_dir)
        skill_backup_path: Optional[str] = None

        if target_skill.exists():
            curr_skill_hash = compute_sha256(target_skill)
            new_skill_hash = compute_sha256(src_skill)

            # Check if user modified it
            prev_recorded_hash = prev_manifest.get("skill_sha256") if prev_manifest else None

            if curr_skill_hash != new_skill_hash:
                if prev_recorded_hash and curr_skill_hash != prev_recorded_hash:
                    # Skill has been modified by user! Create backup
                    ts_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                    backup_name = f"SKILL.md.user-backup-{ts_str}"
                    backup_file = target_skill.parent / backup_name
                    try:
                        shutil.copy2(target_skill, backup_file)
                        skill_backup_path = str(backup_file)
                        print(f"[+] Phát hiện tùy biến người dùng! Đã sao lưu: {backup_file.name}")
                    except Exception as e:
                        err_desc = f"Không thể sao lưu file SKILL.md tùy biến: {e}"
                        print(f"[ERROR] {err_desc}")
                        print("[ERROR] HỦY CÀI ĐẶT để bảo vệ tùy biến của người dùng!")
                        receipt_error = err_desc
                        return False

        # Create transactional rollback journal before modifying any destination files
        old_exe_bak = bin_dir / "disk_investigator.exe.rollback"
        old_skill_bak = skill_dir / "SKILL.md.rollback"
        old_docs_bak = install_dir / "README.md.rollback"
        old_ref_docs_bak = skill_ref_dir / "README.md.rollback"
        old_manifest_bak = install_dir / "install_manifest.json.rollback"
        manifest_file = install_dir / "install_manifest.json"

        lifecycle_dir = install_dir / "lifecycle"
        lifecycle_dir.mkdir(parents=True, exist_ok=True)
        lifecycle_exe = lifecycle_dir / "disk-investigator-setup.exe"
        old_lifecycle_bak = lifecycle_dir / "disk-investigator-setup.exe.rollback"

        uninstaller_cmd = install_dir / "uninstall.cmd"
        old_uninstaller_bak = install_dir / "uninstall.cmd.rollback"

        had_old_exe = target_exe.exists()
        had_old_skill = target_skill.exists()
        had_old_docs = target_docs.exists()
        had_old_ref_docs = target_skill_ref_docs.exists()
        had_old_manifest = manifest_file.exists()
        had_old_lifecycle = lifecycle_exe.exists()
        had_old_uninstaller = uninstaller_cmd.exists()

        try:
            if had_old_exe:
                shutil.copy2(target_exe, old_exe_bak)
            if had_old_skill:
                shutil.copy2(target_skill, old_skill_bak)
            if had_old_docs:
                shutil.copy2(target_docs, old_docs_bak)
            if had_old_ref_docs:
                shutil.copy2(target_skill_ref_docs, old_ref_docs_bak)
            if had_old_manifest:
                shutil.copy2(manifest_file, old_manifest_bak)
            if had_old_lifecycle:
                shutil.copy2(lifecycle_exe, old_lifecycle_bak)
            if had_old_uninstaller:
                shutil.copy2(uninstaller_cmd, old_uninstaller_bak)
        except Exception as e:
            err_desc = f"Không thể tạo rollback journal: {e}"
            print(f"[ERROR] {err_desc}")
            receipt_error = err_desc
            return False

        def perform_rollback(path_changed: bool = False) -> None:
            """Restores previous state and removes partial installations."""
            print("[!] ĐANG THỰC HIỆN ROLLBACK...")
            try:
                if had_old_exe and old_exe_bak.exists():
                    os.replace(str(old_exe_bak), str(target_exe))
                elif target_exe.exists():
                    target_exe.unlink()

                if had_old_skill and old_skill_bak.exists():
                    os.replace(str(old_skill_bak), str(target_skill))
                elif target_skill.exists():
                    target_skill.unlink()

                if had_old_docs and old_docs_bak.exists():
                    os.replace(str(old_docs_bak), str(target_docs))
                elif target_docs.exists():
                    target_docs.unlink()

                if had_old_ref_docs and old_ref_docs_bak.exists():
                    os.replace(str(old_ref_docs_bak), str(target_skill_ref_docs))
                elif target_skill_ref_docs.exists():
                    target_skill_ref_docs.unlink()

                if had_old_manifest and old_manifest_bak.exists():
                    os.replace(str(old_manifest_bak), str(manifest_file))
                elif manifest_file.exists():
                    manifest_file.unlink()

                if had_old_lifecycle and old_lifecycle_bak.exists():
                    os.replace(str(old_lifecycle_bak), str(lifecycle_exe))
                elif lifecycle_exe.exists():
                    lifecycle_exe.unlink()

                if had_old_uninstaller and old_uninstaller_bak.exists():
                    os.replace(str(old_uninstaller_bak), str(uninstaller_cmd))
                elif uninstaller_cmd.exists():
                    uninstaller_cmd.unlink()

                if path_changed:
                    remove_bin_from_user_path(bin_dir)

                # Cleanup rollback files
                for bf in [
                    old_exe_bak,
                    old_skill_bak,
                    old_docs_bak,
                    old_ref_docs_bak,
                    old_manifest_bak,
                    old_lifecycle_bak,
                    old_uninstaller_bak,
                ]:
                    if bf.exists():
                        try:
                            bf.unlink()
                        except Exception:
                            pass
                print("[+] Hoàn tất Rollback. Trạng thái cũ được bảo toàn 100%.")
            except Exception as re:
                print(f"[ERROR] Lỗi trong quá trình rollback: {re}")

        # Execute full installation transaction within a single exception boundary
        path_changed = False
        try:
            # Step 3: Copy files via atomic replace
            tmp_exe = bin_dir / "disk_investigator.exe.tmp"
            shutil.copy2(src_exe, tmp_exe)
            os.replace(str(tmp_exe), str(target_exe))

            # Skill & references
            tmp_skill = skill_dir / "SKILL.md.tmp"
            shutil.copy2(src_skill, tmp_skill)
            os.replace(str(tmp_skill), str(target_skill))

            # Local docs & skill reference docs
            shutil.copy2(src_readme, target_docs)
            shutil.copy2(src_readme, target_skill_ref_docs)

            # Deploy lifecycle binaries for self-contained uninstallation/upgrades
            curr_proc = Path(sys.executable)
            if curr_proc.name.lower() == "disk-investigator-setup.exe" and curr_proc.exists():
                shutil.copy2(curr_proc, lifecycle_exe)
            elif Path(sys.argv[0]).name.lower() == "disk-investigator-setup.exe" and Path(sys.argv[0]).exists():
                shutil.copy2(Path(sys.argv[0]), lifecycle_exe)
            else:
                dev_setup = get_resource_path("disk-investigator-setup.exe")
                if dev_setup.exists():
                    shutil.copy2(dev_setup, lifecycle_exe)

            dev_uninstaller = get_resource_path("disk-investigator-uninstall.exe")
            if dev_uninstaller.exists():
                shutil.copy2(dev_uninstaller, lifecycle_dir / "disk-investigator-uninstall.exe")

            print("[+] Đã cài đặt binary, Skill AI Agent, lifecycle engine và tài liệu kỹ thuật.")

            # Step 4: Configure User PATH (FAIL-CLOSED)
            print("[4/6] Cập nhật biến môi trường User PATH (Registry an toàn)...")
            path_ok, path_changed = add_bin_to_user_path(bin_dir)
            if not path_ok:
                raise RuntimeError("Thất bại khi cấu hình biến môi trường User PATH trong Registry.")

            # Step 5: Generate uninstaller & manifest
            print("[5/6] Tạo bộ gỡ cài đặt và ghi nhận Install Manifest...")
            generate_uninstaller_script(install_dir, bin_dir, target_skill)

            current_version = get_installer_version()
            manifest_data: Dict[str, Any] = {
                "app_name": APP_NAME,
                "version": current_version,
                "installed_at": datetime.datetime.now().astimezone().isoformat(),
                "install_dir": str(install_dir),
                "bin_dir": str(bin_dir),
                "bin_file": str(target_exe),
                "bin_sha256": compute_sha256(target_exe),
                "docs_file": str(target_docs),
                "docs_sha256": compute_sha256(target_docs),
                "skill_file": str(target_skill),
                "skill_sha256": compute_sha256(target_skill),
                "skill_backup": skill_backup_path,
                "path_configured": path_ok,
            }
            write_manifest(install_dir, manifest_data)

            # Step 6: Post-install verification smoke test
            print("[6/6] Kiểm tra xác thực vận hành (Smoke Test)...")
            smoke_ok = run_smoke_test(target_exe)
            if not smoke_ok:
                raise RuntimeError("Smoke test vận hành thất bại.")

        except Exception as e:
            print(f"[ERROR] Quá trình cài đặt thất bại: {e}")
            receipt_error = str(e)
            receipt_rollback = True
            perform_rollback(path_changed=path_changed)
            return False

        # Clean up rollback journal on success
        for bf in [
            old_exe_bak,
            old_skill_bak,
            old_docs_bak,
            old_ref_docs_bak,
            old_manifest_bak,
            old_lifecycle_bak,
            old_uninstaller_bak,
        ]:
            if bf.exists():
                try:
                    bf.unlink()
                except Exception:
                    pass

        receipt_status = "success"
        receipt_exit_code = 0
        receipt_error = None
        receipt_rollback = False
        success = True

        print("\n=======================================================")
        print(f"       CÀI ĐẶT THÀNH CÔNG {APP_DISPLAY_NAME}!       ")
        print("=======================================================")
        print(f"1. Khởi động công cụ:  Mở PowerShell / CMD mới và gõ:")
        print(f"       disk_investigator --help")
        print(f"2. Với AI Agent:       Yêu cầu Antigravity dọn ổ đĩa bất kỳ:")
        print(f"       'Hãy kiểm tra dung lượng ổ C và tìm thư mục chiếm nhiều chỗ'")
        print(f"3. Gỡ bỏ cài đặt:      Chạy file {install_dir}\\uninstall.cmd")
        print("=======================================================\n")

        return True

    finally:
        write_update_receipt(
            update_result,
            status=receipt_status,
            from_ver=prev_version,
            to_ver=current_version,
            exit_code=receipt_exit_code,
            error_msg=receipt_error,
            rollback=receipt_rollback,
        )
        release_update_lock(
            expected_update_id=update_id,
            expected_owner_pid=os.getpid() if wait_for_pid > 0 else None,
        )


def uninstall(silent: bool = False, purge_data: bool = False) -> bool:
    """
    Cleans up the installation, restoring user PATH and removing skill (if unmodified).
    Delegates directly to UninstallEngine to ensure unified lifecycle logic.
    """
    result = UninstallEngine.execute(purge_data=purge_data, silent=silent)
    return result.status == UninstallStatus.SUCCESS


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="disk-investigator-setup",
        description=f"1-Click All-in-One Installer for {APP_DISPLAY_NAME}",
    )
    parser.add_argument(
        "--version", "-V",
        action="version",
        version=f"%(prog)s {get_installer_version()}",
        help="Show installer version and exit.",
    )
    parser.add_argument(
        "--silent", "-s",
        action="store_true",
        help="Run unattended installation without interactive prompts.",
    )
    parser.add_argument(
        "--uninstall", "-u",
        action="store_true",
        help="Uninstall Disk Investigator from the system.",
    )
    parser.add_argument(
        "--purge-data",
        action="store_true",
        help="Purge all user cache, logs, and state during uninstallation.",
    )
    parser.add_argument(
        "--repair", "-r",
        action="store_true",
        help="Reinstall or repair all binaries, PATH, and Skill integration.",
    )
    parser.add_argument(
        "--no-pause",
        action="store_true",
        help="Skip final pause in interactive mode.",
    )
    parser.add_argument(
        "--wait-for-pid",
        type=int,
        default=0,
        help="Wait for specified PID to exit before starting installation.",
    )
    parser.add_argument(
        "--update-result",
        type=Path,
        default=None,
        help="Optional path to write update result receipt JSON.",
    )
    parser.add_argument(
        "--update-id",
        type=str,
        default=None,
        help="Expected update transaction ID matching update.lock metadata.",
    )

    args = parser.parse_args()

    interactive = not args.silent

    if args.uninstall:
        result = UninstallEngine.execute(purge_data=args.purge_data, silent=args.silent)
        if interactive and not args.no_pause:
            try:
                input("\nNhấn Enter để đóng cửa sổ...")
            except (EOFError, KeyboardInterrupt):
                pass
        return result.exit_code
    else:
        success = install(
            silent=args.silent,
            repair=args.repair,
            wait_for_pid=args.wait_for_pid,
            update_result=args.update_result,
            update_id=args.update_id,
        )
        if interactive and not args.no_pause:
            try:
                input("\nNhấn Enter để đóng cửa sổ...")
            except (EOFError, KeyboardInterrupt):
                pass
        return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
