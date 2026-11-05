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


def wait_for_pid_to_exit(pid: int, timeout_seconds: float = 30.0) -> bool:
    """
    Waits for process with PID to exit without force-killing.
    Returns True if process has exited, False if timed out.
    """
    if pid <= 0:
        return True

    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        if sys.platform == "win32":
            SYNCHRONIZE = 0x00100000
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            handle = ctypes.windll.kernel32.OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            if not handle:
                return True  # Process does not exist or already exited
            try:
                exit_code = wintypes.DWORD()
                if ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                    STILL_ACTIVE = 259
                    if exit_code.value != STILL_ACTIVE:
                        return True
                else:
                    return True
            finally:
                ctypes.windll.kernel32.CloseHandle(handle)
        else:
            try:
                os.kill(pid, 0)
            except OSError:
                return True
        time.sleep(0.2)

    return False


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
) -> bool:
    """
    Main 1-Click All-in-One installation procedure.
    Guarantees transactional execution, user PATH setup, skill deployment, and backup.
    """
    current_version = get_installer_version()

    print("=======================================================")
    print(f"       CÀI ĐẶT {APP_DISPLAY_NAME}")
    print("=======================================================")

    # Non-elevated recommendation check
    if check_is_admin():
        print("[!] Lưu ý: Bạn đang chạy với quyền Administrator.")
        print("[!] Disk Investigator được thiết kế cài đặt theo User-scope an toàn")
        print("[!] (%LOCALAPPDATA% và HKCU Registry). Tiếp tục cài đặt cho User hiện tại...\n")

    # Resolve paths
    install_dir, bin_dir, skill_dir, skill_ref_dir = get_target_directories()
    target_exe = bin_dir / "disk_investigator.exe"
    target_docs = install_dir / "README.md"
    target_skill = skill_dir / "SKILL.md"
    target_skill_ref_docs = skill_ref_dir / "README.md"

    prev_manifest = load_manifest(install_dir)
    prev_version = prev_manifest.get("version", "unknown") if prev_manifest else "unknown"

    # Staged lifecycle handoff: wait for parent PID to exit if requested
    if wait_for_pid > 0:
        print(f"[*] Đang chờ tiến trình cha (PID: {wait_for_pid}) kết thúc...")
        if not wait_for_pid_to_exit(wait_for_pid, timeout_seconds=30.0):
            print(f"[ERROR] Quá thời gian 30s chờ PID {wait_for_pid} kết thúc. HỦY CÀI ĐẶT.")
            write_update_receipt(
                update_result,
                status="failed",
                from_ver=prev_version,
                to_ver=current_version,
                exit_code=1,
                error_msg=f"Timeout waiting for parent PID {wait_for_pid} to exit",
                rollback=False,
            )
            return False
        print(f"[+] Tiến trình cha PID {wait_for_pid} đã kết thúc an toàn.")

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
        print(f"[ERROR] Không thể tạo thư mục cài đặt: {e}")
        return False

    if target_exe.exists():
        try:
            with open(target_exe, "a+b"):
                pass
        except PermissionError:
            print(f"[ERROR] File '{target_exe.name}' đang bị khóa bởi một tiến trình đang chạy.")
            print("[ERROR] Vui lòng tắt các cửa sổ dòng lệnh hoặc ứng dụng đang dùng tool trước khi cài đặt lại.")
            return False
        except Exception as e:
            print(f"[ERROR] Kiểm tra ghi file thất bại: {e}")
            return False

    # Step 2: Locate source payload
    print("[2/6] Trích xuất tài nguyên cài đặt (Payload)...")
    src_exe = get_resource_path("disk_investigator.exe")
    src_skill = get_resource_path("SKILL.md")
    src_readme = get_resource_path("README.md")

    if not src_exe.exists():
        print(f"[ERROR] Không tìm thấy tệp nhị phân nguồn: {src_exe}")
        return False
    if not src_skill.exists():
        print(f"[ERROR] Không tìm thấy tệp Skill AI nguồn: {src_skill}")
        return False
    if not src_readme.exists():
        print(f"[ERROR] Không tìm thấy tệp hướng dẫn nguồn: {src_readme}")
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
                    print(f"[ERROR] Không thể sao lưu file SKILL.md tùy biến: {e}")
                    print("[ERROR] HỦY CÀI ĐẶT để bảo vệ tùy biến của người dùng!")
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
        print(f"[ERROR] Không thể tạo rollback journal: {e}")
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
        perform_rollback(path_changed=path_changed)
        write_update_receipt(
            update_result,
            status="failed",
            from_ver=prev_version,
            to_ver=current_version,
            exit_code=1,
            error_msg=str(e),
            rollback=True,
        )
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

    write_update_receipt(
        update_result,
        status="success",
        from_ver=prev_version,
        to_ver=current_version,
        exit_code=0,
        rollback=False,
    )

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
        )
        if interactive and not args.no_pause:
            try:
                input("\nNhấn Enter để đóng cửa sổ...")
            except (EOFError, KeyboardInterrupt):
                pass
        return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
