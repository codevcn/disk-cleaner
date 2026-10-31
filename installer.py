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

APP_NAME = "DiskInvestigator"
APP_DISPLAY_NAME = "Disk Investigator (AI-Native Storage Cleaner)"
SKILL_FOLDER_NAME = "disk-cleanup"
GITHUB_REPO = "codevcn/disk-cleaner"


def get_installer_version() -> str:
    """
    Retrieves authoritative version from embedded build_info.json or __init__.py.
    Provides Single Source of Truth across CLI, installer, and manifests.
    """
    # 1. Check embedded build_info.json (PyInstaller bundled mode)
    build_info_path = get_resource_path("build_info.json")
    if build_info_path and build_info_path.exists():
        try:
            with open(build_info_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if data.get("version"):
                    return str(data["version"]).strip()
        except Exception:
            pass

    # 2. Check disk_investigator/__init__.py in development workspace
    dev_root = Path(__file__).resolve().parent
    init_file = dev_root / "disk_investigator" / "__init__.py"
    if init_file.exists():
        try:
            with open(init_file, "r", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("__version__"):
                        return line.split("=")[1].strip().strip('"').strip("'")
        except Exception:
            pass

    return "2.1.2"


def compute_sha256(filepath: Path) -> str:
    """Computes SHA-256 hash of a file."""
    sha = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            sha.update(chunk)
    return sha.hexdigest()


def get_resource_path(relative_name: str) -> Path:
    """
    Returns absolute path to embedded resource (works both in PyInstaller bundled mode
    and standard development script mode).
    """
    if hasattr(sys, "_MEIPASS"):
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = Path(sys._MEIPASS)  # type: ignore
        candidate = base_path / relative_name
        if candidate.exists():
            return candidate

    # Development or local folder mode
    dev_root = Path(__file__).resolve().parent
    local_candidate = dev_root / relative_name
    if local_candidate.exists():
        return local_candidate

    # Check common relative locations
    if relative_name == "disk_investigator.exe":
        c = dev_root / "disk_investigator.exe"
        if c.exists():
            return c
    elif relative_name == "SKILL.md":
        c = dev_root / "skills" / SKILL_FOLDER_NAME / "SKILL.md"
        if c.exists():
            return c
    elif relative_name == "README.md":
        c = dev_root / "README.md"
        if c.exists():
            return c

    return dev_root / relative_name


def get_target_directories() -> Tuple[Path, Path, Path, Path]:
    """
    Returns canonical target installation directories:
    1. install_dir: %LOCALAPPDATA%\\DiskInvestigator
    2. bin_dir: %LOCALAPPDATA%\\DiskInvestigator\\bin
    3. skill_dir: %USERPROFILE%\\.gemini\\config\\skills\\disk-cleanup
    4. skill_ref_dir: %USERPROFILE%\\.gemini\\config\\skills\\disk-cleanup\\references
    """
    local_app_data = os.environ.get("LOCALAPPDATA")
    if not local_app_data:
        local_app_data = str(Path.home() / "AppData" / "Local")

    user_profile = os.environ.get("USERPROFILE")
    if not user_profile:
        user_profile = str(Path.home())

    install_dir = Path(local_app_data) / APP_NAME
    bin_dir = install_dir / "bin"
    skill_dir = Path(user_profile) / ".gemini" / "config" / "skills" / SKILL_FOLDER_NAME
    skill_ref_dir = skill_dir / "references"

    return install_dir, bin_dir, skill_dir, skill_ref_dir


def broadcast_environment_change() -> None:
    """
    Broadcasts WM_SETTINGCHANGE message to notify all running top-level windows
    that system/user environment variables have been updated.
    """
    if sys.platform != "win32":
        return

    HWND_BROADCAST = 0xFFFF
    WM_SETTINGCHANGE = 0x001A
    SMTO_ABORTIFHUNG = 0x0002

    try:
        send_message_timeout = ctypes.windll.user32.SendMessageTimeoutW
        result = wintypes.DWORD()
        send_message_timeout(
            HWND_BROADCAST,
            WM_SETTINGCHANGE,
            0,
            "Environment",
            SMTO_ABORTIFHUNG,
            2000,
            ctypes.byref(result),
        )
    except Exception as e:
        print(f"[!] Cảnh báo: Không thể phát thông báo WM_SETTINGCHANGE: {e}")


def add_bin_to_user_path(bin_dir: Path) -> Tuple[bool, bool]:
    """
    Safely adds bin_dir to HKCU\\Environment\\Path using winreg.
    Preserves all existing variables and REG_EXPAND_SZ typing.
    Never uses 'setx' to prevent length truncation bugs.
    Returns:
        (success: bool, changed: bool)
        'changed' is True ONLY if bin_dir was newly added in this operation.
    """
    if sys.platform != "win32":
        return False, False

    import winreg

    bin_str = str(bin_dir.resolve())
    bin_norm = bin_str.lower().rstrip("\\")

    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, r"Environment", 0, winreg.KEY_READ | winreg.KEY_WRITE
        ) as key:
            try:
                current_path_val, val_type = winreg.QueryValueEx(key, "Path")
            except FileNotFoundError:
                current_path_val = ""
                val_type = winreg.REG_EXPAND_SZ

            # Split existing paths
            entries = [p.strip() for p in current_path_val.split(";") if p.strip()]

            # Check if already present (case-insensitive)
            for entry in entries:
                if entry.lower().rstrip("\\") == bin_norm:
                    print(f"[*] Thư mục bin đã tồn tại trong User PATH: {bin_dir}")
                    return True, False

            # Append new entry
            entries.append(bin_str)
            new_path_val = ";".join(entries)

            winreg.SetValueEx(key, "Path", 0, winreg.REG_EXPAND_SZ, new_path_val)
            print(f"[+] Đã thêm vào User PATH: {bin_dir}")

        broadcast_environment_change()
        return True, True
    except Exception as e:
        print(f"[ERROR] Thất bại khi ghi Registry User PATH: {e}")
        return False, False


def remove_bin_from_user_path(bin_dir: Path) -> bool:
    """
    Safely removes bin_dir from HKCU\\Environment\\Path using winreg.
    """
    if sys.platform != "win32":
        return False

    import winreg

    bin_norm = str(bin_dir.resolve()).lower().rstrip("\\")

    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, r"Environment", 0, winreg.KEY_READ | winreg.KEY_WRITE
        ) as key:
            try:
                current_path_val, val_type = winreg.QueryValueEx(key, "Path")
            except FileNotFoundError:
                return True

            entries = [p.strip() for p in current_path_val.split(";") if p.strip()]
            new_entries = [p for p in entries if p.lower().rstrip("\\") != bin_norm]

            if len(entries) != len(new_entries):
                new_path_val = ";".join(new_entries)
                winreg.SetValueEx(key, "Path", 0, winreg.REG_EXPAND_SZ, new_path_val)
                print(f"[+] Đã gỡ bỏ khỏi User PATH: {bin_dir}")
                broadcast_environment_change()
            else:
                print(f"[*] Thư mục bin không có trong User PATH.")

        return True
    except Exception as e:
        print(f"[ERROR] Thất bại khi cập nhật Registry User PATH: {e}")
        return False


def load_manifest(install_dir: Path) -> Optional[Dict[str, Any]]:
    """Loads existing install_manifest.json if present."""
    manifest_file = install_dir / "install_manifest.json"
    if manifest_file.exists():
        try:
            with open(manifest_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return None


def write_manifest(install_dir: Path, manifest_data: Dict[str, Any]) -> None:
    """Writes install_manifest.json atomically."""
    manifest_file = install_dir / "install_manifest.json"
    tmp_file = manifest_file.with_suffix(".tmp")
    with open(tmp_file, "w", encoding="utf-8") as f:
        json.dump(manifest_data, f, indent=2, ensure_ascii=False)
    os.replace(str(tmp_file), str(manifest_file))
    print(f"[+] Đã lưu bản ghi cấu hình cài đặt: {manifest_file.name}")


def generate_uninstaller_script(install_dir: Path, bin_dir: Path, skill_path: Path) -> Path:
    """
    Generates a standalone uninstall.cmd script in the install directory.
    Enables one-click uninstallation from Windows Explorer or CMD.
    Ensures safe cleanup of the lifecycle directory and executable after exit.
    """
    uninstaller_path = install_dir / "uninstall.cmd"
    lifecycle_dir = install_dir / "lifecycle"
    lifecycle_setup_exe = lifecycle_dir / "disk-investigator-setup.exe"

    batch_content = f"""@echo off
chcp 65001 >nul
echo =======================================================
echo          GỠ BỎ CÀI ĐẶT {APP_NAME}
echo =======================================================
echo Thư mục cài đặt: {install_dir}
echo.

set /p CONFIRM="Bạn có chắc chắn muốn gỡ cài đặt {APP_NAME}? (Y/N): "
if /i "%CONFIRM%" neq "Y" (
    echo Đã hủy thao tác.
    pause
    exit /b 0
)

echo.
echo [*] Đang gỡ bỏ binary và thiết lập môi trường...

if exist "{lifecycle_setup_exe}" (
    "{lifecycle_setup_exe}" --uninstall --silent
    set "UNINST_CODE=%ERRORLEVEL%"
    del /f /q "{lifecycle_setup_exe}" >nul 2>&1
    rd /q "{lifecycle_dir}" >nul 2>&1
) else (
    echo [*] Xóa thư mục cài đặt...
    rd /s /q "{install_dir}\\bin" >nul 2>&1
    del /f /q "{install_dir}\\README.md" >nul 2>&1
    del /f /q "{install_dir}\\install_manifest.json" >nul 2>&1
    rd /s /q "{lifecycle_dir}" >nul 2>&1
)

echo.
echo [+] Hoàn tất gỡ bỏ {APP_NAME}.
pause
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
) -> bool:
    """
    Main 1-Click All-in-One installation procedure.
    Guarantees transactional execution, user PATH setup, skill deployment, and backup.
    """
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

    # Copy files via atomic replace
    try:
        # Binary
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

        # Deploy lifecycle setup binary for self-contained uninstallation/upgrades
        curr_proc = Path(sys.executable)
        if curr_proc.name.lower() == "disk-investigator-setup.exe" and curr_proc.exists():
            shutil.copy2(curr_proc, lifecycle_exe)
        elif Path(sys.argv[0]).name.lower() == "disk-investigator-setup.exe" and Path(sys.argv[0]).exists():
            shutil.copy2(Path(sys.argv[0]), lifecycle_exe)
        else:
            dev_setup = get_resource_path("disk-investigator-setup.exe")
            if dev_setup.exists():
                shutil.copy2(dev_setup, lifecycle_exe)

        print("[+] Đã cài đặt binary, Skill AI Agent, lifecycle engine và tài liệu kỹ thuật.")
    except Exception as e:
        print(f"[ERROR] Gặp lỗi khi ghi tệp hệ thống: {e}")
        perform_rollback(path_changed=False)
        return False

    # Step 4: Configure User PATH
    print("[4/6] Cập nhật biến môi trường User PATH (Registry an toàn)...")
    path_ok, path_changed = add_bin_to_user_path(bin_dir)

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
        print("[ERROR] Smoke test thất bại! Khởi động quy trình hoàn tác (Rollback)...")
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
    Preserves user customizations and investigation logs unless --purge-data is specified.
    """
    install_dir, bin_dir, skill_dir, skill_ref_dir = get_target_directories()
    target_exe = bin_dir / "disk_investigator.exe"
    target_skill = skill_dir / "SKILL.md"
    target_skill_ref_docs = skill_ref_dir / "README.md"
    manifest = load_manifest(install_dir)

    print("=======================================================")
    print(f"       GỠ CÀI ĐẶT {APP_DISPLAY_NAME}")
    print("=======================================================")
    print(f"Thư mục cài đặt:   {install_dir}")
    print(f"Xóa dữ liệu phụ:   {purge_data}")
    print("=======================================================\n")

    # 1. Remove PATH
    print("[1/4] Gỡ bỏ thư mục bin khỏi biến môi trường User PATH...")
    remove_bin_from_user_path(bin_dir)

    # 2. Check skill preservation
    print("[2/4] Kiểm tra và gỡ bỏ Antigravity Skill...")
    if target_skill.exists():
        curr_hash = compute_sha256(target_skill)
        recorded_hash = manifest.get("skill_sha256") if manifest else None

        if recorded_hash and curr_hash != recorded_hash:
            print(f"[*] Phát hiện người dùng đã tùy chỉnh SKILL.md. Giữ lại tệp để bảo toàn dữ liệu:")
            print(f"    {target_skill}")
        else:
            try:
                target_skill.unlink()
                print(f"[+] Đã gỡ bỏ Skill: {target_skill}")
            except Exception as e:
                print(f"[!] Không thể xóa Skill: {e}")

    # Remove references readme if present
    if target_skill_ref_docs.exists():
        try:
            target_skill_ref_docs.unlink()
        except Exception:
            pass

    # Try removing skill folders if empty
    try:
        if skill_ref_dir.exists() and not any(skill_ref_dir.iterdir()):
            skill_ref_dir.rmdir()
        if skill_dir.exists() and not any(skill_dir.iterdir()):
            skill_dir.rmdir()
    except Exception:
        pass

    # 3. Remove binary and core files
    print("[3/4] Xóa tệp nhị phân và tài nguyên...")
    if target_exe.exists():
        try:
            target_exe.unlink()
            print(f"[+] Đã xóa: {target_exe.name}")
        except Exception as e:
            print(f"[!] Lỗi khi xóa executable (có thể đang chạy): {e}")

    docs_file = install_dir / "README.md"
    if docs_file.exists():
        try:
            docs_file.unlink()
        except Exception:
            pass

    manifest_file = install_dir / "install_manifest.json"
    if manifest_file.exists():
        try:
            manifest_file.unlink()
        except Exception:
            pass

    # Remove lifecycle engine if present
    lifecycle_dir = install_dir / "lifecycle"
    if lifecycle_dir.exists():
        try:
            shutil.rmtree(lifecycle_dir, ignore_errors=True)
            print(f"[+] Đã xóa lifecycle engine: {lifecycle_dir.name}")
        except Exception:
            pass

    # 4. Handle remaining data / purge
    print("[4/4] Dọn dẹp thư mục cài đặt...")
    if purge_data:
        try:
            shutil.rmtree(install_dir, ignore_errors=True)
            print(f"[+] Đã xóa toàn bộ thư mục dữ liệu {install_dir}")
        except Exception as e:
            print(f"[!] Lỗi khi xóa thư mục: {e}")
    else:
        # Check if bin dir is empty
        try:
            if bin_dir.exists() and not any(bin_dir.iterdir()):
                bin_dir.rmdir()
        except Exception:
            pass
        print(f"[*] Đã hoàn tất gỡ cài đặt. Dữ liệu báo cáo/cache được giữ lại tại {install_dir}.")

    print("\n[+] Gỡ cài đặt hoàn tất thành công.\n")
    return True


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

    args = parser.parse_args()

    if args.uninstall:
        success = uninstall(silent=args.silent, purge_data=args.purge_data)
    else:
        success = install(silent=args.silent, repair=args.repair)

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
