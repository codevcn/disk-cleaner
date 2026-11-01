"""
Shared lifecycle utilities and constants for Disk Investigator.
Used across installer, uninstaller, CLI, and CI build systems.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
import hashlib
import json
import os
import shutil
import subprocess
import sys
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

APP_NAME = "DiskInvestigator"
APP_DISPLAY_NAME = "Disk Investigator (AI-Native Storage Cleaner)"
SKILL_FOLDER_NAME = "disk-cleanup"
GITHUB_REPO = "codevcn/disk-cleaner"

RELEASE_ASSETS: List[str] = [
    "disk_investigator.exe",
    "disk-investigator-setup.exe",
    "disk-investigator-uninstall.exe",
]

KNOWN_OWNED_SUBDIRS: Set[str] = {
    "bin",
    "lifecycle",
    "logs",
    "cache",
    "plans",
    "updates",
    ".investigation_cache",
}

KNOWN_OWNED_FILES: Set[str] = {
    "readme.md",
    "install_manifest.json",
    "uninstall.cmd",
    "disk_investigator.exe",
    "disk-investigator-setup.exe",
    "disk-investigator-uninstall.exe",
}


class ProcessState(str, Enum):
    """Tri-state process verification status."""
    NOT_RUNNING = "NOT_RUNNING"
    RUNNING = "RUNNING"
    UNKNOWN = "UNKNOWN"


def check_process_state(exe_name: str) -> ProcessState:
    """
    Check if an executable is actively running on Windows without terminating it.
    Strict fail-closed: returns ProcessState.UNKNOWN on any error, timeout, or non-zero exit.
    """
    if sys.platform != "win32":
        return ProcessState.NOT_RUNNING

    try:
        proc = subprocess.run(
            ["tasklist", "/FI", f"IMAGENAME eq {exe_name}", "/NH"],
            capture_output=True,
            text=True,
            timeout=3,
            shell=False,
        )
        if proc.returncode != 0:
            return ProcessState.UNKNOWN
        stdout = proc.stdout.lower()
        if exe_name.lower() in stdout:
            return ProcessState.RUNNING
        return ProcessState.NOT_RUNNING
    except Exception:
        return ProcessState.UNKNOWN


def compute_sha256(filepath: Path) -> str:
    """Computes SHA-256 hash of a file safely in 64KB blocks."""
    sha = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            sha.update(chunk)
    return sha.hexdigest()


def get_resource_path(relative_name: str) -> Path:
    """
    Returns absolute path to embedded or project resource.
    Supports PyInstaller bundled mode (_MEIPASS) and source repository mode.
    """
    if hasattr(sys, "_MEIPASS"):
        candidate = Path(sys._MEIPASS) / relative_name  # type: ignore
        if candidate.exists():
            return candidate

    # Find project root by searching upwards for marker files
    current = Path(__file__).resolve().parent
    for parent in [current] + list(current.parents):
        if (parent / "disk_investigator").is_dir() or (parent / "build_exe.py").is_file():
            root_candidate = parent / relative_name
            if root_candidate.exists():
                return root_candidate
            # Check specific subfolder candidates
            if relative_name == "SKILL.md":
                sk = parent / "skills" / SKILL_FOLDER_NAME / "SKILL.md"
                if sk.exists():
                    return sk
            elif relative_name == "README.md":
                rm = parent / "README.md"
                if rm.exists():
                    return rm
            elif relative_name == "disk_investigator.exe":
                de = parent / "disk_investigator.exe"
                if de.exists():
                    return de
            elif relative_name == "disk-investigator-setup.exe":
                se = parent / "disk-investigator-setup.exe"
                if se.exists():
                    return se
            elif relative_name == "disk-investigator-uninstall.exe":
                ue = parent / "disk-investigator-uninstall.exe"
                if ue.exists():
                    return ue
            return root_candidate

    return Path(relative_name).resolve()


def get_app_version() -> str:
    """
    Retrieves authoritative version from embedded build_info.json or __init__.py.
    Provides Single Source of Truth across CLI, installer, uninstaller, and manifests.
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

    # 2. Check disk_investigator/__init__.py
    try:
        from disk_investigator import __version__
        return __version__
    except Exception:
        pass

    # 3. Fallback to reading file directly
    current = Path(__file__).resolve().parent
    for parent in [current] + list(current.parents):
        init_file = parent / "disk_investigator" / "__init__.py"
        if init_file.exists():
            try:
                with open(init_file, "r", encoding="utf-8") as f:
                    for line in f:
                        if line.startswith("__version__"):
                            return line.split("=")[1].strip().strip('"').strip("'")
            except Exception:
                pass

    return "unknown"


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
    Broadcasts WM_SETTINGCHANGE message to notify running top-level windows
    that user environment variables have been updated.
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


def add_bin_to_user_path(bin_dir: Path, broadcast_fn: Optional[Any] = None) -> Tuple[bool, bool]:
    """
    Safely adds bin_dir to HKCU\\Environment\\Path using winreg.
    Preserves all existing variables and REG_EXPAND_SZ typing.
    Never uses 'setx' to prevent length truncation bugs.
    Returns:
        (success: bool, changed: bool)
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

            entries = [p.strip() for p in current_path_val.split(";") if p.strip()]

            for entry in entries:
                if entry.lower().rstrip("\\") == bin_norm:
                    print(f"[*] Thư mục bin đã tồn tại trong User PATH: {bin_dir}")
                    return True, False

            entries.append(bin_str)
            new_path_val = ";".join(entries)

            winreg.SetValueEx(key, "Path", 0, winreg.REG_EXPAND_SZ, new_path_val)
            print(f"[+] Đã thêm vào User PATH: {bin_dir}")

        if broadcast_fn is not None:
            broadcast_fn()
        else:
            broadcast_environment_change()
        return True, True
    except Exception as e:
        print(f"[ERROR] Thất bại khi ghi Registry User PATH: {e}")
        return False, False


def remove_bin_from_user_path(bin_dir: Path, broadcast_fn: Optional[Any] = None) -> bool:
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
                if broadcast_fn is not None:
                    broadcast_fn()
                else:
                    broadcast_environment_change()
            else:
                print(f"[*] Thư mục bin không có trong User PATH.")

        return True
    except Exception as e:
        print(f"[ERROR] Thất bại khi cập nhật Registry User PATH: {e}")
        return False


def load_manifest(install_dir: Path) -> Optional[Dict[str, Any]]:
    """Loads existing install_manifest.json if present and valid."""
    manifest_file = install_dir / "install_manifest.json"
    if manifest_file.exists():
        try:
            with open(manifest_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None
    return None


def write_manifest(install_dir: Path, manifest_data: Dict[str, Any]) -> None:
    """Writes install_manifest.json atomically."""
    manifest_file = install_dir / "install_manifest.json"
    tmp_file = manifest_file.with_suffix(".tmp")
    with open(tmp_file, "w", encoding="utf-8") as f:
        json.dump(manifest_data, f, indent=2, ensure_ascii=False)
    os.replace(str(tmp_file), str(manifest_file))
    print(f"[+] Đã lưu bản ghi cấu hình cài đặt: {manifest_file.name}")
