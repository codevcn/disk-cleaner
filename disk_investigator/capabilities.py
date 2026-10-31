"""
Environment capabilities and diagnostics for disk_investigator on Windows 11.
Provides self-test / doctor inspection.
"""

from __future__ import annotations

import ctypes
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional


def get_default_cache_dir() -> Path:
    """Returns the default directory for persistent state and plans."""
    env_dir = os.environ.get("DISK_INVESTIGATOR_CACHE_DIR")
    if env_dir:
        return Path(env_dir)
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        return Path(local_app_data) / "DiskInvestigator"
    return Path(os.getcwd()) / ".investigation_cache"


def is_admin() -> bool:
    """Checks whether the current process is running with elevated Administrator privileges (advises non-admin mode)."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def get_available_drives(fixed_only: bool = True) -> List[str]:
    """Returns the list of available local drives, filtering for DRIVE_FIXED by default."""
    all_drives = []
    if hasattr(os, "listdrives"):
        all_drives = list(os.listdrives())
    else:
        import string
        bitmask = ctypes.windll.kernel32.GetLogicalDrives()
        for letter in string.ascii_uppercase:
            if bitmask & 1:
                all_drives.append(f"{letter}:\\")
            bitmask >>= 1

    if not fixed_only:
        return all_drives

    fixed_drives = []
    for d in all_drives:
        try:
            if hasattr(ctypes, "windll") and hasattr(ctypes.windll, "kernel32"):
                dtype = ctypes.windll.kernel32.GetDriveTypeW(d)
                if dtype == 3:  # DRIVE_FIXED
                    fixed_drives.append(d)
            else:
                fixed_drives.append(d)
        except Exception:
            fixed_drives.append(d)
    return fixed_drives if fixed_drives else all_drives


def get_tool_info(tool_name: str, version_arg: str = "--version") -> Dict[str, Any]:
    """Inspects if a CLI tool is available on PATH and queries its version."""
    path = shutil.which(tool_name)
    if not path:
        return {"available": False, "path": None, "version": None}

    version = None
    try:
        proc = subprocess.run(
            [path, version_arg],
            capture_output=True,
            text=True,
            timeout=3,
            shell=False,
        )
        if proc.returncode == 0:
            version = proc.stdout.strip().splitlines()[0] if proc.stdout else None
        elif proc.stderr:
            version = proc.stderr.strip().splitlines()[0]
    except Exception as e:
        version = f"Error querying version: {e}"

    return {"available": True, "path": path, "version": version}


def get_doctor_report() -> Dict[str, Any]:
    """Generates a complete diagnostic report of the host environment."""
    drives = get_available_drives()
    drive_stats = {}
    for d in drives:
        try:
            usage = shutil.disk_usage(d)
            drive_stats[d] = {
                "total_bytes": usage.total,
                "used_bytes": usage.used,
                "free_bytes": usage.free,
                "percent_used": round((usage.used / usage.total) * 100, 2),
            }
        except Exception as e:
            drive_stats[d] = {"error": str(e)}

    dust_info = get_tool_info("dust")
    czkawka_info = get_tool_info("czkawka_cli")
    bleachbit_info = get_tool_info("bleachbit_console.exe")
    docker_info = get_tool_info("docker", "--version")

    return {
        "os": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "platform": platform.platform(),
            "is_windows": platform.system().lower() == "windows",
        },
        "python": {
            "version": platform.python_version(),
            "executable": sys.executable,
            "has_listdrives": hasattr(os, "listdrives"),
            "has_isjunction": hasattr(os.path, "isjunction"),
        },
        "security": {
            "is_admin": is_admin(),
            "execution_mode": "ELEVATED (Admin)" if is_admin() else "NON-ELEVATED (Standard)",
            "safety_recommendation": (
                "Running non-elevated is safe for standard investigation."
                if not is_admin()
                else "Running as Administrator. Extreme caution required."
            ),
        },
        "storage": {
            "drives_count": len(drives),
            "drives": drives,
            "drive_details": drive_stats,
        },
        "tools": {
            "dust": dust_info,
            "czkawka_cli": czkawka_info,
            "bleachbit": bleachbit_info,
            "docker": docker_info,
        },
        "recommendation": (
            "Ready for high-speed scanning with DustBackend."
            if dust_info["available"]
            else "Dust CLI not found in PATH. Operating with NativeWindowsBackend."
        ),
    }
