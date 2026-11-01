#!/usr/bin/env python3
"""
build_uninstaller.py - Builds the Standalone Uninstaller Executable
(disk-investigator-uninstall.exe) for Disk Investigator.

Embeds:
1. skills/disk-cleanup/SKILL.md (for conservative hash comparison if manifest missing)
2. build_info.json (authoritative build version metadata)

Outputs:
Exactly one self-contained, offline uninstaller executable into the project root:
'disk-investigator-uninstall.exe'.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent
ENTRY_POINT = ROOT_DIR / "uninstaller.py"
TARGET_EXE_NAME = "disk-investigator-uninstall.exe"
TARGET_EXE_PATH = ROOT_DIR / TARGET_EXE_NAME

SKILL_PAYLOAD = ROOT_DIR / "skills" / "disk-cleanup" / "SKILL.md"
BUILD_INFO_PAYLOAD = ROOT_DIR / "build_info.json"

BUILD_WORK_DIR = ROOT_DIR / "_pyinstaller_uninstaller_work"
BUILD_DIST_DIR = ROOT_DIR / "_pyinstaller_uninstaller_dist"


def get_current_version() -> str:
    """Reads current __version__ from disk_investigator/__init__.py."""
    init_file = ROOT_DIR / "disk_investigator" / "__init__.py"
    if init_file.exists():
        with open(init_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("__version__"):
                    parts = line.split("=")
                    if len(parts) == 2:
                        return parts[1].strip().strip('"').strip("'")
    raise RuntimeError("Cannot resolve __version__ from disk_investigator/__init__.py")


def compute_sha256(filepath: Path) -> str:
    """Computes SHA-256 digest in 64KB chunks."""
    sha = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            sha.update(chunk)
    return sha.hexdigest()


def format_bytes(size: int) -> str:
    """Formats bytes into human-readable string."""
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} TB"


def clean_temporary_dirs() -> None:
    """Cleans temporary compilation directories."""
    for d in [BUILD_WORK_DIR, BUILD_DIST_DIR]:
        if d.exists() and d.is_dir():
            try:
                shutil.rmtree(d, ignore_errors=True)
            except Exception:
                pass


def build_uninstaller() -> bool:
    """Executes PyInstaller to package uninstaller.py into a standalone executable."""
    start_time = time.time()
    print("=======================================================")
    print("      BUILDING STANDALONE UNINSTALLER EXECUTABLE       ")
    print("=======================================================")
    print(f"Target Binary:     {TARGET_EXE_NAME}")
    print(f"Workspace Root:    {ROOT_DIR}")
    print("=======================================================\n")

    # Step 1: Check destination file lock
    print("[1/5] Checking file locks...")
    if TARGET_EXE_PATH.exists():
        try:
            with open(TARGET_EXE_PATH, "a+b"):
                pass
        except PermissionError:
            print(f"[ERROR] '{TARGET_EXE_NAME}' is currently running or locked by another process.")
            return False

    # Step 2: Clean temp dirs & write build_info.json
    print("[2/5] Cleaning temporary build folders & writing build_info.json...")
    clean_temporary_dirs()
    BUILD_WORK_DIR.mkdir(parents=True, exist_ok=True)
    BUILD_DIST_DIR.mkdir(parents=True, exist_ok=True)

    version = get_current_version()
    build_info_data = {
        "version": version,
        "release_tag": f"v{version}",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    with open(BUILD_INFO_PAYLOAD, "w", encoding="utf-8") as f:
        json.dump(build_info_data, f, indent=2)

    # Step 3: Run PyInstaller
    print(f"[3/5] Compiling single-file Uninstaller EXE (v{version})...")
    add_data_delimiter = ";" if sys.platform == "win32" else ":"

    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onefile",
        f"--name={TARGET_EXE_PATH.stem}",
        f"--distpath={str(BUILD_DIST_DIR)}",
        f"--workpath={str(BUILD_WORK_DIR)}",
        f"--specpath={str(BUILD_WORK_DIR)}",
        f"--add-data={str(BUILD_INFO_PAYLOAD)}{add_data_delimiter}.",
    ]
    if SKILL_PAYLOAD.exists():
        cmd.append(f"--add-data={str(SKILL_PAYLOAD)}{add_data_delimiter}.")

    cmd.append(str(ENTRY_POINT))

    print(f"[*] Running: {' '.join(cmd)}")
    proc = subprocess.run(cmd, cwd=str(ROOT_DIR))

    if proc.returncode != 0:
        print(f"[ERROR] PyInstaller failed with exit code {proc.returncode}")
        clean_temporary_dirs()
        return False

    compiled_uninstaller = BUILD_DIST_DIR / TARGET_EXE_NAME
    if not compiled_uninstaller.exists():
        print(f"[ERROR] Compiled uninstaller not found at {compiled_uninstaller}")
        clean_temporary_dirs()
        return False

    # Step 4: Quality Gate verification
    print("[4/5] Verifying compiled Uninstaller EXE (--help & --version smoke tests)...")
    try:
        smoke_proc = subprocess.run(
            [str(compiled_uninstaller), "--help"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
        )
        if smoke_proc.returncode != 0:
            print(f"[ERROR] Uninstaller EXE self-test failed with code {smoke_proc.returncode}")
            print(smoke_proc.stderr)
            clean_temporary_dirs()
            return False

        ver_proc = subprocess.run(
            [str(compiled_uninstaller), "--version"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
        )
        if ver_proc.returncode != 0:
            print(f"[ERROR] Uninstaller EXE --version self-test failed with code {ver_proc.returncode}")
            print(ver_proc.stderr)
            clean_temporary_dirs()
            return False

        ver_output = ver_proc.stdout.strip() or ver_proc.stderr.strip()
        if version not in ver_output:
            print(f"[ERROR] Version mismatch! Expected {version}, got: {ver_output}")
            clean_temporary_dirs()
            return False
        print(f"[+] Uninstaller EXE self-test OK (--help & --version: {ver_output}).")
    except Exception as e:
        print(f"[ERROR] Uninstaller EXE smoke test exception: {e}")
        clean_temporary_dirs()
        return False

    # Step 5: Atomic swap to root
    print("[5/5] Performing atomic swap to root folder...")
    try:
        os.replace(str(compiled_uninstaller), str(TARGET_EXE_PATH))
    except Exception as e:
        print(f"[ERROR] Failed atomic swap to {TARGET_EXE_PATH}: {e}")
        clean_temporary_dirs()
        return False

    clean_temporary_dirs()

    file_size = TARGET_EXE_PATH.stat().st_size
    duration_sec = time.time() - start_time
    sha256_hash = compute_sha256(TARGET_EXE_PATH)

    print("\n=======================================================")
    print("   UNINSTALLER EXE PACKAGING COMPLETED SUCCESSFULLY    ")
    print(f" Output:   {TARGET_EXE_PATH.name}")
    print(f" Size:     {format_bytes(file_size)} ({file_size:,} bytes)")
    print(f" SHA-256:  {sha256_hash}")
    print(f" Duration: {duration_sec:.2f} seconds")
    print("=======================================================\n")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="build_uninstaller.py",
        description="Packager for disk-investigator-uninstall.exe.",
    )
    args = parser.parse_args()
    success = build_uninstaller()
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
