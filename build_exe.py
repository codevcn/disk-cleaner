#!/usr/bin/env python3
"""
build_exe.py - Standalone Single-File Executable Packaging Script
for disk_investigator (AI-native Windows 11 Disk Investigation Harness).

Rules enforced:
1. Outputs exactly ONE executable into the project root folder: 'disk_investigator.exe'.
2. Before packaging (especially from the 2nd time onwards), automatically removes any existing
   executable in the root directory to guarantee a clean build and identical filename.
3. Automatically cleans up all temporary PyInstaller directories (build, dist, .spec).
4. Records every build event into 'build_history.json' with build number, version, ISO timestamp,
   file size, SHA-256 digest, Python/PyInstaller runtime environment, and duration.
5. Verifies the newly compiled executable post-build.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

# Root directory of the repository
ROOT_DIR = Path(__file__).resolve().parent
ENTRY_POINT = ROOT_DIR / "disk_investigator" / "__main__.py"
HISTORY_FILE = ROOT_DIR / "build_history.json"
TARGET_EXE_NAME = "disk_investigator.exe"
TARGET_EXE_PATH = ROOT_DIR / TARGET_EXE_NAME

# Temporary directories used during PyInstaller compilation
BUILD_WORK_DIR = ROOT_DIR / "_pyinstaller_work"
BUILD_DIST_DIR = ROOT_DIR / "_pyinstaller_dist"


def get_current_package_version() -> str:
    """Reads current __version__ from disk_investigator/__init__.py."""
    init_path = ROOT_DIR / "disk_investigator" / "__init__.py"
    if init_path.exists():
        with open(init_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("__version__"):
                    parts = line.split("=")
                    if len(parts) == 2:
                        return parts[1].strip().strip('"').strip("'")
    return "2.0.3"


def compute_sha256(filepath: Path) -> str:
    """Computes SHA-256 checksum of a file in 64KB blocks."""
    sha = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            sha.update(chunk)
    return sha.hexdigest()


def format_bytes(size: int) -> str:
    """Formats raw bytes to human-readable string (KB, MB, GB)."""
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} TB"


def clean_root_executables() -> List[str]:
    """
    Finds and deletes any .exe files in the root folder.
    Raises PermissionError if a file is currently locked by a running process.
    """
    removed: List[str] = []
    for item in ROOT_DIR.glob("*.exe"):
        if item.is_file():
            print(f"[*] Removing existing root executable: {item.name}")
            try:
                item.unlink()
                removed.append(item.name)
            except PermissionError as pe:
                print(f"[ERROR] Cannot delete '{item.name}': file is locked by a running process.")
                print("[ERROR] Please terminate any running instances of disk_investigator.exe and try again.")
                raise pe
            except OSError as oe:
                print(f"[ERROR] Failed to delete '{item.name}': {oe}")
                raise oe
    return removed


def clean_temporary_build_dirs() -> None:
    """Removes PyInstaller temporary build artifacts to keep root pristine."""
    dirs_to_clean = [
        BUILD_WORK_DIR,
        BUILD_DIST_DIR,
        ROOT_DIR / "build",
        ROOT_DIR / "dist",
    ]
    for d in dirs_to_clean:
        if d.exists() and d.is_dir():
            try:
                shutil.rmtree(d, ignore_errors=True)
            except Exception as e:
                print(f"[!] Warning: Could not remove temporary dir {d}: {e}")

    # Remove lingering .spec files in root
    for spec_file in ROOT_DIR.glob("*.spec"):
        try:
            spec_file.unlink()
        except Exception:
            pass


def load_build_history() -> Dict[str, Any]:
    """Loads existing build_history.json or initializes empty schema."""
    if HISTORY_FILE.exists():
        try:
            with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict) and "history" in data:
                    return data
        except Exception as e:
            print(f"[!] Warning: Could not parse existing build_history.json: {e}")
    return {"latest": None, "history": []}


def save_build_history(history_data: Dict[str, Any]) -> None:
    """Saves build history cleanly to build_history.json."""
    with open(HISTORY_FILE, "w", encoding="utf-8") as f:
        json.dump(history_data, f, indent=2, ensure_ascii=False)
    print(f"[+] Updated build manifest: {HISTORY_FILE.name}")


def show_build_history() -> None:
    """Prints formatted build history table."""
    data = load_build_history()
    history = data.get("history", [])
    if not history:
        print("[*] No builds recorded yet in build_history.json.")
        return

    print("\n=======================================================")
    print("               DISK INVESTIGATOR BUILD HISTORY        ")
    print("=======================================================")
    print(f"Total builds recorded: {len(history)}\n")
    for item in history:
        b_num = item.get("build_number", "?")
        ver = item.get("version", "?")
        ts = item.get("timestamp", "?")
        size = item.get("file_size_formatted", "?")
        sha = item.get("sha256", "?")[:16] + "..." if item.get("sha256") else "?"
        dur = f"{item.get('build_duration_sec', 0):.1f}s"
        print(f"Build #{b_num:02d} | v{ver:<7} | {ts} | {size:>9} | SHA: {sha} | Time: {dur}")
    print("=======================================================\n")


def build_executable(version_override: Optional[str] = None) -> bool:
    """
    Executes the PyInstaller packaging workflow.
    Ensures single executable in root, clean temporary folders, and history tracking.
    """
    start_time = time.time()
    version = version_override or get_current_package_version()

    print(f"=======================================================")
    print(f" Packaging disk_investigator v{version} as Standalone EXE ")
    print(f"=======================================================")
    print(f"Python Runtime:    {sys.executable} ({platform.python_version()})")
    print(f"Platform:          {platform.system()} {platform.release()} ({platform.machine()})")
    print(f"Workspace Root:    {ROOT_DIR}")
    print(f"Target Binary:     {TARGET_EXE_NAME}")
    print(f"=======================================================\n")

    # Step 1: Pre-build cleanup of existing root executables
    print("[1/6] Scanning and removing existing root executables...")
    try:
        clean_root_executables()
    except Exception:
        return False

    # Step 2: Clean up previous temporary build artifacts
    print("[2/6] Cleaning up previous temporary build directories...")
    clean_temporary_build_dirs()

    # Step 3: Check PyInstaller availability
    print("[3/6] Verifying PyInstaller availability...")
    try:
        import PyInstaller  # type: ignore
        pyinstaller_version = getattr(PyInstaller, "__version__", "unknown")
        print(f"[+] Found PyInstaller v{pyinstaller_version}")
    except ImportError:
        print("[ERROR] PyInstaller is not installed in the current Python environment.")
        print("[ERROR] Please install it using: pip install pyinstaller")
        return False

    # Prepare directories
    BUILD_WORK_DIR.mkdir(parents=True, exist_ok=True)
    BUILD_DIST_DIR.mkdir(parents=True, exist_ok=True)

    # Step 4: Run PyInstaller
    print("[4/6] Compiling single-file binary with PyInstaller...")
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
        str(ENTRY_POINT),
    ]

    print(f"[*] Running: {' '.join(cmd)}")
    proc = subprocess.run(cmd, cwd=str(ROOT_DIR))

    if proc.returncode != 0:
        print(f"[ERROR] PyInstaller compilation failed with exit code {proc.returncode}")
        clean_temporary_build_dirs()
        return False

    # Step 5: Move binary to root & clean temporary dirs
    print("[5/6] Moving final executable to project root...")
    compiled_binary = BUILD_DIST_DIR / TARGET_EXE_NAME
    if not compiled_binary.exists():
        print(f"[ERROR] Expected binary not found at: {compiled_binary}")
        clean_temporary_build_dirs()
        return False

    shutil.move(str(compiled_binary), str(TARGET_EXE_PATH))
    clean_temporary_build_dirs()

    # Verify ONLY 1 .exe exists in root
    root_exes = list(ROOT_DIR.glob("*.exe"))
    if len(root_exes) != 1 or root_exes[0].name != TARGET_EXE_NAME:
        print(f"[!] Warning: Root folder has unexpected .exe files: {[e.name for e in root_exes]}")

    # Compute binary metadata
    file_size = TARGET_EXE_PATH.stat().st_size
    formatted_size = format_bytes(file_size)
    sha256_hash = compute_sha256(TARGET_EXE_PATH)
    duration_sec = time.time() - start_time
    iso_timestamp = datetime.datetime.now().astimezone().isoformat()

    print(f"[+] Output executable: {TARGET_EXE_PATH.name}")
    print(f"[+] File Size:         {formatted_size} ({file_size:,} bytes)")
    print(f"[+] SHA-256 Digest:    {sha256_hash}")
    print(f"[+] Build Time:        {duration_sec:.2f} seconds")

    # Step 6: Post-build self-test & history recording
    print("[6/6] Verifying standalone executable and recording build history...")

    # Run --version test on the compiled binary
    try:
        test_proc = subprocess.run(
            [str(TARGET_EXE_PATH), "--version"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        version_output = test_proc.stdout.strip() or test_proc.stderr.strip()
        print(f"[+] Executable self-test OK: '{version_output}'")
    except Exception as e:
        print(f"[!] Warning: Executable self-test failed: {e}")

    # Update build_history.json
    history_data = load_build_history()
    existing_history: List[Dict[str, Any]] = history_data.get("history", [])
    next_build_number = len(existing_history) + 1

    build_entry: Dict[str, Any] = {
        "build_number": next_build_number,
        "version": version,
        "timestamp": iso_timestamp,
        "executable": TARGET_EXE_NAME,
        "file_size_bytes": file_size,
        "file_size_formatted": formatted_size,
        "sha256": sha256_hash,
        "build_duration_sec": round(duration_sec, 2),
        "python_version": platform.python_version(),
        "pyinstaller_version": pyinstaller_version,
        "platform": f"{platform.system()} {platform.release()} ({platform.machine()})",
        "status": "SUCCESS",
    }

    existing_history.append(build_entry)
    history_data["latest"] = build_entry
    history_data["history"] = existing_history
    save_build_history(history_data)

    print("\n=======================================================")
    print("           PACKAGING COMPLETED SUCCESSFULLY           ")
    print(f" Build #{next_build_number} | v{version} | {TARGET_EXE_NAME} ")
    print("=======================================================\n")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="build_exe.py",
        description="Packager for disk_investigator into a single root .exe with build history.",
    )
    parser.add_argument(
        "--clean-only",
        action="store_true",
        help="Remove existing root .exe and temporary build folders without building.",
    )
    parser.add_argument(
        "--history",
        action="store_true",
        help="Display build history from build_history.json and exit.",
    )
    parser.add_argument(
        "--version",
        dest="version_override",
        default=None,
        help="Override version recorded in manifest and build.",
    )

    args = parser.parse_args()

    if args.history:
        show_build_history()
        return 0

    if args.clean_only:
        print("[*] Cleaning root executables and temporary build directories...")
        clean_root_executables()
        clean_temporary_build_dirs()
        print("[+] Cleanup complete.")
        return 0

    success = build_executable(version_override=args.version_override)
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
