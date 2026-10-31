#!/usr/bin/env python3
"""
update_from_github.py - Autonomous Updater for disk_investigator.

Enables the AI Agent or User to:
1. Query GitHub (codevcn/disk-cleaner) for the latest release/commits.
2. Safely pull down code updates via Git.
3. Automatically execute unit tests to ensure integrity.
4. Rebuild the standalone root executable (disk_investigator.exe) via build_exe.py.
5. Synchronize the Antigravity Agent skill file (~/.gemini/config/skills/disk-cleanup/SKILL.md).
6. Update build history manifest and clear update check cache.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

# Ensure UTF-8 output on Windows consoles
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

ROOT_DIR = Path(__file__).resolve().parent
GLOBAL_SKILL_PATH = (
    Path.home() / ".gemini" / "config" / "skills" / "disk-cleanup" / "SKILL.md"
)
LOCAL_SKILL_PATH = ROOT_DIR / "skills" / "disk-cleanup" / "SKILL.md"
GITHUB_REPO = "codevcn/disk-cleaner"


def run_cmd(
    cmd: list[str], cwd: Optional[Path] = None, check: bool = False
) -> subprocess.CompletedProcess[str]:
    """Helper to run command with UTF-8 encoding."""
    return subprocess.run(
        cmd,
        cwd=str(cwd or ROOT_DIR),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=check,
    )


def get_local_version() -> str:
    """Reads current local version from disk_investigator/__init__.py."""
    init_file = ROOT_DIR / "disk_investigator" / "__init__.py"
    if init_file.exists():
        with open(init_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("__version__"):
                    parts = line.split("=")
                    if len(parts) == 2:
                        return parts[1].strip().strip('"').strip("'")
    return "unknown"


def is_git_repo() -> bool:
    """Checks if workspace is a git work tree."""
    res = run_cmd(["git", "rev-parse", "--is-inside-work-tree"])
    return res.returncode == 0 and res.stdout.strip() == "true"


def check_remote_status() -> Dict[str, Any]:
    """Checks GitHub for newer commits/releases."""
    sys.path.insert(0, str(ROOT_DIR))
    from disk_investigator.version_checker import check_for_updates

    current_ver = get_local_version()
    info = check_for_updates(current_version=current_ver, repo=GITHUB_REPO, force=True)
    return info


def sync_antigravity_skill() -> bool:
    """Copies workspace skill file to Antigravity global skill config."""
    if not LOCAL_SKILL_PATH.exists():
        return False
    try:
        GLOBAL_SKILL_PATH.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(LOCAL_SKILL_PATH, GLOBAL_SKILL_PATH)
        print(f"[+] Synchronized Antigravity skill: {GLOBAL_SKILL_PATH}")
        return True
    except Exception as e:
        print(f"[!] Warning: Could not sync skill to global directory: {e}")
        return False


def run_tests() -> bool:
    """Executes full unit test suite."""
    print("[*] Running test suite to verify code health...")
    res = run_cmd([sys.executable, "-m", "unittest", "discover", "-s", "disk_investigator/tests", "-v"])
    if res.returncode == 0:
        print("[+] Test suite passed 100% OK.")
        return True
    else:
        print("[ERROR] Test suite failed! Update aborted to prevent breaking existing installation.")
        print(res.stdout)
        print(res.stderr)
        return False


def rebuild_executable() -> bool:
    """Triggers build_exe.py to rebuild root executable."""
    print("[*] Rebuilding standalone root executable (disk_investigator.exe)...")
    res = run_cmd([sys.executable, "build_exe.py"])
    if res.returncode == 0:
        print("[+] Standalone executable successfully rebuilt.")
        return True
    else:
        print(f"[ERROR] Failed to compile executable. Code: {res.returncode}")
        print(res.stderr)
        return False


def clear_update_cache() -> None:
    """Clears cached update status file."""
    cache_file = ROOT_DIR / ".investigation_cache" / "update_status.json"
    if cache_file.exists():
        try:
            cache_file.unlink()
        except Exception:
            pass


def perform_update(force: bool = False) -> int:
    """Main update workflow."""
    local_ver = get_local_version()
    print("=======================================================")
    print("       DISK INVESTIGATOR - GITHUB AUTO-UPDATER         ")
    print("=======================================================")
    print(f"Local Version:     v{local_ver}")
    print(f"Repository:        https://github.com/{GITHUB_REPO}")
    print(f"Workspace:         {ROOT_DIR}")
    print("=======================================================\n")

    if not is_git_repo():
        print("[ERROR] Current directory is not a Git repository.")
        print("Please initialize git and connect to the remote repository first.")
        return 1

    # Step 1: Check remote version
    print("[1/5] Checking remote status on GitHub...")
    update_info = check_remote_status()
    latest_ver = update_info.get("latest_version", local_ver)
    has_update = update_info.get("update_available", False)

    print(f"[*] Local: v{local_ver} | Remote: v{latest_ver}")

    if not has_update and not force:
        print(f"\n[+] You are already running the latest version (v{local_ver}).")
        print("[*] Use --force if you want to pull and recompile anyway.")
        return 0

    if has_update:
        print(f"[!] New version v{latest_ver} detected on GitHub!")

    # Step 2: Git fetch and pull
    print("[2/5] Pulling latest changes from GitHub origin/main...")
    fetch_res = run_cmd(["git", "fetch", "origin"])
    if fetch_res.returncode != 0:
        print(f"[ERROR] Git fetch failed: {fetch_res.stderr.strip()}")
        return 1

    pull_res = run_cmd(["git", "pull", "--rebase", "origin", "main"])
    if pull_res.returncode != 0:
        print(f"[!] Warning: 'git pull --rebase' failed: {pull_res.stderr.strip()}")
        print("[*] Attempting standard 'git pull'...")
        pull_res = run_cmd(["git", "pull", "origin", "main"])
        if pull_res.returncode != 0:
            print(f"[ERROR] Git pull failed: {pull_res.stderr.strip()}")
            return 1

    print(f"[+] Git output: {pull_res.stdout.strip()}")
    new_local_ver = get_local_version()

    # Step 3: Run test suite
    print("[3/5] Verifying code integrity with automated tests...")
    if not run_tests():
        print("[ERROR] Tests failed post-pull. Please inspect codebase.")
        return 1

    # Step 4: Rebuild executable
    print("[4/5] Updating standalone binary...")
    if not rebuild_executable():
        print("[ERROR] Standalone binary build failed.")
        return 1

    # Step 5: Sync skill & clear cache
    print("[5/5] Finalizing update...")
    sync_antigravity_skill()
    clear_update_cache()

    print("\n=======================================================")
    print("             UPDATE COMPLETED SUCCESSFULLY             ")
    print(f" Previous Version: v{local_ver}")
    print(f" Current Version:  v{new_local_ver}")
    print(f" Binary:           disk_investigator.exe")
    print("=======================================================\n")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="update_from_github.py",
        description="Autonomous update runner for disk_investigator from GitHub.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Check if an update is available without pulling.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force pull, re-test, and rebuild even if versions match.",
    )

    args = parser.parse_args()

    if args.check:
        info = check_remote_status()
        print(json.dumps(info, indent=2, ensure_ascii=False))
        return 0

    return perform_update(force=args.force)


if __name__ == "__main__":
    sys.exit(main())
