#!/usr/bin/env python3
"""
publish_release.py - Automated Release & Remote Publishing Engine
for disk_investigator (https://github.com/codevcn/disk-cleaner).

Automates the complete release lifecycle:
1. Version management (bump patch/minor or specify custom version).
2. Quality Gate: runs the full unit test suite (48 tests).
3. Compiles the standalone root executable (disk_investigator.exe) via build_exe.py.
4. Updates build_history.json.
5. Commits and pushes changes to GitHub origin/main.
6. Publishes a GitHub Release (vX.Y.Z) with attached binary asset via GitHub CLI (gh).
7. Cleans cache and verifies deployment.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Ensure UTF-8 output on Windows consoles
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

ROOT_DIR = Path(__file__).resolve().parent
INIT_FILE = ROOT_DIR / "disk_investigator" / "__init__.py"
TARGET_EXE = ROOT_DIR / "disk_investigator.exe"
GITHUB_REPO = "codevcn/disk-cleaner"


def run_cmd(
    cmd: List[str],
    cwd: Optional[Path] = None,
    check: bool = False,
) -> subprocess.CompletedProcess[str]:
    """Runs subprocess command safely with UTF-8 encoding."""
    return subprocess.run(
        cmd,
        cwd=str(cwd or ROOT_DIR),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=check,
    )


def get_current_version() -> str:
    """Reads current __version__ from disk_investigator/__init__.py."""
    if INIT_FILE.exists():
        with open(INIT_FILE, "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("__version__"):
                    parts = line.split("=")
                    if len(parts) == 2:
                        return parts[1].strip().strip('"').strip("'")
    return "2.0.3"


def bump_version(current: str, bump_type: str = "patch") -> str:
    """Bumps semver patch or minor number."""
    parts = [int(p) for p in re.findall(r"\d+", current)]
    while len(parts) < 3:
        parts.append(0)

    major, minor, patch = parts[0], parts[1], parts[2]
    if bump_type == "minor":
        minor += 1
        patch = 0
    elif bump_type == "major":
        major += 1
        minor = 0
        patch = 0
    else:  # patch
        patch += 1

    return f"{major}.{minor}.{patch}"


def update_version_in_init(new_version: str) -> bool:
    """Writes new version into disk_investigator/__init__.py."""
    if not INIT_FILE.exists():
        return False
    with open(INIT_FILE, "r", encoding="utf-8") as f:
        content = f.read()

    new_content = re.sub(
        r'__version__\s*=\s*["\'][^"\']+["\']',
        f'__version__ = "{new_version}"',
        content,
    )
    with open(INIT_FILE, "w", encoding="utf-8") as f:
        f.write(new_content)
    return True


def check_prerequisites() -> Tuple[bool, str]:
    """Verifies Git and GitHub CLI availability and auth status."""
    # Check git
    git_check = run_cmd(["git", "rev-parse", "--is-inside-work-tree"])
    if git_check.returncode != 0:
        return False, "Not inside a valid Git repository."

    # Check gh
    gh_check = run_cmd(["gh", "auth", "status"])
    if gh_check.returncode != 0:
        return False, f"GitHub CLI is not authenticated. Error: {gh_check.stderr.strip()}"

    return True, "Prerequisites OK."


def run_tests() -> bool:
    """Runs test suite to prevent releasing broken builds."""
    print("[*] Running automated test suite (Quality Gate)...")
    res = run_cmd([sys.executable, "-m", "unittest", "discover", "-s", "disk_investigator/tests", "-v"])
    if res.returncode == 0:
        print("[+] All unit & destructive tests passed successfully.")
        return True
    else:
        print("[ERROR] Tests failed! Release process aborted to ensure production stability.")
        print(res.stdout)
        print(res.stderr)
        return False


def build_binary(version: str) -> bool:
    """Invokes build_exe.py to package the standalone binary."""
    print(f"[*] Packaging disk_investigator.exe for v{version}...")
    res = run_cmd([sys.executable, "build_exe.py", "--version", version])
    if res.returncode == 0:
        print("[+] Binary compiled and verified successfully.")
        return True
    else:
        print(f"[ERROR] Build packaging failed with code {res.returncode}")
        print(res.stdout)
        print(res.stderr)
        return False


def publish_release(
    target_version: str,
    release_notes: str,
    dry_run: bool = False,
) -> bool:
    """Executes git commit, push, and GitHub Release publication."""
    tag_name = f"v{target_version}"
    release_title = f"{tag_name} - {release_notes}"

    print(f"=======================================================")
    print(f"    PUBLISHING RELEASE {tag_name} TO GITHUB REMOTE    ")
    print(f"=======================================================")
    print(f"Repository:    https://github.com/{GITHUB_REPO}")
    print(f"Target Tag:    {tag_name}")
    print(f"Release Title: {release_title}")
    print(f"Dry Run:       {dry_run}")
    print(f"=======================================================\n")

    if dry_run:
        print("[DRY-RUN] Step 1: Would stage all files with 'git add .'")
        print(f"[DRY-RUN] Step 2: Would commit with message: 'release: {release_title}'")
        print("[DRY-RUN] Step 3: Would push commits with 'git push origin main'")
        print(f"[DRY-RUN] Step 4: Would publish release '{tag_name}' with attached asset '{TARGET_EXE.name}'")
        print("[DRY-RUN] Success (simulation complete).")
        return True

    # 1. Git Add & Commit
    print("[1/4] Staging and committing changes to Git...")
    run_cmd(["git", "add", "."])

    # Check if there are changes to commit
    diff_check = run_cmd(["git", "status", "--porcelain"])
    if diff_check.stdout.strip():
        commit_res = run_cmd(["git", "commit", "-m", f"release: {release_title}"])
        if commit_res.returncode != 0:
            print(f"[ERROR] Git commit failed: {commit_res.stderr.strip()}")
            return False
        print(f"[+] Committed: release: {release_title}")
    else:
        print("[*] No uncommitted changes detected in working tree.")

    # 2. Git Push
    print("[2/4] Pushing commits to GitHub origin/main...")
    push_res = run_cmd(["git", "push", "origin", "main"])
    if push_res.returncode != 0:
        print(f"[ERROR] Git push failed: {push_res.stderr.strip()}")
        return False
    print("[+] Pushed commits to origin/main.")

    # 3. Create or Update GitHub Release
    print(f"[3/4] Publishing GitHub Release {tag_name} with executable asset...")
    if not TARGET_EXE.exists():
        print(f"[ERROR] Binary '{TARGET_EXE.name}' not found for upload.")
        return False

    # Check if release tag already exists
    view_res = run_cmd(["gh", "release", "view", tag_name])
    if view_res.returncode == 0:
        print(f"[*] Release {tag_name} already exists. Updating release asset...")
        upload_res = run_cmd(["gh", "release", "upload", tag_name, str(TARGET_EXE), "--clobber"])
        if upload_res.returncode != 0:
            print(f"[ERROR] Failed to upload asset: {upload_res.stderr.strip()}")
            return False
        print(f"[+] Asset {TARGET_EXE.name} updated on release {tag_name}.")
    else:
        # Create fresh release
        create_res = run_cmd([
            "gh", "release", "create", tag_name, str(TARGET_EXE),
            "--title", release_title,
            "--notes", f"Release {tag_name}: {release_notes}\n\nAutomated production build for Windows 11.",
        ])
        if create_res.returncode != 0:
            print(f"[ERROR] Failed to create GitHub release: {create_res.stderr.strip()}")
            return False
        print(f"[+] GitHub Release {tag_name} published successfully!")

    # 4. Invalidate local update cache
    print("[4/4] Finalizing deployment...")
    cache_file = ROOT_DIR / ".investigation_cache" / "update_status.json"
    if cache_file.exists():
        try:
            cache_file.unlink()
        except Exception:
            pass

    release_url = f"https://github.com/{GITHUB_REPO}/releases/tag/{tag_name}"
    print("\n=======================================================")
    print("           RELEASE PUBLISHED SUCCESSFULLY!             ")
    print(f" Version:  {tag_name}")
    print(f" URL:      {release_url}")
    print(f" Binary:   {TARGET_EXE.name}")
    print("=======================================================\n")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="publish_release.py",
        description="Publish release to GitHub with automated test, build, commit, and tag.",
    )
    parser.add_argument(
        "notes",
        nargs="?",
        default="Update and maintenance release",
        help="Release notes or commit message summary (e.g. 'feat: new scanning speed')",
    )
    parser.add_argument(
        "--version",
        dest="custom_version",
        default=None,
        help="Specify exact version (e.g. 2.0.4). Defaults to current or bumped version.",
    )
    parser.add_argument(
        "--bump-patch",
        action="store_true",
        help="Automatically bump patch number (e.g. 2.0.3 -> 2.0.4).",
    )
    parser.add_argument(
        "--bump-minor",
        action="store_true",
        help="Automatically bump minor number (e.g. 2.0.3 -> 2.1.0).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate the entire process without committing, pushing, or creating release.",
    )
    parser.add_argument(
        "--skip-tests",
        action="store_true",
        help="Skip running tests before building (not recommended).",
    )

    args = parser.parse_args()

    # Step 1: Check prerequisites
    ok, err_msg = check_prerequisites()
    if not ok:
        print(f"[ERROR] {err_msg}")
        return 1

    # Step 2: Determine version
    current_ver = get_current_version()
    if args.custom_version:
        target_ver = args.custom_version.lstrip("v")
    elif args.bump_minor:
        target_ver = bump_version(current_ver, bump_type="minor")
    elif args.bump_patch:
        target_ver = bump_version(current_ver, bump_type="patch")
    else:
        target_ver = current_ver

    print(f"[*] Current Version: v{current_ver} -> Target Version: v{target_ver}")

    # Update __init__.py if version changed
    if target_ver != current_ver:
        if not args.dry_run:
            print(f"[+] Updating version to v{target_ver} in disk_investigator/__init__.py...")
            update_version_in_init(target_ver)
        else:
            print(f"[DRY-RUN] Would update version to v{target_ver} in __init__.py")

    # Step 3: Quality Gate (Tests)
    if not args.skip_tests and not args.dry_run:
        if not run_tests():
            return 1

    # Step 4: Build Executable
    if not args.dry_run:
        if not build_binary(target_ver):
            return 1

    # Step 5: Publish Release
    success = publish_release(
        target_version=target_ver,
        release_notes=args.notes,
        dry_run=args.dry_run,
    )
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
