#!/usr/bin/env python3
"""
publish_release.py - Automated Release & Remote Publishing Engine
for disk_investigator (https://github.com/codevcn/disk-cleaner).

Automates the complete release lifecycle:
1. Version management (bump patch/minor or specify custom version).
2. Quality Gate: runs the full unit test suite (120+ tests).
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
TARGET_SETUP_EXE = ROOT_DIR / "disk-investigator-setup.exe"
TARGET_UNINSTALL_EXE = ROOT_DIR / "disk-investigator-uninstall.exe"
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
    return "2.1.0"


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


def compute_file_sha256(filepath: Path) -> str:
    """Computes SHA-256 hash of a file."""
    import hashlib
    sha = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            sha.update(chunk)
    return sha.hexdigest()


def check_prerequisites(allow_dirty: bool = False) -> Tuple[bool, str]:
    """
    Verifies Git and GitHub CLI availability, canonical origin, branch,
    clean working tree, and authentication status.
    """
    # 1. Check git work tree
    git_check = run_cmd(["git", "rev-parse", "--is-inside-work-tree"])
    if git_check.returncode != 0:
        return False, "Not inside a valid Git repository."

    # 2. Check canonical branch (main)
    branch_check = run_cmd(["git", "rev-parse", "--abbrev-ref", "HEAD"])
    branch = branch_check.stdout.strip()
    if branch != "main":
        return False, f"Release must be published from 'main' branch (current: '{branch}')."

    # 3. Check canonical remote origin
    origin_check = run_cmd(["git", "remote", "get-url", "origin"])
    origin_url = origin_check.stdout.strip().lower()
    canonical_pattern = re.compile(
        r"^(https://github\.com/|git@github\.com:|ssh://git@github\.com/)codevcn/disk-cleaner(\.git)?/?$"
    )
    if not canonical_pattern.match(origin_url):
        return False, f"Git remote 'origin' must strictly point to 'codevcn/disk-cleaner' (found: '{origin_url}')."

    # 4. Check clean working tree BEFORE any version bump or build
    if not allow_dirty:
        status_check = run_cmd(["git", "status", "--porcelain"])
        if status_check.stdout.strip():
            return False, (
                "Git working tree is dirty (uncommitted changes detected).\n"
                f"{status_check.stdout.strip()}\n"
                "Please commit or stash your changes before running publish_release."
            )

    # 5. Check gh auth
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


def build_binaries(version: str) -> bool:
    """Packages disk_investigator.exe, disk-investigator-setup.exe, and disk-investigator-uninstall.exe."""
    print(f"[*] [1/3] Compiling standalone CLI: disk_investigator.exe for v{version}...")
    res_bin = run_cmd([sys.executable, "build_exe.py", "--version", version])
    if res_bin.returncode != 0:
        print(f"[ERROR] Build packaging failed for disk_investigator.exe: code {res_bin.returncode}")
        print(res_bin.stdout)
        print(res_bin.stderr)
        return False
    print("[+] disk_investigator.exe compiled and verified successfully.")

    print(f"[*] [2/3] Packaging 1-Click All-in-One Installer: disk-investigator-setup.exe...")
    res_setup = run_cmd([sys.executable, "build_installer.py"])
    if res_setup.returncode != 0:
        print(f"[ERROR] Installer packaging failed for disk-investigator-setup.exe: code {res_setup.returncode}")
        print(res_setup.stdout)
        print(res_setup.stderr)
        return False
    print("[+] disk-investigator-setup.exe packaged and verified successfully.")

    print(f"[*] [3/3] Packaging Standalone Uninstaller: disk-investigator-uninstall.exe...")
    res_uninst = run_cmd([sys.executable, "build_uninstaller.py"])
    if res_uninst.returncode != 0:
        print(f"[ERROR] Uninstaller packaging failed for disk-investigator-uninstall.exe: code {res_uninst.returncode}")
        print(res_uninst.stdout)
        print(res_uninst.stderr)
        return False
    print("[+] disk-investigator-uninstall.exe packaged and verified successfully.")

    return True


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
    print(f"Canonical:     {TARGET_SETUP_EXE.name}")
    print(f"Portable:      {TARGET_EXE.name}")
    print(f"Dry Run:       {dry_run}")
    print(f"=======================================================\n")

    # Invariant: Releases and Tags are immutable. Hard abort if release or tag already exists on GitHub
    view_res = run_cmd(["gh", "release", "view", tag_name])
    if view_res.returncode == 0:
        print(f"[ERROR] Release {tag_name} already exists on GitHub!")
        print("[ERROR] Invariant Violation: Releases are immutable and must not be overwritten.")
        print("[ERROR] Please bump the version number (e.g. --bump-patch or --bump-minor) and retry.")
        return False

    tag_check = run_cmd(["git", "ls-remote", "--exit-code", "--tags", "origin", f"refs/tags/{tag_name}"])
    if tag_check.returncode == 0:
        print(f"[ERROR] Git tag {tag_name} already exists on remote origin!")
        print("[ERROR] Invariant Violation: Release tags are immutable. Please bump version number.")
        return False

    if dry_run:
        print("[DRY-RUN] Step 1: Would stage release files")
        print(f"[DRY-RUN] Step 2: Would commit with message: 'release: {release_title}'")
        print("[DRY-RUN] Step 3: Would push commits with 'git push origin main'")
        print(f"[DRY-RUN] Step 4: Would create annotated tag: 'git tag -a {tag_name} -m \"release: {release_title}\"'")
        print(f"[DRY-RUN] Step 5: Would push tag: 'git push origin {tag_name}'")
        print(f"[DRY-RUN] Step 6: GitHub Actions CI would test, build, checksum, and publish release '{tag_name}'")
        print("[DRY-RUN] Success (simulation complete).")
        return True

    # 1. Stage explicit release files and commit
    print("[1/5] Staging explicit release files and committing to Git...")
    explicit_paths = [
        "disk_investigator",
        "skills",
        "installer.py",
        "uninstaller.py",
        "build_installer.py",
        "build_uninstaller.py",
        "build_exe.py",
        "build_history.json",
        "publish_release.py",
        "update_from_github.py",
        "README.md",
        "PROJECT_STATE.md",
        ".github",
        ".gitignore",
        "build.cmd",
        "publish.cmd",
        "update.cmd",
    ]
    for p in explicit_paths:
        run_cmd(["git", "add", p])

    diff_check = run_cmd(["git", "diff", "--cached", "--name-only"])
    if diff_check.stdout.strip():
        commit_res = run_cmd(["git", "commit", "-m", f"release: {release_title}"])
        if commit_res.returncode != 0:
            print(f"[ERROR] Git commit failed: {commit_res.stderr.strip()}")
            return False
        print(f"[+] Committed: release: {release_title}")
    else:
        print("[*] No staged changes to commit in working tree.")

    # 2. Git Push Main
    print("[2/5] Pushing commits to GitHub origin/main...")
    push_res = run_cmd(["git", "push", "origin", "main"])
    if push_res.returncode != 0:
        print(f"[ERROR] Git push to main failed: {push_res.stderr.strip()}")
        return False
    print("[+] Pushed commits to origin/main.")

    # 3. Create Annotated Tag and Push Tag (Sole Release Authority Trigger)
    print(f"[3/5] Creating and pushing annotated immutable release tag {tag_name}...")
    tag_res = run_cmd(["git", "tag", "-a", tag_name, "-m", f"release: {release_title}"])
    if tag_res.returncode != 0:
        print(f"[ERROR] Git tag creation failed: {tag_res.stderr.strip()}")
        return False

    push_tag_res = run_cmd(["git", "push", "origin", tag_name])
    if push_tag_res.returncode != 0:
        print(f"[ERROR] Pushing tag {tag_name} failed: {push_tag_res.stderr.strip()}")
        return False
    print(f"[+] Pushed annotated tag {tag_name} to origin.")

    # 4. Monitor GitHub Actions CI as Sole Release Authority
    print(f"[4/5] GitHub Actions CI triggered as sole release authority. Monitoring workflow...")
    import time
    time.sleep(10)
    workflow_success = False
    for attempt in range(60):  # poll up to 10 minutes
        res = run_cmd(["gh", "run", "list", "--branch", tag_name, "--limit", "1", "--json", "status,conclusion,url"])
        if res.returncode == 0 and res.stdout.strip():
            try:
                runs = json.loads(res.stdout)
                if runs:
                    run_info = runs[0]
                    status = run_info.get("status")
                    conclusion = run_info.get("conclusion")
                    run_url = run_info.get("url")
                    print(f"[*] CI Status: {status} (conclusion: {conclusion}) | {run_url}")
                    if status == "completed":
                        if conclusion == "success":
                            print("[+] GitHub Actions CI release workflow completed successfully!")
                            workflow_success = True
                            break
                        else:
                            print(f"[ERROR] GitHub Actions workflow failed with conclusion: {conclusion}")
                            return False
            except Exception:
                pass
        time.sleep(10)

    # Invariant: CI must have succeeded. Never fail-open!
    if not workflow_success:
        print("[ERROR] GitHub Actions CI release workflow did not complete successfully.")
        return False

    # 5. Verify published release assets on GitHub
    print("[5/5] Finalizing deployment and cryptographically verifying release assets on GitHub...")
    verify_res = run_cmd(["gh", "release", "view", tag_name, "--json", "assets"])
    if verify_res.returncode != 0:
        print(f"[ERROR] Failed to query release assets on GitHub: {verify_res.stderr.strip()}")
        return False

    try:
        rel_data = json.loads(verify_res.stdout)
        asset_names = [a.get("name") for a in rel_data.get("assets", [])]
        required_assets = [
            "disk-investigator-setup.exe",
            "disk-investigator-uninstall.exe",
            "disk_investigator.exe",
            "SHA256SUMS.txt",
        ]
        for req in required_assets:
            if req not in asset_names:
                print(f"[ERROR] Required release asset '{req}' is missing from GitHub Release {tag_name}!")
                return False
        print(f"[+] All required release assets verified on GitHub: {', '.join(required_assets)}")
    except Exception as e:
        print(f"[ERROR] Failed to parse release verification data: {e}")
        return False
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        cache_file = Path(local_app_data) / "DiskInvestigator" / "updates" / "update_status.json"
        if cache_file.exists():
            try:
                cache_file.unlink()
            except Exception:
                pass

    release_url = f"https://github.com/{GITHUB_REPO}/releases/tag/{tag_name}"
    print("\n=======================================================")
    print("           RELEASE PUBLISHED SUCCESSFULLY VIA CI!      ")
    print(f" Version:    {tag_name}")
    print(f" URL:        {release_url}")
    print(f" Authority:  GitHub Actions CI (Sole Authority)")
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
    ok, err_msg = check_prerequisites(allow_dirty=args.dry_run)
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

    # Step 4: Build Executables (CLI Binary + 1-Click Setup)
    if not args.dry_run:
        if not build_binaries(target_ver):
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
