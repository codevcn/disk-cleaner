#!/usr/bin/env python3
"""
update_from_github.py - Autonomous Exact-Release Updater for disk_investigator.

Enables the AI Agent or User to:
1. Query GitHub Releases (codevcn/disk-cleaner) for the latest immutable release tag.
2. In Git Workspace mode:
   - Fetches tags and checks out the exact immutable release tag.
   - Executes quality gate tests to guarantee code integrity.
   - Rebuilds standalone executables (disk_investigator.exe and disk-investigator-setup.exe).
   - Synchronizes Antigravity Agent skill.
3. In Standalone / Installed mode:
   - Downloads the canonical 'disk-investigator-setup.exe' directly from GitHub Releases.
   - Runs 'disk-investigator-setup.exe --silent' to perform atomic, transactional upgrade.
4. Clears update check cache safely in %LOCALAPPDATA%.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request
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
    """Reads current local version from disk_investigator/__init__.py or manifest."""
    # Check manifest if installed
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        manifest_file = Path(local_app_data) / "DiskInvestigator" / "install_manifest.json"
        if manifest_file.exists():
            try:
                with open(manifest_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if "version" in data:
                        return data["version"]
            except Exception:
                pass

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
    """Checks GitHub for latest release."""
    sys.path.insert(0, str(ROOT_DIR))
    from disk_investigator.version_checker import check_for_updates

    current_ver = get_local_version()
    info = check_for_updates(current_version=current_ver, repo=GITHUB_REPO, force=True)
    return info


def check_git_origin() -> bool:
    """Verifies that Git remote origin strictly points to canonical codevcn/disk-cleaner."""
    res = run_cmd(["git", "remote", "get-url", "origin"])
    if res.returncode != 0:
        return False
    url = res.stdout.strip().lower()
    canonical_pattern = re.compile(
        r"^(https://github\.com/|git@github\.com:|ssh://git@github\.com/)codevcn/disk-cleaner(\.git)?/?$"
    )
    return bool(canonical_pattern.match(url))


def compute_sha256(filepath: Path) -> str:
    """Computes SHA-256 hash of a file."""
    import hashlib
    sha = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            sha.update(chunk)
    return sha.hexdigest()


def sync_antigravity_skill() -> bool:
    """Copies workspace skill file to Antigravity global config with safe backup."""
    if not LOCAL_SKILL_PATH.exists():
        return False
    try:
        GLOBAL_SKILL_PATH.parent.mkdir(parents=True, exist_ok=True)
        if GLOBAL_SKILL_PATH.exists():
            curr_h = compute_sha256(GLOBAL_SKILL_PATH)
            new_h = compute_sha256(LOCAL_SKILL_PATH)
            if curr_h != new_h:
                import datetime
                ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                backup_file = GLOBAL_SKILL_PATH.parent / f"SKILL.md.user-backup-{ts}"
                shutil.copy2(GLOBAL_SKILL_PATH, backup_file)
                print(f"[+] Đã sao lưu Skill tùy biến trước đó: {backup_file.name}")

        shutil.copy2(LOCAL_SKILL_PATH, GLOBAL_SKILL_PATH)
        print(f"[+] Đã đồng bộ Skill cho Antigravity: {GLOBAL_SKILL_PATH}")
        return True
    except Exception as e:
        print(f"[!] Cảnh báo: Không thể đồng bộ Skill: {e}")
        return False


def run_tests() -> bool:
    """Executes full unit test suite."""
    print("[*] Đang chạy kiểm thử tự động (Quality Gate)...")
    res = run_cmd([sys.executable, "-m", "unittest", "discover", "-s", "disk_investigator/tests", "-v"])
    if res.returncode == 0:
        print("[+] Toàn bộ bài kiểm thử đã vượt qua thành công.")
        return True
    else:
        print("[ERROR] Kiểm thử thất bại! Hủy cập nhật để bảo vệ hệ thống hiện tại.")
        print(res.stdout)
        print(res.stderr)
        return False


def rebuild_executables() -> bool:
    """Triggers build_exe.py, build_installer.py, and build_uninstaller.py."""
    print("[*] Đang biên dịch lại binary độc lập (disk_investigator.exe)...")
    res_bin = run_cmd([sys.executable, "build_exe.py"])
    if res_bin.returncode != 0:
        print(f"[ERROR] Thất bại khi đóng gói binary. Code: {res_bin.returncode}")
        print(res_bin.stderr)
        return False
    print("[+] Binary độc lập đã được biên dịch thành công.")

    print("[*] Đang đóng gói bộ cài đặt All-in-One (disk-investigator-setup.exe)...")
    res_inst = run_cmd([sys.executable, "build_installer.py"])
    if res_inst.returncode != 0:
        print(f"[ERROR] Thất bại khi đóng gói setup. Code: {res_inst.returncode}")
        print(res_inst.stderr)
        return False
    print("[+] Setup EXE đã được đóng gói thành công.")

    print("[*] Đang đóng gói bộ gỡ cài đặt độc lập (disk-investigator-uninstall.exe)...")
    res_uninst = run_cmd([sys.executable, "build_uninstaller.py"])
    if res_uninst.returncode != 0:
        print(f"[ERROR] Thất bại khi đóng gói uninstaller. Code: {res_uninst.returncode}")
        print(res_uninst.stderr)
        return False
    print("[+] Uninstaller EXE đã được đóng gói thành công.")
    return True


def clear_update_cache() -> None:
    """Clears cached update status file in %LOCALAPPDATA%."""
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        cache_file = Path(local_app_data) / "DiskInvestigator" / "updates" / "update_status.json"
        if cache_file.exists():
            try:
                cache_file.unlink()
            except Exception:
                pass


def update_via_standalone_download(latest_ver: str) -> int:
    """
    Downloads canonical disk-investigator-setup.exe and SHA256SUMS.txt from GitHub Releases,
    verifies SHA-256 checksum cryptographically, and runs silent upgrade.
    Enforces strict fail-closed security: missing, unparseable, or mismatched checksum
    hard-aborts the update immediately.
    """
    tag = f"v{latest_ver}"
    base_url = f"https://github.com/{GITHUB_REPO}/releases/download/{tag}"
    download_url = f"{base_url}/disk-investigator-setup.exe"
    checksum_url = f"{base_url}/SHA256SUMS.txt"

    print(f"[*] Đang tải bản cài đặt {tag} từ GitHub Releases...")
    print(f"    Binary URL:   {download_url}")
    print(f"    Checksum URL: {checksum_url}")

    with tempfile.TemporaryDirectory() as tmp_dir:
        dest_exe = Path(tmp_dir) / "disk-investigator-setup.exe"
        dest_sums = Path(tmp_dir) / "SHA256SUMS.txt"

        # 1. Download checksum manifest (MANDATORY, FAIL-CLOSED)
        try:
            req_sum = urllib.request.Request(
                checksum_url,
                headers={"User-Agent": "disk-investigator-updater"},
            )
            with urllib.request.urlopen(req_sum, timeout=15) as resp:
                sums_text = resp.read().decode("utf-8", errors="replace")
                dest_sums.write_text(sums_text, encoding="utf-8")
        except Exception as e:
            print(f"[ERROR] Không thể tải SHA256SUMS.txt từ GitHub Release: {e}")
            print("[ERROR] Bảo mật: Thiếu checksum manifest. HỦY CẬP NHẬT để bảo vệ hệ thống.")
            return 1

        # Parse exact SHA-256 pattern: 64 hex characters followed by whitespace and filename
        sha_pattern = re.compile(r"^([0-9a-fA-F]{64})\s+(?:\*|\s)?disk-investigator-setup\.exe$", re.MULTILINE)
        match = sha_pattern.search(sums_text)
        if not match:
            print("[ERROR] SHA256SUMS.txt không chứa mã băm hợp lệ cho disk-investigator-setup.exe!")
            print("[ERROR] Bảo mật: HỦY CẬP NHẬT để bảo vệ hệ thống.")
            return 1

        expected_sha = match.group(1).lower()

        # 2. Download installer
        try:
            req = urllib.request.Request(
                download_url,
                headers={"User-Agent": "disk-investigator-updater"},
            )
            with urllib.request.urlopen(req, timeout=45) as resp, open(dest_exe, "wb") as f:
                shutil.copyfileobj(resp, f)
            print(f"[+] Tải thành công ({dest_exe.stat().st_size:,} bytes).")
        except Exception as e:
            print(f"[ERROR] Tải bản cài đặt thất bại: {e}")
            return 1

        # 3. Verify SHA-256 Checksum (MANDATORY)
        computed_sha = compute_sha256(dest_exe).lower()
        print(f"[*] Kiểm tra SHA-256 Checksum...")
        print(f"    Kỳ vọng:  {expected_sha}")
        print(f"    Thực tế:  {computed_sha}")
        if computed_sha != expected_sha:
            print("[ERROR] Checksum SHA-256 KHÔNG KHỚP! Bản cài đặt có thể bị lỗi hoặc can thiệp.")
            print("[ERROR] HỦY CẬP NHẬT để bảo vệ an toàn hệ thống.")
            return 1
        print("[+] Checksum SHA-256 khớp 100% (Tính toàn vẹn bảo đảm).")

        print("[*] Tiến hành chạy cài đặt tự động...")
        run_res = subprocess.run([str(dest_exe), "--silent"], capture_output=True, text=True, encoding="utf-8", errors="replace")
        if run_res.returncode == 0:
            print("[+] Cập nhật thành công!")
            clear_update_cache()
            return 0
        else:
            print(f"[ERROR] Cài đặt thất bại với mã lỗi {run_res.returncode}: {run_res.stderr}")
            return 1


def update_via_git(latest_ver: str, force: bool = False) -> int:
    """
    Pulls exact Git release tag, runs quality gate tests, and rebuilds binaries.
    Enforces canonical origin and fail-closed behavior (no fallback to main).
    """
    if not check_git_origin():
        print(f"[ERROR] Remote origin không trỏ về {GITHUB_REPO}. Hủy cập nhật để bảo vệ workspace.")
        return 1

    tag = f"v{latest_ver}"
    print(f"[2/5] Lấy danh sách tag từ remote origin...")
    fetch_res = run_cmd(["git", "fetch", "--tags", "origin"])
    if fetch_res.returncode != 0:
        print(f"[ERROR] 'git fetch' thất bại: {fetch_res.stderr.strip()}")
        return 1

    print(f"[3/5] Chuyển sang tag phát hành chính thức: {tag}...")
    tag_check = run_cmd(["git", "tag", "-l", tag])
    if tag not in tag_check.stdout.split():
        print(f"[*] Fetching cụ thể tag {tag}...")
        fetch_tag_res = run_cmd(["git", "fetch", "origin", f"refs/tags/{tag}:refs/tags/{tag}"])
        if fetch_tag_res.returncode != 0:
            print(f"[ERROR] Không thể lấy tag {tag} từ remote: {fetch_tag_res.stderr.strip()}")
            return 1

    # Invariant: Checkout exact tag only, fail closed without falling back to main
    checkout_res = run_cmd(["git", "checkout", tag])
    if checkout_res.returncode != 0:
        print(f"[ERROR] Không thể checkout tag {tag}: {checkout_res.stderr.strip()}")
        print("[ERROR] Invariant Violation: Cập nhật yêu cầu đúng immutable tag phát hành. Hủy cập nhật.")
        return 1

    # Run tests
    print("[4/5] Chạy kiểm thử chất lượng mã nguồn mới...")
    if not run_tests():
        return 1

    # Rebuild binaries
    print("[5/5] Biên dịch lại các tệp thực thi...")
    if not rebuild_executables():
        return 1

    sync_antigravity_skill()
    clear_update_cache()
    return 0


def perform_update(force: bool = False) -> int:
    """Main update workflow."""
    local_ver = get_local_version()
    print("=======================================================")
    print("       DISK INVESTIGATOR - GITHUB AUTO-UPDATER         ")
    print("=======================================================")
    print(f"Phiên bản hiện tại: v{local_ver}")
    print(f"Repository:        https://github.com/{GITHUB_REPO}")
    print(f"Thư mục làm việc:  {ROOT_DIR}")
    print("=======================================================\n")

    # Step 1: Check remote version
    print("[1/5] Kiểm tra phiên bản mới trên GitHub...")
    update_info = check_remote_status()
    latest_ver = update_info.get("latest_version", local_ver)
    has_update = update_info.get("update_available", False)

    print(f"[*] Local: v{local_ver} | Remote: v{latest_ver}")

    if not has_update and not force:
        print(f"\n[+] Bạn đang sử dụng phiên bản mới nhất (v{local_ver}).")
        print("[*] Dùng tùy chọn --force nếu muốn buộc cập nhật và biên dịch lại.")
        return 0

    if has_update:
        print(f"[!] Đã tìm thấy phiên bản mới v{latest_ver} trên GitHub!")

    if is_git_repo():
        print("[*] Môi trường: Git Workspace -> Cập nhật qua Git Tag & Local Build.")
        ret = update_via_git(latest_ver, force=force)
    else:
        print("[*] Môi trường: Standalone/User -> Tải trực tiếp Setup EXE từ GitHub Releases.")
        ret = update_via_standalone_download(latest_ver)

    if ret == 0:
        new_ver = get_local_version()
        print("\n=======================================================")
        print("             CẬP NHẬT HOÀN TẤT THÀNH CÔNG              ")
        print(f" Phiên bản cũ: v{local_ver}")
        print(f" Phiên bản mới:v{new_ver}")
        print("=======================================================\n")
    return ret


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
