"""
uninstall_core.py - Shared Core Uninstallation Engine for Disk Investigator.
Used identically by installer.py (--uninstall) and standalone uninstaller.py.

Guarantees:
- Safe preflight checks (process active check, fail-closed on UNKNOWN, manifest scope validation).
- Never terminates user processes.
- Never deletes unknown user files (even with --purge-data).
- Preserves customized SKILL.md and user backup files.
- Never performs recursive raw destructive directory deletes.
- Does not attempt self-deletion tricks.
- Reports typed UninstallResult with standard exit codes.
"""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .common import (
    APP_NAME,
    APP_DISPLAY_NAME,
    KNOWN_OWNED_FILES,
    KNOWN_OWNED_SUBDIRS,
    ProcessState,
    check_process_state,
    compute_sha256,
    get_resource_path,
    get_target_directories,
    load_manifest,
    remove_bin_from_user_path,
)
from .models import UninstallResult, UninstallStatus


class UninstallEngine:
    """Core transactional uninstallation engine."""

    @staticmethod
    def is_within_scope(path: Path, allowed_roots: List[Path]) -> bool:
        """
        Validates that a path resides strictly within one of the allowed roots.
        Prevents path traversal or destructive deletion of arbitrary system files.
        """
        try:
            resolved = path.resolve()
            for root in allowed_roots:
                try:
                    resolved.relative_to(root.resolve())
                    return True
                except ValueError:
                    continue
            return False
        except Exception:
            return False

    @classmethod
    def preflight_check(
        cls,
        install_dir: Path,
        bin_dir: Path,
        skill_dir: Path,
    ) -> Tuple[bool, Optional[UninstallStatus], List[str], List[str]]:
        """
        Executes preflight verification before any mutation:
        1. Checks if disk_investigator.exe is currently running (fail-closed).
        2. Validates manifest paths against allowed directory scopes.
        Returns:
            (can_proceed: bool, status_override: Optional[UninstallStatus], errors: List[str], warnings: List[str])
        """
        errors: List[str] = []
        warnings: List[str] = []

        # 1. Process Check (FAIL-CLOSED)
        # UNINSTALL-FINAL-08, 09, 10
        state = check_process_state("disk_investigator.exe")
        if state == ProcessState.RUNNING:
            errors.append(
                "Tiến trình 'disk_investigator.exe' đang hoạt động trên hệ thống.\n"
                "Vui lòng đóng tất cả phiên làm việc trước khi thực hiện gỡ cài đặt."
            )
            return False, UninstallStatus.BLOCKED, errors, warnings

        if state == ProcessState.UNKNOWN:
            errors.append(
                "Không thể xác định trạng thái tiến trình 'disk_investigator.exe' (Trạng thái: UNKNOWN).\n"
                "Quy trình gỡ cài đặt bị chặn theo nguyên tắc Fail-Closed để bảo vệ an toàn hệ thống."
            )
            return False, UninstallStatus.BLOCKED, errors, warnings

        # 2. Manifest Path Scope Validation (UNINSTALL-FINAL-06, 07)
        manifest_file = install_dir / "install_manifest.json"
        if manifest_file.exists():
            manifest = load_manifest(install_dir)
            if manifest is None:
                warnings.append(
                    "Bản ghi 'install_manifest.json' bị hỏng hoặc sai định dạng. "
                    "Chuyển sang cơ chế gỡ cài đặt an toàn dự phòng (Conservative Fallback)."
                )
            else:
                allowed_roots = [install_dir.resolve(), skill_dir.resolve()]
                path_keys = ["bin_file", "docs_file", "skill_file", "skill_backup"]
                for k in path_keys:
                    p_str = manifest.get(k)
                    if p_str:
                        p_val = Path(p_str)
                        if not cls.is_within_scope(p_val, allowed_roots):
                            warnings.append(
                                f"Cảnh báo bảo mật: Bản ghi manifest chứa đường dẫn ngoài phạm vi cho phép: {p_str}. "
                                f"Đường dẫn này sẽ bị loại trừ và không bao giờ bị xóa."
                            )

        return True, None, errors, warnings

    @classmethod
    def execute(
        cls,
        purge_data: bool = False,
        silent: bool = False,
        install_dir_override: Optional[Path] = None,
        bin_dir_override: Optional[Path] = None,
        skill_dir_override: Optional[Path] = None,
    ) -> UninstallResult:
        """
        Executes complete uninstallation of Disk Investigator.
        """
        install_dir, bin_dir, skill_dir, skill_ref_dir = get_target_directories()
        if install_dir_override:
            install_dir = install_dir_override
        if bin_dir_override:
            bin_dir = bin_dir_override
        if skill_dir_override:
            skill_dir = skill_dir_override
            skill_ref_dir = skill_dir / "references"

        result = UninstallResult()

        if not silent:
            print("=======================================================")
            print(f"       GỠ CÀI ĐẶT {APP_DISPLAY_NAME}")
            print("=======================================================")
            print(f"Thư mục cài đặt:   {install_dir}")
            print(f"Xóa dữ liệu phụ:   {purge_data}")
            print("=======================================================\n")

        # Step 0: Preflight check
        can_proceed, status_override, pre_errors, pre_warnings = cls.preflight_check(
            install_dir=install_dir,
            bin_dir=bin_dir,
            skill_dir=skill_dir,
        )
        result.errors.extend(pre_errors)
        result.warnings.extend(pre_warnings)

        if not can_proceed:
            result.status = status_override or UninstallStatus.BLOCKED
            if not silent:
                for err in result.errors:
                    print(f"[ERROR] {err}")
            return result

        manifest = load_manifest(install_dir)
        allowed_roots = [install_dir.resolve(), skill_dir.resolve()]

        # Step 1: Remove bin from User PATH
        if not silent:
            print("[1/4] Gỡ bỏ thư mục bin khỏi biến môi trường User PATH...")
        path_ok = remove_bin_from_user_path(bin_dir)
        result.path_removed = path_ok
        if not path_ok and sys.platform == "win32":
            result.errors.append("Không thể cập nhật Registry User PATH.")

        # Step 2: Handle Antigravity Skill
        if not silent:
            print("[2/4] Kiểm tra và gỡ bỏ Antigravity Skill...")
        target_skill = skill_dir / "SKILL.md"

        if target_skill.exists() and cls.is_within_scope(target_skill, allowed_roots):
            curr_skill_hash = compute_sha256(target_skill)
            recorded_hash = manifest.get("skill_sha256") if manifest else None

            if recorded_hash:
                if curr_skill_hash != recorded_hash:
                    result.skill_preserved = True
                    result.preserved_paths.append(str(target_skill))
                    if not silent:
                        print(f"[*] Phát hiện tùy chỉnh người dùng trong SKILL.md. Giữ lại tệp để bảo toàn:")
                        print(f"    {target_skill}")
                else:
                    try:
                        target_skill.unlink()
                        result.skill_removed = True
                        result.removed_paths.append(str(target_skill))
                        if not silent:
                            print(f"[+] Đã gỡ bỏ Skill: {target_skill}")
                    except Exception as e:
                        result.errors.append(f"Không thể xóa Skill: {e}")
            else:
                # Conservative fallback: manifest missing or has no hash
                default_skill = get_resource_path("SKILL.md")
                if default_skill.exists():
                    default_hash = compute_sha256(default_skill)
                    if curr_skill_hash == default_hash:
                        try:
                            target_skill.unlink()
                            result.skill_removed = True
                            result.removed_paths.append(str(target_skill))
                            if not silent:
                                print(f"[+] Đã gỡ bỏ Skill (theo default hash): {target_skill}")
                        except Exception as e:
                            result.errors.append(f"Không thể xóa Skill: {e}")
                    else:
                        result.skill_preserved = True
                        result.preserved_paths.append(str(target_skill))
                        if not silent:
                            print(f"[*] SKILL.md không khớp bản mặc định. Bảo toàn tệp: {target_skill}")
                else:
                    # Cannot confirm default -> preserve conservatively
                    result.skill_preserved = True
                    result.preserved_paths.append(str(target_skill))
                    if not silent:
                        print(f"[*] Không có thông tin đối chiếu SKILL.md. Bảo toàn tệp: {target_skill}")

        # Check references/README.md
        target_skill_ref_docs = skill_ref_dir / "README.md"
        if target_skill_ref_docs.exists() and cls.is_within_scope(target_skill_ref_docs, allowed_roots):
            try:
                target_skill_ref_docs.unlink()
                result.removed_paths.append(str(target_skill_ref_docs))
            except Exception:
                pass

        # Preserve any user backups (SKILL.md.user-backup-*)
        if skill_dir.exists():
            for bk in skill_dir.glob("SKILL.md.user-backup-*"):
                result.preserved_paths.append(str(bk))

        # Safely remove skill folders ONLY IF empty
        try:
            if skill_ref_dir.exists() and not any(skill_ref_dir.iterdir()):
                skill_ref_dir.rmdir()
                result.removed_paths.append(str(skill_ref_dir))
            if skill_dir.exists() and not any(skill_dir.iterdir()):
                skill_dir.rmdir()
                result.removed_paths.append(str(skill_dir))
        except Exception:
            pass

        # Step 3: Remove binary and core files
        if not silent:
            print("[3/4] Xóa tệp nhị phân và tài nguyên...")

        target_exe = bin_dir / "disk_investigator.exe"
        if target_exe.exists() and cls.is_within_scope(target_exe, allowed_roots):
            try:
                target_exe.unlink()
                result.binary_removed = True
                result.removed_paths.append(str(target_exe))
                if not silent:
                    print(f"[+] Đã xóa: {target_exe.name}")
            except Exception as e:
                result.errors.append(f"Không thể xóa tệp executable {target_exe.name}: {e}")

        docs_file = install_dir / "README.md"
        if docs_file.exists() and cls.is_within_scope(docs_file, allowed_roots):
            try:
                docs_file.unlink()
                result.removed_paths.append(str(docs_file))
            except Exception:
                pass

        uninst_cmd = install_dir / "uninstall.cmd"
        if uninst_cmd.exists() and cls.is_within_scope(uninst_cmd, allowed_roots):
            try:
                uninst_cmd.unlink()
                result.removed_paths.append(str(uninst_cmd))
            except Exception:
                pass

        manifest_file = install_dir / "install_manifest.json"
        if manifest_file.exists() and cls.is_within_scope(manifest_file, allowed_roots):
            try:
                manifest_file.unlink()
                result.removed_paths.append(str(manifest_file))
            except Exception:
                pass

        # Lifecycle directory: UNINSTALL-FINAL-11 (never delete currently running executable)
        lifecycle_dir = install_dir / "lifecycle"
        if lifecycle_dir.exists() and cls.is_within_scope(lifecycle_dir, allowed_roots):
            current_exe = Path(sys.executable).resolve()
            argv0_exe = Path(sys.argv[0]).resolve() if sys.argv and sys.argv[0] else None

            for item in list(lifecycle_dir.iterdir()):
                resolved_item = item.resolve()
                if resolved_item == current_exe or (argv0_exe and resolved_item == argv0_exe):
                    result.preserved_paths.append(str(item))
                    continue
                try:
                    if item.is_file():
                        item.unlink()
                        result.removed_paths.append(str(item))
                    elif item.is_dir():
                        shutil.rmtree(item, ignore_errors=True)
                        result.removed_paths.append(str(item))
                except Exception:
                    pass

            try:
                if not any(lifecycle_dir.iterdir()):
                    lifecycle_dir.rmdir()
                    result.removed_paths.append(str(lifecycle_dir))
            except Exception:
                pass

        # Step 4: Handle Data & Cleanup
        if not silent:
            print("[4/4] Dọn dẹp thư mục cài đặt...")

        if purge_data:
            result.runtime_data_removed = True
            if install_dir.exists() and cls.is_within_scope(install_dir, allowed_roots):
                for item in list(install_dir.iterdir()):
                    item_name_lower = item.name.lower()
                    if item.is_dir():
                        if item_name_lower in KNOWN_OWNED_SUBDIRS:
                            try:
                                shutil.rmtree(item, ignore_errors=True)
                                result.removed_paths.append(str(item))
                            except Exception as e:
                                result.warnings.append(f"Không thể xóa thư mục {item.name}: {e}")
                        else:
                            # Preserve unknown directory!
                            result.preserved_paths.append(str(item))
                            result.warnings.append(
                                f"Phát hiện thư mục không thuộc sở hữu công cụ: {item.name}. Bảo toàn an toàn."
                            )
                    elif item.is_file():
                        if item_name_lower in KNOWN_OWNED_FILES:
                            try:
                                item.unlink()
                                result.removed_paths.append(str(item))
                            except Exception:
                                pass
                        else:
                            # Preserve unknown file!
                            result.preserved_paths.append(str(item))
                            result.warnings.append(
                                f"Phát hiện tệp không thuộc sở hữu công cụ: {item.name}. Bảo toàn an toàn."
                            )

                # Remove install_dir only if completely empty
                try:
                    if install_dir.exists() and not any(install_dir.iterdir()):
                        install_dir.rmdir()
                        result.removed_paths.append(str(install_dir))
                    elif install_dir.exists():
                        result.preserved_paths.append(str(install_dir))
                except Exception:
                    pass
        else:
            # Default mode: Preserve runtime data (cache, logs, plans, etc.)
            try:
                if bin_dir.exists() and not any(bin_dir.iterdir()):
                    bin_dir.rmdir()
                    result.removed_paths.append(str(bin_dir))
            except Exception:
                pass
            if install_dir.exists():
                result.preserved_paths.append(str(install_dir))
                if not silent:
                    print(f"[*] Đã hoàn tất gỡ cài đặt. Dữ liệu báo cáo/cache được giữ lại tại: {install_dir}")

        # Final Status Resolution (UNINSTALL-FINAL-13)
        if result.errors:
            if result.binary_removed or result.path_removed:
                result.status = UninstallStatus.PARTIAL
            else:
                result.status = UninstallStatus.FAILED
        else:
            result.status = UninstallStatus.SUCCESS

        if not silent:
            if result.status == UninstallStatus.SUCCESS:
                print("\n[+] Gỡ cài đặt hoàn tất thành công.\n")
            elif result.status == UninstallStatus.PARTIAL:
                print("\n[!] Gỡ cài đặt hoàn tất một phần (có một số cảnh báo/lỗi không nghiêm trọng).\n")
            else:
                print("\n[ERROR] Quá trình gỡ cài đặt thất bại.\n")

        return result
