"""
uninstall_core.py - Shared Core Uninstallation Engine for Disk Investigator.
Used identically by installer.py (--uninstall) and standalone uninstaller.py.

Guarantees:
- Safe preflight checks (process active check, fail-closed on UNKNOWN, manifest scope validation).
- Never terminates user processes.
- Never deletes unknown user files (even with --purge-data or inside known directories).
- Ownership-aware purge semantics: unknown subdirectories inside known roots are preserved wholly without descent.
- Self-preservation: uninstaller NEVER deletes itself or the directory tree containing it.
- Preserves customized SKILL.md and user backup files.
- Never performs recursive raw destructive directory deletes (no blind rmtree).
- Post-delete verification before reporting removal (zero false SUCCESS).
- Strict junction/reparse point canonicalization against target roots (blocks junction escape attacks).
- Reports typed UninstallResult with standard exit codes (0=SUCCESS, 1=FAILED, 2=CANCELLED, 3=PARTIAL, 4=BLOCKED).
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

# Explicit known nested subdirectories inside tool-owned directories
KNOWN_NESTED_SUBDIRS: Set[str] = {
    "snapshots",
    "plans",
    "updates",
}


def is_self_or_ancestor_of_self(path: Path) -> bool:
    """
    Checks if a given path is the currently executing file or an ancestor directory of it.
    Prevents self-deletion in all modes (UNINSTALL-FINAL-11).
    """
    try:
        resolved = path.resolve()
        current_exe = Path(sys.executable).resolve()
        if resolved == current_exe:
            return True
        try:
            current_exe.relative_to(resolved)
            return True
        except ValueError:
            pass

        if sys.argv and sys.argv[0]:
            argv_exe = Path(sys.argv[0]).resolve()
            if resolved == argv_exe:
                return True
            try:
                argv_exe.relative_to(resolved)
                return True
            except ValueError:
                pass

        return False
    except Exception:
        return False


def is_known_tool_owned_file(file_path: Path) -> bool:
    """
    Checks if a file strictly matches the explicit ownership schema of Disk Investigator.
    Never uses broad extension matching (e.g. arbitrary .db or arbitrary .json).
    """
    name_lower = file_path.name.lower()
    if name_lower in {f.lower() for f in KNOWN_OWNED_FILES}:
        return True
    if name_lower.endswith(".rollback") or name_lower.endswith(".tmp"):
        return True
    if name_lower.endswith(".log"):
        return True
    if name_lower in {"cache.db", "update_status.json", "metadata.json", "build_info.json"}:
        return True
    if name_lower.startswith("plan_") and name_lower.endswith(".json"):
        return True
    if name_lower.startswith("snap_") and name_lower.endswith(".json"):
        return True
    return False


def safe_delete_file(file_path: Path, result: UninstallResult, allowed_roots: List[Path]) -> bool:
    """
    Safely deletes a single file with scope validation, self-preservation check,
    and post-delete verification. Never reports removed_paths without verification.
    """
    if not file_path.exists():
        return True

    if not UninstallEngine.is_within_scope(file_path, allowed_roots):
        result.warnings.append(
            f"Cảnh báo bảo mật: Bỏ qua tệp ngoài phạm vi an toàn: {file_path}"
        )
        return False

    if is_self_or_ancestor_of_self(file_path):
        result.preserved_paths.append(str(file_path))
        return False

    try:
        file_path.unlink()
        if file_path.exists():
            result.errors.append(f"Tệp vẫn tồn tại sau thao tác xóa (có thể đang bị khóa): {file_path.name}")
            return False
        result.removed_paths.append(str(file_path))
        return True
    except Exception as e:
        result.errors.append(f"Lỗi khi xóa tệp {file_path.name}: {e}")
        return False


def safe_clean_owned_directory(
    dir_path: Path,
    result: UninstallResult,
    allowed_roots: List[Path],
) -> None:
    """
    Safely cleans a known tool-owned directory without blindly destroying unknown user files.
    Recursively removes known tool artifacts and removes the directory only if completely empty.
    Preserves unknown user files and protects any folder containing the running executable.
    Never descends into unknown subdirectories or out-of-scope junctions.
    """
    if not dir_path.exists() or not dir_path.is_dir():
        return

    # Junction / Symlink protection: never descend into junctions pointing out-of-scope
    if dir_path.is_symlink():
        if not UninstallEngine.is_within_scope(dir_path, allowed_roots):
            result.warnings.append(
                f"Cảnh báo bảo mật: Junction/symlink trỏ ra ngoài phạm vi cho phép: {dir_path}. Không duyệt qua."
            )
            return

    if not UninstallEngine.is_within_scope(dir_path, allowed_roots):
        result.warnings.append(f"Cảnh báo bảo mật: Thư mục ngoài phạm vi an toàn: {dir_path}")
        return

    # If the directory is self or contains self, preserve it and only clean non-self children
    is_self_tree = is_self_or_ancestor_of_self(dir_path)
    if is_self_tree:
        result.preserved_paths.append(str(dir_path))

    for child in list(dir_path.iterdir()):
        if is_self_or_ancestor_of_self(child):
            result.preserved_paths.append(str(child))
            continue

        # Check junction / symlink on child
        if child.is_symlink():
            if not UninstallEngine.is_within_scope(child, allowed_roots):
                result.warnings.append(
                    f"Cảnh báo bảo mật: Bỏ qua junction/symlink trỏ ra ngoài phạm vi: {child}."
                )
                continue

        if child.is_file():
            if is_known_tool_owned_file(child):
                safe_delete_file(child, result, allowed_roots)
            else:
                result.preserved_paths.append(str(child))
                result.warnings.append(
                    f"Phát hiện tệp không thuộc sở hữu công cụ: {child.name}. Bảo toàn an toàn."
                )
        elif child.is_dir():
            child_name_lower = child.name.lower()
            if child_name_lower in KNOWN_NESTED_SUBDIRS:
                # Explicit known nested schema -> descend and safely clean
                safe_clean_owned_directory(child, result, allowed_roots)
            else:
                # UNKNOWN SUBDIRECTORY -> PRESERVE WHOLE TREE, DO NOT DESCEND!
                result.preserved_paths.append(str(child))
                result.warnings.append(
                    f"Phát hiện thư mục con không thuộc sở hữu công cụ trong {dir_path.name}: {child.name}. Bảo toàn toàn bộ cây thư mục."
                )

    # Only remove dir_path if empty and not self/ancestor
    try:
        if dir_path.exists() and not any(dir_path.iterdir()) and not is_self_tree:
            dir_path.rmdir()
            if not dir_path.exists():
                result.removed_paths.append(str(dir_path))
            else:
                result.warnings.append(f"Không thể xóa thư mục rỗng {dir_path.name}.")
        elif dir_path.exists() and not is_self_tree:
            result.preserved_paths.append(str(dir_path))
    except Exception as e:
        result.warnings.append(f"Lỗi khi xóa thư mục {dir_path.name}: {e}")


class UninstallEngine:
    """Core transactional uninstallation engine."""

    @staticmethod
    def is_within_scope(path: Path, allowed_roots: List[Path]) -> bool:
        """
        Validates that a path resides strictly within one of the allowed roots.
        Canonicalizes reparse points, symlinks, and junctions before checking.
        Prevents path traversal or destructive deletion of arbitrary system files.
        """
        try:
            resolved = path.resolve(strict=False)
            for root in allowed_roots:
                resolved_root = root.resolve(strict=False)
                try:
                    resolved.relative_to(resolved_root)
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
            result.errors.append("Không thể gỡ bỏ thư mục bin khỏi Registry User PATH.")

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
                    skill_deleted = safe_delete_file(target_skill, result, allowed_roots)
                    if skill_deleted:
                        result.skill_removed = True
                        if not silent:
                            print(f"[+] Đã gỡ bỏ Skill: {target_skill}")
            else:
                # Conservative fallback: manifest missing or has no hash
                default_skill = get_resource_path("SKILL.md")
                if default_skill.exists():
                    default_hash = compute_sha256(default_skill)
                    if curr_skill_hash == default_hash:
                        skill_deleted = safe_delete_file(target_skill, result, allowed_roots)
                        if skill_deleted:
                            result.skill_removed = True
                            if not silent:
                                print(f"[+] Đã gỡ bỏ Skill (theo default hash): {target_skill}")
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
            safe_delete_file(target_skill_ref_docs, result, allowed_roots)

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
        if target_exe.exists():
            bin_deleted = safe_delete_file(target_exe, result, allowed_roots)
            if bin_deleted:
                result.binary_removed = True
                if not silent:
                    print(f"[+] Đã xóa: {target_exe.name}")
            else:
                result.errors.append(f"Không thể xóa tệp executable chính: {target_exe.name}")

        docs_file = install_dir / "README.md"
        if docs_file.exists():
            safe_delete_file(docs_file, result, allowed_roots)

        uninst_cmd = install_dir / "uninstall.cmd"
        if uninst_cmd.exists():
            safe_delete_file(uninst_cmd, result, allowed_roots)

        manifest_file = install_dir / "install_manifest.json"
        if manifest_file.exists():
            safe_delete_file(manifest_file, result, allowed_roots)

        # Lifecycle directory: UNINSTALL-FINAL-11 (never delete currently running executable or self-tree)
        lifecycle_dir = install_dir / "lifecycle"
        if lifecycle_dir.exists() and cls.is_within_scope(lifecycle_dir, allowed_roots):
            safe_clean_owned_directory(lifecycle_dir, result, allowed_roots)

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
                            safe_clean_owned_directory(item, result, allowed_roots)
                        else:
                            # Preserve unknown directory wholly!
                            result.preserved_paths.append(str(item))
                            result.warnings.append(
                                f"Phát hiện thư mục không thuộc sở hữu công cụ: {item.name}. Bảo toàn an toàn."
                            )
                    elif item.is_file():
                        if item_name_lower in KNOWN_OWNED_FILES:
                            safe_delete_file(item, result, allowed_roots)
                        else:
                            # Preserve unknown file!
                            result.preserved_paths.append(str(item))
                            result.warnings.append(
                                f"Phát hiện tệp không thuộc sở hữu công cụ: {item.name}. Bảo toàn an toàn."
                            )

                # Remove install_dir only if completely empty and not self-tree
                try:
                    if (
                        install_dir.exists()
                        and not any(install_dir.iterdir())
                        and not is_self_or_ancestor_of_self(install_dir)
                    ):
                        install_dir.rmdir()
                        result.removed_paths.append(str(install_dir))
                    elif install_dir.exists():
                        result.preserved_paths.append(str(install_dir))
                except Exception:
                    pass
        else:
            # Default mode: Preserve runtime data (cache, logs, plans, etc.)
            try:
                if bin_dir.exists() and not any(bin_dir.iterdir()) and not is_self_or_ancestor_of_self(bin_dir):
                    bin_dir.rmdir()
                    result.removed_paths.append(str(bin_dir))
            except Exception:
                pass
            if install_dir.exists():
                result.preserved_paths.append(str(install_dir))
                if not silent:
                    print(f"[*] Đã hoàn tất gỡ cài đặt. Dữ liệu báo cáo/cache được giữ lại tại: {install_dir}")

        # Final Status Resolution (UNINSTALL-FINAL-13: ZERO FALSE SUCCESS)
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
