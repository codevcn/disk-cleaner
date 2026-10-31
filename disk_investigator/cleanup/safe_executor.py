"""
Safe Executor for disk_investigator.
Executes approved plan items using typed handlers and native Windows Recycle Bin.
Strict invariants:
- Pre-flight verification (TOCTOU mitigation & stale-plan defense).
- Untrusted plan defense: Re-validates policies independently from the plan JSON.
- Never falls back to permanent delete if Recycle Bin fails.
- Explicit item selection required (fails closed on empty/missing item lists).
"""

from __future__ import annotations

import ctypes
import os
import shutil
import subprocess
import sys
from ctypes import wintypes
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..capabilities import get_default_cache_dir
from ..path_policy import (
    canonicalize_path,
    determine_node_kind,
    has_reparse_point_ancestor,
    is_cloud_sync_path,
    is_critical_boundary,
    is_network_share,
    is_protected_system_path,
    is_reparse_point,
    is_safe_fixed_drive,
    resolve_windows_aliases,
)
from .plan_generator import (
    ActionType,
    CleanupPlan,
    PlanItem,
    compute_plan_hash,
    get_plan_signing_key,
    get_tool_cache_path,
    validate_plan_schema,
)

class PlanIntegrityError(ValueError, PermissionError):
    """Raised when a cleanup plan fails cryptographic integrity, schema, or signature validation."""
    pass

# Windows Shell API Constants for Recycle Bin
FO_DELETE = 0x0003
FOF_ALLOWUNDO = 0x0040
FOF_NOCONFIRMATION = 0x0010
FOF_SILENT = 0x0004
FOF_NOERRORUI = 0x0400


class SHFILEOPSTRUCTW(ctypes.Structure):
    _fields_ = [
        ("hwnd", wintypes.HWND),
        ("wFunc", wintypes.UINT),
        ("pFrom", wintypes.LPCWSTR),
        ("pTo", wintypes.LPCWSTR),
        ("fFlags", wintypes.WORD),
        ("fAnyOperationsAborted", wintypes.BOOL),
        ("hNameMappings", wintypes.LPVOID),
        ("lpszProgressTitle", wintypes.LPCWSTR),
    ]


def send_to_recycle_bin(path: str) -> bool:
    """
    Moves a file or directory directly to the Windows Recycle Bin using SHFileOperationW.
    CRITICAL: Never falls back to os.remove/shutil.rmtree if this fails!
    """
    canon = canonicalize_path(path)
    if not os.path.exists(canon):
        return False

    # Windows SHFileOperationW expects double null-terminated string
    p_from = canon + "\0\0"

    fileop = SHFILEOPSTRUCTW()
    fileop.hwnd = None
    fileop.wFunc = FO_DELETE
    fileop.pFrom = p_from
    fileop.pTo = None
    fileop.fFlags = FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_SILENT | FOF_NOERRORUI
    fileop.fAnyOperationsAborted = False
    fileop.hNameMappings = None
    fileop.lpszProgressTitle = None

    res = ctypes.windll.shell32.SHFileOperationW(ctypes.byref(fileop))
    if res != 0 or fileop.fAnyOperationsAborted:
        raise OSError(f"Failed to move '{canon}' to Recycle Bin (SHFileOperation code: {res}). Operation aborted.")

    return True


@dataclass
class ExecutionResult:
    plan_id: str
    dry_run: bool
    succeeded_items: List[int] = field(default_factory=list)
    failed_items: List[Dict[str, Any]] = field(default_factory=list)
    skipped_items: List[Dict[str, Any]] = field(default_factory=list)
    immediate_reclaimed_bytes: int = 0
    estimated_immediate_reclaimed_bytes: int = 0
    observed_volume_free_delta_bytes: int = 0
    observed_volume_deltas: Dict[str, int] = field(default_factory=dict)
    recycle_bin_bytes: int = 0
    potential_reclaimed_bytes: int = 0
    projected_immediate_reclaimable_bytes: int = 0
    projected_recycle_bin_bytes: int = 0
    projected_potential_reclaimed_bytes: int = 0
    explanation: str = ""

    @property
    def succeeded_count(self) -> int:
        return len(self.succeeded_items)

    @property
    def failed_count(self) -> int:
        return len(self.failed_items)

    @property
    def skipped_count(self) -> int:
        return len(self.skipped_items)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "dry_run": self.dry_run,
            "succeeded_count": self.succeeded_count,
            "succeeded_items": self.succeeded_items,
            "failed_count": self.failed_count,
            "failed_items": self.failed_items,
            "skipped_count": self.skipped_count,
            "skipped_items": self.skipped_items,
            "immediate_reclaimed_bytes": self.immediate_reclaimed_bytes,
            "estimated_immediate_reclaimed_bytes": self.estimated_immediate_reclaimed_bytes,
            "observed_volume_free_delta_bytes": self.observed_volume_free_delta_bytes,
            "observed_volume_deltas": self.observed_volume_deltas,
            "recycle_bin_bytes": self.recycle_bin_bytes,
            "potential_reclaimed_bytes": self.potential_reclaimed_bytes,
            "projected_immediate_reclaimable_bytes": self.projected_immediate_reclaimable_bytes,
            "projected_recycle_bin_bytes": self.projected_recycle_bin_bytes,
            "projected_potential_reclaimed_bytes": self.projected_potential_reclaimed_bytes,
            "explanation": self.explanation,
        }


class SafeExecutor:
    """Pre-flights and executes explicit approved plan items with untrusted plan protection."""

    def __init__(self, secret_key: Optional[bytes] = None, cache_dir: Optional[Any] = None):
        if cache_dir is not None:
            self.cache_dir = Path(cache_dir)
        else:
            self.cache_dir = get_default_cache_dir() / "plans"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.secret_key = secret_key or get_plan_signing_key(self.cache_dir)

    def preflight_check(self, item: PlanItem) -> Optional[str]:
        """
        Validates the resource before execution (TOCTOU mitigation & stale-plan defense).
        Independently re-validates policies, ignoring any untrusted plan data.
        Returns None if passed, or an error string if invalid.
        """
        p = canonicalize_path(item.path)

        # 1. Hard block policy & boundary protections (checked before touching filesystem I/O)
        if is_network_share(p):
            return f"SECURITY REFUSAL: Path is a network share/UNC path which does not guarantee Recycle Bin semantics: '{p}'"

        if is_critical_boundary(p):
            return f"SECURITY REFUSAL: Path is a critical system, user, or security boundary: '{p}'"

        if is_protected_system_path(p):
            return f"SECURITY REFUSAL: Path is inside protected Windows operating system boundary: '{p}'"

        # Check resolved 8.3 / filesystem alias
        resolved_p = resolve_windows_aliases(p)
        if is_critical_boundary(resolved_p):
            return f"SECURITY REFUSAL: Path resolves to a critical system, user, or security boundary: '{resolved_p}' (alias: '{p}')"
        if is_protected_system_path(resolved_p):
            return f"SECURITY REFUSAL: Path resolves to a protected Windows operating system boundary: '{resolved_p}' (alias: '{p}')"

        if is_cloud_sync_path(p) or is_cloud_sync_path(resolved_p):
            return f"SECURITY REFUSAL: Path or resolved alias is inside cloud sync folder: '{resolved_p}'"

        if p.lower().endswith(".vhdx"):
            return f"SECURITY REFUSAL: Path is a virtual hard disk (VHDX): '{p}'"

        # Check drive type: Recycle Bin requires local fixed drive
        if item.action_type == ActionType.RECYCLE_PATH and not is_safe_fixed_drive(p):
            return f"SECURITY REFUSAL: Path is not on a local fixed drive (mapped network, removable, or unsupported volume). Recycle Bin semantics cannot be guaranteed: '{p}'"

        # 2. Reparse point & junction check (including all ancestor directories)
        # Checked before existence to catch broken junctions or swapped ancestor junctions
        if is_reparse_point(p) or has_reparse_point_ancestor(p):
            return f"SECURITY REFUSAL: Path or an ancestor directory has become a reparse point or junction: '{p}'"

        # 3. Existence check
        if not os.path.exists(p):
            return f"Resource no longer exists: '{p}'"

        # 4. Kind check
        curr_kind = determine_node_kind(p).value
        if curr_kind != item.expected_kind:
            return f"STALE_PLAN: Resource kind changed from '{item.expected_kind}' to '{curr_kind}'"

        # 5. Modification check (TOCTOU: file size and mtime drift - fail closed)
        if item.expected_kind == "file" and item.candidate_bytes is not None:
            try:
                curr_size = os.path.getsize(p)
                if abs(curr_size - item.candidate_bytes) > 0:
                    return f"STALE_PLAN: File size changed from {item.candidate_bytes} to {curr_size} bytes since plan creation. Rescan required."
            except (OSError, PermissionError) as e:
                return f"VERIFY_FAILED: Unable to verify file size ({e}). Refusing execution for safety."

        if item.expected_mtime is not None:
            try:
                curr_mtime = os.path.getmtime(p)
                if abs(curr_mtime - item.expected_mtime) > 5.0:  # > 5 seconds drift
                    return f"STALE_PLAN: Resource has been modified since plan creation (mtime drift). Rescan required."
            except (OSError, PermissionError) as e:
                return f"VERIFY_FAILED: Unable to verify resource modification time ({e}). Refusing execution for safety."

        # 6. Typed action target binding verification
        if item.action_type == ActionType.NPM_CACHE_CLEAN:
            active_npm = get_tool_cache_path("npm")
            if not active_npm or p.lower() != active_npm:
                return f"VERIFY_FAILED: Active npm cache path '{active_npm}' does not match plan target '{p}'. Refusing execution."

        if item.action_type == ActionType.PIP_CACHE_PURGE:
            active_pip = get_tool_cache_path("pip")
            if not active_pip or p.lower() != active_pip:
                return f"VERIFY_FAILED: Active pip cache path '{active_pip}' does not match plan target '{p}'. Refusing execution."

        return None

    def execute(
        self,
        plan: CleanupPlan,
        item_ids: List[int],
        dry_run: bool = True,
    ) -> ExecutionResult:
        """
        Executes specified items from the plan.
        Requires explicit item_ids. Refuses execution if item_ids is empty.
        Verifies plan integrity hash (fail-closed if missing, invalid, or tampered).
        """
        if not item_ids:
            raise ValueError("Explicit item_ids list is required. Bulk cleanup without item selection is forbidden.")

        # 1. Structural schema validation (duplicate IDs, count mismatch, non-positive IDs)
        validate_plan_schema(plan)

        # 2. Fail-closed plan HMAC signature verification
        plan_hash = getattr(plan, "plan_hash", None)
        if not plan_hash or len(plan_hash) != 64:
            raise PlanIntegrityError("SECURITY REFUSAL: Missing or invalid plan_hash. Plan integrity cannot be verified.")

        signing_key = getattr(self, "secret_key", None) or get_plan_signing_key()
        expected_hash = compute_plan_hash(
            plan_id=plan.plan_id,
            target_root=plan.target_root,
            created_at=plan.created_at,
            items=plan.items,
            secret_key=signing_key,
            total_items=plan.total_items,
            total_candidate_bytes=plan.total_candidate_bytes,
            total_immediate_reclaimable_bytes=plan.total_immediate_reclaimable_bytes,
            total_recycle_bin_bytes=plan.total_recycle_bin_bytes,
            total_potential_reclaim_bytes=plan.total_potential_reclaim_bytes,
        )
        import hmac
        if not hmac.compare_digest(plan_hash, expected_hash):
            raise PlanIntegrityError("SECURITY REFUSAL: Plan hash mismatch. Plan content appears to have been tampered with.")

        # Record volume initial free bytes for all unique drives involved in planned items
        items_map = {item.item_id: item for item in plan.items}
        volumes = set()
        drive, _ = os.path.splitdrive(plan.target_root)
        if drive:
            volumes.add(f"{drive.upper()}\\")
        for item_id in item_ids:
            item = items_map.get(item_id)
            if item:
                d, _ = os.path.splitdrive(item.path)
                if d:
                    volumes.add(f"{d.upper()}\\")

        initial_free_by_volume = {}
        for vol in volumes:
            if os.path.exists(vol):
                try:
                    initial_free_by_volume[vol] = shutil.disk_usage(vol).free
                except Exception:
                    pass

        result = ExecutionResult(plan_id=plan.plan_id, dry_run=dry_run)

        for item_id in item_ids:
            item = items_map.get(item_id)
            if not item:
                result.skipped_items.append({"item_id": item_id, "reason": "Item ID not found in plan"})
                continue

            # Run Pre-flight check
            preflight_err = self.preflight_check(item)
            if preflight_err:
                result.failed_items.append({"item_id": item_id, "path": item.path, "error": preflight_err})
                continue

            if dry_run:
                # Dry run: record projected metrics, no disk mutations
                result.succeeded_items.append(item_id)
                result.projected_immediate_reclaimable_bytes += item.immediate_reclaimable_bytes
                result.projected_recycle_bin_bytes += item.recycle_bin_bytes
                result.projected_potential_reclaimed_bytes += item.potential_reclaim_bytes
                continue

            # Actual execution via typed action handlers
            try:
                if item.action_type == ActionType.RECYCLE_PATH:
                    send_to_recycle_bin(item.path)
                    result.succeeded_items.append(item_id)
                    result.recycle_bin_bytes += item.recycle_bin_bytes
                    result.potential_reclaimed_bytes += item.recycle_bin_bytes

                elif item.action_type == ActionType.NPM_CACHE_CLEAN:
                    npm_exe = shutil.which("npm.cmd") or shutil.which("npm")
                    if not npm_exe:
                        result.failed_items.append({"item_id": item_id, "path": item.path, "error": "npm executable not found on PATH"})
                        continue
                    proc = subprocess.run([npm_exe, "cache", "clean", "--force"], capture_output=True, timeout=30, shell=False)
                    if proc.returncode == 0:
                        result.succeeded_items.append(item_id)
                        result.immediate_reclaimed_bytes += item.immediate_reclaimable_bytes
                        result.potential_reclaimed_bytes += item.immediate_reclaimable_bytes
                    else:
                        result.failed_items.append({"item_id": item_id, "path": item.path, "error": proc.stderr.decode()})

                elif item.action_type == ActionType.PIP_CACHE_PURGE:
                    proc = subprocess.run([sys.executable, "-m", "pip", "cache", "purge"], capture_output=True, timeout=30, shell=False)
                    if proc.returncode == 0:
                        result.succeeded_items.append(item_id)
                        result.immediate_reclaimed_bytes += item.immediate_reclaimable_bytes
                        result.potential_reclaimed_bytes += item.immediate_reclaimable_bytes
                    else:
                        result.failed_items.append({"item_id": item_id, "path": item.path, "error": proc.stderr.decode()})

                elif item.action_type == ActionType.DOCKER_BUILDER_PRUNE:
                    docker_exe = shutil.which("docker.exe") or shutil.which("docker")
                    if not docker_exe:
                        result.failed_items.append({"item_id": item_id, "path": item.path, "error": "docker executable not found on PATH"})
                        continue
                    proc = subprocess.run([docker_exe, "builder", "prune", "-f"], capture_output=True, timeout=30, shell=False)
                    if proc.returncode == 0:
                        result.succeeded_items.append(item_id)
                        result.immediate_reclaimed_bytes += item.immediate_reclaimable_bytes
                        result.potential_reclaimed_bytes += item.immediate_reclaimable_bytes
                    else:
                        result.failed_items.append({"item_id": item_id, "path": item.path, "error": proc.stderr.decode()})

            except Exception as e:
                result.failed_items.append({"item_id": item_id, "path": item.path, "error": str(e)})

        # Measure volume free space delta across all touched volumes
        if not dry_run and initial_free_by_volume:
            total_observed = 0
            deltas = {}
            for vol, init_free in initial_free_by_volume.items():
                try:
                    curr_free = shutil.disk_usage(vol).free
                    delta = max(0, curr_free - init_free)
                    deltas[vol] = delta
                    total_observed += delta
                except Exception:
                    pass
            result.observed_volume_free_delta_bytes = total_observed
            result.observed_volume_deltas = deltas
        result.estimated_immediate_reclaimed_bytes = result.immediate_reclaimed_bytes

        # Generate accurate explanation distinguishing dry-run projections from observed execution
        if result.dry_run:
            result.explanation = (
                f"[DRY-RUN] Previewed {result.succeeded_count} items. "
                f"Projected immediate reclaim: {result.projected_immediate_reclaimable_bytes / (1024*1024):.2f} MB, "
                f"Projected Recycle Bin deferral: {result.projected_recycle_bin_bytes / (1024*1024):.2f} MB. "
                f"No files were modified."
            )
        else:
            result.explanation = (
                f"Successfully executed {result.succeeded_count} items. "
                f"Estimated immediate reclaim: {result.estimated_immediate_reclaimed_bytes / (1024*1024):.2f} MB. "
                f"Observed volume free-space delta: {result.observed_volume_free_delta_bytes / (1024*1024):.2f} MB. "
                f"Moved to Windows Recycle Bin: {result.recycle_bin_bytes / (1024*1024):.2f} MB "
                f"(reclaimable upon emptying Recycle Bin)."
            )

        return result
