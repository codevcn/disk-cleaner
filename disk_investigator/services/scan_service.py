"""
ScanService coordinates scanning backends, manages scan snapshots, and provides drive overviews.
"""

from __future__ import annotations

import json
import os
import shutil
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..backends import DustBackend, NativeWindowsBackend, ScannerBackend
from ..capabilities import get_available_drives, get_default_cache_dir
from ..models import (
    BackendKind,
    DriveOverview,
    FileSystemNode,
    ScanSnapshot,
    ScanStatus,
)
from ..path_policy import canonicalize_path


import re

SNAPSHOT_ID_REGEX = re.compile(r"^snap_[0-9a-f]{8,32}$")


def _count_nodes_and_issues(node: FileSystemNode) -> Tuple[int, int, int]:
    """Returns (total_nodes, inaccessible_count, reparse_count) recursively."""
    total = 1
    inaccessible = 1 if node.scan_status == ScanStatus.INACCESSIBLE else 0
    reparse = 1 if node.is_reparse_point else 0

    for child in node.children:
        t, i, r = _count_nodes_and_issues(child)
        total += t
        inaccessible += i
        reparse += r

    return total, inaccessible, reparse


class ScanService:
    """Core orchestration service for disk scanning and snapshot management."""

    def __init__(
        self,
        cache_dir: Optional[str] = None,
        dust_path: Optional[str] = None,
    ):
        if cache_dir:
            self.cache_dir = Path(cache_dir)
        else:
            self.cache_dir = get_default_cache_dir()
        self.snapshots_dir = self.cache_dir / "snapshots"
        self.snapshots_dir.mkdir(parents=True, exist_ok=True)

        self.dust_backend = DustBackend(dust_path)
        self.native_backend = NativeWindowsBackend()

    def get_backend(self, preferred: Optional[BackendKind] = None) -> ScannerBackend:
        """Selects the best available backend based on preference and system availability."""
        if preferred == BackendKind.DUST:
            if self.dust_backend.is_available():
                return self.dust_backend
            # Fallback if preferred is not available
            return self.native_backend
        elif preferred == BackendKind.NATIVE:
            return self.native_backend

        # Auto-selection: prefer dust if present
        if self.dust_backend.is_available():
            return self.dust_backend
        return self.native_backend

    def scan_path(
        self,
        path: str,
        depth: int = 1,
        max_entries: Optional[int] = 30,
        only_dir: bool = False,
        min_size_bytes: Optional[int] = None,
        collapse_node_modules: bool = True,
        preferred_backend: Optional[BackendKind] = None,
        parent_snapshot_id: Optional[str] = None,
    ) -> ScanSnapshot:
        """
        Executes a scan on target path and records a ScanSnapshot.
        """
        canon_path = canonicalize_path(path)
        backend = self.get_backend(preferred_backend)

        start_time = time.perf_counter()
        root_node = backend.scan(
            path=canon_path,
            depth=depth,
            max_entries=max_entries,
            only_dir=only_dir,
            min_size_bytes=min_size_bytes,
            collapse_node_modules=collapse_node_modules,
        )
        duration_ms = (time.perf_counter() - start_time) * 1000

        total_nodes, inacc_count, reparse_count = _count_nodes_and_issues(root_node)

        snapshot_id = f"snap_{uuid.uuid4().hex[:12]}"
        summary = {
            "root_path": canon_path,
            "total_bytes": root_node.logical_bytes,
            "total_nodes": total_nodes,
            "inaccessible_count": inacc_count,
            "reparse_points_count": reparse_count,
            "duration_ms": round(duration_ms, 2),
            "backend_used": backend.name.value,
        }

        snapshot = ScanSnapshot(
            snapshot_id=snapshot_id,
            parent_snapshot_id=parent_snapshot_id,
            root_path=canon_path,
            backend=backend.name,
            depth=depth,
            root_node=root_node,
            summary=summary,
        )

        # Persist snapshot to cache
        self.save_snapshot(snapshot)

        return snapshot

    def save_snapshot(self, snapshot: ScanSnapshot) -> str:
        """Saves a snapshot to the cache directory with traversal validation."""
        if not SNAPSHOT_ID_REGEX.match(snapshot.snapshot_id):
            raise ValueError(f"SECURITY REFUSAL: Invalid snapshot_id '{snapshot.snapshot_id}'. Path traversal prevented.")
        file_path = self.snapshots_dir / f"{snapshot.snapshot_id}.json"
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(snapshot.to_dict(), f, indent=2, ensure_ascii=False)
        return str(file_path)

    def load_snapshot(self, snapshot_id: str) -> Optional[ScanSnapshot]:
        """Loads a snapshot from cache by its ID with traversal validation."""
        if not SNAPSHOT_ID_REGEX.match(snapshot_id):
            raise ValueError(f"SECURITY REFUSAL: Invalid snapshot_id '{snapshot_id}'. Path traversal prevented.")
        file_path = self.snapshots_dir / f"{snapshot_id}.json"
        if not file_path.exists():
            return None
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return ScanSnapshot.from_dict(data)

    def drive_overview(
        self,
        drive_letter_or_path: Optional[str] = None,
        preferred_backend: Optional[BackendKind] = None,
        deep: bool = False,
    ) -> List[DriveOverview]:
        """
        Provides high-level disk usage overview and root consumer directories for drive(s).
        By default (deep=False), runs in < 20ms using fast root-level directory enumeration.
        """
        from ..models import NodeKind, ScanStatus, SizeSemantics
        from ..path_policy import (
            determine_node_kind,
            is_cloud_sync_path,
            is_protected_system_path,
            is_reparse_point,
        )

        targets = []
        if drive_letter_or_path:
            targets.append(canonicalize_path(drive_letter_or_path))
        else:
            targets = [canonicalize_path(d) for d in get_available_drives()]

        overviews: List[DriveOverview] = []
        backend = self.get_backend(preferred_backend)

        for drive in targets:
            start_t = time.perf_counter()
            total_b = 0
            used_b = 0
            free_b = 0
            pct_used = 0.0

            try:
                usage = shutil.disk_usage(drive)
                total_b = usage.total
                used_b = usage.used
                free_b = usage.free
                pct_used = (usage.used / usage.total) * 100 if usage.total > 0 else 0.0
            except Exception:
                pass

            top_consumers: List[FileSystemNode] = []

            if deep:
                # Full recursive scan of root (takes longer on large drives)
                root_node = backend.scan(
                    path=drive,
                    depth=1,
                    max_entries=15,
                    only_dir=True,
                    collapse_node_modules=True,
                )
                top_consumers = [c for c in root_node.children if c.logical_bytes > 0]
                top_consumers.sort(key=lambda x: x.logical_bytes, reverse=True)
            else:
                # Instantaneous root enumeration (< 15ms)
                try:
                    with os.scandir(drive) as it:
                        for entry in it:
                            try:
                                entry_path = canonicalize_path(entry.path)
                                is_junc = hasattr(entry, "is_junction") and entry.is_junction()
                                is_sym = entry.is_symlink()
                                is_reparse = is_junc or is_sym or is_reparse_point(entry_path)
                                is_cloud = is_cloud_sync_path(entry_path)
                                is_sys = is_protected_system_path(entry_path)

                                if is_junc:
                                    kind = NodeKind.JUNCTION
                                elif is_sym:
                                    kind = NodeKind.SYMLINK
                                elif entry.is_dir(follow_symlinks=False):
                                    kind = NodeKind.DIRECTORY
                                elif entry.is_file(follow_symlinks=False):
                                    kind = NodeKind.FILE
                                else:
                                    kind = NodeKind.OTHER

                                file_sz = 0
                                mtime = None
                                try:
                                    st = entry.stat(follow_symlinks=False)
                                    if kind == NodeKind.FILE:
                                        file_sz = st.st_size
                                    mtime = st.st_mtime
                                except (OSError, PermissionError):
                                    pass

                                top_consumers.append(
                                    FileSystemNode(
                                        path=entry_path,
                                        canonical_path=entry_path,
                                        name=entry.name,
                                        kind=kind,
                                        logical_bytes=file_sz,
                                        allocated_bytes=None,
                                        size_semantics=SizeSemantics.APPARENT if kind == NodeKind.FILE else SizeSemantics.ESTIMATED,
                                        mtime=mtime,
                                        source_backend=BackendKind.NATIVE,
                                        scan_status=ScanStatus.COMPLETE,
                                        is_reparse_point=is_reparse,
                                        is_cloud_sync=is_cloud,
                                        is_protected_system=is_sys,
                                        children_complete=False,
                                        children=[],
                                    )
                                )
                            except (OSError, PermissionError):
                                continue
                except (OSError, PermissionError):
                    pass

                # Sort: directories first (alphabetical or prioritized), then files by size
                top_consumers.sort(
                    key=lambda x: (
                        0 if x.kind == NodeKind.DIRECTORY else 1,
                        -x.logical_bytes if x.kind == NodeKind.FILE else 0,
                        x.name.lower(),
                    )
                )

            duration_ms = (time.perf_counter() - start_t) * 1000

            overviews.append(
                DriveOverview(
                    drive=drive,
                    total_bytes=total_b,
                    used_bytes=used_b,
                    free_bytes=free_b,
                    percent_used=pct_used,
                    top_consumers=top_consumers,
                    backend=backend.name if deep else BackendKind.NATIVE,
                    duration_ms=duration_ms,
                )
            )

        return overviews
