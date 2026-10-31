"""
Native Windows scanner backend for disk_investigator.
Provides a resilient, scoped fallback scanner using Python 3.12 os.scandir.
Strictly adheres to safety rules: does not follow junctions or symlinks.
"""

from __future__ import annotations

import os
import stat
from typing import List, Optional, Tuple

from ..models import BackendKind, FileSystemNode, NodeKind, ScanStatus, SizeSemantics
from ..path_policy import (
    canonicalize_path,
    determine_node_kind,
    is_cloud_sync_path,
    is_protected_system_path,
    is_reparse_point,
)
from .base import ScannerBackend


def _fast_dir_size(dir_path: str, max_files: int = 50000) -> Tuple[int, int, bool]:
    """
    Rapidly sums sizes of all files under dir_path without building tree nodes.
    Returns (total_bytes, file_count, completed_cleanly).
    Skips junctions and symlinks to prevent infinite loops.
    """
    total = 0
    count = 0
    stack = [dir_path]
    clean = True

    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as it:
                for entry in it:
                    try:
                        # Safety: never follow junctions or symlinks
                        is_junc = hasattr(entry, "is_junction") and entry.is_junction()
                        if is_junc or entry.is_symlink():
                            continue

                        if entry.is_file(follow_symlinks=False):
                            total += entry.stat(follow_symlinks=False).st_size
                            count += 1
                            if count >= max_files:
                                return total, count, False
                        elif entry.is_dir(follow_symlinks=False):
                            stack.append(entry.path)
                    except (OSError, PermissionError):
                        clean = False
                        continue
        except (OSError, PermissionError):
            clean = False
            continue

    return total, count, clean


class NativeWindowsBackend(ScannerBackend):
    """Scoped native filesystem scanner with strict Windows reparse point safety."""

    @property
    def name(self) -> BackendKind:
        return BackendKind.NATIVE

    def is_available(self) -> bool:
        return True  # Always available in Python on Windows

    def _scan_dir(
        self,
        path: str,
        current_depth: int,
        max_depth: int,
        only_dir: bool,
        collapse_node_modules: bool,
    ) -> FileSystemNode:
        canon_path = canonicalize_path(path)
        base_name = os.path.basename(canon_path) or canon_path
        kind = determine_node_kind(canon_path)
        is_reparse = is_reparse_point(canon_path)
        is_cloud = is_cloud_sync_path(canon_path)
        is_sys = is_protected_system_path(canon_path)

        mtime = None
        try:
            mtime = os.path.getmtime(canon_path)
        except (OSError, PermissionError):
            pass

        # If it's a junction or symlink, never recurse into it
        if is_reparse or kind in (NodeKind.JUNCTION, NodeKind.SYMLINK):
            return FileSystemNode(
                path=canon_path,
                canonical_path=canon_path,
                name=base_name,
                kind=kind,
                logical_bytes=0,
                allocated_bytes=0,
                reclaimable_bytes=None,
                size_semantics=SizeSemantics.EXACT,
                mtime=mtime,
                source_backend=BackendKind.NATIVE,
                scan_status=ScanStatus.SKIPPED,
                error="Reparse point / junction skipped by safety policy",
                is_reparse_point=True,
                is_cloud_sync=is_cloud,
                is_protected_system=is_sys,
                children_complete=True,
                children=[],
            )

        # Handle collapsed directory (e.g. node_modules)
        if collapse_node_modules and base_name.lower() == "node_modules":
            sz, _, complete = _fast_dir_size(canon_path)
            return FileSystemNode(
                path=canon_path,
                canonical_path=canon_path,
                name=base_name,
                kind=NodeKind.DIRECTORY,
                logical_bytes=sz,
                allocated_bytes=None,
                reclaimable_bytes=None,
                size_semantics=SizeSemantics.APPARENT if complete else SizeSemantics.ESTIMATED,
                mtime=mtime,
                source_backend=BackendKind.NATIVE,
                scan_status=ScanStatus.COMPLETE if complete else ScanStatus.PARTIAL,
                is_reparse_point=is_reparse,
                is_cloud_sync=is_cloud,
                is_protected_system=is_sys,
                children_complete=False,
                children=[],
            )

        children: List[FileSystemNode] = []
        total_logical_bytes = 0
        scan_status = ScanStatus.COMPLETE
        scan_error = None
        children_complete = True

        try:
            with os.scandir(canon_path) as it:
                entries = list(it)

            for entry in entries:
                try:
                    entry_path = entry.path
                    canon_entry = canonicalize_path(entry_path)
                    child_is_cloud = is_cloud_sync_path(canon_entry)
                    child_is_sys = is_protected_system_path(canon_entry)
                    entry_is_junc = hasattr(entry, "is_junction") and entry.is_junction()
                    entry_is_sym = entry.is_symlink()

                    if entry_is_junc or entry_is_sym:
                        if not only_dir or entry.is_dir(follow_symlinks=False):
                            child_node = FileSystemNode(
                                path=canon_entry,
                                canonical_path=canon_entry,
                                name=entry.name,
                                kind=NodeKind.JUNCTION if entry_is_junc else NodeKind.SYMLINK,
                                logical_bytes=0,
                                allocated_bytes=None,
                                size_semantics=SizeSemantics.EXACT,
                                source_backend=BackendKind.NATIVE,
                                scan_status=ScanStatus.SKIPPED,
                                error="Reparse point / junction skipped",
                                is_reparse_point=True,
                                is_cloud_sync=child_is_cloud,
                                is_protected_system=child_is_sys,
                                children_complete=True,
                                children=[],
                            )
                            children.append(child_node)
                        continue

                    if entry.is_file(follow_symlinks=False):
                        file_sz = entry.stat(follow_symlinks=False).st_size
                        total_logical_bytes += file_sz
                        if not only_dir:
                            child_node = FileSystemNode(
                                path=canon_entry,
                                canonical_path=canon_entry,
                                name=entry.name,
                                kind=NodeKind.FILE,
                                logical_bytes=file_sz,
                                allocated_bytes=None,
                                size_semantics=SizeSemantics.APPARENT,
                                mtime=entry.stat(follow_symlinks=False).st_mtime,
                                source_backend=BackendKind.NATIVE,
                                scan_status=ScanStatus.COMPLETE,
                                is_cloud_sync=child_is_cloud,
                                is_protected_system=child_is_sys,
                                children_complete=True,
                                children=[],
                            )
                            children.append(child_node)

                    elif entry.is_dir(follow_symlinks=False):
                        if current_depth < max_depth:
                            child_node = self._scan_dir(
                                entry_path,
                                current_depth + 1,
                                max_depth,
                                only_dir,
                                collapse_node_modules,
                            )
                            total_logical_bytes += child_node.logical_bytes
                            children.append(child_node)
                        else:
                            # Depth limit reached: calculate size rapidly without populating deep child nodes
                            dir_sz, _, dir_complete = _fast_dir_size(entry_path)
                            total_logical_bytes += dir_sz
                            child_node = FileSystemNode(
                                path=canon_entry,
                                canonical_path=canon_entry,
                                name=entry.name,
                                kind=NodeKind.DIRECTORY,
                                logical_bytes=dir_sz,
                                allocated_bytes=None,
                                size_semantics=SizeSemantics.APPARENT if dir_complete else SizeSemantics.ESTIMATED,
                                source_backend=BackendKind.NATIVE,
                                scan_status=ScanStatus.COMPLETE if dir_complete else ScanStatus.PARTIAL,
                                is_cloud_sync=child_is_cloud,
                                is_protected_system=child_is_sys,
                                children_complete=False,
                                children=[],
                            )
                            children.append(child_node)

                except (OSError, PermissionError) as e:
                    # Inaccessible child item does not abort sibling processing
                    children.append(
                        FileSystemNode(
                            path=canonicalize_path(entry.path),
                            canonical_path=canonicalize_path(entry.path),
                            name=entry.name,
                            kind=NodeKind.OTHER,
                            logical_bytes=0,
                            allocated_bytes=None,
                            source_backend=BackendKind.NATIVE,
                            scan_status=ScanStatus.INACCESSIBLE,
                            error=str(e),
                            children_complete=False,
                            children=[],
                        )
                    )

        except (PermissionError, OSError) as e:
            scan_status = ScanStatus.INACCESSIBLE
            scan_error = str(e)
            children_complete = False

        # Sort children largest first
        children.sort(key=lambda x: x.logical_bytes, reverse=True)

        # Propagate child partial/inaccessible issues up to parent
        if any(c.scan_status in (ScanStatus.PARTIAL, ScanStatus.INACCESSIBLE) for c in children):
            if scan_status == ScanStatus.COMPLETE:
                scan_status = ScanStatus.PARTIAL
            parent_size_semantics = SizeSemantics.ESTIMATED
        else:
            parent_size_semantics = SizeSemantics.APPARENT

        return FileSystemNode(
            path=canon_path,
            canonical_path=canon_path,
            name=base_name,
            kind=NodeKind.DIRECTORY,
            logical_bytes=total_logical_bytes,
            allocated_bytes=None,
            reclaimable_bytes=None,
            size_semantics=parent_size_semantics,
            mtime=mtime,
            source_backend=BackendKind.NATIVE,
            scan_status=scan_status,
            error=scan_error,
            is_reparse_point=is_reparse,
            is_cloud_sync=is_cloud,
            is_protected_system=is_sys,
            children_complete=children_complete,
            children=children,
        )

    def scan(
        self,
        path: str,
        depth: int = 1,
        max_entries: Optional[int] = None,
        only_dir: bool = False,
        min_size_bytes: Optional[int] = None,
        collapse_node_modules: bool = True,
    ) -> FileSystemNode:
        canon_path = canonicalize_path(path)
        if not os.path.exists(canon_path):
            return FileSystemNode(
                path=canon_path,
                canonical_path=canon_path,
                name=os.path.basename(canon_path) or canon_path,
                kind=NodeKind.OTHER,
                logical_bytes=0,
                source_backend=BackendKind.NATIVE,
                scan_status=ScanStatus.INACCESSIBLE,
                error="Path does not exist",
            )

        if os.path.isfile(canon_path):
            sz = os.path.getsize(canon_path)
            return FileSystemNode(
                path=canon_path,
                canonical_path=canon_path,
                name=os.path.basename(canon_path),
                kind=NodeKind.FILE,
                logical_bytes=sz,
                allocated_bytes=None,
                size_semantics=SizeSemantics.APPARENT,
                mtime=os.path.getmtime(canon_path),
                source_backend=BackendKind.NATIVE,
                scan_status=ScanStatus.COMPLETE,
            )

        root = self._scan_dir(
            canon_path,
            current_depth=1,
            max_depth=max(1, depth),
            only_dir=only_dir,
            collapse_node_modules=collapse_node_modules,
        )

        if min_size_bytes and min_size_bytes > 0:
            root.children = [c for c in root.children if c.logical_bytes >= min_size_bytes]

        if max_entries and max_entries > 0:
            if len(root.children) > max_entries:
                root.children_complete = False
            root.children = root.children[:max_entries]

        return root
