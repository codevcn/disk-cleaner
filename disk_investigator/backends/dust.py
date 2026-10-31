"""
Dust scanner backend for disk_investigator.
Leverages bootandy/dust for ultra-fast, multithreaded, read-only disk scanning on Windows.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from typing import Any, Dict, List, Optional

from ..models import BackendKind, FileSystemNode, NodeKind, ScanStatus, SizeSemantics
from ..path_policy import (
    canonicalize_path,
    determine_node_kind,
    is_cloud_sync_path,
    is_protected_system_path,
    is_reparse_point,
)
from .base import ScannerBackend


def parse_dust_size(size_str: str) -> int:
    """Parses dust size string (e.g. '18831B', '420KiB', '2.5MiB') into bytes."""
    if not size_str:
        return 0

    s = size_str.strip()

    # Exact byte representation with -o b (e.g. '18831B')
    if s.endswith("B") and not (s.endswith("KiB") or s.endswith("MiB") or s.endswith("GiB") or s.endswith("TiB")):
        num_part = s[:-1]
        try:
            return int(num_part)
        except ValueError:
            pass

    # Fallback parser for standard human-readable units if -o b was not respected
    match = re.match(r"^([\d\.]+)\s*([A-Za-z]+)?$", s)
    if not match:
        return 0

    val = float(match.group(1))
    unit = (match.group(2) or "").lower()

    multipliers = {
        "b": 1,
        "k": 1024,
        "ki": 1024,
        "kib": 1024,
        "kb": 1000,
        "m": 1024**2,
        "mi": 1024**2,
        "mib": 1024**2,
        "mb": 1000**2,
        "g": 1024**3,
        "gi": 1024**3,
        "gib": 1024**3,
        "gb": 1000**3,
        "t": 1024**4,
        "ti": 1024**4,
        "tib": 1024**4,
        "tb": 1000**4,
    }
    return int(val * multipliers.get(unit, 1))


class DustBackend(ScannerBackend):
    """Primary high-performance scanner using bootandy/dust."""

    def __init__(self, dust_path: Optional[str] = None):
        self._dust_path = dust_path or shutil.which("dust")

    @property
    def name(self) -> BackendKind:
        return BackendKind.DUST

    def is_available(self) -> bool:
        return bool(self._dust_path and os.path.exists(self._dust_path))

    def _convert_node(
        self,
        raw_node: Dict[str, Any],
        depth_remaining: int,
        max_entries_applied: bool = False,
        has_warnings: bool = False,
    ) -> FileSystemNode:
        """Converts a raw JSON node from dust into our FileSystemNode model."""
        raw_path = raw_node.get("name", "")
        raw_size = raw_node.get("size", "0B")
        bytes_val = parse_dust_size(raw_size)

        canon_path = canonicalize_path(raw_path)
        base_name = os.path.basename(canon_path)
        if not base_name:  # For drive roots like C:\
            base_name = canon_path

        kind = determine_node_kind(canon_path)
        is_reparse = is_reparse_point(canon_path)
        is_cloud = is_cloud_sync_path(canon_path)
        is_sys = is_protected_system_path(canon_path)

        mtime = None
        try:
            mtime = os.path.getmtime(canon_path)
        except (OSError, PermissionError):
            pass

        children: List[FileSystemNode] = []
        raw_children = raw_node.get("children", [])

        # Dust already limits depth, but we recursively convert all children returned
        for child_raw in raw_children:
            children.append(
                self._convert_node(
                    child_raw,
                    depth_remaining - 1,
                    max_entries_applied=max_entries_applied,
                    has_warnings=has_warnings,
                )
            )

        # Sort children by size descending
        children.sort(key=lambda x: x.logical_bytes, reverse=True)

        # Accurately reflect completeness
        if kind == NodeKind.DIRECTORY and (depth_remaining <= 0 or max_entries_applied):
            node_children_complete = False
        else:
            node_children_complete = True

        return FileSystemNode(
            path=canon_path,
            canonical_path=canon_path,
            name=base_name,
            kind=kind,
            logical_bytes=bytes_val,
            allocated_bytes=bytes_val,  # Dust measures allocated disk blocks
            reclaimable_bytes=None,  # Do not invent without verification
            size_semantics=SizeSemantics.ALLOCATED,
            mtime=mtime,
            source_backend=BackendKind.DUST,
            scan_status=ScanStatus.PARTIAL if has_warnings else ScanStatus.COMPLETE,
            error=None,
            is_reparse_point=is_reparse,
            is_cloud_sync=is_cloud,
            is_protected_system=is_sys,
            children_complete=node_children_complete,
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
        if not self.is_available():
            raise RuntimeError("Dust binary is not available on PATH")

        target_path = canonicalize_path(path)
        if not os.path.exists(target_path):
            return FileSystemNode(
                path=target_path,
                canonical_path=target_path,
                name=os.path.basename(target_path) or target_path,
                kind=NodeKind.OTHER,
                logical_bytes=0,
                source_backend=BackendKind.DUST,
                scan_status=ScanStatus.INACCESSIBLE,
                error="Path does not exist",
            )

        # Build dust arguments strictly according to safety policies:
        # -j: JSON output
        # -o b: Output in exact bytes
        # -p: Full paths
        # -P: Disable progress spinner
        # --print-errors: Report filesystem errors
        # -d <depth>: Depth limit
        # NEVER -L (never dereference symlinks/junctions)
        cmd = [
            self._dust_path,
            "-j",
            "-o",
            "b",
            "-p",
            "-P",
            "--print-errors",
            "-d",
            str(max(1, depth)),
        ]

        if only_dir:
            cmd.append("-D")

        if max_entries:
            cmd.extend(["-n", str(max_entries)])

        if collapse_node_modules:
            cmd.append("--collapse=node-modules")

        if min_size_bytes and min_size_bytes > 0:
            cmd.extend(["-z", f"{min_size_bytes}B"])

        cmd_target = target_path
        if len(cmd_target) == 3 and cmd_target[1:3] == ":\\":
            cmd_target = f"{cmd_target[:2]}/"  # "C:\" -> "C:/" so dust targets root, not CWD of drive
        elif cmd_target.endswith("\\") and len(cmd_target) > 3:
            cmd_target = cmd_target.rstrip("\\")

        cmd.append(cmd_target)

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,  # 60s timeout protection
                shell=False,
            )

            stdout = proc.stdout.strip()
            if not stdout:
                # If dust produced no output, check stderr
                err_msg = proc.stderr.strip() if proc.stderr else "Empty output from dust"
                return FileSystemNode(
                    path=target_path,
                    canonical_path=target_path,
                    name=os.path.basename(target_path) or target_path,
                    kind=determine_node_kind(target_path),
                    logical_bytes=0,
                    source_backend=BackendKind.DUST,
                    scan_status=ScanStatus.PARTIAL,
                    error=err_msg,
                )

            has_warnings = bool((proc.stderr and proc.stderr.strip()) or proc.returncode != 0)
            max_entries_applied = bool(max_entries and max_entries > 0)
            data = json.loads(stdout)
            root_node = self._convert_node(
                data,
                depth,
                max_entries_applied=max_entries_applied,
                has_warnings=has_warnings,
            )
            return root_node

        except subprocess.TimeoutExpired:
            return FileSystemNode(
                path=target_path,
                canonical_path=target_path,
                name=os.path.basename(target_path) or target_path,
                kind=determine_node_kind(target_path),
                logical_bytes=0,
                source_backend=BackendKind.DUST,
                scan_status=ScanStatus.PARTIAL,
                error="Scan timed out after 60 seconds",
            )
        except json.JSONDecodeError as jde:
            return FileSystemNode(
                path=target_path,
                canonical_path=target_path,
                name=os.path.basename(target_path) or target_path,
                kind=determine_node_kind(target_path),
                logical_bytes=0,
                source_backend=BackendKind.DUST,
                scan_status=ScanStatus.PARTIAL,
                error=f"Failed to parse dust JSON output: {jde}",
            )
        except Exception as e:
            return FileSystemNode(
                path=target_path,
                canonical_path=target_path,
                name=os.path.basename(target_path) or target_path,
                kind=determine_node_kind(target_path),
                logical_bytes=0,
                source_backend=BackendKind.DUST,
                scan_status=ScanStatus.PARTIAL,
                error=str(e),
            )
