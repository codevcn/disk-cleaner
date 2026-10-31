"""
DrilldownService provides targeted, conversational filesystem exploration.
Enables AI Agents to dig into specific hotspots with session lineage.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from ..models import BackendKind, FileSystemNode, NodeKind, ScanSnapshot
from ..path_policy import canonicalize_path, is_protected_system_path
from .scan_service import ScanService


class DrilldownService:
    """Manages conversational, step-by-step drilldown into suspicious or large storage areas."""

    def __init__(self, scan_service: ScanService):
        self.scan_service = scan_service

    def drilldown(
        self,
        target_path: str,
        depth: int = 2,
        parent_snapshot_id: Optional[str] = None,
        max_entries: int = 30,
        min_size_bytes: Optional[int] = None,
        only_dir: bool = False,
        preferred_backend: Optional[BackendKind] = None,
    ) -> Dict[str, Any]:
        """
        Drills down into target_path, establishing parent snapshot lineage.
        Returns a structured dictionary enriched with AI agent hints.
        """
        canon_path = canonicalize_path(target_path)

        # Parent snapshot check
        parent_snapshot = None
        if parent_snapshot_id:
            parent_snapshot = self.scan_service.load_snapshot(parent_snapshot_id)

        # Perform child scan
        snapshot = self.scan_service.scan_path(
            path=canon_path,
            depth=depth,
            max_entries=max_entries,
            only_dir=only_dir,
            min_size_bytes=min_size_bytes,
            collapse_node_modules=True,
            preferred_backend=preferred_backend,
            parent_snapshot_id=parent_snapshot_id,
        )

        root = snapshot.root_node
        total_b = root.logical_bytes

        # Analyze dominant consumers (taking >= 15% of the target folder's total)
        dominant_consumers: List[Dict[str, Any]] = []
        for child in root.children:
            ratio = (child.logical_bytes / total_b) if total_b > 0 else 0.0
            dominant_consumers.append({
                "path": child.path,
                "name": child.name,
                "kind": child.kind.value,
                "logical_bytes": child.logical_bytes,
                "ratio_of_parent": round(ratio * 100, 2),
                "is_dominant": ratio >= 0.15,
                "is_protected": child.is_protected_system,
                "is_reparse": child.is_reparse_point,
            })

        # Suggest logical next drilldown targets for the AI agent
        drill_suggestions = []
        for d in dominant_consumers:
            if d["kind"] in (NodeKind.DIRECTORY.value,) and not d["is_reparse"] and d["logical_bytes"] > 50 * 1024 * 1024:  # > 50MB
                drill_suggestions.append({
                    "path": d["path"],
                    "reason": f"Dominant directory consuming {d['ratio_of_parent']}% of {root.name}",
                })

        return {
            "snapshot_id": snapshot.snapshot_id,
            "parent_snapshot_id": parent_snapshot_id,
            "root_path": canon_path,
            "total_bytes": total_b,
            "backend_used": snapshot.backend.value,
            "depth_explored": depth,
            "children_count": len(root.children),
            "dominant_consumers": dominant_consumers,
            "recommended_next_drilldowns": drill_suggestions[:5],
            "tree": snapshot.to_dict(),
        }
