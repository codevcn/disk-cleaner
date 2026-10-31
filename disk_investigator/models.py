"""
Core data models and schemas for disk_investigator.
Designed specifically for machine-readable AI agent reasoning.
"""

from __future__ import annotations

import datetime
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class NodeKind(str, Enum):
    FILE = "file"
    DIRECTORY = "directory"
    JUNCTION = "junction"
    SYMLINK = "symlink"
    MOUNT = "mount"
    OTHER = "other"


class ScanStatus(str, Enum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    INACCESSIBLE = "inaccessible"
    SKIPPED = "skipped"


class BackendKind(str, Enum):
    DUST = "dust"
    NATIVE = "native"


class SizeSemantics(str, Enum):
    EXACT = "exact"
    APPARENT = "apparent"
    ALLOCATED = "allocated"
    ESTIMATED = "estimated"


@dataclass
class FileSystemNode:
    path: str
    canonical_path: str
    name: str
    kind: NodeKind
    logical_bytes: int
    allocated_bytes: Optional[int] = None
    reclaimable_bytes: Optional[int] = None
    size_semantics: SizeSemantics = SizeSemantics.EXACT
    mtime: Optional[float] = None
    source_backend: BackendKind = BackendKind.NATIVE
    scan_status: ScanStatus = ScanStatus.COMPLETE
    error: Optional[str] = None
    is_reparse_point: bool = False
    is_cloud_sync: bool = False
    is_protected_system: bool = False
    volume_id: Optional[str] = None
    children_complete: bool = True
    children: List[FileSystemNode] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        result = {
            "path": self.path,
            "canonical_path": self.canonical_path,
            "name": self.name,
            "kind": self.kind.value if isinstance(self.kind, NodeKind) else self.kind,
            "logical_bytes": self.logical_bytes,
            "allocated_bytes": self.allocated_bytes,
            "reclaimable_bytes": self.reclaimable_bytes,
            "size_semantics": (
                self.size_semantics.value
                if isinstance(self.size_semantics, SizeSemantics)
                else self.size_semantics
            ),
            "mtime": self.mtime,
            "source_backend": (
                self.source_backend.value
                if isinstance(self.source_backend, BackendKind)
                else self.source_backend
            ),
            "scan_status": (
                self.scan_status.value
                if isinstance(self.scan_status, ScanStatus)
                else self.scan_status
            ),
            "error": self.error,
            "is_reparse_point": self.is_reparse_point,
            "is_cloud_sync": self.is_cloud_sync,
            "is_protected_system": self.is_protected_system,
            "volume_id": self.volume_id,
            "children_complete": self.children_complete,
            "children_count": len(self.children),
            "children": [child.to_dict() for child in self.children],
        }
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> FileSystemNode:
        children_data = data.get("children", [])
        children = [cls.from_dict(c) for c in children_data]
        return cls(
            path=data["path"],
            canonical_path=data.get("canonical_path", data["path"]),
            name=data.get("name", ""),
            kind=NodeKind(data.get("kind", NodeKind.DIRECTORY)),
            logical_bytes=data.get("logical_bytes", 0),
            allocated_bytes=data.get("allocated_bytes"),
            reclaimable_bytes=data.get("reclaimable_bytes"),
            size_semantics=SizeSemantics(data.get("size_semantics", SizeSemantics.EXACT)),
            mtime=data.get("mtime"),
            source_backend=BackendKind(data.get("source_backend", BackendKind.NATIVE)),
            scan_status=ScanStatus(data.get("scan_status", ScanStatus.COMPLETE)),
            error=data.get("error"),
            is_reparse_point=data.get("is_reparse_point", False),
            is_cloud_sync=data.get("is_cloud_sync", False),
            is_protected_system=data.get("is_protected_system", False),
            volume_id=data.get("volume_id"),
            children_complete=data.get("children_complete", True),
            children=children,
        )


@dataclass
class DriveOverview:
    drive: str
    total_bytes: int
    used_bytes: int
    free_bytes: int
    percent_used: float
    top_consumers: List[FileSystemNode] = field(default_factory=list)
    backend: BackendKind = BackendKind.NATIVE
    duration_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "drive": self.drive,
            "total_bytes": self.total_bytes,
            "used_bytes": self.used_bytes,
            "free_bytes": self.free_bytes,
            "percent_used": round(self.percent_used, 2),
            "top_consumers_count": len(self.top_consumers),
            "top_consumers": [c.to_dict() for c in self.top_consumers],
            "backend": (
                self.backend.value
                if isinstance(self.backend, BackendKind)
                else self.backend
            ),
            "duration_ms": round(self.duration_ms, 2),
        }


@dataclass
class ScanSnapshot:
    snapshot_id: str
    root_path: str
    backend: BackendKind
    depth: int
    root_node: FileSystemNode
    parent_snapshot_id: Optional[str] = None
    created_at: str = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
    )
    summary: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "snapshot_id": self.snapshot_id,
            "parent_snapshot_id": self.parent_snapshot_id,
            "root_path": self.root_path,
            "created_at": self.created_at,
            "backend": (
                self.backend.value
                if isinstance(self.backend, BackendKind)
                else self.backend
            ),
            "depth": self.depth,
            "summary": self.summary,
            "root_node": self.root_node.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ScanSnapshot:
        return cls(
            snapshot_id=data["snapshot_id"],
            parent_snapshot_id=data.get("parent_snapshot_id"),
            root_path=data["root_path"],
            created_at=data.get("created_at", ""),
            backend=BackendKind(data.get("backend", BackendKind.NATIVE)),
            depth=data.get("depth", 1),
            summary=data.get("summary", {}),
            root_node=FileSystemNode.from_dict(data["root_node"]),
        )
