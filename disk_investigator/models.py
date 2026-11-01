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


# ==============================================================================
# General-Purpose Windows AI Storage Investigator Domain Contracts (v2.2+)
# ==============================================================================


class ArtifactDomain(str, Enum):
    SYSTEM = "system"
    BROWSER = "browser"
    OFFICE = "office"
    CREATOR = "creator"
    GAMING = "gaming"
    STREAMING = "streaming"
    DEVELOPER = "developer"
    AI_ML = "ai_ml"
    GENERAL = "general"


class ArtifactCategory(str, Enum):
    CACHE = "cache"
    TEMPORARY = "temporary"
    BUILD_ARTIFACT = "build_artifact"
    DEPENDENCY = "dependency"

    RENDER_CACHE = "render_cache"
    PROXY_MEDIA = "proxy_media"

    USER_DOCUMENT = "user_document"
    USER_MEDIA = "user_media"
    EMAIL_ARCHIVE = "email_archive"
    MEDICAL_DATA = "medical_data"

    GAME_INSTALL = "game_install"
    GAME_CACHE = "game_cache"

    MODEL_CACHE = "model_cache"
    MODEL_ASSET = "model_asset"

    LOG = "log"
    CRASH_DUMP = "crash_dump"
    DATABASE = "database"
    VIRTUAL_DISK = "virtual_disk"

    UNKNOWN = "unknown"


class Regenerability(str, Enum):
    FULL = "FULL"
    PARTIAL = "PARTIAL"
    NONE = "NONE"


class UserDataProbability(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class RecoveryCost(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    IMPOSSIBLE = "IMPOSSIBLE"


class RecommendedAction(str, Enum):
    KEEP = "KEEP"
    TYPED_CLEANUP = "TYPED_CLEANUP"
    RECYCLE_KNOWN_CACHE = "RECYCLE_KNOWN_CACHE"
    UNINSTALL_VIA_APP = "UNINSTALL_VIA_APP"
    REVIEW_ONLY = "REVIEW_ONLY"
    BLOCK = "BLOCK"


class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class Evidence:
    kind: str
    source: str
    value: str
    message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        res: Dict[str, Any] = {
            "kind": self.kind,
            "source": self.source,
            "value": self.value,
        }
        if self.message is not None:
            res["message"] = self.message
        return res

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Evidence:
        return cls(
            kind=data.get("kind", "unknown"),
            source=data.get("source", ""),
            value=str(data.get("value", "")),
            message=data.get("message"),
        )


def generate_artifact_id(canonical_path: str, artifact_type: str, source_detector: str) -> str:
    """Generate a deterministic 16-hex identifier for an artifact."""
    import hashlib
    raw = f"{canonical_path.lower().strip()}|{artifact_type.strip()}|{source_detector.strip()}"
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:16]


@dataclass
class StorageArtifact:
    """
    Universal machine-readable storage artifact representing detected disk items.
    Common across all modular detectors (system, browser, office, creator, gaming, etc.).
    """
    artifact_id: str
    path: str
    canonical_path: str
    domain: ArtifactDomain
    category: ArtifactCategory
    artifact_type: str
    owner_app: Optional[str] = None
    capability_id: Optional[str] = None
    source_detector: str = "unknown"
    logical_bytes: int = 0
    mtime: Optional[float] = None
    regenerability: Regenerability = Regenerability.NONE
    user_data_probability: UserDataProbability = UserDataProbability.HIGH
    recovery_cost: RecoveryCost = RecoveryCost.IMPOSSIBLE
    recommended_action: RecommendedAction = RecommendedAction.REVIEW_ONLY
    confidence: Confidence = Confidence.MEDIUM
    evidence: List[Evidence] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "path": self.path,
            "canonical_path": self.canonical_path,
            "domain": self.domain.value if isinstance(self.domain, ArtifactDomain) else self.domain,
            "category": self.category.value if isinstance(self.category, ArtifactCategory) else self.category,
            "artifact_type": self.artifact_type,
            "owner_app": self.owner_app,
            "capability_id": self.capability_id,
            "source_detector": self.source_detector,
            "logical_bytes": self.logical_bytes,
            "mtime": self.mtime,
            "regenerability": (
                self.regenerability.value
                if isinstance(self.regenerability, Regenerability)
                else self.regenerability
            ),
            "user_data_probability": (
                self.user_data_probability.value
                if isinstance(self.user_data_probability, UserDataProbability)
                else self.user_data_probability
            ),
            "recovery_cost": (
                self.recovery_cost.value
                if isinstance(self.recovery_cost, RecoveryCost)
                else self.recovery_cost
            ),
            "recommended_action": (
                self.recommended_action.value
                if isinstance(self.recommended_action, RecommendedAction)
                else self.recommended_action
            ),
            "confidence": (
                self.confidence.value
                if isinstance(self.confidence, Confidence)
                else self.confidence
            ),
            "evidence": [e.to_dict() if isinstance(e, Evidence) else e for e in self.evidence],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> StorageArtifact:
        evidence_raw = data.get("evidence", [])
        evidence_list: List[Evidence] = []
        for e in evidence_raw:
            if isinstance(e, dict):
                evidence_list.append(Evidence.from_dict(e))
            elif isinstance(e, str):
                evidence_list.append(Evidence(kind="text", source="detector", value=e, message=e))
            elif isinstance(e, Evidence):
                evidence_list.append(e)

        return cls(
            artifact_id=data.get("artifact_id", ""),
            path=data.get("path", ""),
            canonical_path=data.get("canonical_path", data.get("path", "")),
            domain=ArtifactDomain(data.get("domain", ArtifactDomain.GENERAL)),
            category=ArtifactCategory(data.get("category", ArtifactCategory.UNKNOWN)),
            artifact_type=data.get("artifact_type", "unknown"),
            owner_app=data.get("owner_app"),
            capability_id=data.get("capability_id"),
            source_detector=data.get("source_detector", "unknown"),
            logical_bytes=data.get("logical_bytes", 0),
            mtime=data.get("mtime"),
            regenerability=Regenerability(data.get("regenerability", Regenerability.NONE)),
            user_data_probability=UserDataProbability(data.get("user_data_probability", UserDataProbability.HIGH)),
            recovery_cost=RecoveryCost(data.get("recovery_cost", RecoveryCost.IMPOSSIBLE)),
            recommended_action=RecommendedAction(data.get("recommended_action", RecommendedAction.REVIEW_ONLY)),
            confidence=Confidence(data.get("confidence", Confidence.MEDIUM)),
            evidence=evidence_list,
        )


@dataclass
class Capability:
    """Discovered application or ecosystem capability on Windows."""
    capability_id: str
    detected: bool
    confidence: Confidence = Confidence.HIGH
    version: Optional[str] = None
    executable_paths: List[str] = field(default_factory=list)
    install_paths: List[str] = field(default_factory=list)
    data_roots: List[str] = field(default_factory=list)
    evidence: List[Evidence] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "capability_id": self.capability_id,
            "detected": self.detected,
            "confidence": (
                self.confidence.value
                if isinstance(self.confidence, Confidence)
                else self.confidence
            ),
            "version": self.version,
            "executable_paths": list(self.executable_paths),
            "install_paths": list(self.install_paths),
            "data_roots": list(self.data_roots),
            "evidence": [e.to_dict() if isinstance(e, Evidence) else e for e in self.evidence],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Capability:
        evidence_raw = data.get("evidence", [])
        evidence_list = [
            Evidence.from_dict(e) if isinstance(e, dict) else e for e in evidence_raw
        ]
        return cls(
            capability_id=data["capability_id"],
            detected=bool(data.get("detected", False)),
            confidence=Confidence(data.get("confidence", Confidence.HIGH)),
            version=data.get("version"),
            executable_paths=list(data.get("executable_paths", [])),
            install_paths=list(data.get("install_paths", [])),
            data_roots=list(data.get("data_roots", [])),
            evidence=evidence_list,
        )


@dataclass
class DetectionContext:
    """Context passed to detectors during investigation."""
    target_path: str
    capabilities: Dict[str, Capability] = field(default_factory=dict)
    current_time: float = field(default_factory=lambda: datetime.datetime.now().timestamp())
    env: Dict[str, str] = field(default_factory=dict)

