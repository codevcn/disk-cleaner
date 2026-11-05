"""
disk_investigator.updates.models
Domain contracts, typed representations, and serialization schemas for Update & Lifecycle subsystem.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional, Tuple


class UpdateState(str, Enum):
    UP_TO_DATE = "up_to_date"
    UPDATE_AVAILABLE = "update_available"
    HANDOFF_STARTED = "handoff_started"
    IN_PROGRESS = "in_progress"
    FAILED = "failed"
    CANCELLED = "cancelled"
    BLOCKED = "blocked"


class CacheFreshness(str, Enum):
    FRESH = "fresh"      # 0 to 24 hours
    STALE = "stale"      # 24 hours to 7 days
    EXPIRED = "expired"  # > 7 days or missing/corrupt


def parse_semver(ver_str: str) -> Tuple[int, ...]:
    """Extracts numeric semver tuple from string like 'v2.0.3' -> (2, 0, 3)."""
    cleaned = re.sub(r"^[^\d]*", "", str(ver_str).strip())
    numbers = []
    for part in cleaned.split("."):
        try:
            match = re.match(r"^\d+", part)
            if match:
                numbers.append(int(match.group(0)))
            else:
                numbers.append(0)
        except Exception:
            numbers.append(0)
    while len(numbers) < 3:
        numbers.append(0)
    return tuple(numbers[:3])


@dataclass
class ReleaseAsset:
    name: str
    download_url: str
    size: int = 0
    content_type: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "download_url": self.download_url,
            "size": self.size,
            "content_type": self.content_type,
        }


@dataclass
class ReleaseInfo:
    tag: str
    version: str
    release_url: str
    published_at: str
    release_name: str
    assets: Dict[str, ReleaseAsset] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tag": self.tag,
            "version": self.version,
            "release_url": self.release_url,
            "published_at": self.published_at,
            "release_name": self.release_name,
            "assets": {k: v.to_dict() for k, v in self.assets.items()},
        }


@dataclass
class UpdateCache:
    schema_version: int = 1
    repo: str = "codevcn/disk-cleaner"
    current_version: str = "0.0.0"
    latest_version: str = "0.0.0"
    release_url: str = ""
    published_at: str = ""
    checked_at: float = 0.0
    update_available: bool = False
    freshness: CacheFreshness = CacheFreshness.EXPIRED
    message: str = ""

    def to_dict(self) -> Dict[str, Any]:
        msg = self.message
        if not msg:
            if self.update_available:
                msg = f"Phiên bản mới v{self.latest_version} đã có trên GitHub (hiện tại: v{self.current_version})."
            else:
                msg = "You are on the latest version."
        return {
            "schema_version": self.schema_version,
            "repo": self.repo,
            "current_version": self.current_version,
            "latest_version": self.latest_version,
            "release_url": self.release_url,
            "published_at": self.published_at,
            "checked_at": self.checked_at,
            "update_available": self.update_available,
            "freshness": self.freshness.value,
            "message": msg,
        }


@dataclass
class UpdateReceipt:
    schema_version: int = 1
    status: str = "success"  # success, failed
    from_version: str = ""
    to_version: str = ""
    completed_at: str = ""
    installer_exit_code: int = 0
    error_message: Optional[str] = None
    rollback_attempted: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "status": self.status,
            "from_version": self.from_version,
            "to_version": self.to_version,
            "completed_at": self.completed_at,
            "installer_exit_code": self.installer_exit_code,
            "error_message": self.error_message,
            "rollback_attempted": self.rollback_attempted,
        }


@dataclass
class UpdateResult:
    state: UpdateState
    from_version: str
    target_version: str
    release_url: Optional[str] = None
    installer_pid: Optional[int] = None
    installer_verified: bool = False
    message: str = ""
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "state": self.state.value,
            "from_version": self.from_version,
            "target_version": self.target_version,
            "installer_verified": self.installer_verified,
            "message": self.message,
        }
        if self.release_url:
            d["release_url"] = self.release_url
        if self.installer_pid is not None:
            d["installer_pid"] = self.installer_pid
        if self.error:
            d["error"] = self.error
        return d
