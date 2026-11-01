"""
Lifecycle data models and status definitions for Disk Investigator.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List


class UninstallStatus(str, Enum):
    """Execution status for uninstallation operations."""
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    PARTIAL = "PARTIAL"
    BLOCKED = "BLOCKED"


STATUS_EXIT_CODES: Dict[UninstallStatus, int] = {
    UninstallStatus.SUCCESS: 0,
    UninstallStatus.FAILED: 1,
    UninstallStatus.CANCELLED: 2,
    UninstallStatus.PARTIAL: 3,
    UninstallStatus.BLOCKED: 4,
}


@dataclass
class UninstallResult:
    """Comprehensive result of an uninstallation procedure."""
    status: UninstallStatus = UninstallStatus.FAILED
    path_removed: bool = False
    binary_removed: bool = False
    skill_removed: bool = False
    skill_preserved: bool = False
    runtime_data_removed: bool = False
    preserved_paths: List[str] = field(default_factory=list)
    removed_paths: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def exit_code(self) -> int:
        """Returns standard exit code defined in UNINSTALL-FINAL-13."""
        return STATUS_EXIT_CODES.get(self.status, 1)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes result to dictionary."""
        return {
            "status": self.status.value,
            "exit_code": self.exit_code,
            "path_removed": self.path_removed,
            "binary_removed": self.binary_removed,
            "skill_removed": self.skill_removed,
            "skill_preserved": self.skill_preserved,
            "runtime_data_removed": self.runtime_data_removed,
            "preserved_paths": self.preserved_paths,
            "removed_paths": self.removed_paths,
            "warnings": self.warnings,
            "errors": self.errors,
        }
