"""
Risk & disposition classifier for disk_investigator.
Strictly separates intrinsic risk from actionable policy disposition.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from ..path_policy import (
    canonicalize_path,
    has_reparse_point_ancestor,
    is_cloud_sync_path,
    is_critical_boundary,
    is_network_share,
    is_protected_system_path,
    is_reparse_point,
)


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class Disposition(str, Enum):
    CLEANABLE = "CLEANABLE"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    BLOCKED = "BLOCKED"


class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class ClassificationResult:
    path: str
    risk: RiskLevel
    disposition: Disposition
    confidence: Confidence
    regenerable: str  # "YES", "NO", "UNKNOWN"
    owner_app: Optional[str]
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "risk": self.risk.value,
            "disposition": self.disposition.value,
            "confidence": self.confidence.value,
            "regenerable": self.regenerable,
            "owner_app": self.owner_app,
            "evidence": self.evidence,
        }


class RiskClassifier:
    """Classifies filesystem candidates according to safety policies and risk tiers."""

    def classify(
        self,
        path: str,
        artifact_type: Optional[str] = None,
        owner_app: Optional[str] = None,
        stale_candidate: bool = False,
        regenerable: Optional[str] = None,
    ) -> ClassificationResult:
        canon = canonicalize_path(path)
        canon_lower = canon.lower()
        evidence: List[str] = []

        # 1. HARD BLOCKS (Always BLOCKED & HIGH RISK)
        if is_critical_boundary(canon):
            return ClassificationResult(
                path=canon,
                risk=RiskLevel.HIGH,
                disposition=Disposition.BLOCKED,
                confidence=Confidence.HIGH,
                regenerable="NO",
                owner_app="System/UserRoot",
                evidence=["Critical drive root, user profile, or credential boundary. Deletion strictly forbidden."],
            )

        if is_network_share(canon):
            return ClassificationResult(
                path=canon,
                risk=RiskLevel.HIGH,
                disposition=Disposition.BLOCKED,
                confidence=Confidence.HIGH,
                regenerable="UNKNOWN",
                owner_app="NetworkShare",
                evidence=["Network share / UNC path lacks Windows Recycle Bin guarantees. Deletion forbidden."],
            )

        if is_protected_system_path(canon):
            return ClassificationResult(
                path=canon,
                risk=RiskLevel.HIGH,
                disposition=Disposition.BLOCKED,
                confidence=Confidence.HIGH,
                regenerable="NO",
                owner_app="Windows",
                evidence=["Protected Windows operating system boundary. Deletion forbidden."],
            )

        if is_cloud_sync_path(canon):
            return ClassificationResult(
                path=canon,
                risk=RiskLevel.HIGH,
                disposition=Disposition.BLOCKED,
                confidence=Confidence.HIGH,
                regenerable="UNKNOWN",
                owner_app="CloudSync",
                evidence=["Cloud synchronization root (OneDrive/Dropbox/etc). Deletion replicates remotely."],
            )

        if is_reparse_point(canon) or has_reparse_point_ancestor(canon):
            return ClassificationResult(
                path=canon,
                risk=RiskLevel.HIGH,
                disposition=Disposition.BLOCKED,
                confidence=Confidence.HIGH,
                regenerable="UNKNOWN",
                owner_app=owner_app,
                evidence=["Reparse point, directory junction, or parent junction detected. Direct deletion risks target data."],
            )

        if canon_lower.endswith(".vhdx"):
            return ClassificationResult(
                path=canon,
                risk=RiskLevel.HIGH,
                disposition=Disposition.BLOCKED,
                confidence=Confidence.HIGH,
                regenerable="NO",
                owner_app="WSL/Docker",
                evidence=["Virtual Hard Disk file. Raw deletion corrupts virtualization registration."],
            )

        # 2. Known Developer Caches (LOW RISK, CLEANABLE)
        if artifact_type == "package_cache" or "npm-cache" in canon_lower or ("pip" in canon_lower and "cache" in canon_lower):
            evidence.append("Recognized package manager download cache")
            evidence.append("Package manager will automatically redownload packages when needed")
            return ClassificationResult(
                path=canon,
                risk=RiskLevel.LOW,
                disposition=Disposition.CLEANABLE,
                confidence=Confidence.HIGH,
                regenerable="YES",
                owner_app=owner_app or "package_manager",
                evidence=evidence,
            )

        if artifact_type == "pycache" or canon_lower.endswith("__pycache__"):
            evidence.append("Python compiled bytecode cache (.pyc)")
            evidence.append("Python re-compiles bytecode automatically upon next execution")
            return ClassificationResult(
                path=canon,
                risk=RiskLevel.LOW,
                disposition=Disposition.CLEANABLE,
                confidence=Confidence.HIGH,
                regenerable="YES",
                owner_app="python",
                evidence=evidence,
            )

        # 3. Build artifacts (.next, target)
        if artifact_type == "build_artifact" or canon_lower.endswith("\\.next") or canon_lower.endswith("\\target"):
            evidence.append("Build compilation artifact")
            evidence.append("Can be regenerated by running project build command (npm run build / cargo build)")
            return ClassificationResult(
                path=canon,
                risk=RiskLevel.LOW,
                disposition=Disposition.CLEANABLE,
                confidence=Confidence.HIGH,
                regenerable="YES",
                owner_app=owner_app or "compiler",
                evidence=evidence,
            )

        # 4. node_modules (MEDIUM RISK, REVIEW REQUIRED)
        if artifact_type == "node_modules" or canon_lower.endswith("\\node_modules"):
            evidence.append("Node.js dependency tree")
            if stale_candidate:
                evidence.append("Project has not been modified in > 90 days (candidate for reclaim)")
            evidence.append("Can be reinstalled via 'npm install' or 'pnpm install'")
            return ClassificationResult(
                path=canon,
                risk=RiskLevel.MEDIUM,
                disposition=Disposition.REVIEW_REQUIRED,
                confidence=Confidence.HIGH,
                regenerable="YES",
                owner_app="npm/node",
                evidence=evidence,
            )

        # 5. Python virtual environments (MEDIUM RISK, REVIEW REQUIRED)
        if artifact_type == "python_venv":
            evidence.append("Python isolated virtual environment")
            evidence.append("Review required to ensure dependencies can be re-installed from requirements.txt")
            return ClassificationResult(
                path=canon,
                risk=RiskLevel.MEDIUM,
                disposition=Disposition.REVIEW_REQUIRED,
                confidence=Confidence.HIGH,
                regenerable=regenerable or "UNKNOWN",
                owner_app="python",
                evidence=evidence,
            )

        # 6. Default fallback for unknown items
        evidence.append("Unclassified file or directory")
        return ClassificationResult(
            path=canon,
            risk=RiskLevel.MEDIUM,
            disposition=Disposition.REVIEW_REQUIRED,
            confidence=Confidence.LOW,
            regenerable="UNKNOWN",
            owner_app=owner_app,
            evidence=evidence,
        )
