"""
System user temporary files detector for Windows.
"""

from __future__ import annotations

import os
import time
from typing import List, Optional

from ...backends.native_windows import _fast_dir_size
from ...models import (
    ArtifactCategory,
    ArtifactDomain,
    Confidence,
    DetectionContext,
    Evidence,
    RecommendedAction,
    RecoveryCost,
    Regenerability,
    StorageArtifact,
    UserDataProbability,
    generate_artifact_id,
)
from ...path_policy import canonicalize_path
from ..base import BaseDetector


class UserTempDetector(BaseDetector):
    """Detects Windows User Temporary files in %TEMP% and LocalAppData\\Temp."""

    detector_id = "system.user_temp"
    domain = ArtifactDomain.SYSTEM

    def __init__(self, min_age_hours: float = 24.0) -> None:
        self.min_age_seconds = min_age_hours * 3600.0

    def applicable(self, context: DetectionContext) -> bool:
        # Applicable in global scan or if target_path is within a temp folder
        if not context.target_path:
            return True
        temp_dir = context.env.get("TEMP") or os.environ.get("TEMP", "")
        if temp_dir and canonicalize_path(context.target_path).lower().startswith(
            canonicalize_path(temp_dir).lower()
        ):
            return True
        return True

    def detect(self, context: DetectionContext) -> List[StorageArtifact]:
        artifacts: List[StorageArtifact] = []
        temp_dir = context.env.get("TEMP") or os.environ.get("TEMP", "")
        if not temp_dir or not os.path.isdir(temp_dir):
            return artifacts

        now = context.current_time or time.time()

        try:
            with os.scandir(temp_dir) as it:
                for entry in it:
                    try:
                        stat = entry.stat()
                        age = now - stat.st_mtime
                        if age < self.min_age_seconds:
                            continue  # Skip fresh files created within threshold

                        canon = canonicalize_path(entry.path)
                        if entry.is_dir(follow_symlinks=False):
                            sz, _, _ = _fast_dir_size(entry.path)
                        else:
                            sz = stat.st_size

                        artifacts.append(
                            StorageArtifact(
                                artifact_id=generate_artifact_id(canon, "temp_item", self.detector_id),
                                path=entry.path,
                                canonical_path=canon,
                                domain=self.domain,
                                category=ArtifactCategory.TEMPORARY,
                                artifact_type="temp_item",
                                owner_app="windows_temp",
                                source_detector=self.detector_id,
                                logical_bytes=sz,
                                mtime=stat.st_mtime,
                                regenerability=Regenerability.NONE,
                                user_data_probability=UserDataProbability.LOW,
                                recovery_cost=RecoveryCost.LOW,
                                recommended_action=RecommendedAction.RECYCLE_KNOWN_CACHE,
                                confidence=Confidence.HIGH,
                                evidence=[
                                    Evidence(
                                        kind="path_heuristic",
                                        source=self.detector_id,
                                        value=canon,
                                        message=f"Temp file/dir older than {self.min_age_seconds / 3600:.1f}h (age: {age/86400:.1f}d)",
                                    )
                                ],
                            )
                        )
                    except (OSError, PermissionError):
                        continue
        except (OSError, PermissionError):
            pass

        return artifacts
