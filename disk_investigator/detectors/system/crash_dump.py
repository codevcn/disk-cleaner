"""
System crash dumps detector for Windows (.dmp files).
"""

from __future__ import annotations

import os
from typing import List

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


class CrashDumpDetector(BaseDetector):
    """Detects Windows application and kernel crash dump files."""

    detector_id = "system.crash_dump"
    domain = ArtifactDomain.SYSTEM

    def applicable(self, context: DetectionContext) -> bool:
        return True

    def detect(self, context: DetectionContext) -> List[StorageArtifact]:
        artifacts: List[StorageArtifact] = []

        if context.target_path and os.path.isdir(context.target_path):
            candidate_dirs = [context.target_path]
        else:
            local_app = context.env.get("LOCALAPPDATA") or os.environ.get("LOCALAPPDATA", "")
            system_root = context.env.get("SystemRoot") or os.environ.get("SystemRoot", "C:\\Windows")
            candidate_dirs = [
                os.path.join(local_app, "CrashDumps"),
                os.path.join(system_root, "Minidump"),
            ]

        seen_files = set()

        for d in candidate_dirs:
            if not os.path.isdir(d):
                continue
            try:
                with os.scandir(d) as it:
                    for entry in it:
                        try:
                            if entry.is_file() and entry.name.lower().endswith(".dmp"):
                                canon = canonicalize_path(entry.path)
                                if canon.lower() in seen_files:
                                    continue
                                seen_files.add(canon.lower())
                                stat = entry.stat()

                                artifacts.append(
                                    StorageArtifact(
                                        artifact_id=generate_artifact_id(canon, "crash_dump", self.detector_id),
                                        path=entry.path,
                                        canonical_path=canon,
                                        domain=self.domain,
                                        category=ArtifactCategory.CRASH_DUMP,
                                        artifact_type="crash_dump",
                                        owner_app="windows_error_reporting",
                                        source_detector=self.detector_id,
                                        logical_bytes=stat.st_size,
                                        mtime=stat.st_mtime,
                                        regenerability=Regenerability.NONE,
                                        user_data_probability=UserDataProbability.HIGH,  # May contain process memory
                                        recovery_cost=RecoveryCost.IMPOSSIBLE,
                                        recommended_action=RecommendedAction.REVIEW_ONLY,
                                        confidence=Confidence.HIGH,
                                        evidence=[
                                            Evidence(
                                                kind="file_extension",
                                                source=self.detector_id,
                                                value=entry.name,
                                                message="Process memory crash dump file",
                                            )
                                        ],
                                    )
                                )
                        except (OSError, PermissionError):
                            continue
            except (OSError, PermissionError):
                continue

        return artifacts
