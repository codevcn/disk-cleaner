"""
Microsoft Teams cache detector.
"""

from __future__ import annotations

import os
from typing import List

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


class TeamsCacheDetector(BaseDetector):
    """Detects Microsoft Teams classic and new Teams cache folders."""

    detector_id = "office.teams"
    domain = ArtifactDomain.OFFICE

    def applicable(self, context: DetectionContext) -> bool:
        cap = context.capabilities.get("office.teams")
        if cap and cap.detected:
            return True
        if context.target_path and "teams" in context.target_path.lower():
            return True
        return True

    def detect(self, context: DetectionContext) -> List[StorageArtifact]:
        artifacts: List[StorageArtifact] = []
        app_data = context.env.get("APPDATA") or os.environ.get("APPDATA", "")
        local_app = context.env.get("LOCALAPPDATA") or os.environ.get("LOCALAPPDATA", "")

        candidates = [
            os.path.join(app_data, "Microsoft", "Teams", "Cache"),
            os.path.join(app_data, "Microsoft", "Teams", "blob_storage"),
            os.path.join(app_data, "Microsoft", "Teams", "GPUCache"),
            os.path.join(local_app, "Packages", "MSTeams_8wekyb3d8bbwe", "LocalCache", "Microsoft", "MSTeams"),
        ]

        if context.target_path and os.path.isdir(context.target_path):
            if "teams" in context.target_path.lower():
                candidates = [context.target_path]

        for c in candidates:
            if not os.path.isdir(c):
                continue
            canon = canonicalize_path(c)
            sz, _, _ = _fast_dir_size(c)

            artifacts.append(
                StorageArtifact(
                    artifact_id=generate_artifact_id(canon, "teams_cache", self.detector_id),
                    path=c,
                    canonical_path=canon,
                    domain=self.domain,
                    category=ArtifactCategory.CACHE,
                    artifact_type="teams_cache",
                    owner_app="Microsoft Teams",
                    capability_id="office.teams",
                    source_detector=self.detector_id,
                    logical_bytes=sz,
                    mtime=None,
                    regenerability=Regenerability.FULL,
                    user_data_probability=UserDataProbability.LOW,
                    recovery_cost=RecoveryCost.LOW,
                    recommended_action=RecommendedAction.TYPED_CLEANUP,
                    confidence=Confidence.HIGH,
                    evidence=[
                        Evidence(
                            kind="teams_cache_path",
                            source=self.detector_id,
                            value=canon,
                            message="Microsoft Teams ephemeral cache directory",
                        )
                    ],
                )
            )

        return artifacts
