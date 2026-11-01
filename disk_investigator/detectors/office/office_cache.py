"""
Microsoft Office File Cache detector.
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


class OfficeCacheDetector(BaseDetector):
    """Detects Microsoft Office File Cache directories."""

    detector_id = "office.cache"
    domain = ArtifactDomain.OFFICE

    def applicable(self, context: DetectionContext) -> bool:
        return True

    def detect(self, context: DetectionContext) -> List[StorageArtifact]:
        artifacts: List[StorageArtifact] = []
        local_app = context.env.get("LOCALAPPDATA") or os.environ.get("LOCALAPPDATA", "")

        candidates = [
            os.path.join(local_app, "Microsoft", "Office", "16.0", "OfficeFileCache"),
            os.path.join(local_app, "Microsoft", "Office", "15.0", "OfficeFileCache"),
        ]

        if context.target_path and os.path.isdir(context.target_path):
            if "officefilecache" in context.target_path.lower():
                candidates = [context.target_path]

        for c in candidates:
            if not os.path.isdir(c):
                continue
            canon = canonicalize_path(c)
            sz, _, _ = _fast_dir_size(c)

            artifacts.append(
                StorageArtifact(
                    artifact_id=generate_artifact_id(canon, "office_file_cache", self.detector_id),
                    path=c,
                    canonical_path=canon,
                    domain=self.domain,
                    category=ArtifactCategory.CACHE,
                    artifact_type="office_file_cache",
                    owner_app="Microsoft Office",
                    capability_id=None,
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
                            kind="office_cache_path",
                            source=self.detector_id,
                            value=canon,
                            message="Microsoft Office Document Cache",
                        )
                    ],
                )
            )

        return artifacts
