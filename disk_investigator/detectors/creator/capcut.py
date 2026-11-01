"""
CapCut video editor cache vs draft projects detector.
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


class CapCutDetector(BaseDetector):
    """Detects CapCut ephemeral caches while safeguarding active project drafts."""

    detector_id = "creator.capcut"
    domain = ArtifactDomain.CREATOR

    def applicable(self, context: DetectionContext) -> bool:
        cap = context.capabilities.get("creator.capcut")
        if cap and cap.detected:
            return True
        if context.target_path and "capcut" in context.target_path.lower():
            return True
        return True

    def detect(self, context: DetectionContext) -> List[StorageArtifact]:
        artifacts: List[StorageArtifact] = []
        local_app = context.env.get("LOCALAPPDATA") or os.environ.get("LOCALAPPDATA", "")

        capcut_root = os.path.join(local_app, "CapCut", "User Data")
        if context.target_path and os.path.isdir(context.target_path):
            if "capcut" in context.target_path.lower():
                capcut_root = context.target_path

        if not os.path.isdir(capcut_root):
            return artifacts

        # 1. Ephemeral cache dirs
        cache_dirs = [
            os.path.join(capcut_root, "Cache"),
            os.path.join(capcut_root, "temp"),
        ]
        for cd in cache_dirs:
            if os.path.isdir(cd):
                canon = canonicalize_path(cd)
                sz, _, _ = _fast_dir_size(cd)
                artifacts.append(
                    StorageArtifact(
                        artifact_id=generate_artifact_id(canon, "capcut_cache", self.detector_id),
                        path=cd,
                        canonical_path=canon,
                        domain=self.domain,
                        category=ArtifactCategory.CACHE,
                        artifact_type="capcut_cache",
                        owner_app="CapCut",
                        capability_id="creator.capcut",
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
                                kind="capcut_cache_path",
                                source=self.detector_id,
                                value=canon,
                                message="CapCut proxy/draft video render cache",
                            )
                        ],
                    )
                )

        # 2. Draft Projects directory -> STRICT BLOCK
        proj_dir = os.path.join(capcut_root, "Projects")
        if os.path.isdir(proj_dir):
            canon = canonicalize_path(proj_dir)
            sz, _, _ = _fast_dir_size(proj_dir)
            artifacts.append(
                StorageArtifact(
                    artifact_id=generate_artifact_id(canon, "capcut_projects", self.detector_id),
                    path=proj_dir,
                    canonical_path=canon,
                    domain=self.domain,
                    category=ArtifactCategory.USER_DOCUMENT,
                    artifact_type="capcut_projects",
                    owner_app="CapCut",
                    capability_id="creator.capcut",
                    source_detector=self.detector_id,
                    logical_bytes=sz,
                    mtime=None,
                    regenerability=Regenerability.NONE,
                    user_data_probability=UserDataProbability.HIGH,
                    recovery_cost=RecoveryCost.IMPOSSIBLE,
                    recommended_action=RecommendedAction.BLOCK,  # STRICT BLOCK
                    confidence=Confidence.HIGH,
                    evidence=[
                        Evidence(
                            kind="user_project_draft_lock",
                            source=self.detector_id,
                            value=canon,
                            message="CRITICAL: CapCut user draft project directories. Never cleanable.",
                        )
                    ],
                )
            )

        return artifacts
