"""
Blackmagic DaVinci Resolve storage detector (CacheClip render cache vs source footage).
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


class DaVinciResolveDetector(BaseDetector):
    """Detects DaVinci Resolve CacheClip render cache while protecting footage and project databases."""

    detector_id = "creator.davinci"
    domain = ArtifactDomain.CREATOR

    def applicable(self, context: DetectionContext) -> bool:
        cap = context.capabilities.get("creator.davinci")
        if cap and cap.detected:
            return True
        if context.target_path and ("davinci" in context.target_path.lower() or "cacheclip" in context.target_path.lower()):
            return True
        return True

    def detect(self, context: DetectionContext) -> List[StorageArtifact]:
        artifacts: List[StorageArtifact] = []
        if not context.target_path or not os.path.isdir(context.target_path):
            return artifacts

        try:
            for root, dirs, files in os.walk(context.target_path):
                # Check for CacheClip directory
                if os.path.basename(root).lower() == "cacheclip":
                    canon = canonicalize_path(root)
                    sz, _, _ = _fast_dir_size(root)
                    artifacts.append(
                        StorageArtifact(
                            artifact_id=generate_artifact_id(canon, "davinci_render_cache", self.detector_id),
                            path=root,
                            canonical_path=canon,
                            domain=self.domain,
                            category=ArtifactCategory.RENDER_CACHE,
                            artifact_type="davinci_render_cache",
                            owner_app="DaVinci Resolve",
                            capability_id="creator.davinci",
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
                                    kind="davinci_cache_clip",
                                    source=self.detector_id,
                                    value=canon,
                                    message="DaVinci Resolve CacheClip optimized/proxy render cache",
                                )
                            ],
                        )
                    )

                # Check for project database or project backup files (.resolve, .dra)
                for f in files:
                    ext = os.path.splitext(f)[1].lower()
                    if ext in (".resolve", ".dra", ".db"):
                        full_p = os.path.join(root, f)
                        canon = canonicalize_path(full_p)
                        try:
                            sz = os.path.getsize(full_p)
                            mtime = os.path.getmtime(full_p)
                        except (OSError, PermissionError):
                            sz = 0
                            mtime = None

                        artifacts.append(
                            StorageArtifact(
                                artifact_id=generate_artifact_id(canon, "davinci_project_db", self.detector_id),
                                path=full_p,
                                canonical_path=canon,
                                domain=self.domain,
                                category=ArtifactCategory.DATABASE,
                                artifact_type="davinci_project_db",
                                owner_app="DaVinci Resolve",
                                capability_id="creator.davinci",
                                source_detector=self.detector_id,
                                logical_bytes=sz,
                                mtime=mtime,
                                regenerability=Regenerability.NONE,
                                user_data_probability=UserDataProbability.HIGH,
                                recovery_cost=RecoveryCost.IMPOSSIBLE,
                                recommended_action=RecommendedAction.BLOCK,  # STRICT BLOCK
                                confidence=Confidence.HIGH,
                                evidence=[
                                    Evidence(
                                        kind="project_database_lock",
                                        source=self.detector_id,
                                        value=canon,
                                        message="CRITICAL: DaVinci Resolve project database/archive. Never cleanable.",
                                    )
                                ],
                            )
                        )
        except (OSError, PermissionError):
            pass

        return artifacts
