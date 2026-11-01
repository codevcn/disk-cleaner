"""
Adobe Premiere Pro & After Effects detector.
Strictly distinguishes ephemeral media/render caches from original user footage and projects.
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


class AdobeCreatorDetector(BaseDetector):
    """Detects Adobe media/render caches with strict protection for projects and footage."""

    detector_id = "creator.adobe"
    domain = ArtifactDomain.CREATOR

    MEDIA_EXTENSIONS = {".mp4", ".mov", ".mkv", ".avi", ".wav", ".aif", ".mp3", ".r3d", ".braw", ".arw", ".cr2"}
    PROJECT_EXTENSIONS = {".prproj", ".aep", ".aepx", ".psd", ".ai"}

    def applicable(self, context: DetectionContext) -> bool:
        cap_pr = context.capabilities.get("creator.premiere")
        cap_ae = context.capabilities.get("creator.after_effects")
        if (cap_pr and cap_pr.detected) or (cap_ae and cap_ae.detected):
            return True
        if context.target_path and "adobe" in context.target_path.lower():
            return True
        return True

    def detect(self, context: DetectionContext) -> List[StorageArtifact]:
        artifacts: List[StorageArtifact] = []
        cache_dirs: List[str] = []
        app_data = context.env.get("APPDATA") or os.environ.get("APPDATA", "")

        if context.target_path and os.path.isdir(context.target_path):
            base_name = os.path.basename(context.target_path).lower()
            if base_name in ("media cache files", "media cache", "peak files"):
                cache_dirs.append(context.target_path)
            else:
                # Walk/scandir target_path for media cache subdirectories
                try:
                    for root, dirs, _ in os.walk(context.target_path):
                        for d in list(dirs):
                            if d.lower() in ("media cache files", "media cache", "peak files"):
                                cache_dirs.append(os.path.join(root, d))
                                dirs.remove(d)  # Don't descend into cache dir
                except (OSError, PermissionError):
                    pass
        else:
            cache_dirs = [
                os.path.join(app_data, "Adobe", "Common", "Media Cache Files"),
                os.path.join(app_data, "Adobe", "Common", "Media Cache"),
                os.path.join(app_data, "Adobe", "Common", "Peak Files"),
            ]

        # 1. Detect Cache directories
        for c in cache_dirs:
            if not os.path.isdir(c):
                continue
            canon = canonicalize_path(c)
            sz, _, _ = _fast_dir_size(c)
            artifacts.append(
                StorageArtifact(
                    artifact_id=generate_artifact_id(canon, "adobe_media_cache", self.detector_id),
                    path=c,
                    canonical_path=canon,
                    domain=self.domain,
                    category=ArtifactCategory.RENDER_CACHE,
                    artifact_type="adobe_media_cache",
                    owner_app="Adobe Premiere/After Effects",
                    capability_id="creator.premiere",
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
                            kind="adobe_cache_path",
                            source=self.detector_id,
                            value=canon,
                            message="Adobe regenerated media cache and peak files",
                        )
                    ],
                )
            )

        # 2. Inspect target_path for project files and source media -> STRICT BLOCK
        if context.target_path and os.path.isdir(context.target_path):
            try:
                for root, _, files in os.walk(context.target_path):
                    for f in files:
                        ext = os.path.splitext(f)[1].lower()
                        if ext in self.PROJECT_EXTENSIONS or ext in self.MEDIA_EXTENSIONS:
                            full_p = os.path.join(root, f)
                            canon = canonicalize_path(full_p)
                            try:
                                sz = os.path.getsize(full_p)
                                mtime = os.path.getmtime(full_p)
                            except (OSError, PermissionError):
                                sz = 0
                                mtime = None

                            is_proj = ext in self.PROJECT_EXTENSIONS
                            artifacts.append(
                                StorageArtifact(
                                    artifact_id=generate_artifact_id(
                                        canon,
                                        "adobe_project" if is_proj else "original_footage",
                                        self.detector_id,
                                    ),
                                    path=full_p,
                                    canonical_path=canon,
                                    domain=self.domain,
                                    category=ArtifactCategory.USER_DOCUMENT if is_proj else ArtifactCategory.USER_MEDIA,
                                    artifact_type="adobe_project" if is_proj else "original_footage",
                                    owner_app="Adobe",
                                    capability_id="creator.premiere",
                                    source_detector=self.detector_id,
                                    logical_bytes=sz,
                                    mtime=mtime,
                                    regenerability=Regenerability.NONE,
                                    user_data_probability=UserDataProbability.HIGH,
                                    recovery_cost=RecoveryCost.IMPOSSIBLE,
                                    recommended_action=RecommendedAction.BLOCK,  # STRICT INVARIANT
                                    confidence=Confidence.HIGH,
                                    evidence=[
                                        Evidence(
                                            kind="creator_source_lock",
                                            source=self.detector_id,
                                            value=canon,
                                            message="CRITICAL: Original video footage or project file. Deletion causes irreversible loss.",
                                        )
                                    ],
                                )
                            )
            except (OSError, PermissionError):
                pass

        return artifacts
