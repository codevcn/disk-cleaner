"""
OBS Studio streaming detector (logs/crashes vs user stream recordings).
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


class OBSStudioDetector(BaseDetector):
    """
    Detects OBS Studio logs and crashes.
    Strictly prevents deletion of OBS video recordings (.mkv, .mp4, .flv).
    """

    detector_id = "streaming.obs_studio"
    domain = ArtifactDomain.STREAMING

    RECORDING_EXTENSIONS = {".mkv", ".mp4", ".flv", ".mov", ".ts"}

    def applicable(self, context: DetectionContext) -> bool:
        cap = context.capabilities.get("streaming.obs_studio")
        if cap and cap.detected:
            return True
        if context.target_path and "obs-studio" in context.target_path.lower():
            return True
        return True

    def detect(self, context: DetectionContext) -> List[StorageArtifact]:
        artifacts: List[StorageArtifact] = []
        app_data = context.env.get("APPDATA") or os.environ.get("APPDATA", "")

        obs_root = os.path.join(app_data, "obs-studio")
        if context.target_path and os.path.isdir(context.target_path):
            if "obs" in context.target_path.lower():
                obs_root = context.target_path

        # 1. Ephemeral log and crash directories
        for sub, cat, art_type in [
            ("logs", ArtifactCategory.LOG, "obs_log_dir"),
            ("crashes", ArtifactCategory.CRASH_DUMP, "obs_crash_dir"),
        ]:
            dir_path = os.path.join(obs_root, sub)
            if os.path.isdir(dir_path):
                canon = canonicalize_path(dir_path)
                sz, _, _ = _fast_dir_size(dir_path)
                artifacts.append(
                    StorageArtifact(
                        artifact_id=generate_artifact_id(canon, art_type, self.detector_id),
                        path=dir_path,
                        canonical_path=canon,
                        domain=self.domain,
                        category=cat,
                        artifact_type=art_type,
                        owner_app="OBS Studio",
                        capability_id="streaming.obs_studio",
                        source_detector=self.detector_id,
                        logical_bytes=sz,
                        mtime=None,
                        regenerability=Regenerability.NONE,
                        user_data_probability=UserDataProbability.LOW,
                        recovery_cost=RecoveryCost.LOW,
                        recommended_action=RecommendedAction.RECYCLE_KNOWN_CACHE,
                        confidence=Confidence.HIGH,
                        evidence=[
                            Evidence(
                                kind="obs_ephemeral_dir",
                                source=self.detector_id,
                                value=canon,
                                message=f"OBS Studio ephemeral {sub} folder",
                            )
                        ],
                    )
                )

        # 2. If target path contains media recordings -> STRICT BLOCK
        if context.target_path and os.path.isdir(context.target_path):
            try:
                for root, _, files in os.walk(context.target_path):
                    for f in files:
                        ext = os.path.splitext(f)[1].lower()
                        if ext in self.RECORDING_EXTENSIONS:
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
                                    artifact_id=generate_artifact_id(canon, "obs_recording", self.detector_id),
                                    path=full_p,
                                    canonical_path=canon,
                                    domain=self.domain,
                                    category=ArtifactCategory.USER_MEDIA,
                                    artifact_type="obs_recording",
                                    owner_app="OBS Studio",
                                    capability_id="streaming.obs_studio",
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
                                            kind="recording_protection",
                                            source=self.detector_id,
                                            value=canon,
                                            message="CRITICAL: Stream recording file. Deletion causes irreversible data loss.",
                                        )
                                    ],
                                )
                            )
            except (OSError, PermissionError):
                pass

        return artifacts
