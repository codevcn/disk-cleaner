"""
HuggingFace Hub cache detector.
Discovers downloaded model checkpoints and weights.
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


class HuggingFaceCacheDetector(BaseDetector):
    """Detects Hugging Face hub cached models and datasets."""

    detector_id = "ai_ml.huggingface"
    domain = ArtifactDomain.AI_ML

    def applicable(self, context: DetectionContext) -> bool:
        cap = context.capabilities.get("ai_ml.huggingface")
        if cap and cap.detected:
            return True
        if context.target_path and "huggingface" in context.target_path.lower():
            return True
        return True

    def detect(self, context: DetectionContext) -> List[StorageArtifact]:
        artifacts: List[StorageArtifact] = []

        # Check HF_HOME or default %USERPROFILE%\.cache\huggingface
        user_prof = context.env.get("USERPROFILE") or os.environ.get("USERPROFILE", "")
        hf_home = context.env.get("HF_HOME") or os.environ.get("HF_HOME")
        if not hf_home:
            hf_home = os.path.join(user_prof, ".cache", "huggingface")

        candidate_dirs = [os.path.join(hf_home, "hub")]
        if context.target_path and os.path.isdir(context.target_path):
            if "huggingface" in context.target_path.lower():
                candidate_dirs = [context.target_path]

        for d in candidate_dirs:
            if not os.path.isdir(d):
                continue
            canon = canonicalize_path(d)
            sz, _, _ = _fast_dir_size(d)

            if sz > 0:
                artifacts.append(
                    StorageArtifact(
                        artifact_id=generate_artifact_id(canon, "hf_hub_cache", self.detector_id),
                        path=d,
                        canonical_path=canon,
                        domain=self.domain,
                        category=ArtifactCategory.MODEL_CACHE,
                        artifact_type="hf_hub_cache",
                        owner_app="HuggingFace Hub",
                        capability_id="ai_ml.huggingface",
                        source_detector=self.detector_id,
                        logical_bytes=sz,
                        mtime=None,
                        regenerability=Regenerability.FULL,
                        user_data_probability=UserDataProbability.LOW,
                        recovery_cost=RecoveryCost.HIGH,
                        recommended_action=RecommendedAction.REVIEW_ONLY,  # INVARIANT: review required
                        confidence=Confidence.HIGH,
                        evidence=[
                            Evidence(
                                kind="ai_model_storage",
                                source=self.detector_id,
                                value=canon,
                                message="HuggingFace model hub cache. Can be reclaimed via 'huggingface-cli delete-cache'.",
                            )
                        ],
                    )
                )

        return artifacts
