"""
Ollama local AI model weights detector.
Strict safety invariant: Large model weights (>2GB+) can be re-pulled, but require user review
and should ideally be managed via `ollama rm <model>`.
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


class OllamaModelDetector(BaseDetector):
    """Detects Ollama model blob storage."""

    detector_id = "ai_ml.ollama"
    domain = ArtifactDomain.AI_ML

    def applicable(self, context: DetectionContext) -> bool:
        cap = context.capabilities.get("ai_ml.ollama")
        if cap and cap.detected:
            return True
        if context.target_path and "ollama" in context.target_path.lower():
            return True
        return True

    def detect(self, context: DetectionContext) -> List[StorageArtifact]:
        artifacts: List[StorageArtifact] = []

        # Check OLLAMA_MODELS env var or default %USERPROFILE%\.ollama\models
        user_prof = context.env.get("USERPROFILE") or os.environ.get("USERPROFILE", "")
        ollama_models = context.env.get("OLLAMA_MODELS") or os.environ.get("OLLAMA_MODELS")
        if not ollama_models:
            ollama_models = os.path.join(user_prof, ".ollama", "models")

        candidate_dirs = [ollama_models]
        if context.target_path and os.path.isdir(context.target_path):
            if "ollama" in context.target_path.lower() or "models" in context.target_path.lower():
                candidate_dirs = [context.target_path]

        for d in candidate_dirs:
            if not os.path.isdir(d):
                continue
            blobs_dir = os.path.join(d, "blobs")
            target_inspect = blobs_dir if os.path.isdir(blobs_dir) else d
            canon = canonicalize_path(target_inspect)
            sz, _, _ = _fast_dir_size(target_inspect)

            if sz > 0:
                artifacts.append(
                    StorageArtifact(
                        artifact_id=generate_artifact_id(canon, "ollama_model_blobs", self.detector_id),
                        path=target_inspect,
                        canonical_path=canon,
                        domain=self.domain,
                        category=ArtifactCategory.MODEL_CACHE,
                        artifact_type="ollama_model_blobs",
                        owner_app="Ollama",
                        capability_id="ai_ml.ollama",
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
                                message="Ollama GGUF model weights cache. Can be reclaimed via 'ollama rm'.",
                            )
                        ],
                    )
                )

        return artifacts
