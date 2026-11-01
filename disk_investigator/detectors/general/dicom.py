"""
Medical Imaging Data (DICOM) detector.
Enforces strict protection for sensitive healthcare files.
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


class DicomMedicalDetector(BaseDetector):
    """
    Detects DICOM medical imaging files (.dcm, .dicom, or files with DICM magic at offset 128).
    Strict safety invariant: NEVER cleanable. Recommended action is permanently BLOCK.
    """

    detector_id = "general.dicom"
    domain = ArtifactDomain.GENERAL

    def applicable(self, context: DetectionContext) -> bool:
        return bool(context.target_path and os.path.isdir(context.target_path))

    @staticmethod
    def is_dicom_file(file_path: str) -> bool:
        """Check by extension or DICM magic header at byte offset 128."""
        ext = os.path.splitext(file_path)[1].lower()
        if ext in (".dcm", ".dicom"):
            return True
        try:
            if os.path.getsize(file_path) >= 132:
                with open(file_path, "rb") as f:
                    f.seek(128)
                    magic = f.read(4)
                    return magic == b"DICM"
        except (OSError, PermissionError):
            pass
        return False

    def detect(self, context: DetectionContext) -> List[StorageArtifact]:
        artifacts: List[StorageArtifact] = []
        if not context.target_path or not os.path.isdir(context.target_path):
            return artifacts

        try:
            for root, _, files in os.walk(context.target_path):
                for f in files:
                    full_path = os.path.join(root, f)
                    if self.is_dicom_file(full_path):
                        canon = canonicalize_path(full_path)
                        try:
                            sz = os.path.getsize(full_path)
                            mtime = os.path.getmtime(full_path)
                        except (OSError, PermissionError):
                            sz = 0
                            mtime = None

                        artifacts.append(
                            StorageArtifact(
                                artifact_id=generate_artifact_id(canon, "medical_dicom", self.detector_id),
                                path=full_path,
                                canonical_path=canon,
                                domain=self.domain,
                                category=ArtifactCategory.MEDICAL_DATA,
                                artifact_type="medical_dicom",
                                owner_app="medical_imaging",
                                capability_id=None,
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
                                        kind="medical_data_protection",
                                        source=self.detector_id,
                                        value=canon,
                                        message="CRITICAL: Medical/DICOM imaging record. Protected from deletion.",
                                    )
                                ],
                            )
                        )
        except (OSError, PermissionError):
            pass

        return artifacts
