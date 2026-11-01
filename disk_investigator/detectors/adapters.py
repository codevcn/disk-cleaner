"""
Adapters bridging existing legacy detectors (DeveloperDetector, DockerDetector, LargeFilesDetector)
to the common Detector protocol and StorageArtifact model.
"""

from __future__ import annotations

import os
from typing import List

from ..models import (
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
from ..path_policy import canonicalize_path
from .base import BaseDetector
from .developer_detector import DeveloperDetector
from .docker_detector import DockerDetector
from .large_files_detector import LargeFilesDetector


class DeveloperStorageDetector(BaseDetector):
    """Detector adapter for developer artifacts (node_modules, venvs, build caches)."""

    detector_id = "developer.general"
    domain = ArtifactDomain.DEVELOPER

    def __init__(self) -> None:
        self.detector = DeveloperDetector()

    def applicable(self, context: DetectionContext) -> bool:
        # Applicable if scanning any target path or if developer capabilities are present
        dev_caps = ("developer.node", "developer.python", "developer.vscode", "developer.docker")
        if any(context.capabilities.get(c) and context.capabilities[c].detected for c in dev_caps):
            return True
        # If target path is explicitly specified and exists
        return bool(context.target_path and os.path.exists(context.target_path))

    def detect(self, context: DetectionContext) -> List[StorageArtifact]:
        artifacts: List[StorageArtifact] = []
        raw_artifacts = []

        if context.target_path and os.path.exists(context.target_path):
            raw_artifacts.extend(self.detector.scan_project_tree(context.target_path))
        else:
            raw_artifacts.extend(self.detector.detect_known_global_caches())

        for raw in raw_artifacts:
            canon = canonicalize_path(raw.path)

            if raw.artifact_type in ("package_cache", "pycache"):
                cat = ArtifactCategory.CACHE
                action = RecommendedAction.RECYCLE_KNOWN_CACHE
                udp = UserDataProbability.LOW
                rec_cost = RecoveryCost.LOW
            elif raw.artifact_type == "build_artifact":
                cat = ArtifactCategory.BUILD_ARTIFACT
                action = RecommendedAction.TYPED_CLEANUP
                udp = UserDataProbability.LOW
                rec_cost = RecoveryCost.MEDIUM
            else:
                cat = ArtifactCategory.DEPENDENCY
                action = RecommendedAction.TYPED_CLEANUP
                udp = UserDataProbability.LOW
                rec_cost = RecoveryCost.MEDIUM

            if raw.regenerable == "YES":
                regen = Regenerability.FULL
            elif raw.regenerable == "NO":
                regen = Regenerability.NONE
            else:
                regen = Regenerability.PARTIAL

            ev_list = [
                Evidence(
                    kind="path_heuristic",
                    source="DeveloperDetector",
                    value=e,
                    message=e,
                )
                for e in raw.evidence
            ]

            artifacts.append(
                StorageArtifact(
                    artifact_id=generate_artifact_id(canon, raw.artifact_type, self.detector_id),
                    path=raw.path,
                    canonical_path=canon,
                    domain=self.domain,
                    category=cat,
                    artifact_type=raw.artifact_type,
                    owner_app=raw.owner_app,
                    capability_id=None,
                    source_detector=self.detector_id,
                    logical_bytes=raw.logical_bytes,
                    mtime=raw.mtime,
                    regenerability=regen,
                    user_data_probability=udp,
                    recovery_cost=rec_cost,
                    recommended_action=action,
                    confidence=Confidence.HIGH,
                    evidence=ev_list,
                )
            )

        return artifacts


class DockerStorageDetector(BaseDetector):
    """Detector adapter for Docker desktop and WSL2 backing disks."""

    detector_id = "developer.docker"
    domain = ArtifactDomain.DEVELOPER

    def __init__(self) -> None:
        self.detector = DockerDetector()

    def applicable(self, context: DetectionContext) -> bool:
        cap = context.capabilities.get("developer.docker")
        if cap and cap.detected:
            return True
        local_app = context.env.get("LOCALAPPDATA") or os.environ.get("LOCALAPPDATA", "")
        docker_dir = os.path.join(local_app, "Docker")
        return os.path.isdir(docker_dir)

    def detect(self, context: DetectionContext) -> List[StorageArtifact]:
        artifacts: List[StorageArtifact] = []
        vhdx_files = self.detector.find_vhdx_storage()

        for vhdx in vhdx_files:
            canon = canonicalize_path(vhdx["path"])
            artifacts.append(
                StorageArtifact(
                    artifact_id=generate_artifact_id(canon, "docker_vhdx", self.detector_id),
                    path=vhdx["path"],
                    canonical_path=canon,
                    domain=self.domain,
                    category=ArtifactCategory.VIRTUAL_DISK,
                    artifact_type="docker_vhdx",
                    owner_app="docker",
                    capability_id="developer.docker",
                    source_detector=self.detector_id,
                    logical_bytes=vhdx.get("logical_bytes", 0),
                    mtime=None,
                    regenerability=Regenerability.NONE,
                    user_data_probability=UserDataProbability.HIGH,
                    recovery_cost=RecoveryCost.IMPOSSIBLE,
                    recommended_action=RecommendedAction.BLOCK,  # INVARIANT: never raw delete ext4.vhdx
                    confidence=Confidence.HIGH,
                    evidence=[
                        Evidence(
                            kind="safety_lock",
                            source="DockerDetector",
                            value="ext4.vhdx",
                            message=vhdx.get("warning", "Raw deletion corrupts Docker Desktop registration"),
                        )
                    ],
                )
            )

        return artifacts


class LargeFilesStorageDetector(BaseDetector):
    """Detector adapter for large standalone files."""

    detector_id = "general.large_files"
    domain = ArtifactDomain.GENERAL

    def __init__(self, min_size_bytes: int = 100 * 1024 * 1024) -> None:
        self.min_size_bytes = min_size_bytes
        self.detector = LargeFilesDetector()

    def applicable(self, context: DetectionContext) -> bool:
        return bool(context.target_path and os.path.exists(context.target_path))

    def detect(self, context: DetectionContext) -> List[StorageArtifact]:
        artifacts: List[StorageArtifact] = []
        if not context.target_path or not os.path.exists(context.target_path):
            return artifacts

        large_files = self.detector.find_large_files(
            root_path=context.target_path,
            min_size_bytes=self.min_size_bytes,
        )

        for lf in large_files:
            canon = canonicalize_path(lf.path)
            # Large files are general user files or disk images -> default REVIEW_ONLY
            cat = ArtifactCategory.UNKNOWN
            if lf.category == "disk_image":
                cat = ArtifactCategory.VIRTUAL_DISK
            elif lf.category == "video":
                cat = ArtifactCategory.USER_MEDIA
            elif lf.category == "archive":
                cat = ArtifactCategory.USER_DOCUMENT
            elif lf.category == "ai_model":
                cat = ArtifactCategory.MODEL_ASSET

            artifacts.append(
                StorageArtifact(
                    artifact_id=generate_artifact_id(canon, f"large_file_{lf.category}", self.detector_id),
                    path=lf.path,
                    canonical_path=canon,
                    domain=self.domain,
                    category=cat,
                    artifact_type=f"large_file_{lf.category}",
                    owner_app=None,
                    capability_id=None,
                    source_detector=self.detector_id,
                    logical_bytes=lf.size_bytes,
                    mtime=lf.mtime,
                    regenerability=Regenerability.NONE,
                    user_data_probability=UserDataProbability.HIGH,
                    recovery_cost=RecoveryCost.IMPOSSIBLE,
                    recommended_action=RecommendedAction.REVIEW_ONLY,  # INVARIANT: never mark large files cleanable by default
                    confidence=Confidence.MEDIUM,
                    evidence=[
                        Evidence(
                            kind="size_threshold",
                            source="LargeFilesDetector",
                            value=f"{lf.size_bytes} bytes",
                            message=f"Category: {lf.category}, age: {lf.age_days} days",
                        )
                    ],
                )
            )

        return artifacts
