"""
Artifact Policy Engine: Centralized, fail-closed security and policy guardrails
for StorageArtifact objects across all domains.
"""

from __future__ import annotations

import os
from typing import List, Optional

from ..models import (
    ArtifactCategory,
    ArtifactDomain,
    Confidence,
    Evidence,
    RecommendedAction,
    RecoveryCost,
    Regenerability,
    StorageArtifact,
    UserDataProbability,
)
from ..path_policy import (
    canonicalize_path,
    is_cloud_sync_path,
    is_protected_system_path,
)


class ArtifactPolicyEngine:
    """
    Enforces hierarchical, fail-closed policy validation on StorageArtifact instances.
    Guarantees that no user data, healthcare record, original footage, email archive,
    or critical system file is ever approved for deletion.
    """

    CRITICAL_SYSTEM_DIRS = (
        "\\windows",
        "\\windows\\system32",
        "\\windows\\syswow64",
        "\\program files",
        "\\program files (x86)",
        "\\programdata\\microsoft\\windows",
    )

    BLOCKED_EXTENSIONS = {
        ".pst",        # Outlook personal archive
        ".dcm",        # DICOM medical imaging
        ".dicom",      # DICOM medical imaging
        ".prproj",     # Adobe Premiere project
        ".aep",        # Adobe After Effects project
        ".resolve",    # DaVinci Resolve project
        ".vhdx",       # Virtual Hard Disk (WSL/Docker/Hyper-V)
        ".vmdk",       # VMware disk
        ".vdi",        # VirtualBox disk
        ".iso",        # Disk image
    }

    PROTECTED_BROWSER_NAMES = {
        "history",
        "history-journal",
        "login data",
        "login data-journal",
        "cookies",
        "cookies-journal",
        "web data",
        "web data-journal",
        "bookmarks",
        "preferences",
        "secure preferences",
        "sessions",
        "current session",
        "last session",
        "current tabs",
        "last tabs",
    }

    MEDIA_EXTENSIONS = {
        ".mp4", ".mkv", ".mov", ".avi", ".wmv", ".flv", ".ts",
        ".wav", ".mp3", ".aif", ".flac", ".r3d", ".braw", ".arw", ".cr2",
    }

    KNOWN_CACHE_SUBSTRINGS = (
        "\\cache",
        "\\code cache",
        "\\gpucache",
        "\\dawncache",
        "\\shadercache",
        "\\media cache files",
        "\\media cache",
        "\\cacheclip",
        "\\temp",
        "\\tmp",
        "\\officefilecache",
    )

    @classmethod
    def evaluate(cls, artifact: StorageArtifact) -> StorageArtifact:
        """
        Evaluate and harden an artifact against safety policy rules.
        Modifications strictly escalate conservatism (fail-closed).
        """
        canon = canonicalize_path(artifact.canonical_path or artifact.path).lower()
        base_name = os.path.basename(canon)
        _, ext = os.path.splitext(canon)

        # -------------------------------------------------------------
        # LAYER 1: Hard Path Policy
        # -------------------------------------------------------------
        if is_protected_system_path(canon):
            return cls._escalate_to_block(
                artifact,
                "Matched protected Windows system path (System32/WinSxS/Boot/etc.)",
            )

        for sys_dir in cls.CRITICAL_SYSTEM_DIRS:
            if canon.endswith(sys_dir):
                return cls._escalate_to_block(
                    artifact,
                    f"Direct target is a protected system directory: {sys_dir}",
                )

        if is_cloud_sync_path(canon):
            # Cloud sync paths (OneDrive, Dropbox, etc.) must not be wiped silently
            if artifact.recommended_action == RecommendedAction.TYPED_CLEANUP:
                artifact.recommended_action = RecommendedAction.REVIEW_ONLY
                artifact.evidence.append(
                    Evidence(
                        kind="policy_guardrail",
                        source="ArtifactPolicyEngine",
                        value=canon,
                        message="File is in cloud sync directory (e.g. OneDrive); requires explicit user review",
                    )
                )

        # -------------------------------------------------------------
        # LAYER 2: Semantic Protection Rules
        # -------------------------------------------------------------

        # Rule 2.1: Healthcare / DICOM medical imaging
        if (
            artifact.category == ArtifactCategory.MEDICAL_DATA
            or ext in (".dcm", ".dicom")
            or "medical" in artifact.artifact_type
        ):
            return cls._escalate_to_block(
                artifact,
                "Medical imaging record (DICOM) is strictly non-deletable user healthcare data.",
            )

        # Rule 2.2: Email archives (.pst)
        if ext == ".pst" or artifact.category == ArtifactCategory.EMAIL_ARCHIVE:
            return cls._escalate_to_block(
                artifact,
                "Personal Storage Table (.pst) is a permanent local email archive.",
            )

        # Rule 2.3: Offline mail cache (.ost) -> REVIEW_ONLY
        if ext == ".ost" or artifact.artifact_type == "outlook_ost":
            if artifact.recommended_action != RecommendedAction.BLOCK:
                artifact.recommended_action = RecommendedAction.REVIEW_ONLY
                artifact.user_data_probability = UserDataProbability.HIGH
                artifact.recovery_cost = RecoveryCost.HIGH
                artifact.evidence.append(
                    Evidence(
                        kind="policy_guardrail",
                        source="ArtifactPolicyEngine",
                        value=canon,
                        message="Offline Exchange/Outlook mailbox cache (.ost) requires user review to manage",
                    )
                )

        # Rule 2.4: Browser profile data & passwords
        if base_name in cls.PROTECTED_BROWSER_NAMES or "user_data" in artifact.artifact_type:
            return cls._escalate_to_block(
                artifact,
                f"Protected browser user profile database/settings: {base_name}",
            )

        # Rule 2.5: Virtual disks (VHDX, VMDK, VDI, ISO)
        if ext in (".vhdx", ".vmdk", ".vdi", ".iso") or artifact.category == ArtifactCategory.VIRTUAL_DISK:
            return cls._escalate_to_block(
                artifact,
                f"Virtual hard disk or backing store ({ext or 'VHDX'}) must never be raw deleted",
            )

        # Rule 2.6: Creator projects and source media
        if ext in (".prproj", ".aep", ".aepx", ".resolve", ".dra"):
            return cls._escalate_to_block(
                artifact,
                f"Creative project file ({ext}) contains original user compositions.",
            )

        # Rule 2.7: Media recordings & video files NOT inside a recognized cache path
        if ext in cls.MEDIA_EXTENSIONS:
            is_in_cache = any(c in canon for c in cls.KNOWN_CACHE_SUBSTRINGS)
            if not is_in_cache:
                return cls._escalate_to_block(
                    artifact,
                    f"Original user media recording ({ext}) outside confirmed cache directory.",
                )

        # Rule 2.8: Steam game installs -> REVIEW_ONLY / UNINSTALL_VIA_APP
        if artifact.category == ArtifactCategory.GAME_INSTALL or "steamapps\\common" in canon:
            if artifact.recommended_action != RecommendedAction.BLOCK:
                artifact.recommended_action = RecommendedAction.REVIEW_ONLY
                artifact.user_data_probability = UserDataProbability.HIGH
                artifact.recovery_cost = RecoveryCost.HIGH
                artifact.evidence.append(
                    Evidence(
                        kind="policy_guardrail",
                        source="ArtifactPolicyEngine",
                        value=canon,
                        message="Steam game install must be uninstalled via Steam client, not raw deleted",
                    )
                )

        # Rule 2.9: AI Model weights -> REVIEW_ONLY
        if (
            artifact.category in (ArtifactCategory.MODEL_CACHE, ArtifactCategory.MODEL_ASSET)
            or ext in (".gguf", ".safetensors", ".onnx")
            or "ollama" in canon
            or "huggingface" in canon
        ):
            if artifact.recommended_action == RecommendedAction.TYPED_CLEANUP:
                artifact.recommended_action = RecommendedAction.REVIEW_ONLY
                artifact.recovery_cost = RecoveryCost.HIGH
                artifact.evidence.append(
                    Evidence(
                        kind="policy_guardrail",
                        source="ArtifactPolicyEngine",
                        value=canon,
                        message="AI model weights require user review and should be managed via Ollama/HF CLI",
                    )
                )

        # Rule 2.10: Stale user files (age > 180 days) -> NEVER cleanable
        if artifact.category in (ArtifactCategory.USER_DOCUMENT, ArtifactCategory.USER_MEDIA, ArtifactCategory.UNKNOWN):
            if artifact.recommended_action in (RecommendedAction.TYPED_CLEANUP, RecommendedAction.RECYCLE_KNOWN_CACHE):
                artifact.recommended_action = RecommendedAction.REVIEW_ONLY
                artifact.evidence.append(
                    Evidence(
                        kind="policy_guardrail",
                        source="ArtifactPolicyEngine",
                        value=canon,
                        message="Stale age does not imply permission to delete. Stale user documents require human review.",
                    )
                )

        # Rule 2.11: Unknown artifacts fail-closed to REVIEW_ONLY
        if artifact.category == ArtifactCategory.UNKNOWN or artifact.artifact_type == "unknown":
            if artifact.recommended_action != RecommendedAction.BLOCK:
                artifact.recommended_action = RecommendedAction.REVIEW_ONLY
                artifact.confidence = Confidence.LOW
                artifact.evidence.append(
                    Evidence(
                        kind="policy_guardrail",
                        source="ArtifactPolicyEngine",
                        value=canon,
                        message="Unrecognized artifact type defaults to fail-closed REVIEW_ONLY",
                    )
                )

        return artifact

    @classmethod
    def evaluate_all(cls, artifacts: List[StorageArtifact]) -> List[StorageArtifact]:
        """Evaluate a list of artifacts through the policy engine."""
        return [cls.evaluate(a) for a in artifacts]

    @classmethod
    def _escalate_to_block(cls, artifact: StorageArtifact, reason: str) -> StorageArtifact:
        """Escalate artifact to permanent BLOCK with maximum conservatism."""
        artifact.recommended_action = RecommendedAction.BLOCK
        artifact.user_data_probability = UserDataProbability.HIGH
        artifact.regenerability = Regenerability.NONE
        artifact.recovery_cost = RecoveryCost.IMPOSSIBLE
        artifact.confidence = Confidence.HIGH
        artifact.evidence.append(
            Evidence(
                kind="policy_security_block",
                source="ArtifactPolicyEngine",
                value=artifact.canonical_path,
                message=f"SECURITY LOCK: {reason}",
            )
        )
        return artifact
