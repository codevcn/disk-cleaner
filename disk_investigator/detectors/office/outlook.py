"""
Outlook email archive and cache detector (.pst, .ost).
Strict safety invariants:
- .pst files are permanent user archives -> strictly BLOCKED from deletion.
- .ost files are large offline caches -> REVIEW_ONLY (never auto-cleaned).
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


class OutlookStorageDetector(BaseDetector):
    """Detects Outlook mailboxes (.ost, .pst) with strict data loss prevention."""

    detector_id = "office.outlook"
    domain = ArtifactDomain.OFFICE

    def applicable(self, context: DetectionContext) -> bool:
        cap = context.capabilities.get("office.outlook")
        if cap and cap.detected:
            return True
        if context.target_path and "outlook" in context.target_path.lower():
            return True
        return True

    def detect(self, context: DetectionContext) -> List[StorageArtifact]:
        artifacts: List[StorageArtifact] = []

        if context.target_path and os.path.isdir(context.target_path):
            candidate_dirs = [context.target_path]
        else:
            local_app = context.env.get("LOCALAPPDATA") or os.environ.get("LOCALAPPDATA", "")
            user_profile = context.env.get("USERPROFILE") or os.environ.get("USERPROFILE", "")
            candidate_dirs = [
                os.path.join(local_app, "Microsoft", "Outlook"),
                os.path.join(user_profile, "Documents", "Outlook Files"),
            ]

        seen_files = set()

        for d in candidate_dirs:
            if not os.path.isdir(d):
                continue
            try:
                with os.scandir(d) as it:
                    for entry in it:
                        try:
                            if not entry.is_file():
                                continue
                            canon = canonicalize_path(entry.path)
                            if canon.lower() in seen_files:
                                continue

                            ext = os.path.splitext(entry.name)[1].lower()
                            if ext not in (".pst", ".ost"):
                                continue

                            seen_files.add(canon.lower())
                            stat = entry.stat()

                            if ext == ".pst":
                                # Personal Storage Table: Local, permanent user archive
                                artifacts.append(
                                    StorageArtifact(
                                        artifact_id=generate_artifact_id(canon, "outlook_pst", self.detector_id),
                                        path=entry.path,
                                        canonical_path=canon,
                                        domain=self.domain,
                                        category=ArtifactCategory.EMAIL_ARCHIVE,
                                        artifact_type="outlook_pst",
                                        owner_app="Microsoft Outlook",
                                        capability_id="office.outlook",
                                        source_detector=self.detector_id,
                                        logical_bytes=stat.st_size,
                                        mtime=stat.st_mtime,
                                        regenerability=Regenerability.NONE,
                                        user_data_probability=UserDataProbability.HIGH,
                                        recovery_cost=RecoveryCost.IMPOSSIBLE,
                                        recommended_action=RecommendedAction.BLOCK,  # STRICT BLOCK
                                        confidence=Confidence.HIGH,
                                        evidence=[
                                            Evidence(
                                                kind="email_archive_lock",
                                                source=self.detector_id,
                                                value=entry.name,
                                                message="Outlook Personal Storage (.pst) contains non-regenerable email archives",
                                            )
                                        ],
                                    )
                                )
                            elif ext == ".ost":
                                # Offline Storage Table: Cached mailbox copy from Exchange/O365
                                artifacts.append(
                                    StorageArtifact(
                                        artifact_id=generate_artifact_id(canon, "outlook_ost", self.detector_id),
                                        path=entry.path,
                                        canonical_path=canon,
                                        domain=self.domain,
                                        category=ArtifactCategory.CACHE,
                                        artifact_type="outlook_ost",
                                        owner_app="Microsoft Outlook",
                                        capability_id="office.outlook",
                                        source_detector=self.detector_id,
                                        logical_bytes=stat.st_size,
                                        mtime=stat.st_mtime,
                                        regenerability=Regenerability.FULL,
                                        user_data_probability=UserDataProbability.HIGH,
                                        recovery_cost=RecoveryCost.HIGH,  # Redownload takes gigabytes and hours
                                        recommended_action=RecommendedAction.REVIEW_ONLY,  # NEVER auto-clean
                                        confidence=Confidence.HIGH,
                                        evidence=[
                                            Evidence(
                                                kind="offline_cache_table",
                                                source=self.detector_id,
                                                value=entry.name,
                                                message="Outlook Offline Data File (.ost). Requires manual user review to manage",
                                            )
                                        ],
                                    )
                                )
                        except (OSError, PermissionError):
                            continue
            except (OSError, PermissionError):
                continue

        return artifacts
