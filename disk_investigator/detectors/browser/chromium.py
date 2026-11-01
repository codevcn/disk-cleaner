"""
Chromium-based browser detector (Google Chrome, Microsoft Edge).
Discovers browser caches while strictly protecting browser history, cookies, and login credentials.
"""

from __future__ import annotations

import os
from typing import List, Tuple

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


class ChromiumBrowserDetector(BaseDetector):
    """
    Detects Chromium browser storage.
    Strictly distinguishes ephemeral caches from non-regenerable user databases.
    """

    detector_id = "browser.chromium"
    domain = ArtifactDomain.BROWSER

    CACHE_SUBDIRS = (
        "Cache",
        "Code Cache",
        "GPUCache",
        "DawnCache",
        "ShaderCache",
        "Service Worker\\CacheStorage",
        "Service Worker\\ScriptCache",
    )

    BLOCKED_ITEMS = (
        "History",
        "History-journal",
        "Login Data",
        "Login Data-journal",
        "Cookies",
        "Cookies-journal",
        "Web Data",
        "Web Data-journal",
        "Bookmarks",
        "Preferences",
        "Secure Preferences",
        "Sessions",
        "Current Session",
        "Current Tabs",
        "Last Session",
        "Last Tabs",
        "Extensions",
    )

    def applicable(self, context: DetectionContext) -> bool:
        # Applicable if chrome or edge capability detected, or target_path points to browser data
        chrome_cap = context.capabilities.get("browser.chrome")
        edge_cap = context.capabilities.get("browser.edge")
        if (chrome_cap and chrome_cap.detected) or (edge_cap and edge_cap.detected):
            return True
        if context.target_path and (
            "google\\chrome" in context.target_path.lower()
            or "microsoft\\edge" in context.target_path.lower()
        ):
            return True
        return True

    def detect(self, context: DetectionContext) -> List[StorageArtifact]:
        artifacts: List[StorageArtifact] = []
        if context.target_path and os.path.isdir(context.target_path):
            t_low = context.target_path.lower()
            if "edge" in t_low:
                roots = [("Microsoft Edge", "browser.edge", context.target_path)]
            else:
                roots = [("Google Chrome", "browser.chrome", context.target_path)]
        else:
            local_app = context.env.get("LOCALAPPDATA") or os.environ.get("LOCALAPPDATA", "")
            roots = [
                ("Google Chrome", "browser.chrome", os.path.join(local_app, "Google", "Chrome", "User Data")),
                ("Microsoft Edge", "browser.edge", os.path.join(local_app, "Microsoft", "Edge", "User Data")),
            ]

        for app_name, cap_id, root in roots:
            if not os.path.isdir(root):
                continue

            # Check profile dirs (Default, Profile 1, Profile 2, System Profile, etc.)
            profile_dirs: List[str] = []
            try:
                with os.scandir(root) as it:
                    for entry in it:
                        if entry.is_dir(follow_symlinks=False):
                            if entry.name == "Default" or entry.name.startswith("Profile "):
                                profile_dirs.append(entry.path)
            except (OSError, PermissionError):
                continue

            # If root itself is a profile dir
            if not profile_dirs and (os.path.basename(root) == "Default" or os.path.basename(root).startswith("Profile ")):
                profile_dirs.append(root)

            for pdir in profile_dirs:
                # 1. Detect Cache directories -> TYPED_CLEANUP
                for cache_sub in self.CACHE_SUBDIRS:
                    cpath = os.path.join(pdir, cache_sub)
                    if os.path.isdir(cpath):
                        canon = canonicalize_path(cpath)
                        sz, _, _ = _fast_dir_size(cpath)
                        artifacts.append(
                            StorageArtifact(
                                artifact_id=generate_artifact_id(canon, "browser_cache", self.detector_id),
                                path=cpath,
                                canonical_path=canon,
                                domain=self.domain,
                                category=ArtifactCategory.CACHE,
                                artifact_type="browser_cache",
                                owner_app=app_name,
                                capability_id=cap_id,
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
                                        kind="browser_cache_path",
                                        source=self.detector_id,
                                        value=canon,
                                        message=f"{app_name} web/code/gpu cache",
                                    )
                                ],
                            )
                        )

                # 2. Detect Blocked user data items -> BLOCK
                for blocked_name in self.BLOCKED_ITEMS:
                    bpath = os.path.join(pdir, blocked_name)
                    if os.path.exists(bpath):
                        canon = canonicalize_path(bpath)
                        if os.path.isdir(bpath):
                            sz, _, _ = _fast_dir_size(bpath)
                        else:
                            try:
                                sz = os.path.getsize(bpath)
                            except (OSError, PermissionError):
                                sz = 0

                        artifacts.append(
                            StorageArtifact(
                                artifact_id=generate_artifact_id(canon, "browser_user_data", self.detector_id),
                                path=bpath,
                                canonical_path=canon,
                                domain=self.domain,
                                category=ArtifactCategory.USER_DOCUMENT,
                                artifact_type="browser_user_data",
                                owner_app=app_name,
                                capability_id=cap_id,
                                source_detector=self.detector_id,
                                logical_bytes=sz,
                                mtime=None,
                                regenerability=Regenerability.NONE,
                                user_data_probability=UserDataProbability.HIGH,
                                recovery_cost=RecoveryCost.IMPOSSIBLE,
                                recommended_action=RecommendedAction.BLOCK,  # STRICT INVARIANT
                                confidence=Confidence.HIGH,
                                evidence=[
                                    Evidence(
                                        kind="protected_user_credential_history",
                                        source=self.detector_id,
                                        value=canon,
                                        message=f"CRITICAL: {app_name} user history/passwords/profile data must never be deleted",
                                    )
                                ],
                            )
                        )

        return artifacts
