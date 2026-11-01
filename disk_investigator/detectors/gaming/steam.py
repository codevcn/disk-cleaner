"""
Valve Steam storage detector (shader cache vs game installs).
Strictly separates cleanable shader cache from games requiring review/uninstall via Steam.
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


class SteamGamingDetector(BaseDetector):
    """Detects Steam shader cache and game installs."""

    detector_id = "gaming.steam"
    domain = ArtifactDomain.GAMING

    def applicable(self, context: DetectionContext) -> bool:
        cap = context.capabilities.get("gaming.steam")
        if cap and cap.detected:
            return True
        if context.target_path and "steam" in context.target_path.lower():
            return True
        return True

    def detect(self, context: DetectionContext) -> List[StorageArtifact]:
        artifacts: List[StorageArtifact] = []

        steam_roots: List[str] = []
        cap = context.capabilities.get("gaming.steam")
        if cap and cap.install_paths:
            steam_roots.extend(cap.install_paths)

        prog_files = os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)")
        default_root = os.path.join(prog_files, "Steam")
        if default_root not in steam_roots:
            steam_roots.append(default_root)

        if context.target_path and os.path.isdir(context.target_path):
            if "steam" in context.target_path.lower():
                steam_roots = [context.target_path]

        for sroot in steam_roots:
            steamapps = os.path.join(sroot, "steamapps")
            if not os.path.isdir(steamapps):
                # Check if sroot itself is steamapps
                if os.path.basename(sroot).lower() == "steamapps":
                    steamapps = sroot
                else:
                    continue

            # 1. Shader Cache -> TYPED_CLEANUP
            shader_dir = os.path.join(steamapps, "shadercache")
            if os.path.isdir(shader_dir):
                canon = canonicalize_path(shader_dir)
                sz, _, _ = _fast_dir_size(shader_dir)
                artifacts.append(
                    StorageArtifact(
                        artifact_id=generate_artifact_id(canon, "steam_shader_cache", self.detector_id),
                        path=shader_dir,
                        canonical_path=canon,
                        domain=self.domain,
                        category=ArtifactCategory.GAME_CACHE,
                        artifact_type="steam_shader_cache",
                        owner_app="Valve Steam",
                        capability_id="gaming.steam",
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
                                kind="steam_shader_cache",
                                source=self.detector_id,
                                value=canon,
                                message="Steam precompiled Vulkan/DX shader cache",
                            )
                        ],
                    )
                )

            # 2. Download temporary folder -> TYPED_CLEANUP
            dl_dir = os.path.join(steamapps, "downloading")
            if os.path.isdir(dl_dir):
                canon = canonicalize_path(dl_dir)
                sz, _, _ = _fast_dir_size(dl_dir)
                artifacts.append(
                    StorageArtifact(
                        artifact_id=generate_artifact_id(canon, "steam_downloading", self.detector_id),
                        path=dl_dir,
                        canonical_path=canon,
                        domain=self.domain,
                        category=ArtifactCategory.CACHE,
                        artifact_type="steam_downloading",
                        owner_app="Valve Steam",
                        capability_id="gaming.steam",
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
                                kind="steam_download_cache",
                                source=self.detector_id,
                                value=canon,
                                message="Steam unfinished download cache",
                            )
                        ],
                    )
                )

            # 3. Game Installs in common/ -> REVIEW_ONLY / UNINSTALL_VIA_APP
            common_dir = os.path.join(steamapps, "common")
            if os.path.isdir(common_dir):
                try:
                    with os.scandir(common_dir) as it:
                        for entry in it:
                            if entry.is_dir(follow_symlinks=False):
                                canon = canonicalize_path(entry.path)
                                sz, _, _ = _fast_dir_size(entry.path)
                                artifacts.append(
                                    StorageArtifact(
                                        artifact_id=generate_artifact_id(canon, "steam_game_install", self.detector_id),
                                        path=entry.path,
                                        canonical_path=canon,
                                        domain=self.domain,
                                        category=ArtifactCategory.GAME_INSTALL,
                                        artifact_type="steam_game_install",
                                        owner_app="Valve Steam",
                                        capability_id="gaming.steam",
                                        source_detector=self.detector_id,
                                        logical_bytes=sz,
                                        mtime=None,
                                        regenerability=Regenerability.FULL,
                                        user_data_probability=UserDataProbability.HIGH,  # saves/mods/configs
                                        recovery_cost=RecoveryCost.HIGH,
                                        recommended_action=RecommendedAction.REVIEW_ONLY,  # INVARIANT: never direct delete
                                        confidence=Confidence.HIGH,
                                        evidence=[
                                            Evidence(
                                                kind="steam_installed_game",
                                                source=self.detector_id,
                                                value=canon,
                                                message=f"Steam installed game '{entry.name}'. Uninstall via Steam client.",
                                            )
                                        ],
                                    )
                                )
                except (OSError, PermissionError):
                    pass

        return artifacts
