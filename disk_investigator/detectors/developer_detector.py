"""
Developer artifact & cache detector for Windows 11.
Scans for node_modules, virtual environments, build artifacts, and package caches.
Adheres strictly to safety policies (stale != safe to delete).
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..backends.native_windows import _fast_dir_size
from ..path_policy import canonicalize_path, is_cloud_sync_path, is_protected_system_path


@dataclass
class DeveloperArtifact:
    path: str
    artifact_type: str  # "node_modules", "python_venv", "build_artifact", "package_cache", "pycache"
    owner_app: str  # "npm", "pnpm", "yarn", "python", "cargo", "nextjs", "gradle", etc.
    logical_bytes: int
    mtime: Optional[float]
    age_days: Optional[float]
    stale_candidate: bool
    stale_reason: Optional[str]
    regenerable: str  # "YES", "NO", "UNKNOWN"
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "artifact_type": self.artifact_type,
            "owner_app": self.owner_app,
            "logical_bytes": self.logical_bytes,
            "mtime": self.mtime,
            "age_days": round(self.age_days, 1) if self.age_days is not None else None,
            "stale_candidate": self.stale_candidate,
            "stale_reason": self.stale_reason,
            "regenerable": self.regenerable,
            "evidence": self.evidence,
        }


class DeveloperDetector:
    """Discovers developer storage consumers across projects and global user caches."""

    def __init__(self, now_timestamp: Optional[float] = None):
        self.now = now_timestamp or time.time()

    def detect_known_global_caches(self) -> List[DeveloperArtifact]:
        """Inspects standard global package and developer caches in the user profile."""
        artifacts: List[DeveloperArtifact] = []
        user_profile = os.environ.get("USERPROFILE")
        local_app_data = os.environ.get("LOCALAPPDATA")

        cache_definitions = [
            (
                os.path.join(local_app_data, "npm-cache") if local_app_data else None,
                "package_cache",
                "npm",
                "YES",
                ["Standard Windows npm cache location"],
            ),
            (
                os.path.join(local_app_data, "pip", "cache") if local_app_data else None,
                "package_cache",
                "pip",
                "YES",
                ["Standard Windows pip download cache location"],
            ),
            (
                os.path.join(local_app_data, "pnpm", "store") if local_app_data else None,
                "package_cache",
                "pnpm",
                "YES",
                ["Standard pnpm content-addressable store"],
            ),
            (
                os.path.join(local_app_data, "Yarn", "Cache") if local_app_data else None,
                "package_cache",
                "yarn",
                "YES",
                ["Standard Yarn v1 global cache"],
            ),
            (
                os.path.join(user_profile, ".gradle", "caches") if user_profile else None,
                "package_cache",
                "gradle",
                "YES",
                ["Gradle build tool dependency cache"],
            ),
            (
                os.path.join(user_profile, ".cargo", "registry", "cache") if user_profile else None,
                "package_cache",
                "cargo",
                "YES",
                ["Cargo/Rust downloaded crate archive cache"],
            ),
        ]

        for p, a_type, owner, regen, ev in cache_definitions:
            if p and os.path.isdir(p):
                canon = canonicalize_path(p)
                sz, _, _ = _fast_dir_size(canon)
                if sz > 0:
                    mtime = None
                    age = None
                    try:
                        mtime = os.path.getmtime(canon)
                        age = (self.now - mtime) / 86400
                    except (OSError, PermissionError):
                        pass

                    artifacts.append(
                        DeveloperArtifact(
                            path=canon,
                            artifact_type=a_type,
                            owner_app=owner,
                            logical_bytes=sz,
                            mtime=mtime,
                            age_days=age,
                            stale_candidate=False,
                            stale_reason=None,
                            regenerable=regen,
                            evidence=ev,
                        )
                    )

        return artifacts

    def scan_project_tree(
        self,
        root_path: str,
        max_depth: int = 5,
        max_results: int = 50,
    ) -> List[DeveloperArtifact]:
        """
        Scans a directory tree for node_modules, virtualenvs, and build artifacts.
        Does not recurse into node_modules or .git.
        """
        canon_root = canonicalize_path(root_path)
        if not os.path.isdir(canon_root):
            return []

        artifacts: List[DeveloperArtifact] = []

        stack = [(canon_root, 0)]
        while stack and len(artifacts) < max_results:
            curr_dir, depth = stack.pop()
            if depth > max_depth:
                continue

            try:
                with os.scandir(curr_dir) as it:
                    for entry in it:
                        try:
                            # Skip junctions, symlinks, and .git to avoid loops & git corruptions
                            is_junc = hasattr(entry, "is_junction") and entry.is_junction()
                            if is_junc or entry.is_symlink():
                                continue

                            entry_name = entry.name.lower()
                            if entry_name == ".git":
                                continue

                            if entry.is_dir(follow_symlinks=False):
                                entry_path = canonicalize_path(entry.path)
                                mtime = None
                                age = None
                                try:
                                    mtime = entry.stat(follow_symlinks=False).st_mtime
                                    age = (self.now - mtime) / 86400
                                except (OSError, PermissionError):
                                    pass

                                is_stale = age is not None and age > 90
                                stale_msg = f"Directory not modified in {int(age)} days (>90d)" if is_stale else None

                                # Check node_modules
                                if entry_name == "node_modules":
                                    sz, _, _ = _fast_dir_size(entry_path)
                                    parent_has_pkg = os.path.isfile(os.path.join(curr_dir, "package.json"))
                                    artifacts.append(
                                        DeveloperArtifact(
                                            path=entry_path,
                                            artifact_type="node_modules",
                                            owner_app="npm/node",
                                            logical_bytes=sz,
                                            mtime=mtime,
                                            age_days=age,
                                            stale_candidate=is_stale,
                                            stale_reason=stale_msg,
                                            regenerable="YES" if parent_has_pkg else "UNKNOWN",
                                            evidence=[
                                                "Node.js dependency directory",
                                                f"Parent package.json present: {parent_has_pkg}",
                                            ],
                                        )
                                    )
                                    # Do not recurse into node_modules
                                    continue

                                # Check Python venv (.venv, venv, env)
                                if entry_name in (".venv", "venv", "env"):
                                    has_cfg = os.path.isfile(os.path.join(entry_path, "pyvenv.cfg"))
                                    has_scripts = os.path.isdir(os.path.join(entry_path, "Scripts"))
                                    if has_cfg or has_scripts:
                                        sz, _, _ = _fast_dir_size(entry_path)
                                        has_req = (
                                            os.path.isfile(os.path.join(curr_dir, "requirements.txt"))
                                            or os.path.isfile(os.path.join(curr_dir, "pyproject.toml"))
                                        )
                                        artifacts.append(
                                            DeveloperArtifact(
                                                path=entry_path,
                                                artifact_type="python_venv",
                                                owner_app="python",
                                                logical_bytes=sz,
                                                mtime=mtime,
                                                age_days=age,
                                                stale_candidate=is_stale,
                                                stale_reason=stale_msg,
                                                regenerable="YES" if has_req else "UNKNOWN",
                                                evidence=[
                                                    f"Python virtual environment (pyvenv.cfg: {has_cfg})",
                                                    f"Parent requirements/pyproject present: {has_req}",
                                                ],
                                            )
                                        )
                                        # Do not recurse into venv
                                        continue

                                # Check Cargo target
                                if entry_name == "target":
                                    has_tag = os.path.isfile(os.path.join(entry_path, "CACHEDIR.TAG"))
                                    has_cargo = os.path.isfile(os.path.join(curr_dir, "Cargo.toml"))
                                    if has_tag or has_cargo:
                                        sz, _, _ = _fast_dir_size(entry_path)
                                        artifacts.append(
                                            DeveloperArtifact(
                                                path=entry_path,
                                                artifact_type="build_artifact",
                                                owner_app="cargo/rust",
                                                logical_bytes=sz,
                                                mtime=mtime,
                                                age_days=age,
                                                stale_candidate=is_stale,
                                                stale_reason=stale_msg,
                                                regenerable="YES" if has_cargo else "UNKNOWN",
                                                evidence=[
                                                    f"Cargo build target directory (Cargo.toml: {has_cargo})",
                                                ],
                                            )
                                        )
                                        continue

                                # Check Next.js build cache (.next)
                                if entry_name == ".next":
                                    sz, _, _ = _fast_dir_size(entry_path)
                                    artifacts.append(
                                        DeveloperArtifact(
                                            path=entry_path,
                                            artifact_type="build_artifact",
                                            owner_app="nextjs",
                                            logical_bytes=sz,
                                            mtime=mtime,
                                            age_days=age,
                                            stale_candidate=is_stale,
                                            stale_reason=stale_msg,
                                            regenerable="YES",
                                            evidence=["Next.js build cache directory"],
                                        )
                                    )
                                    continue

                                # Check __pycache__
                                if entry_name == "__pycache__":
                                    sz, _, _ = _fast_dir_size(entry_path)
                                    artifacts.append(
                                        DeveloperArtifact(
                                            path=entry_path,
                                            artifact_type="pycache",
                                            owner_app="python",
                                            logical_bytes=sz,
                                            mtime=mtime,
                                            age_days=age,
                                            stale_candidate=False,
                                            stale_reason=None,
                                            regenerable="YES",
                                            evidence=["Python compiled bytecode cache"],
                                        )
                                    )
                                    continue

                                # Otherwise recurse into regular subdirectories
                                stack.append((entry_path, depth + 1))

                        except (OSError, PermissionError):
                            continue
            except (OSError, PermissionError):
                continue

        # Sort largest first
        artifacts.sort(key=lambda x: x.logical_bytes, reverse=True)
        return artifacts
