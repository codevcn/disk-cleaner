"""
Docker storage detector for Windows 11.
Inspects WSL2 ext4.vhdx backing storage and Docker Desktop daemon state.
Strict safety invariant: NEVER permits direct raw deletion of VHDX files.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..path_policy import canonicalize_path


@dataclass
class DockerComponent:
    component_type: str  # "vhdx_backing", "build_cache", "images", "containers", "volumes"
    description: str
    total_bytes: int
    reclaimable_bytes: Optional[int]
    risk_level: str  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    disposition: str  # "CLEANABLE", "REVIEW_REQUIRED", "BLOCKED"
    recommended_action: Optional[str]
    warning: Optional[str] = None


class DockerDetector:
    """Discovers and breaks down Docker storage on Windows 11."""

    def __init__(self):
        self.local_app_data = os.environ.get("LOCALAPPDATA", "")

    def find_vhdx_storage(self) -> List[Dict[str, Any]]:
        """Finds WSL2 / Docker Desktop backing VHDX virtual hard disk files."""
        candidates = [
            os.path.join(self.local_app_data, "Docker", "wsl", "data", "ext4.vhdx"),
            os.path.join(self.local_app_data, "Docker", "wsl", "distro", "ext4.vhdx"),
            os.path.join(self.local_app_data, "Docker", "wsl", "disk", "docker-desktop-data.vhdx"),
        ]

        found = []
        for c in candidates:
            if os.path.isfile(c):
                canon = canonicalize_path(c)
                sz = os.path.getsize(canon)
                found.append({
                    "path": canon,
                    "logical_bytes": sz,
                    "risk_level": "CRITICAL",
                    "disposition": "BLOCKED",
                    "warning": (
                        "DO NOT delete ext4.vhdx directly! Raw deletion corrupts Docker Desktop WSL "
                        "registration. Use Docker CLI prune operations or Docker Settings to manage space."
                    ),
                })
        return found

    def query_docker_daemon(self) -> Optional[Dict[str, Any]]:
        """Attempts to query the running Docker daemon using docker system df."""
        docker_cli = shutil.which("docker.exe") or shutil.which("docker")
        if not docker_cli:
            return None

        try:
            # Query docker system df in JSON format with resolved binary and shell=False
            proc = subprocess.run(
                [docker_cli, "system", "df", "--format", "{{json .}}"],
                capture_output=True,
                text=True,
                timeout=5,
                shell=False,
            )
            if proc.returncode != 0 or not proc.stdout.strip():
                return None

            items = []
            for line in proc.stdout.strip().splitlines():
                if line.strip():
                    try:
                        items.append(json.loads(line.strip()))
                    except json.JSONDecodeError:
                        pass

            return {"available": True, "raw_components": items}

        except (subprocess.TimeoutExpired, Exception) as e:
            return {"available": False, "error": str(e)}

    def inspect(self) -> Dict[str, Any]:
        """Provides a complete, classified report of Docker storage on Windows 11."""
        vhdx_files = self.find_vhdx_storage()
        total_vhdx_bytes = sum(v["logical_bytes"] for v in vhdx_files)

        daemon_info = self.query_docker_daemon()
        daemon_online = daemon_info is not None and daemon_info.get("available", False)

        components: List[DockerComponent] = []

        # 1. Backing VHDX (Always BLOCKED from raw file deletion)
        for v in vhdx_files:
            components.append(
                DockerComponent(
                    component_type="vhdx_backing",
                    description="WSL2 Virtual Hard Disk backing Docker engine",
                    total_bytes=v["logical_bytes"],
                    reclaimable_bytes=None,
                    risk_level="CRITICAL",
                    disposition="BLOCKED",
                    recommended_action="Run 'docker system prune' or compact disk via diskpart/wsl --manage",
                    warning=v["warning"],
                )
            )

        # 2. Daemon breakdown if online
        if daemon_online and "raw_components" in daemon_info:
            for item in daemon_info["raw_components"]:
                c_type = item.get("Type", "").lower()
                total_str = item.get("TotalSize", "0B")
                reclaim_str = item.get("Reclaimable", "0B")

                if "build" in c_type:
                    components.append(
                        DockerComponent(
                            component_type="build_cache",
                            description="Docker build cache layers",
                            total_bytes=0,
                            reclaimable_bytes=None,
                            risk_level="LOW",
                            disposition="CLEANABLE",
                            recommended_action="docker builder prune",
                        )
                    )
                elif "image" in c_type:
                    components.append(
                        DockerComponent(
                            component_type="images",
                            description="Container images (active & unused)",
                            total_bytes=0,
                            reclaimable_bytes=None,
                            risk_level="MEDIUM",
                            disposition="REVIEW_REQUIRED",
                            recommended_action="docker image prune",
                        )
                    )
                elif "volume" in c_type:
                    components.append(
                        DockerComponent(
                            component_type="volumes",
                            description="Persistent data volumes",
                            total_bytes=0,
                            reclaimable_bytes=None,
                            risk_level="HIGH",
                            disposition="REVIEW_REQUIRED",
                            recommended_action="Review before running 'docker volume prune' (data loss hazard)",
                            warning="Volumes contain persistent application state/databases.",
                        )
                    )

        return {
            "docker_installed": shutil.which("docker") is not None,
            "daemon_online": daemon_online,
            "vhdx_files_count": len(vhdx_files),
            "total_vhdx_bytes": total_vhdx_bytes,
            "vhdx_files": vhdx_files,
            "components": [
                {
                    "component_type": c.component_type,
                    "description": c.description,
                    "total_bytes": c.total_bytes,
                    "reclaimable_bytes": c.reclaimable_bytes,
                    "risk_level": c.risk_level,
                    "disposition": c.disposition,
                    "recommended_action": c.recommended_action,
                    "warning": c.warning,
                }
                for c in components
            ],
        }
