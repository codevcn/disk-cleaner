"""
Large file detector for Windows 11.
Locates heavy storage consumers above customizable size thresholds.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from ..path_policy import (
    canonicalize_path,
    is_cloud_sync_path,
    is_protected_system_path,
)


def categorize_file_by_extension(name: str) -> str:
    ext = os.path.splitext(name)[1].lower()
    mapping = {
        (".iso", ".vmdk", ".vhdx", ".vdi", ".img", ".wim"): "disk_image",
        (".mp4", ".mkv", ".mov", ".avi", ".wmv", ".flv"): "video",
        (".zip", ".tar", ".gz", ".7z", ".rar", ".bz2", ".xz"): "archive",
        (".exe", ".msi", ".pkg"): "installer",
        (".mdf", ".ldf", ".sqlite", ".db", ".bak"): "database",
        (".gguf", ".bin", ".safetensors", ".onnx", ".pt"): "ai_model",
        (".log", ".txt", ".dmp"): "log_or_dump",
    }
    for extensions, category in mapping.items():
        if ext in extensions:
            return category
    return "other"


@dataclass
class LargeFileItem:
    path: str
    name: str
    size_bytes: int
    mtime: Optional[float]
    age_days: Optional[float]
    category: str
    is_protected_system: bool
    is_cloud_sync: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "name": self.name,
            "size_bytes": self.size_bytes,
            "mtime": self.mtime,
            "age_days": round(self.age_days, 1) if self.age_days is not None else None,
            "category": self.category,
            "is_protected_system": self.is_protected_system,
            "is_cloud_sync": self.is_cloud_sync,
        }


class LargeFilesDetector:
    """Finds files larger than a given size threshold (default 100MB)."""

    def __init__(self, now_timestamp: Optional[float] = None):
        self.now = now_timestamp or time.time()

    def find_large_files(
        self,
        root_path: str,
        min_size_bytes: int = 100 * 1024 * 1024,  # 100 MB
        max_results: int = 50,
        max_depth: int = 6,
    ) -> List[LargeFileItem]:
        canon_root = canonicalize_path(root_path)
        if not os.path.isdir(canon_root):
            return []

        results: List[LargeFileItem] = []
        stack = [(canon_root, 0)]

        while stack and len(results) < max_results * 4:  # Collect candidate pool
            curr_dir, depth = stack.pop()
            if depth > max_depth:
                continue

            try:
                with os.scandir(curr_dir) as it:
                    for entry in it:
                        try:
                            # Skip junctions & symlinks
                            is_junc = hasattr(entry, "is_junction") and entry.is_junction()
                            if is_junc or entry.is_symlink():
                                continue

                            if entry.is_file(follow_symlinks=False):
                                st = entry.stat(follow_symlinks=False)
                                if st.st_size >= min_size_bytes:
                                    p = canonicalize_path(entry.path)
                                    age = (self.now - st.st_mtime) / 86400 if st.st_mtime else None
                                    cat = categorize_file_by_extension(entry.name)
                                    is_sys = is_protected_system_path(p)
                                    is_cloud = is_cloud_sync_path(p)

                                    results.append(
                                        LargeFileItem(
                                            path=p,
                                            name=entry.name,
                                            size_bytes=st.st_size,
                                            mtime=st.st_mtime,
                                            age_days=age,
                                            category=cat,
                                            is_protected_system=is_sys,
                                            is_cloud_sync=is_cloud,
                                        )
                                    )

                            elif entry.is_dir(follow_symlinks=False):
                                stack.append((entry.path, depth + 1))

                        except (OSError, PermissionError):
                            continue
            except (OSError, PermissionError):
                continue

        # Sort largest first and limit
        results.sort(key=lambda x: x.size_bytes, reverse=True)
        return results[:max_results]
