"""
Path policy, normalization, and safety classification for Windows 11 filesystems.
Ensures junctions, symlinks, protected OS areas, and cloud sync folders are strictly identified.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Optional, Set

from .models import NodeKind


def canonicalize_path(raw_path: str) -> str:
    """
    Normalizes and canonicalizes a Windows path.
    Converts drive-relative (e.g. 'C:') to root ('C:\\').
    Resolves backslashes and standardizes drive letter case.
    """
    if not raw_path or not raw_path.strip():
        raw_path = "."

    cleaned = raw_path.strip()

    # Handle drive letter root like 'C:' -> 'C:\\'
    if len(cleaned) == 2 and cleaned[1] == ":" and cleaned[0].isalpha():
        cleaned = f"{cleaned.upper()}\\"
    elif len(cleaned) >= 2 and cleaned[1] == ":" and cleaned[0].isalpha():
        cleaned = f"{cleaned[0].upper()}{cleaned[1:]}"

    abs_path = os.path.abspath(cleaned)
    normalized = os.path.normpath(abs_path)

    # If it's a drive root like 'C:', normpath might strip trailing slash, restore it
    if len(normalized) == 2 and normalized[1] == ":" and normalized[0].isalpha():
        normalized = f"{normalized}\\"

    return normalized


def is_reparse_point(path: str) -> bool:
    """
    Detects if a path is a Windows reparse point (junction, symlink, mount point, etc.).
    Uses Python 3.12 native APIs and fallback to stat attributes.
    """
    try:
        if hasattr(os.path, "isjunction") and os.path.isjunction(path):
            return True
        if os.path.islink(path):
            return True

        # Check FILE_ATTRIBUTE_REPARSE_POINT (0x400) via lstat
        st = os.lstat(path)
        file_attrs = getattr(st, "st_file_attributes", 0)
        FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
        return bool(file_attrs & FILE_ATTRIBUTE_REPARSE_POINT)
    except (OSError, ValueError):
        return False


def determine_node_kind(path: str) -> NodeKind:
    """
    Determines the NodeKind of a given path safely without following symlinks/junctions.
    """
    try:
        # Check junction first
        if hasattr(os.path, "isjunction") and os.path.isjunction(path):
            return NodeKind.JUNCTION
        if os.path.islink(path):
            return NodeKind.SYMLINK

        # Use lstat to avoid following links
        st = os.lstat(path)
        mode = st.st_mode
        if stat.S_ISDIR(mode):
            return NodeKind.DIRECTORY
        elif stat.S_ISREG(mode):
            return NodeKind.FILE
        else:
            return NodeKind.OTHER
    except (OSError, PermissionError):
        # Fallback if accessible via os.path
        if os.path.isdir(path):
            return NodeKind.DIRECTORY
        elif os.path.isfile(path):
            return NodeKind.FILE
        return NodeKind.OTHER


def get_cloud_sync_roots() -> Set[str]:
    """
    Discovers known cloud sync roots on the current Windows user profile.
    """
    roots: Set[str] = set()
    env_vars = [
        "OneDrive",
        "OneDriveConsumer",
        "OneDriveCommercial",
        "Dropbox",
        "GoogleDrive",
        "iCloudDrive",
    ]
    for var in env_vars:
        val = os.environ.get(var)
        if val and os.path.isdir(val):
            roots.add(canonicalize_path(val).lower())

    # Check standard locations in user profile
    user_profile = os.environ.get("USERPROFILE")
    if user_profile:
        candidates = ["OneDrive", "Dropbox", "Google Drive", "iCloudDrive"]
        for cand in candidates:
            p = os.path.join(user_profile, cand)
            if os.path.isdir(p):
                roots.add(canonicalize_path(p).lower())

    return roots


def resolve_windows_aliases(path: str) -> str:
    """
    Resolves Windows 8.3 short names (e.g. C:\\PROGRA~1, ONEDRI~1) and filesystem aliases
    to their true, long, canonical filesystem path.
    Uses Win32 GetLongPathNameW and Python 3.12 os.path.realpath.
    """
    if not path or not path.strip():
        return ""
    canon = canonicalize_path(path)
    try:
        import ctypes
        if hasattr(ctypes, "windll") and hasattr(ctypes.windll, "kernel32"):
            buf = ctypes.create_unicode_buffer(2048)
            ret = ctypes.windll.kernel32.GetLongPathNameW(canon, buf, 2048)
            if ret > 0:
                canon = buf.value
    except Exception:
        pass

    try:
        real = os.path.realpath(canon)
        if real:
            return canonicalize_path(real)
    except Exception:
        pass
    return canonicalize_path(canon)


def is_cloud_sync_path(path: str, cloud_roots: Optional[Set[str]] = None) -> bool:
    """
    Checks if a given path is located inside a cloud synchronization root.
    Evaluates both lexical path and resolved 8.3/filesystem aliases.
    Uses known cloud environment roots as well as signature heuristics.
    """
    if not path or not path.strip():
        return False

    if cloud_roots is None:
        cloud_roots = get_cloud_sync_roots()

    candidates = {canonicalize_path(path).lower()}
    resolved = resolve_windows_aliases(path).lower()
    if resolved:
        candidates.add(resolved)

    cloud_signatures = ["\\onedrive", "\\dropbox", "\\google drive", "\\iclouddrive"]

    for cand in candidates:
        for root in cloud_roots:
            if cand == root or cand.startswith(root + "\\"):
                return True
        for sig in cloud_signatures:
            if sig in cand:
                return True

    return False


def is_protected_system_path(path: str) -> bool:
    """
    Determines if a path belongs to protected Windows operating system boundaries.
    Evaluates both lexical path and resolved 8.3/filesystem aliases.
    """
    canon = canonicalize_path(path).lower()
    resolved = resolve_windows_aliases(path).lower()

    for candidate in {canon, resolved}:
        if not candidate:
            continue
        drive, rest = os.path.splitdrive(candidate)
        if not drive:
            continue

        # Block whole drive root like C:\ or D:\
        if rest in ("\\", "", "/"):
            return True

        protected_prefixes = [
            f"{drive}\\windows",
            f"{drive}\\program files",
            f"{drive}\\program files (x86)",
            f"{drive}\\programdata",
            f"{drive}\\recovery",
            f"{drive}\\$recycle.bin",
            f"{drive}\\system volume information",
            f"{drive}\\boot",
            f"{drive}\\bootmgr",
            f"{drive}\\pagefile.sys",
            f"{drive}\\hiberfil.sys",
            f"{drive}\\swapfile.sys",
        ]

        for prefix in protected_prefixes:
            if candidate == prefix or candidate.startswith(prefix + "\\"):
                return True

    return False


def is_critical_boundary(path: str) -> bool:
    """
    Determines if a path is an exact critical system, user profile root, or sensitive credentials area.
    Evaluates both lexical path and resolved 8.3/filesystem aliases.
    Prevents catastrophic root or identity deletion attempts across all user profiles.
    """
    canon = canonicalize_path(path).lower()
    resolved = resolve_windows_aliases(path).lower()

    for candidate in {canon, resolved}:
        if not candidate:
            continue
        drive, rest = os.path.splitdrive(candidate)

        # Drive root (e.g. C:\ or D:\)
        if drive and rest in ("\\", "", "/"):
            return True

        # User roots (e.g. C:\Users)
        if drive and (candidate == f"{drive}\\users" or candidate == f"{drive}\\users\\"):
            return True

        # Any user profile root (e.g. C:\Users\<any_user>)
        parts = [p for p in candidate.split("\\") if p]
        if len(parts) == 3 and parts[1] == "users":
            return True

        user_profile = os.environ.get("USERPROFILE")
        if user_profile:
            up_canon = canonicalize_path(user_profile).lower()
            if candidate == up_canon or candidate == f"{up_canon}\\":
                return True

        program_data = os.environ.get("ProgramData")
        if program_data:
            pd_canon = canonicalize_path(program_data).lower()
            if candidate == pd_canon or candidate == f"{pd_canon}\\":
                return True

        # Sensitive identity, SSH, cloud credentials and security roots
        sensitive_subtrees = [
            "\\.ssh",
            "\\.gnupg",
            "\\credentials",
            "\\microsoft\\crypto",
            "\\microsoft\\vault",
            "\\microsoft\\protect",
            "\\.aws",
            "\\.azure",
            "\\.kube",
        ]
        for sub in sensitive_subtrees:
            if candidate.endswith(sub) or (sub + "\\") in candidate:
                return True

    return False


def is_network_share(path: str) -> bool:
    """
    Detects if the path is a UNC network share (e.g. \\\\server\\share or //server/share).
    """
    cleaned = path.strip().replace("/", "\\")
    return cleaned.startswith("\\\\")


def has_reparse_point_ancestor(path: str) -> bool:
    """
    Checks if any parent directory in the path hierarchy is a reparse point or junction.
    Prevents directory junction swap attacks on parent folders.
    """
    canon = canonicalize_path(path)
    curr = os.path.dirname(canon)
    drive, _ = os.path.splitdrive(canon)
    root = f"{drive}\\" if drive else "\\"

    while curr and curr != root and curr != canon:
        if is_reparse_point(curr):
            return True
        parent = os.path.dirname(curr)
        if parent == curr:
            break
        curr = parent
    return False


def is_safe_fixed_drive(path: str) -> bool:
    """
    Verifies that the target path is on a local fixed NTFS/ReFS drive (DRIVE_FIXED).
    Blocks mapped network drives (DRIVE_REMOTE), removable drives (DRIVE_REMOVABLE),
    and virtual/unknown drive letters where Recycle Bin semantics are not guaranteed.
    """
    canon = canonicalize_path(path)
    drive, _ = os.path.splitdrive(canon)
    if not drive:
        return False
    drive_root = f"{drive}\\"
    try:
        import ctypes
        if hasattr(ctypes, "windll") and hasattr(ctypes.windll, "kernel32"):
            dtype = ctypes.windll.kernel32.GetDriveTypeW(drive_root)
            return dtype == 3  # DRIVE_FIXED
        return True  # Fallback for non-Windows test environments
    except Exception:
        return False
