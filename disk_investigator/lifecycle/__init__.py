"""
Lifecycle module for Disk Investigator.
Handles installation, updates, uninstallation, process safety, and environment configuration.
"""

from .common import (
    APP_NAME,
    APP_DISPLAY_NAME,
    GITHUB_REPO,
    RELEASE_ASSETS,
    SKILL_FOLDER_NAME,
    KNOWN_OWNED_SUBDIRS,
    KNOWN_OWNED_FILES,
    ProcessState,
    add_bin_to_user_path,
    broadcast_environment_change,
    check_process_state,
    compute_sha256,
    get_app_version,
    get_resource_path,
    get_target_directories,
    load_manifest,
    remove_bin_from_user_path,
    write_manifest,
)
from .models import UninstallResult, UninstallStatus
from .uninstall_core import UninstallEngine

__all__ = [
    "APP_NAME",
    "APP_DISPLAY_NAME",
    "GITHUB_REPO",
    "RELEASE_ASSETS",
    "SKILL_FOLDER_NAME",
    "KNOWN_OWNED_SUBDIRS",
    "KNOWN_OWNED_FILES",
    "ProcessState",
    "UninstallResult",
    "UninstallStatus",
    "UninstallEngine",
    "add_bin_to_user_path",
    "broadcast_environment_change",
    "check_process_state",
    "compute_sha256",
    "get_app_version",
    "get_resource_path",
    "get_target_directories",
    "load_manifest",
    "remove_bin_from_user_path",
    "write_manifest",
]
