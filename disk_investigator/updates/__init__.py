"""
disk_investigator.updates package.
Autonomous In-App Self-Update, Staged Lifecycle Handoff, and Non-blocking SWR Update Checker.
"""

from .models import (
    ReleaseInfo,
    ReleaseAsset,
    UpdateState,
    UpdateResult,
    UpdateReceipt,
    CacheFreshness,
    UpdateCache,
)
from .release_client import GitHubReleaseClient
from .checksum import verify_sha256_checksum, parse_sha256sums_manifest, compute_sha256
from .cache import UpdateCacheManager
from .background_refresh import BackgroundRefreshManager
from .update_engine import UpdateEngine

__all__ = [
    "ReleaseInfo",
    "ReleaseAsset",
    "UpdateState",
    "UpdateResult",
    "UpdateReceipt",
    "CacheFreshness",
    "UpdateCache",
    "GitHubReleaseClient",
    "verify_sha256_checksum",
    "parse_sha256sums_manifest",
    "compute_sha256",
    "UpdateCacheManager",
    "BackgroundRefreshManager",
    "UpdateEngine",
]
