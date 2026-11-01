"""
Action types for CleanupPlan items and ActionRegistry dispatching.
"""

from __future__ import annotations

from enum import Enum


class ActionType(str, Enum):
    """Supported typed actions for safe disk cleanup execution."""

    RECYCLE_PATH = "RECYCLE_PATH"
    NPM_CACHE_CLEAN = "NPM_CACHE_CLEAN"
    PIP_CACHE_PURGE = "PIP_CACHE_PURGE"
    DOCKER_BUILDER_PRUNE = "DOCKER_BUILDER_PRUNE"
    BROWSER_CACHE_PURGE = "BROWSER_CACHE_PURGE"
    OFFICE_CACHE_PURGE = "OFFICE_CACHE_PURGE"
    CREATOR_CACHE_PURGE = "CREATOR_CACHE_PURGE"
    GAMING_CACHE_PURGE = "GAMING_CACHE_PURGE"
    STREAMING_LOGS_PURGE = "STREAMING_LOGS_PURGE"
    REVIEW_ONLY = "REVIEW_ONLY"
