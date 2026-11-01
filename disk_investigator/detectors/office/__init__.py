"""
Office detectors package.
"""

from .office_cache import OfficeCacheDetector
from .outlook import OutlookStorageDetector
from .teams import TeamsCacheDetector

__all__ = ["OutlookStorageDetector", "OfficeCacheDetector", "TeamsCacheDetector"]
