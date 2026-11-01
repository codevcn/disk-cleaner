"""
System detectors package.
"""

from .crash_dump import CrashDumpDetector
from .user_temp import UserTempDetector

__all__ = ["UserTempDetector", "CrashDumpDetector"]
