"""
Specialized storage detectors for disk_investigator.
"""

from .base import BaseDetector, Detector
from .registry import DetectorRegistry
from .adapters import (
    DeveloperStorageDetector,
    DockerStorageDetector,
    LargeFilesStorageDetector,
)
from .developer_detector import DeveloperArtifact, DeveloperDetector
from .docker_detector import DockerComponent, DockerDetector
from .large_files_detector import LargeFileItem, LargeFilesDetector

__all__ = [
    "BaseDetector",
    "Detector",
    "DetectorRegistry",
    "DeveloperArtifact",
    "DeveloperDetector",
    "DeveloperStorageDetector",
    "DockerComponent",
    "DockerDetector",
    "DockerStorageDetector",
    "LargeFileItem",
    "LargeFilesDetector",
    "LargeFilesStorageDetector",
]
