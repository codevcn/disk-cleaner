"""
Registry for modular storage artifact detectors.
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional

from ..models import DetectionContext, StorageArtifact
from .base import Detector

logger = logging.getLogger(__name__)


class DetectorRegistry:
    """Manages detector registration, capability-based filtering, and execution."""

    def __init__(self) -> None:
        self._detectors: Dict[str, Detector] = {}
        self.last_runs: List[Dict[str, Any]] = []
        self.last_errors: List[Dict[str, str]] = []

    def register(self, detector: Detector) -> None:
        """Register a detector instance."""
        if not hasattr(detector, "detector_id") or not detector.detector_id:
            raise ValueError("Detector must have a non-empty detector_id")
        self._detectors[detector.detector_id] = detector

    def unregister(self, detector_id: str) -> Optional[Detector]:
        """Unregister a detector by its id."""
        return self._detectors.pop(detector_id, None)

    def get(self, detector_id: str) -> Optional[Detector]:
        """Get a registered detector by id."""
        return self._detectors.get(detector_id)

    def list_detectors(self) -> List[Detector]:
        """List all registered detectors in order of registration."""
        return list(self._detectors.values())

    def get_applicable_detectors(self, context: DetectionContext) -> List[Detector]:
        """Return registered detectors that report applicable(context) == True."""
        applicable: List[Detector] = []
        for det in self._detectors.values():
            try:
                if det.applicable(context):
                    applicable.append(det)
            except Exception as e:
                logger.warning(
                    "Error checking applicability for detector %s: %s",
                    getattr(det, "detector_id", "unknown"),
                    e,
                )
        return applicable

    def run_detectors(self, context: DetectionContext) -> List[StorageArtifact]:
        """
        Execute all applicable detectors with strict fault isolation and fault visibility.
        An unhandled exception in one detector will never abort the entire scan.
        Records execution status and errors for complete coverage reporting.
        """
        all_artifacts: List[StorageArtifact] = []
        self.last_runs = []
        self.last_errors = []
        applicable_detectors = self.get_applicable_detectors(context)

        for det in applicable_detectors:
            det_id = getattr(det, "detector_id", "unknown")
            try:
                found = det.detect(context)
                self.last_runs.append({
                    "detector_id": det_id,
                    "status": "complete",
                    "artifacts": len(found) if found else 0,
                })
                if found:
                    all_artifacts.extend(found)
            except Exception as e:
                err_msg = str(e)
                logger.error("Detector %s encountered an error during detection: %s", det_id, e)
                self.last_runs.append({
                    "detector_id": det_id,
                    "status": "failed",
                    "error": err_msg,
                })
                self.last_errors.append({
                    "detector_id": det_id,
                    "error": err_msg,
                })

        return all_artifacts


def create_default_registry() -> DetectorRegistry:
    """Create a DetectorRegistry pre-populated with all modular detectors."""
    registry = DetectorRegistry()

    from .adapters import DeveloperStorageDetector, DockerStorageDetector, LargeFilesStorageDetector
    from .ai_ml import HuggingFaceCacheDetector, OllamaModelDetector
    from .browser import ChromiumBrowserDetector
    from .creator import AdobeCreatorDetector, CapCutDetector, DaVinciResolveDetector
    from .gaming import SteamGamingDetector
    from .general import DicomMedicalDetector
    from .office import OfficeCacheDetector, OutlookStorageDetector, TeamsCacheDetector
    from .streaming import OBSStudioDetector
    from .system import CrashDumpDetector, UserTempDetector

    default_detectors: List[Detector] = [
        UserTempDetector(),
        CrashDumpDetector(),
        ChromiumBrowserDetector(),
        OutlookStorageDetector(),
        OfficeCacheDetector(),
        TeamsCacheDetector(),
        AdobeCreatorDetector(),
        DaVinciResolveDetector(),
        CapCutDetector(),
        OBSStudioDetector(),
        SteamGamingDetector(),
        DeveloperStorageDetector(),
        DockerStorageDetector(),
        LargeFilesStorageDetector(),
        OllamaModelDetector(),
        HuggingFaceCacheDetector(),
        DicomMedicalDetector(),
    ]

    for det in default_detectors:
        registry.register(det)

    return registry
