"""
Base protocol and class for storage artifact detectors.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List, Protocol, runtime_checkable

from ..models import ArtifactDomain, DetectionContext, StorageArtifact


@runtime_checkable
class Detector(Protocol):
    """Protocol for modular storage artifact detectors."""

    detector_id: str
    domain: ArtifactDomain

    def applicable(self, context: DetectionContext) -> bool:
        """Return True if this detector is applicable given context and discovered capabilities."""
        ...

    def detect(self, context: DetectionContext) -> List[StorageArtifact]:
        """Perform discovery and return detected StorageArtifact instances."""
        ...


class BaseDetector(ABC):
    """Abstract base class for storage artifact detectors."""

    detector_id: str = "base"
    domain: ArtifactDomain = ArtifactDomain.GENERAL

    @abstractmethod
    def applicable(self, context: DetectionContext) -> bool:
        """Return True if this detector is applicable given context and discovered capabilities."""
        pass

    @abstractmethod
    def detect(self, context: DetectionContext) -> List[StorageArtifact]:
        """Perform discovery and return detected StorageArtifact instances."""
        pass
