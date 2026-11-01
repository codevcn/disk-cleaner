"""
Investigation Service: Orchestrates capability discovery, modular detectors,
and artifact correlation into a unified storage investigation report.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..classifiers.artifact_policy import ArtifactPolicyEngine
from ..discovery.capability_discovery import CapabilityDiscovery
from ..detectors.registry import DetectorRegistry, create_default_registry
from ..models import Capability, DetectionContext, StorageArtifact
from .artifact_correlator import ArtifactCorrelator


@dataclass
class InvestigationResult:
    """Consolidated result of a disk investigation."""

    target_path: str
    capabilities: Dict[str, Capability]
    artifacts: List[StorageArtifact]
    total_detected_bytes: int
    net_logical_bytes: int
    by_domain: Dict[str, int] = field(default_factory=dict)
    by_action: Dict[str, int] = field(default_factory=dict)
    by_category: Dict[str, int] = field(default_factory=dict)
    detector_runs: List[Dict[str, Any]] = field(default_factory=list)
    detector_errors: List[Dict[str, str]] = field(default_factory=list)
    coverage_status: str = "complete"  # "complete" or "partial"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_path": self.target_path,
            "coverage_status": self.coverage_status,
            "capabilities_detected": {
                cap_id: cap.to_dict()
                for cap_id, cap in self.capabilities.items()
                if cap.detected
            },
            "artifacts_count": len(self.artifacts),
            "artifacts": [a.to_dict() for a in self.artifacts],
            "total_detected_bytes": self.total_detected_bytes,
            "net_logical_bytes": self.net_logical_bytes,
            "by_domain": self.by_domain,
            "by_action": self.by_action,
            "by_category": self.by_category,
            "detector_runs": self.detector_runs,
            "detector_errors": self.detector_errors,
        }


class InvestigationService:
    """Coordinates the full storage investigation workflow."""

    def __init__(
        self,
        discovery: Optional[CapabilityDiscovery] = None,
        registry: Optional[DetectorRegistry] = None,
    ) -> None:
        self.discovery = discovery or CapabilityDiscovery()
        self.registry = registry or create_default_registry()

    def investigate(
        self,
        target_path: str,
        context: Optional[DetectionContext] = None,
    ) -> InvestigationResult:
        """Run discovery, applicable detectors, and correlate the findings."""
        env = dict(os.environ)

        # 1. Discover capabilities if not provided in context
        if context is None:
            caps = self.discovery.discover_all()
            context = DetectionContext(
                target_path=target_path,
                capabilities=caps,
                env=env,
            )
        elif not context.capabilities:
            context.capabilities = self.discovery.discover_all()

        # 2. Run applicable detectors
        raw_artifacts = self.registry.run_detectors(context)
        detector_runs = list(getattr(self.registry, "last_runs", []))
        detector_errors = list(getattr(self.registry, "last_errors", []))
        coverage_status = "partial" if detector_errors else "complete"

        # 3. Correlate and deduplicate artifacts
        correlated_artifacts = ArtifactCorrelator.correlate(raw_artifacts)

        # 4. Enforce security guardrails and false-positive policy hardening
        hardened_artifacts = ArtifactPolicyEngine.evaluate_all(correlated_artifacts)

        # 5. Calculate aggregated metrics
        total_detected_bytes = sum(a.logical_bytes for a in hardened_artifacts)
        net_logical_bytes = ArtifactCorrelator.calculate_net_bytes(hardened_artifacts)

        by_domain: Dict[str, int] = {}
        by_action: Dict[str, int] = {}
        by_category: Dict[str, int] = {}

        for a in hardened_artifacts:
            d_val = a.domain.value if hasattr(a.domain, "value") else str(a.domain)
            act_val = (
                a.recommended_action.value
                if hasattr(a.recommended_action, "value")
                else str(a.recommended_action)
            )
            cat_val = a.category.value if hasattr(a.category, "value") else str(a.category)

            by_domain[d_val] = by_domain.get(d_val, 0) + a.logical_bytes
            by_action[act_val] = by_action.get(act_val, 0) + a.logical_bytes
            by_category[cat_val] = by_category.get(cat_val, 0) + a.logical_bytes

        return InvestigationResult(
            target_path=target_path,
            capabilities=context.capabilities,
            artifacts=hardened_artifacts,
            total_detected_bytes=total_detected_bytes,
            net_logical_bytes=net_logical_bytes,
            by_domain=by_domain,
            by_action=by_action,
            by_category=by_category,
            detector_runs=detector_runs,
            detector_errors=detector_errors,
            coverage_status=coverage_status,
        )
