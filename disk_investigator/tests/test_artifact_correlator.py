"""
Unit tests for ArtifactCorrelator and InvestigationService.
"""

import unittest
from disk_investigator.detectors import BaseDetector, DetectorRegistry
from disk_investigator.discovery.capability_discovery import CapabilityDiscovery
from disk_investigator.discovery.probes import MockExecutableProbe, MockFileSystemProbe, MockRegistryProbe
from disk_investigator.models import (
    ArtifactCategory,
    ArtifactDomain,
    Confidence,
    DetectionContext,
    Evidence,
    RecommendedAction,
    RecoveryCost,
    Regenerability,
    StorageArtifact,
    UserDataProbability,
)
from disk_investigator.services.artifact_correlator import ArtifactCorrelator
from disk_investigator.services.investigation_service import InvestigationService


class TestArtifactCorrelator(unittest.TestCase):
    def test_deduplicate_identical_path_conservative_resolution(self):
        # Detector A thinks it's a cleanable cache
        art_a = StorageArtifact(
            artifact_id="art-a",
            path="C:\\Users\\User\\AppData\\Local\\App\\Cache",
            canonical_path="C:\\Users\\User\\AppData\\Local\\App\\Cache",
            domain=ArtifactDomain.GENERAL,
            category=ArtifactCategory.CACHE,
            artifact_type="cache",
            source_detector="detector_a",
            logical_bytes=1000,
            regenerability=Regenerability.FULL,
            user_data_probability=UserDataProbability.LOW,
            recovery_cost=RecoveryCost.LOW,
            recommended_action=RecommendedAction.TYPED_CLEANUP,
            confidence=Confidence.MEDIUM,
            evidence=[Evidence(kind="rule", source="det_a", value="matched cache folder")],
        )

        # Detector B recognizes it contains protected user data and blocks it
        art_b = StorageArtifact(
            artifact_id="art-b",
            path="c:\\users\\user\\appdata\\local\\app\\cache",
            canonical_path="c:\\users\\user\\appdata\\local\\app\\cache",
            domain=ArtifactDomain.BROWSER,
            category=ArtifactCategory.USER_DOCUMENT,
            artifact_type="profile_store",
            source_detector="detector_b",
            logical_bytes=1200,
            regenerability=Regenerability.NONE,
            user_data_probability=UserDataProbability.HIGH,
            recovery_cost=RecoveryCost.IMPOSSIBLE,
            recommended_action=RecommendedAction.BLOCK,
            confidence=Confidence.HIGH,
            evidence=[Evidence(kind="rule", source="det_b", value="contains user session tokens")],
        )

        correlated = ArtifactCorrelator.correlate([art_a, art_b])
        self.assertEqual(len(correlated), 1)
        merged = correlated[0]

        # Conservative resolution invariants
        self.assertEqual(merged.recommended_action, RecommendedAction.BLOCK)
        self.assertEqual(merged.user_data_probability, UserDataProbability.HIGH)
        self.assertEqual(merged.regenerability, Regenerability.NONE)
        self.assertEqual(merged.recovery_cost, RecoveryCost.IMPOSSIBLE)
        self.assertEqual(merged.logical_bytes, 1200)
        self.assertEqual(merged.domain, ArtifactDomain.BROWSER)
        self.assertEqual(len(merged.evidence), 2)

    def test_containment_annotation(self):
        parent = StorageArtifact(
            artifact_id="parent-1",
            path="C:\\Projects\\repo",
            canonical_path="C:\\Projects\\repo",
            domain=ArtifactDomain.DEVELOPER,
            category=ArtifactCategory.DEPENDENCY,
            artifact_type="project_dir",
            logical_bytes=50000,
        )
        child = StorageArtifact(
            artifact_id="child-1",
            path="C:\\Projects\\repo\\node_modules",
            canonical_path="C:\\Projects\\repo\\node_modules",
            domain=ArtifactDomain.DEVELOPER,
            category=ArtifactCategory.DEPENDENCY,
            artifact_type="node_modules",
            logical_bytes=45000,
        )

        correlated = ArtifactCorrelator.correlate([parent, child])
        self.assertEqual(len(correlated), 2)

        # Find child in correlated
        c = next(a for a in correlated if a.artifact_id == "child-1")
        containment_ev = [e for e in c.evidence if e.kind == "containment"]
        self.assertTrue(len(containment_ev) > 0)
        self.assertIn("parent-1", containment_ev[0].message)

    def test_calculate_net_bytes_avoids_double_counting(self):
        parent = StorageArtifact(
            artifact_id="parent",
            path="C:\\Projects\\repo",
            canonical_path="C:\\Projects\\repo",
            domain=ArtifactDomain.DEVELOPER,
            category=ArtifactCategory.DEPENDENCY,
            artifact_type="repo",
            logical_bytes=1000,
        )
        child = StorageArtifact(
            artifact_id="child",
            path="C:\\Projects\\repo\\.venv",
            canonical_path="C:\\Projects\\repo\\.venv",
            domain=ArtifactDomain.DEVELOPER,
            category=ArtifactCategory.DEPENDENCY,
            artifact_type="venv",
            logical_bytes=600,
        )
        sibling = StorageArtifact(
            artifact_id="sibling",
            path="C:\\Other\\Dir",
            canonical_path="C:\\Other\\Dir",
            domain=ArtifactDomain.GENERAL,
            category=ArtifactCategory.CACHE,
            artifact_type="cache",
            logical_bytes=400,
        )

        # Total detected = 1000 + 600 + 400 = 2000
        # Net logical bytes = 1000 + 400 = 1400 (child is nested in parent)
        net_bytes = ArtifactCorrelator.calculate_net_bytes([parent, child, sibling])
        self.assertEqual(net_bytes, 1400)


class MockTestDetector(BaseDetector):
    detector_id = "test.mock"
    domain = ArtifactDomain.DEVELOPER

    def applicable(self, context: DetectionContext) -> bool:
        return True

    def detect(self, context: DetectionContext) -> list[StorageArtifact]:
        return [
            StorageArtifact(
                artifact_id="mock-art",
                path=f"{context.target_path}\\test_cache",
                canonical_path=f"{context.target_path}\\test_cache",
                domain=self.domain,
                category=ArtifactCategory.CACHE,
                artifact_type="test_cache",
                logical_bytes=1024,
                recommended_action=RecommendedAction.TYPED_CLEANUP,
            )
        ]


class TestInvestigationService(unittest.TestCase):
    def test_investigate_workflow(self):
        discovery = CapabilityDiscovery(
            registry_probe=MockRegistryProbe(),
            fs_probe=MockFileSystemProbe(),
            exe_probe=MockExecutableProbe(),
        )
        registry = DetectorRegistry()
        registry.register(MockTestDetector())

        svc = InvestigationService(discovery=discovery, registry=registry)
        result = svc.investigate(target_path="C:\\my_target")

        self.assertEqual(result.target_path, "C:\\my_target")
        self.assertEqual(len(result.artifacts), 1)
        self.assertEqual(result.total_detected_bytes, 1024)
        self.assertEqual(result.net_logical_bytes, 1024)
        self.assertEqual(result.by_domain.get("developer"), 1024)
        self.assertEqual(result.by_action.get("TYPED_CLEANUP"), 1024)

        # Test serializability
        res_dict = result.to_dict()
        self.assertIn("capabilities_detected", res_dict)
        self.assertIn("artifacts", res_dict)
        self.assertEqual(res_dict["total_detected_bytes"], 1024)


if __name__ == "__main__":
    unittest.main()
