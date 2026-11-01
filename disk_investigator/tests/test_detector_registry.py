"""
Unit tests for DetectorRegistry and Detector base contracts.
"""

import unittest
from disk_investigator.detectors import BaseDetector, DetectorRegistry
from disk_investigator.models import (
    ArtifactCategory,
    ArtifactDomain,
    Confidence,
    DetectionContext,
    RecommendedAction,
    RecoveryCost,
    Regenerability,
    StorageArtifact,
    UserDataProbability,
)


class DummyDetector(BaseDetector):
    detector_id = "test.dummy"
    domain = ArtifactDomain.DEVELOPER

    def __init__(self, applicable_result=True, should_raise=False):
        self.applicable_result = applicable_result
        self.should_raise = should_raise

    def applicable(self, context: DetectionContext) -> bool:
        if self.should_raise:
            raise RuntimeError("Applicability error")
        return self.applicable_result

    def detect(self, context: DetectionContext) -> list[StorageArtifact]:
        if self.should_raise:
            raise RuntimeError("Detection crash")
        return [
            StorageArtifact(
                artifact_id="art-1",
                path="C:\\dummy\\path",
                canonical_path="C:\\dummy\\path",
                domain=self.domain,
                category=ArtifactCategory.CACHE,
                artifact_type="dummy_cache",
                logical_bytes=1024,
                source_detector=self.detector_id,
                recommended_action=RecommendedAction.RECYCLE_KNOWN_CACHE,
            )
        ]


class TestDetectorRegistry(unittest.TestCase):
    def setUp(self):
        self.registry = DetectorRegistry()

    def test_register_and_list(self):
        d1 = DummyDetector()
        self.registry.register(d1)
        self.assertEqual(len(self.registry.list_detectors()), 1)
        self.assertEqual(self.registry.get("test.dummy"), d1)

    def test_unregister(self):
        d1 = DummyDetector()
        self.registry.register(d1)
        removed = self.registry.unregister("test.dummy")
        self.assertEqual(removed, d1)
        self.assertIsNone(self.registry.get("test.dummy"))
        self.assertEqual(len(self.registry.list_detectors()), 0)

    def test_applicable_filtering(self):
        d_yes = DummyDetector(applicable_result=True)
        d_yes.detector_id = "test.yes"
        d_no = DummyDetector(applicable_result=False)
        d_no.detector_id = "test.no"

        self.registry.register(d_yes)
        self.registry.register(d_no)

        ctx = DetectionContext(target_path="C:\\test")
        applicable = self.registry.get_applicable_detectors(ctx)
        self.assertEqual(len(applicable), 1)
        self.assertEqual(applicable[0].detector_id, "test.yes")

    def test_fault_isolation_applicability(self):
        d_broken = DummyDetector(should_raise=True)
        d_broken.detector_id = "test.broken"
        d_ok = DummyDetector(applicable_result=True)
        d_ok.detector_id = "test.ok"

        self.registry.register(d_broken)
        self.registry.register(d_ok)

        ctx = DetectionContext(target_path="C:\\test")
        # Registry must not raise when checking applicability
        applicable = self.registry.get_applicable_detectors(ctx)
        self.assertEqual(len(applicable), 1)
        self.assertEqual(applicable[0].detector_id, "test.ok")

    def test_fault_isolation_detection_run(self):
        d_crash = DummyDetector(applicable_result=True, should_raise=True)
        d_crash.detector_id = "test.crash"
        d_ok = DummyDetector(applicable_result=True, should_raise=False)
        d_ok.detector_id = "test.ok"

        self.registry.register(d_crash)
        self.registry.register(d_ok)

        ctx = DetectionContext(target_path="C:\\test")
        # Detection run must not crash even if one detector throws
        artifacts = self.registry.run_detectors(ctx)
        self.assertEqual(len(artifacts), 1)
        self.assertEqual(artifacts[0].artifact_id, "art-1")


if __name__ == "__main__":
    unittest.main()
