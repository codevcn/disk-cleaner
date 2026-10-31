"""
Unit tests for RiskClassifier and policy disposition.
"""

import unittest
from disk_investigator.classifiers import (
    RiskClassifier,
    RiskLevel,
    Disposition,
    Confidence,
)


class TestClassifiers(unittest.TestCase):
    def setUp(self):
        self.classifier = RiskClassifier()

    def test_windows_system_blocked(self):
        res = self.classifier.classify("C:\\Windows\\System32")
        self.assertEqual(res.risk, RiskLevel.HIGH)
        self.assertEqual(res.disposition, Disposition.BLOCKED)
        self.assertEqual(res.regenerable, "NO")

    def test_cloud_sync_blocked(self):
        res = self.classifier.classify("C:\\Users\\dell\\OneDrive\\Documents")
        self.assertEqual(res.risk, RiskLevel.HIGH)
        self.assertEqual(res.disposition, Disposition.BLOCKED)

    def test_docker_vhdx_blocked(self):
        res = self.classifier.classify("C:\\Users\\dell\\AppData\\Local\\Docker\\wsl\\data\\ext4.vhdx")
        self.assertEqual(res.risk, RiskLevel.HIGH)
        self.assertEqual(res.disposition, Disposition.BLOCKED)

    def test_package_cache_cleanable(self):
        res = self.classifier.classify(
            path="C:\\Users\\dell\\AppData\\Local\\npm-cache",
            artifact_type="package_cache",
            owner_app="npm",
        )
        self.assertEqual(res.risk, RiskLevel.LOW)
        self.assertEqual(res.disposition, Disposition.CLEANABLE)
        self.assertEqual(res.regenerable, "YES")

    def test_node_modules_review_required(self):
        res = self.classifier.classify(
            path="D:\\Projects\\app\\node_modules",
            artifact_type="node_modules",
            stale_candidate=True,
        )
        self.assertEqual(res.risk, RiskLevel.MEDIUM)
        self.assertEqual(res.disposition, Disposition.REVIEW_REQUIRED)
        self.assertEqual(res.regenerable, "YES")


if __name__ == "__main__":
    unittest.main()
