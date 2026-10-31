"""
Unit tests for DeveloperDetector, DockerDetector, and LargeFilesDetector.
"""

import os
import tempfile
import unittest
from disk_investigator.detectors import DeveloperDetector, DockerDetector, LargeFilesDetector


class TestDetectors(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base = self.temp_dir.name

        # Create dummy project structure
        self.proj = os.path.join(self.base, "my_project")
        os.makedirs(self.proj)
        with open(os.path.join(self.proj, "package.json"), "w") as f:
            f.write("{}")

        self.nm = os.path.join(self.proj, "node_modules")
        os.makedirs(self.nm)
        with open(os.path.join(self.nm, "some_pkg.js"), "w") as f:
            f.write("console.log('hi');")

        # Create dummy large file (1MB)
        self.large_file = os.path.join(self.base, "big_iso.iso")
        with open(self.large_file, "wb") as f:
            f.write(b"0" * (1024 * 1024))

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_developer_detector(self):
        detector = DeveloperDetector()
        artifacts = detector.scan_project_tree(self.base)
        self.assertEqual(len(artifacts), 1)
        self.assertEqual(artifacts[0].artifact_type, "node_modules")
        self.assertEqual(artifacts[0].owner_app, "npm/node")
        self.assertEqual(artifacts[0].regenerable, "YES")

    def test_large_files_detector(self):
        detector = LargeFilesDetector()
        large_files = detector.find_large_files(
            root_path=self.base,
            min_size_bytes=500 * 1024,  # 500 KB
        )
        self.assertEqual(len(large_files), 1)
        self.assertEqual(large_files[0].name, "big_iso.iso")
        self.assertEqual(large_files[0].category, "disk_image")

    def test_docker_detector_vhdx_safety(self):
        detector = DockerDetector()
        report = detector.inspect()
        self.assertIn("docker_installed", report)
        self.assertIn("components", report)
        for comp in report["components"]:
            if comp["component_type"] == "vhdx_backing":
                self.assertEqual(comp["disposition"], "BLOCKED")


if __name__ == "__main__":
    unittest.main()
