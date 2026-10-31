"""
Unit tests for ScanService and DrilldownService.
"""

import os
import tempfile
import unittest
from disk_investigator.services import ScanService, DrilldownService
from disk_investigator.models import BackendKind


class TestServices(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_path = self.temp_dir.name

        self.cache_dir = os.path.join(self.base_path, ".cache")
        self.service = ScanService(cache_dir=self.cache_dir)
        self.drill_service = DrilldownService(self.service)

        # Create sample folder hierarchy
        self.hotspot = os.path.join(self.base_path, "hotspot")
        os.makedirs(self.hotspot)
        with open(os.path.join(self.hotspot, "heavy.bin"), "wb") as f:
            f.write(b"0" * (1024 * 100))  # 100 KB

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_scan_and_snapshot_lifecycle(self):
        snapshot = self.service.scan_path(self.base_path, depth=2)
        self.assertTrue(snapshot.snapshot_id.startswith("snap_"))
        self.assertGreater(snapshot.summary["total_bytes"], 0)

        # Verify snapshot was saved
        loaded = self.service.load_snapshot(snapshot.snapshot_id)
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.snapshot_id, snapshot.snapshot_id)

    def test_drilldown_service(self):
        root_snap = self.service.scan_path(self.base_path, depth=1)
        drill_res = self.drill_service.drilldown(
            target_path=self.hotspot,
            depth=2,
            parent_snapshot_id=root_snap.snapshot_id,
        )
        self.assertEqual(drill_res["parent_snapshot_id"], root_snap.snapshot_id)
        self.assertTrue(drill_res["snapshot_id"].startswith("snap_"))
        self.assertGreaterEqual(len(drill_res["dominant_consumers"]), 1)


if __name__ == "__main__":
    unittest.main()
