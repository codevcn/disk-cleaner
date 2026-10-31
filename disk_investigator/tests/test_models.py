"""
Unit tests for models serialization and deserialization.
"""

import unittest
from disk_investigator.models import (
    FileSystemNode,
    NodeKind,
    ScanStatus,
    SizeSemantics,
    BackendKind,
    ScanSnapshot,
    DriveOverview,
)


class TestModels(unittest.TestCase):
    def test_node_to_from_dict(self):
        child = FileSystemNode(
            path="C:\\test\\sub",
            canonical_path="C:\\test\\sub",
            name="sub",
            kind=NodeKind.DIRECTORY,
            logical_bytes=1024,
            allocated_bytes=1024,
            source_backend=BackendKind.DUST,
        )
        parent = FileSystemNode(
            path="C:\\test",
            canonical_path="C:\\test",
            name="test",
            kind=NodeKind.DIRECTORY,
            logical_bytes=2048,
            allocated_bytes=2048,
            source_backend=BackendKind.DUST,
            children=[child],
        )

        d = parent.to_dict()
        self.assertEqual(d["path"], "C:\\test")
        self.assertEqual(d["logical_bytes"], 2048)
        self.assertEqual(len(d["children"]), 1)
        self.assertEqual(d["children"][0]["path"], "C:\\test\\sub")

        reconstructed = FileSystemNode.from_dict(d)
        self.assertEqual(reconstructed.path, parent.path)
        self.assertEqual(len(reconstructed.children), 1)
        self.assertEqual(reconstructed.children[0].name, "sub")

    def test_snapshot_to_from_dict(self):
        root = FileSystemNode(
            path="D:\\data",
            canonical_path="D:\\data",
            name="data",
            kind=NodeKind.DIRECTORY,
            logical_bytes=5000,
            source_backend=BackendKind.NATIVE,
        )
        snap = ScanSnapshot(
            snapshot_id="snap_12345",
            root_path="D:\\data",
            backend=BackendKind.NATIVE,
            depth=2,
            root_node=root,
            summary={"total_bytes": 5000},
        )
        d = snap.to_dict()
        self.assertEqual(d["snapshot_id"], "snap_12345")
        reconstructed = ScanSnapshot.from_dict(d)
        self.assertEqual(reconstructed.snapshot_id, snap.snapshot_id)
        self.assertEqual(reconstructed.root_node.logical_bytes, 5000)


if __name__ == "__main__":
    unittest.main()
