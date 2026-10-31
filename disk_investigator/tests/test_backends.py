"""
Unit tests for Dust and Native backends.
"""

import os
import tempfile
import unittest
from disk_investigator.backends import DustBackend, NativeWindowsBackend
from disk_investigator.models import BackendKind, NodeKind


class TestBackends(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_path = self.temp_dir.name

        # Create subdirectories and test files
        self.sub_a = os.path.join(self.base_path, "sub_a")
        self.sub_b = os.path.join(self.base_path, "sub_b")
        os.makedirs(self.sub_a)
        os.makedirs(self.sub_b)

        with open(os.path.join(self.sub_a, "file1.txt"), "wb") as f:
            f.write(b"x" * 1024)  # 1 KB

        with open(os.path.join(self.sub_b, "file2.txt"), "wb") as f:
            f.write(b"y" * 2048)  # 2 KB

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_native_backend(self):
        backend = NativeWindowsBackend()
        self.assertTrue(backend.is_available())
        node = backend.scan(self.base_path, depth=2)
        self.assertEqual(node.kind, NodeKind.DIRECTORY)
        self.assertGreaterEqual(node.logical_bytes, 3072)
        self.assertEqual(len(node.children), 2)

    def test_native_backend_max_entries_sets_children_incomplete(self):
        backend = NativeWindowsBackend()
        # Scan with max_entries=1 on a folder with 2 subdirs
        node = backend.scan(self.base_path, depth=1, max_entries=1)
        self.assertEqual(len(node.children), 1)
        self.assertFalse(node.children_complete)

    def test_native_backend_partial_propagation(self):
        from disk_investigator.models import ScanStatus, SizeSemantics
        backend = NativeWindowsBackend()
        # In a deep hierarchy where child reaches depth limit or partial error
        node = backend.scan(self.base_path, depth=1)
        # depth=1 means sub_a and sub_b were scanned at max_depth=1 with _fast_dir_size
        # which has dir_complete=True and children_complete=False for children
        self.assertFalse(node.children[0].children_complete)

    def test_dust_backend_if_available(self):
        backend = DustBackend()
        if not backend.is_available():
            self.skipTest("Dust CLI not installed")

        node = backend.scan(self.base_path, depth=2)
        self.assertEqual(node.source_backend, BackendKind.DUST)
        self.assertGreater(node.logical_bytes, 0)
        self.assertGreaterEqual(len(node.children), 1)


if __name__ == "__main__":
    unittest.main()
