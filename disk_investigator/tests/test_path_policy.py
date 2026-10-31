"""
Unit tests for path_policy module.
"""

import os
import unittest
from disk_investigator.path_policy import (
    canonicalize_path,
    is_protected_system_path,
    is_critical_boundary,
    is_cloud_sync_path,
    determine_node_kind,
    is_network_share,
)
from disk_investigator.models import NodeKind


class TestPathPolicy(unittest.TestCase):
    def test_canonicalize_path(self):
        self.assertEqual(canonicalize_path("c:"), "C:\\")
        self.assertEqual(canonicalize_path("C:"), "C:\\")
        self.assertEqual(canonicalize_path("c:\\"), "C:\\")
        self.assertEqual(canonicalize_path("c:/windows/system32"), "C:\\windows\\system32")

    def test_is_protected_system_path(self):
        self.assertTrue(is_protected_system_path("C:\\Windows"))
        self.assertTrue(is_protected_system_path("C:\\Windows\\System32"))
        self.assertTrue(is_protected_system_path("C:\\Program Files\\Common Files"))
        self.assertTrue(is_protected_system_path("C:\\ProgramData"))
        self.assertTrue(is_protected_system_path("C:\\"))
        self.assertTrue(is_protected_system_path("D:\\"))
        self.assertTrue(is_protected_system_path("c:\\recovery"))
        self.assertTrue(is_protected_system_path("C:\\$Recycle.Bin"))
        self.assertTrue(is_protected_system_path("C:\\pagefile.sys"))

        # User projects should NOT be protected
        self.assertFalse(is_protected_system_path("D:\\D-Personal\\disk-cleaner"))
        self.assertFalse(is_protected_system_path("C:\\Users\\user\\Projects"))

    def test_is_critical_boundary(self):
        self.assertTrue(is_critical_boundary("C:\\"))
        self.assertTrue(is_critical_boundary("D:\\"))
        self.assertTrue(is_critical_boundary("C:\\Users"))
        self.assertTrue(is_critical_boundary("C:\\Users\\"))
        self.assertTrue(is_critical_boundary("C:\\Users\\anyuser\\.ssh"))
        self.assertTrue(is_critical_boundary("C:\\Users\\anyuser\\.ssh\\id_rsa"))
        self.assertTrue(is_critical_boundary("C:\\Users\\anyuser\\.gnupg"))
        self.assertTrue(is_critical_boundary("C:\\Users\\anyuser\\.aws\\credentials"))
        self.assertFalse(is_critical_boundary("C:\\Users\\anyuser\\workspace\\project"))

    def test_is_network_share(self):
        self.assertTrue(is_network_share("\\\\nas\\share\\folder"))
        self.assertTrue(is_network_share("//server/data"))
        self.assertFalse(is_network_share("C:\\local\\folder"))

    def test_determine_node_kind(self):
        # Current file should be FILE
        self.assertEqual(determine_node_kind(__file__), NodeKind.FILE)
        # Current dir should be DIRECTORY
        self.assertEqual(determine_node_kind(os.path.dirname(__file__)), NodeKind.DIRECTORY)


if __name__ == "__main__":
    unittest.main()
