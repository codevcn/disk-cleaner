"""
Unit tests for CleanupPlan generation and SafeExecutor pre-flight checks.
"""

import os
import tempfile
import unittest
from unittest.mock import patch
from disk_investigator.cleanup import PlanGenerator, SafeExecutor, ActionType
from disk_investigator.classifiers import RiskLevel, Disposition
from disk_investigator.path_policy import canonicalize_path


class TestCleanup(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base = self.temp_dir.name
        self.plans_dir = os.path.join(self.base, "plans")
        os.environ["DISK_INVESTIGATOR_CACHE_DIR"] = self.base

        self.cache_item = os.path.join(self.base, "temp_cache")
        os.makedirs(self.cache_item)
        with open(os.path.join(self.cache_item, "cached.bin"), "wb") as f:
            f.write(b"1" * 1024)

    def tearDown(self):
        if "DISK_INVESTIGATOR_CACHE_DIR" in os.environ:
            del os.environ["DISK_INVESTIGATOR_CACHE_DIR"]
        self.temp_dir.cleanup()

    def test_plan_generation_typed_action_binding(self):
        planner = PlanGenerator(cache_dir=os.path.join(self.base, "plans"))
        candidates = [
            {
                "path": self.cache_item,
                "artifact_type": "package_cache",
                "owner_app": "npm",
                "logical_bytes": 1024,
            }
        ]

        # Case A: When path matches active tool cache path, bind typed action NPM_CACHE_CLEAN
        with patch("disk_investigator.cleanup.plan_generator.get_tool_cache_path", return_value=canonicalize_path(self.cache_item).lower()):
            plan = planner.generate_plan(target_root=self.base, candidates=candidates)
            self.assertEqual(plan.total_items, 1)
            self.assertEqual(plan.items[0].action_type, ActionType.NPM_CACHE_CLEAN)
            self.assertEqual(plan.items[0].immediate_reclaimable_bytes, 1024)
            self.assertEqual(plan.items[0].recycle_bin_bytes, 0)
            self.assertEqual(plan.items[0].risk, RiskLevel.LOW)

        # Case B: When path does not match active tool cache path, fallback safely to RECYCLE_PATH
        with patch("disk_investigator.cleanup.plan_generator.get_tool_cache_path", return_value="c:\\other\\npm-cache"):
            plan_fallback = planner.generate_plan(target_root=self.base, candidates=candidates)
            self.assertEqual(plan_fallback.total_items, 1)
            self.assertEqual(plan_fallback.items[0].action_type, ActionType.RECYCLE_PATH)
            self.assertEqual(plan_fallback.items[0].immediate_reclaimable_bytes, 0)
            self.assertEqual(plan_fallback.items[0].recycle_bin_bytes, 1024)

    def test_safe_executor_preflight_and_dryrun(self):
        planner = PlanGenerator(cache_dir=os.path.join(self.base, "plans"))
        candidates = [
            {
                "path": self.cache_item,
                "artifact_type": "package_cache",
                "owner_app": "npm",
                "logical_bytes": 1024,
            }
        ]
        
        # Test dry-run with RECYCLE_PATH: confirms projected recycle bin bytes while actual immediate is 0
        plan_recycle = planner.generate_plan(target_root=self.base, candidates=candidates)
        executor = SafeExecutor()
        res_recycle = executor.execute(plan=plan_recycle, item_ids=[1], dry_run=True)
        self.assertTrue(res_recycle.dry_run)
        self.assertEqual(res_recycle.succeeded_count, 1)
        self.assertEqual(res_recycle.projected_recycle_bin_bytes, 1024)
        self.assertEqual(res_recycle.projected_immediate_reclaimable_bytes, 0)
        self.assertEqual(res_recycle.immediate_reclaimed_bytes, 0)

        # Test dry-run with typed action: confirms projected immediate reclaimable bytes
        with patch("disk_investigator.cleanup.plan_generator.get_tool_cache_path", return_value=canonicalize_path(self.cache_item).lower()):
            plan_typed = planner.generate_plan(target_root=self.base, candidates=candidates)
        
        with patch("disk_investigator.cleanup.safe_executor.get_tool_cache_path", return_value=canonicalize_path(self.cache_item).lower()):
            res_typed = executor.execute(plan=plan_typed, item_ids=[1], dry_run=True)
            self.assertTrue(res_typed.dry_run)
            self.assertEqual(res_typed.succeeded_count, 1)
            self.assertEqual(res_typed.projected_immediate_reclaimable_bytes, 1024)
            self.assertEqual(res_typed.projected_recycle_bin_bytes, 0)
            self.assertEqual(res_typed.immediate_reclaimed_bytes, 0)

        # Ensure empty items raises ValueError (defense-in-depth against bulk deletion)
        with self.assertRaises(ValueError):
            executor.execute(plan=plan_recycle, item_ids=[], dry_run=True)

    def test_plan_id_traversal_refusal(self):
        planner = PlanGenerator(cache_dir=os.path.join(self.base, "plans"))
        # Must refuse path traversal patterns
        with self.assertRaises(ValueError):
            planner.load_plan("../../etc/passwd")
        with self.assertRaises(ValueError):
            planner.load_plan("..\\..\\secret")
        with self.assertRaises(ValueError):
            planner.load_plan("plan_invalid#name")


if __name__ == "__main__":
    unittest.main()
