"""
Unit tests for Phase 6: Typed Action Framework, Plan Schema v2, and Process Running Safeguards.
"""

import os
import tempfile
import time
import unittest
from unittest.mock import patch

from disk_investigator.classifiers import Disposition, RiskLevel
from disk_investigator.cleanup import (
    ActionRegistry,
    ActionType,
    CleanupPlan,
    PlanGenerator,
    PlanItem,
    SafeExecutor,
    create_default_action_registry,
)
from disk_investigator.cleanup.safe_executor import PlanIntegrityError
from disk_investigator.models import (
    ArtifactCategory,
    ArtifactDomain,
    Evidence,
    RecommendedAction,
    RecoveryCost,
    Regenerability,
    StorageArtifact,
    UserDataProbability,
)


class TestActionFramework(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base = self.temp_dir.name
        self.plans_dir = os.path.join(self.base, "plans")
        os.environ["DISK_INVESTIGATOR_CACHE_DIR"] = self.base

    def tearDown(self):
        if "DISK_INVESTIGATOR_CACHE_DIR" in os.environ:
            del os.environ["DISK_INVESTIGATOR_CACHE_DIR"]
        self.temp_dir.cleanup()

    def test_schema_version_2_enforced_legacy_v1_rejected(self):
        target_file = os.path.join(self.base, "item.tmp")
        with open(target_file, "w") as f:
            f.write("content")

        planner = PlanGenerator(cache_dir=self.plans_dir)
        plan = planner.generate_plan(
            target_root=self.base,
            candidates=[{"path": target_file, "artifact_type": "temporary", "logical_bytes": 7}],
        )
        self.assertEqual(plan.schema_version, 2)

        # Force downgrade to legacy schema version 1
        plan.schema_version = 1

        executor = SafeExecutor()
        with self.assertRaises(PlanIntegrityError) as ctx:
            executor.execute(plan=plan, item_ids=[1], dry_run=False)

        self.assertIn("LEGACY_PLAN_UNSUPPORTED", str(ctx.exception))

    def test_plan_overlapping_items_filtered_out(self):
        parent_dir = os.path.join(self.base, "app_cache")
        child_dir = os.path.join(parent_dir, "nested_subcache")
        os.makedirs(child_dir)

        with open(os.path.join(parent_dir, "root.bin"), "w") as f:
            f.write("parent")
        with open(os.path.join(child_dir, "child.bin"), "w") as f:
            f.write("child")

        planner = PlanGenerator(cache_dir=self.plans_dir)
        # Offer both parent and child as cleanup candidates
        candidates = [
            {"path": parent_dir, "artifact_type": "temporary", "logical_bytes": 100},
            {"path": child_dir, "artifact_type": "temporary", "logical_bytes": 40},
        ]
        plan = planner.generate_plan(target_root=self.base, candidates=candidates)

        # Invariant: Child item is filtered out to avoid double deletion / double counting
        self.assertEqual(plan.total_items, 1)
        self.assertEqual(plan.items[0].path, parent_dir)

    def test_app_running_skip_safeguard_never_kills_process(self):
        browser_cache = os.path.join(self.base, "ChromeCache")
        os.makedirs(browser_cache)
        with open(os.path.join(browser_cache, "data"), "w") as f:
            f.write("cache data")

        planner = PlanGenerator(cache_dir=self.plans_dir)
        candidates = [
            {"path": browser_cache, "artifact_type": "browser_cache", "logical_bytes": 10},
        ]
        plan = planner.generate_plan(target_root=self.base, candidates=candidates)
        self.assertEqual(plan.items[0].action_type, ActionType.BROWSER_CACHE_PURGE)

        executor = SafeExecutor()

        # Simulate browser running (e.g. chrome.exe is active)
        with patch("disk_investigator.cleanup.action_registry.is_process_running", return_value=True):
            res = executor.execute(plan=plan, item_ids=[1], dry_run=False)
            self.assertEqual(res.succeeded_count, 0)
            self.assertEqual(res.failed_count, 1)
            self.assertIn("is running", res.failed_items[0]["error"])
            # Cache files must remain untouched
            self.assertTrue(os.path.exists(browser_cache))

    def test_generate_plan_from_storage_artifacts(self):
        # 1. Cleanable cache artifact
        cache_dir = os.path.join(self.base, "MyCache")
        os.makedirs(cache_dir)
        with open(os.path.join(cache_dir, "c.tmp"), "w") as f:
            f.write("tmp")

        art_cleanable = StorageArtifact(
            artifact_id="art-clean",
            path=cache_dir,
            canonical_path=cache_dir,
            domain=ArtifactDomain.BROWSER,
            category=ArtifactCategory.CACHE,
            artifact_type="browser_cache",
            logical_bytes=100,
            recommended_action=RecommendedAction.TYPED_CLEANUP,
            user_data_probability=UserDataProbability.LOW,
        )

        # 2. Blocked user database artifact
        history_file = os.path.join(self.base, "History")
        with open(history_file, "w") as f:
            f.write("sqlite history")

        art_blocked = StorageArtifact(
            artifact_id="art-block",
            path=history_file,
            canonical_path=history_file,
            domain=ArtifactDomain.BROWSER,
            category=ArtifactCategory.USER_DOCUMENT,
            artifact_type="browser_user_data",
            logical_bytes=5000,
            recommended_action=RecommendedAction.BLOCK,
            user_data_probability=UserDataProbability.HIGH,
        )

        planner = PlanGenerator(cache_dir=self.plans_dir)
        plan = planner.generate_plan(target_root=self.base, candidates=[art_cleanable, art_blocked])

        # Blocked artifact must be completely excluded from cleanup plan
        self.assertEqual(plan.total_items, 1)
        self.assertEqual(plan.items[0].path, cache_dir)
        self.assertEqual(plan.items[0].action_type, ActionType.BROWSER_CACHE_PURGE)
        self.assertEqual(plan.items[0].artifact_id, "art-clean")
        self.assertEqual(plan.items[0].domain, "browser")
        self.assertEqual(plan.items[0].category, "cache")
        self.assertIsNotNone(plan.items[0].action_binding)
        self.assertEqual(plan.items[0].action_binding["action"], ActionType.BROWSER_CACHE_PURGE.value)

    def test_plan_item_action_binding_tamper_fails_hmac(self):
        target_file = os.path.join(self.base, "tamper_target.tmp")
        with open(target_file, "w") as f:
            f.write("content")

        planner = PlanGenerator(cache_dir=self.plans_dir)
        plan = planner.generate_plan(
            target_root=self.base,
            candidates=[{"path": target_file, "artifact_type": "temporary", "logical_bytes": 7}],
        )

        # Adversarially tamper with action_binding without recomputing HMAC
        plan.items[0].action_binding = {"action": "MALICIOUS_ACTION"}

        executor = SafeExecutor()
        with self.assertRaises(PlanIntegrityError) as ctx:
            executor.execute(plan=plan, item_ids=[1], dry_run=False)

        self.assertIn("Plan hash mismatch", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
