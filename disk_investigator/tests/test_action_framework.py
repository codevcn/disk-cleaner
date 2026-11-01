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

    def test_plan_generator_strict_allowlist_excludes_keep_and_uninstall(self):
        """V22-FINAL-01 & V22-FINAL-02: Ensure KEEP and UNINSTALL_VIA_APP are strictly impossible in plan."""
        f_keep = os.path.join(self.base, "keep.bin")
        f_uninstall = os.path.join(self.base, "uninstall.bin")
        f_review = os.path.join(self.base, "review.bin")
        f_block = os.path.join(self.base, "block.bin")
        f_typed = os.path.join(self.base, "typed.tmp")
        f_recycle = os.path.join(self.base, "recycle.tmp")

        for fpath in (f_keep, f_uninstall, f_review, f_block, f_typed, f_recycle):
            with open(fpath, "w") as f:
                f.write("data")

        art_keep = StorageArtifact(
            artifact_id="art-keep",
            path=f_keep,
            canonical_path=f_keep,
            domain=ArtifactDomain.SYSTEM,
            category=ArtifactCategory.CACHE,
            artifact_type="temporary",
            logical_bytes=10,
            recommended_action=RecommendedAction.KEEP,
            user_data_probability=UserDataProbability.LOW,
        )
        art_uninstall = StorageArtifact(
            artifact_id="art-uninstall",
            path=f_uninstall,
            canonical_path=f_uninstall,
            domain=ArtifactDomain.DEVELOPER,
            category=ArtifactCategory.CACHE,
            artifact_type="temporary",
            logical_bytes=10,
            recommended_action=RecommendedAction.UNINSTALL_VIA_APP,
            user_data_probability=UserDataProbability.LOW,
        )
        art_review = StorageArtifact(
            artifact_id="art-review",
            path=f_review,
            canonical_path=f_review,
            domain=ArtifactDomain.SYSTEM,
            category=ArtifactCategory.CACHE,
            artifact_type="temporary",
            logical_bytes=10,
            recommended_action=RecommendedAction.REVIEW_ONLY,
            user_data_probability=UserDataProbability.LOW,
        )
        art_block = StorageArtifact(
            artifact_id="art-block",
            path=f_block,
            canonical_path=f_block,
            domain=ArtifactDomain.SYSTEM,
            category=ArtifactCategory.CACHE,
            artifact_type="temporary",
            logical_bytes=10,
            recommended_action=RecommendedAction.BLOCK,
            user_data_probability=UserDataProbability.LOW,
        )
        art_typed = StorageArtifact(
            artifact_id="art-typed",
            path=f_typed,
            canonical_path=f_typed,
            domain=ArtifactDomain.SYSTEM,
            category=ArtifactCategory.CACHE,
            artifact_type="temporary",
            logical_bytes=10,
            recommended_action=RecommendedAction.TYPED_CLEANUP,
            user_data_probability=UserDataProbability.LOW,
        )
        art_recycle = StorageArtifact(
            artifact_id="art-recycle",
            path=f_recycle,
            canonical_path=f_recycle,
            domain=ArtifactDomain.SYSTEM,
            category=ArtifactCategory.CACHE,
            artifact_type="temporary",
            logical_bytes=10,
            recommended_action=RecommendedAction.RECYCLE_KNOWN_CACHE,
            user_data_probability=UserDataProbability.LOW,
        )

        planner = PlanGenerator(cache_dir=self.plans_dir)
        plan = planner.generate_plan(
            target_root=self.base,
            candidates=[art_keep, art_uninstall, art_review, art_block, art_typed, art_recycle],
        )

        # Only TYPED_CLEANUP and RECYCLE_KNOWN_CACHE must be accepted
        self.assertEqual(plan.total_items, 2)
        paths_in_plan = {i.path for i in plan.items}
        self.assertIn(f_typed, paths_in_plan)
        self.assertIn(f_recycle, paths_in_plan)
        self.assertNotIn(f_keep, paths_in_plan)
        self.assertNotIn(f_uninstall, paths_in_plan)
        self.assertNotIn(f_review, paths_in_plan)
        self.assertNotIn(f_block, paths_in_plan)

    def test_correlator_keep_takes_precedence_over_typed_cleanup(self):
        """V22-FINAL-03: Correlator non-cleanup actions strictly take precedence over cleanup actions."""
        from disk_investigator.services.artifact_correlator import ArtifactCorrelator

        shared_path = os.path.join(self.base, "shared.bin")
        art_cleanup = StorageArtifact(
            artifact_id="art-1",
            path=shared_path,
            canonical_path=shared_path,
            domain=ArtifactDomain.DEVELOPER,
            category=ArtifactCategory.CACHE,
            artifact_type="build_cache",
            logical_bytes=1000,
            recommended_action=RecommendedAction.TYPED_CLEANUP,
            user_data_probability=UserDataProbability.LOW,
        )
        art_keep = StorageArtifact(
            artifact_id="art-2",
            path=shared_path,
            canonical_path=shared_path,
            domain=ArtifactDomain.CREATOR,
            category=ArtifactCategory.USER_DOCUMENT,
            artifact_type="source_media",
            logical_bytes=1000,
            recommended_action=RecommendedAction.KEEP,
            user_data_probability=UserDataProbability.HIGH,
        )

        correlated = ArtifactCorrelator.correlate([art_cleanup, art_keep])
        self.assertEqual(len(correlated), 1)
        self.assertEqual(correlated[0].recommended_action, RecommendedAction.KEEP)
        self.assertEqual(correlated[0].user_data_probability, UserDataProbability.HIGH)

    def test_process_state_fail_closed_tri_state(self):
        """V22-FINAL-07: Process guard tri-state fail-closed checks."""
        from disk_investigator.cleanup.action_registry import (
            ProcessState,
            check_process_state,
            is_process_running,
        )

        # 1. Process found -> RUNNING
        with patch("subprocess.run") as mock_sub:
            mock_sub.return_value.returncode = 0
            mock_sub.return_value.stdout = "chrome.exe  1234 Console"
            self.assertEqual(check_process_state("chrome.exe"), ProcessState.RUNNING)
            self.assertTrue(is_process_running("chrome.exe"))

        # 2. Confirmed not running -> NOT_RUNNING
        with patch("subprocess.run") as mock_sub:
            mock_sub.return_value.returncode = 0
            mock_sub.return_value.stdout = "INFO: No tasks are running which match the specified criteria."
            self.assertEqual(check_process_state("chrome.exe"), ProcessState.NOT_RUNNING)
            self.assertFalse(is_process_running("chrome.exe"))

        # 3. Timeout or exception -> UNKNOWN and fail-closed
        with patch("subprocess.run", side_effect=TimeoutError("tasklist timeout")):
            self.assertEqual(check_process_state("chrome.exe"), ProcessState.UNKNOWN)
            # is_process_running fails closed (returns True)
            self.assertTrue(is_process_running("chrome.exe"))

        # 4. Non-zero exit code -> UNKNOWN and fail-closed
        with patch("subprocess.run") as mock_sub:
            mock_sub.return_value.returncode = 1
            mock_sub.return_value.stdout = ""
            self.assertEqual(check_process_state("chrome.exe"), ProcessState.UNKNOWN)
            self.assertTrue(is_process_running("chrome.exe"))

    def test_preflight_target_binding_guards(self):
        """V22-FINAL-06: Target-binding preflight checks across typed actions."""
        executor = SafeExecutor()

        # Browser cache purge targeting a root without cache markers
        bad_browser_item = PlanItem(
            item_id=1,
            path=os.path.join(self.base, "AppData", "Local", "Google", "Chrome", "User Data"),
            expected_kind="directory",
            candidate_bytes=100,
            expected_mtime=time.time(),
            risk=RiskLevel.LOW,
            disposition=Disposition.CLEANABLE,
            action_type=ActionType.BROWSER_CACHE_PURGE,
            description="Bad browser target",
            immediate_reclaimable_bytes=0,
            recycle_bin_bytes=100,
            potential_reclaim_bytes=100,
        )
        os.makedirs(bad_browser_item.path, exist_ok=True)
        err = executor.preflight_check(bad_browser_item)
        self.assertIsNotNone(err)
        self.assertIn("does not contain recognized browser cache marker", err)

        # Office cache purge targeting PST file
        bad_pst_path = os.path.join(self.base, "archive.pst")
        with open(bad_pst_path, "w") as f:
            f.write("pst data")
        bad_office_item = PlanItem(
            item_id=2,
            path=bad_pst_path,
            expected_kind="file",
            candidate_bytes=8,
            expected_mtime=time.time(),
            risk=RiskLevel.LOW,
            disposition=Disposition.CLEANABLE,
            action_type=ActionType.OFFICE_CACHE_PURGE,
            description="Bad office target",
            immediate_reclaimable_bytes=0,
            recycle_bin_bytes=8,
            potential_reclaim_bytes=8,
        )
        err = executor.preflight_check(bad_office_item)
        self.assertIsNotNone(err)
        self.assertIn("recognized Office/Teams cache directory", err)

    def test_detector_fault_visibility_in_investigation_result(self):
        """V22-FINAL-08: Detector faults are exposed in InvestigationResult with partial coverage."""
        from disk_investigator.detectors.base import Detector
        from disk_investigator.detectors.registry import DetectorRegistry
        from disk_investigator.services.investigation_service import InvestigationService
        from disk_investigator.models import DetectionContext

        class FaultyDetector(Detector):
            detector_id = "test.faulty"
            name = "Faulty Detector"

            def applicable(self, context):
                return True

            def detect(self, context):
                raise PermissionError("Access denied to protected volume")

        registry = DetectorRegistry()
        registry.register(FaultyDetector())

        svc = InvestigationService(registry=registry)
        ctx = DetectionContext(target_path=self.base, capabilities={}, env={})
        res = svc.investigate(target_path=self.base, context=ctx)

        self.assertEqual(res.coverage_status, "partial")
        self.assertEqual(len(res.detector_errors), 1)
        self.assertEqual(res.detector_errors[0]["detector_id"], "test.faulty")
        self.assertIn("Access denied", res.detector_errors[0]["error"])


if __name__ == "__main__":
    unittest.main()
