"""
Destructive & TOCTOU end-to-end integration tests for SafeExecutor.
Strictly executed on disposable sacrificial test trees in temporary directories.
Validates:
1. Real Recycle Bin execution and sibling preservation.
2. TOCTOU modification detection and plan staleness refusal.
3. Reparse point / junction shift refusal.
4. Untrusted plan defense (independent policy re-validation).
5. Fail-closed behavior on missing or empty item selections.
"""

import os
import tempfile
import time
import unittest

from disk_investigator.classifiers import Disposition, RiskLevel
from disk_investigator.cleanup import (
    ActionType,
    CleanupPlan,
    PlanGenerator,
    PlanItem,
    SafeExecutor,
)
from disk_investigator.models import RecommendedAction, UserDataProbability


class TestDestructiveE2E(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base = self.temp_dir.name
        self.plans_dir = os.path.join(self.base, "plans")
        os.environ["DISK_INVESTIGATOR_CACHE_DIR"] = self.base

    def tearDown(self):
        if "DISK_INVESTIGATOR_CACHE_DIR" in os.environ:
            del os.environ["DISK_INVESTIGATOR_CACHE_DIR"]
        self.temp_dir.cleanup()

    def test_shell_recycle_operation_and_sibling_preservation(self):
        """Case 1: Executes shell Recycle Bin move on disposable data and confirms sibling is untouched."""
        target_file = os.path.join(self.base, "victim.log")
        sibling_file = os.path.join(self.base, "keeper.txt")

        with open(target_file, "wb") as f:
            f.write(b"SACRIFICIAL LOG DATA" * 100)

        with open(sibling_file, "wb") as f:
            f.write(b"KEEP THIS SIBLING INTACT" * 100)

        planner = PlanGenerator(cache_dir=os.path.join(self.base, "plans"))
        candidates = [
            {
                "path": target_file,
                "artifact_type": "temporary",
                "logical_bytes": os.path.getsize(target_file),
                "recommended_action": RecommendedAction.RECYCLE_KNOWN_CACHE,
                "user_data_probability": UserDataProbability.LOW,
            }
        ]
        plan = planner.generate_plan(target_root=self.base, candidates=candidates)
        self.assertEqual(plan.total_items, 1)

        executor = SafeExecutor()
        # Execute with dry_run = False
        res = executor.execute(plan=plan, item_ids=[1], dry_run=False)

        # 1. Verification of execution result
        self.assertEqual(res.succeeded_count, 1)
        self.assertEqual(res.failed_count, 0)
        self.assertGreater(res.recycle_bin_bytes, 0)
        self.assertIn("Moved to Windows Recycle Bin", res.explanation)

        # 2. Target file must no longer be at the original path (moved to trash)
        self.assertFalse(os.path.exists(target_file))

        # 3. Sibling file must remain completely intact
        self.assertTrue(os.path.exists(sibling_file))
        with open(sibling_file, "rb") as f:
            self.assertIn(b"KEEP THIS SIBLING INTACT", f.read())

    def test_toctou_mtime_drift_refusal(self):
        """Case 2: If a resource is modified after plan generation, executor must refuse (STALE_PLAN)."""
        target_file = os.path.join(self.base, "dynamic_cache.tmp")
        with open(target_file, "wb") as f:
            f.write(b"ORIGINAL CONTENT")

        planner = PlanGenerator(cache_dir=os.path.join(self.base, "plans"))
        plan = planner.generate_plan(
            target_root=self.base,
            candidates=[{
                "path": target_file,
                "artifact_type": "temporary",
                "logical_bytes": 16,
                "recommended_action": RecommendedAction.RECYCLE_KNOWN_CACHE,
                "user_data_probability": UserDataProbability.LOW,
            }],
        )

        # Simulate external process altering file 10 seconds later
        new_mtime = time.time() + 100
        os.utime(target_file, (new_mtime, new_mtime))

        executor = SafeExecutor()
        res = executor.execute(plan=plan, item_ids=[1], dry_run=False)

        # Preflight must catch the drift and refuse
        self.assertEqual(res.succeeded_count, 0)
        self.assertEqual(res.failed_count, 1)
        self.assertIn("STALE_PLAN", res.failed_items[0]["error"])
        # File must NOT have been deleted
        self.assertTrue(os.path.exists(target_file))

    def test_junction_swap_refusal(self):
        """Case 3: If a planned directory is replaced by a junction before execution, executor must refuse."""
        import _winapi

        victim_dir = os.path.join(self.base, "planned_cache_dir")
        os.makedirs(victim_dir)
        sacrificial_sensitive_dir = os.path.join(self.base, "sensitive_data")
        os.makedirs(sacrificial_sensitive_dir)
        canary_file = os.path.join(sacrificial_sensitive_dir, "canary.txt")
        with open(canary_file, "wb") as f:
            f.write(b"CRITICAL USER DATA DO NOT DELETE")

        planner = PlanGenerator(cache_dir=os.path.join(self.base, "plans"))
        plan = planner.generate_plan(
            target_root=self.base,
            candidates=[{
                "path": victim_dir,
                "artifact_type": "temporary",
                "logical_bytes": 0,
                "recommended_action": RecommendedAction.RECYCLE_KNOWN_CACHE,
                "user_data_probability": UserDataProbability.LOW,
            }],
        )

        # Attacker swaps directory for a junction pointing to sensitive data
        os.rmdir(victim_dir)
        _winapi.CreateJunction(sacrificial_sensitive_dir, victim_dir)
        self.assertTrue(os.path.isjunction(victim_dir))

        try:
            executor = SafeExecutor()
            res = executor.execute(plan=plan, item_ids=[1], dry_run=False)

            self.assertEqual(res.succeeded_count, 0)
            self.assertEqual(res.failed_count, 1)
            self.assertIn("reparse point or junction", res.failed_items[0]["error"])

            # Verify sensitive directory was not traversed or deleted
            self.assertTrue(os.path.exists(canary_file))
            with open(canary_file, "rb") as f:
                self.assertEqual(f.read(), b"CRITICAL USER DATA DO NOT DELETE")
        finally:
            if os.path.exists(victim_dir) and os.path.isjunction(victim_dir):
                os.rmdir(victim_dir)

    def test_toctou_size_drift_refusal(self):
        """Case 3b: If a file's size changes between planning and execution, executor must refuse (STALE_PLAN)."""
        target_file = os.path.join(self.base, "drifting_file.tmp")
        with open(target_file, "wb") as f:
            f.write(b"ORIGINAL DATA 123")

        planner = PlanGenerator(cache_dir=os.path.join(self.base, "plans"))
        plan = planner.generate_plan(
            target_root=self.base,
            candidates=[{
                "path": target_file,
                "artifact_type": "temporary",
                "logical_bytes": 17,
                "recommended_action": RecommendedAction.RECYCLE_KNOWN_CACHE,
                "user_data_probability": UserDataProbability.LOW,
            }],
        )

        # Append more bytes so size changes
        with open(target_file, "ab") as f:
            f.write(b"APPENDED UNEXPECTED BYTES")

        executor = SafeExecutor()
        res = executor.execute(plan=plan, item_ids=[1], dry_run=False)

        self.assertEqual(res.succeeded_count, 0)
        self.assertEqual(res.failed_count, 1)
        self.assertIn("File size changed", res.failed_items[0]["error"])
        self.assertTrue(os.path.exists(target_file))

    def test_plan_hash_tamper_refusal(self):
        """Case 3c: If plan items are modified after hash calculation, execution must be refused."""
        target_file = os.path.join(self.base, "hash_victim.tmp")
        with open(target_file, "wb") as f:
            f.write(b"DATA")

        planner = PlanGenerator(cache_dir=os.path.join(self.base, "plans"))
        plan = planner.generate_plan(
            target_root=self.base,
            candidates=[{
                "path": target_file,
                "artifact_type": "temporary",
                "logical_bytes": 4,
                "recommended_action": RecommendedAction.RECYCLE_KNOWN_CACHE,
                "user_data_probability": UserDataProbability.LOW,
            }],
        )
        self.assertTrue(len(plan.plan_hash) > 0)

        # Maliciously modify the candidate item without recomputing hash
        plan.items[0].candidate_bytes = 999999

        executor = SafeExecutor()
        with self.assertRaises(ValueError) as ctx:
            executor.execute(plan=plan, item_ids=[1], dry_run=False)
        self.assertIn("Plan hash mismatch", str(ctx.exception))

    def test_network_share_refusal(self):
        """Case 3d: UNC / Network share paths must be strictly refused by preflight."""
        unc_item = PlanItem(
            item_id=1,
            path="\\\\remote-storage\\volume1\\trash.tmp",
            expected_kind="file",
            candidate_bytes=1000,
            expected_mtime=time.time(),
            risk=RiskLevel.LOW,
            disposition=Disposition.CLEANABLE,
            action_type=ActionType.RECYCLE_PATH,
            description="UNC cleanup attempt",
            immediate_reclaimable_bytes=0,
            recycle_bin_bytes=1000,
            potential_reclaim_bytes=1000,
        )
        plan = CleanupPlan(
            plan_id="plan_unc12345",
            target_root="\\\\remote-storage\\volume1",
            created_at=time.ctime(),
            total_items=1,
            total_candidate_bytes=1000,
            total_immediate_reclaimable_bytes=0,
            total_recycle_bin_bytes=1000,
            total_potential_reclaim_bytes=1000,
            items=[unc_item],
        )
        executor = SafeExecutor()
        from disk_investigator.cleanup.plan_generator import compute_plan_hash
        plan.plan_hash = compute_plan_hash(
            plan.plan_id,
            plan.target_root,
            plan.created_at,
            plan.items,
            secret_key=executor.secret_key,
            total_items=1,
            total_candidate_bytes=1000,
            total_immediate_reclaimable_bytes=0,
            total_recycle_bin_bytes=1000,
            total_potential_reclaim_bytes=1000,
        )

        res = executor.execute(plan=plan, item_ids=[1], dry_run=False)
        self.assertEqual(res.succeeded_count, 0)
        self.assertEqual(res.failed_count, 1)
        self.assertIn("network share", res.failed_items[0]["error"].lower())

    def test_missing_or_invalid_plan_hash_refusal(self):
        """Case 3e: If plan_hash is missing or invalid, executor must fail closed and refuse execution."""
        plan = CleanupPlan(
            plan_id="plan_nohash123",
            target_root=self.base,
            created_at=time.ctime(),
            total_items=1,
            total_candidate_bytes=10,
            total_immediate_reclaimable_bytes=0,
            total_recycle_bin_bytes=10,
            total_potential_reclaim_bytes=10,
            plan_hash="",  # Missing hash
            items=[PlanItem(1, os.path.join(self.base, "f.tmp"), "file", 10, time.time(), RiskLevel.LOW, Disposition.CLEANABLE, ActionType.RECYCLE_PATH, "desc", 0, 10, 10)],
        )
        executor = SafeExecutor()
        with self.assertRaises(ValueError) as ctx:
            executor.execute(plan=plan, item_ids=[1], dry_run=False)
        self.assertIn("Missing or invalid plan_hash", str(ctx.exception))

    def test_stat_verification_failure_refusal(self):
        """Case 3f: If size/mtime cannot be verified (e.g. PermissionError), preflight must fail-closed."""
        from unittest.mock import patch

        target_file = os.path.join(self.base, "unreadable_victim.tmp")
        with open(target_file, "wb") as f:
            f.write(b"SACRIFICE")

        planner = PlanGenerator(cache_dir=os.path.join(self.base, "plans"))
        plan = planner.generate_plan(
            target_root=self.base,
            candidates=[{
                "path": target_file,
                "artifact_type": "temporary",
                "logical_bytes": 9,
                "recommended_action": RecommendedAction.RECYCLE_KNOWN_CACHE,
                "user_data_probability": UserDataProbability.LOW,
            }],
        )

        executor = SafeExecutor()
        # Mock os.path.getsize to simulate unreadable file permissions
        with patch("os.path.getsize", side_effect=PermissionError("Access denied by OS")):
            res = executor.execute(plan=plan, item_ids=[1], dry_run=False)
            self.assertEqual(res.succeeded_count, 0)
            self.assertEqual(res.failed_count, 1)
            self.assertIn("VERIFY_FAILED", res.failed_items[0]["error"])

    def test_parent_junction_swap_refusal(self):
        """Case 3g: If an ancestor directory of a planned item is replaced by a junction, executor must refuse."""
        import _winapi

        parent_dir = os.path.join(self.base, "ancestor_dir")
        os.makedirs(parent_dir)
        sub_dir = os.path.join(parent_dir, "child_dir")
        os.makedirs(sub_dir)
        victim_file = os.path.join(sub_dir, "victim.tmp")
        with open(victim_file, "wb") as f:
            f.write(b"VICTIM DATA")

        planner = PlanGenerator(cache_dir=os.path.join(self.base, "plans"))
        plan = planner.generate_plan(
            target_root=self.base,
            candidates=[{
                "path": victim_file,
                "artifact_type": "temporary",
                "logical_bytes": 11,
                "recommended_action": RecommendedAction.RECYCLE_KNOWN_CACHE,
                "user_data_probability": UserDataProbability.LOW,
            }],
        )

        # Attacker removes parent_dir and replaces parent_dir with a junction pointing elsewhere
        import shutil
        target_bait = os.path.join(self.base, "bait_dir")
        os.makedirs(target_bait)
        shutil.rmtree(parent_dir)
        _winapi.CreateJunction(target_bait, parent_dir)

        try:
            executor = SafeExecutor()
            res = executor.execute(plan=plan, item_ids=[1], dry_run=False)
            self.assertEqual(res.succeeded_count, 0)
            self.assertEqual(res.failed_count, 1)
            self.assertIn("reparse point or junction", res.failed_items[0]["error"])
        finally:
            if os.path.exists(parent_dir) and os.path.isjunction(parent_dir):
                os.rmdir(parent_dir)

    def test_non_fixed_drive_refusal(self):
        """Case 3h: RECYCLE_PATH on non-fixed drives (mapped network, removable) must be refused."""
        from unittest.mock import patch

        target_file = os.path.join(self.base, "removable_victim.tmp")
        with open(target_file, "wb") as f:
            f.write(b"REMOVABLE DATA")

        planner = PlanGenerator(cache_dir=os.path.join(self.base, "plans"))
        plan = planner.generate_plan(
            target_root=self.base,
            candidates=[{
                "path": target_file,
                "artifact_type": "temporary",
                "logical_bytes": 14,
                "recommended_action": RecommendedAction.RECYCLE_KNOWN_CACHE,
                "user_data_probability": UserDataProbability.LOW,
            }],
        )

        executor = SafeExecutor()
        with patch("disk_investigator.cleanup.safe_executor.is_safe_fixed_drive", return_value=False):
            res = executor.execute(plan=plan, item_ids=[1], dry_run=False)
            self.assertEqual(res.succeeded_count, 0)
            self.assertEqual(res.failed_count, 1)
            self.assertIn("local fixed drive", res.failed_items[0]["error"])

    def test_untrusted_plan_policy_revalidation(self):
        """Case 4: Executor must independently re-validate policies, even if plan JSON was tampered with."""
        tampered_item = PlanItem(
            item_id=1,
            path="C:\\Windows\\System32\\cmd.exe",
            expected_kind="file",
            candidate_bytes=300000,
            expected_mtime=time.time(),
            risk=RiskLevel.LOW,  # Maliciously marked as LOW
            disposition=Disposition.CLEANABLE,  # Maliciously marked as CLEANABLE
            action_type=ActionType.RECYCLE_PATH,
            description="Malicious plan injection attempt",
            immediate_reclaimable_bytes=0,
            recycle_bin_bytes=300000,
            potential_reclaim_bytes=300000,
        )

        from disk_investigator.cleanup.plan_generator import compute_plan_hash
        tampered_plan = CleanupPlan(
            plan_id="plan_tamper99",
            target_root="C:\\Windows",
            created_at=time.ctime(),
            total_items=1,
            total_candidate_bytes=300000,
            total_immediate_reclaimable_bytes=0,
            total_recycle_bin_bytes=300000,
            total_potential_reclaim_bytes=300000,
            items=[tampered_item],
        )
        executor = SafeExecutor()
        tampered_plan.plan_hash = compute_plan_hash(
            tampered_plan.plan_id,
            tampered_plan.target_root,
            tampered_plan.created_at,
            tampered_plan.items,
            secret_key=executor.secret_key,
            total_items=1,
            total_candidate_bytes=300000,
            total_immediate_reclaimable_bytes=0,
            total_recycle_bin_bytes=300000,
            total_potential_reclaim_bytes=300000,
        )

        res = executor.execute(plan=tampered_plan, item_ids=[1], dry_run=False)

        # Must fail closed with security refusal
        self.assertEqual(res.succeeded_count, 0)
        self.assertEqual(res.failed_count, 1)
        self.assertIn("SECURITY REFUSAL", res.failed_items[0]["error"])

    def test_fail_closed_on_empty_items(self):
        """Case 5: Executor must refuse execution if items list is empty."""
        plan = CleanupPlan(
            plan_id="empty_test",
            target_root=self.base,
            created_at=time.ctime(),
            total_items=0,
            total_candidate_bytes=0,
            total_immediate_reclaimable_bytes=0,
            total_recycle_bin_bytes=0,
            total_potential_reclaim_bytes=0,
            items=[],
        )
        executor = SafeExecutor()
        with self.assertRaises(ValueError):
            executor.execute(plan=plan, item_ids=[], dry_run=False)

    def test_custom_cache_dir_hmac_roundtrip(self):
        """Case 6a: An unmodified plan generated with custom cache_dir must verify and succeed on SafeExecutor."""
        target_file = os.path.join(self.base, "roundtrip.tmp")
        with open(target_file, "wb") as f:
            f.write(b"ROUNDTRIP DATA")

        custom_cache = os.path.join(self.base, "custom_cache_plans")
        planner = PlanGenerator(cache_dir=custom_cache)
        plan = planner.generate_plan(
            target_root=self.base,
            candidates=[{
                "path": target_file,
                "artifact_type": "temporary",
                "logical_bytes": 14,
                "recommended_action": RecommendedAction.RECYCLE_KNOWN_CACHE,
                "user_data_probability": UserDataProbability.LOW,
            }],
        )

        executor = SafeExecutor(cache_dir=custom_cache)
        res = executor.execute(plan=plan, item_ids=[1], dry_run=True)
        self.assertEqual(res.succeeded_count, 1)
        self.assertTrue(res.dry_run)

    def test_plan_hmac_tamper_refusal(self):
        """Case 6b: Adversarial attempt to edit plan items and recompute hash without authorized secret key must be refused."""
        from disk_investigator.cleanup.safe_executor import PlanIntegrityError
        target_file = os.path.join(self.base, "hmac_target.tmp")
        with open(target_file, "wb") as f:
            f.write(b"SAMPLE DATA")

        custom_cache = os.path.join(self.base, "plans")
        planner = PlanGenerator(cache_dir=custom_cache)
        plan = planner.generate_plan(
            target_root=self.base,
            candidates=[{
                "path": target_file,
                "artifact_type": "temporary",
                "logical_bytes": 11,
                "recommended_action": RecommendedAction.RECYCLE_KNOWN_CACHE,
                "user_data_probability": UserDataProbability.LOW,
            }],
        )

        executor = SafeExecutor(cache_dir=custom_cache)
        # First verify unmodified plan passes HMAC check
        dry_res = executor.execute(plan=plan, item_ids=[1], dry_run=True)
        self.assertEqual(dry_res.succeeded_count, 1)

        # Attacker tampers with the plan items (redirects target to critical system area)
        plan.items[0].path = "C:\\Windows\\System32\\calc.exe"

        # Attacker recomputes HMAC signature using an attacker-controlled secret key
        from disk_investigator.cleanup.plan_generator import compute_plan_hash
        attacker_unauthorized_key = b"attacker_unauthorized_secret_key_12345"
        plan.plan_hash = compute_plan_hash(
            plan.plan_id,
            plan.target_root,
            plan.created_at,
            plan.items,
            secret_key=attacker_unauthorized_key,
            total_items=plan.total_items,
            total_candidate_bytes=plan.total_candidate_bytes,
            total_immediate_reclaimable_bytes=plan.total_immediate_reclaimable_bytes,
            total_recycle_bin_bytes=plan.total_recycle_bin_bytes,
            total_potential_reclaim_bytes=plan.total_potential_reclaim_bytes,
        )

        with self.assertRaises(PlanIntegrityError) as ctx:
            executor.execute(plan=plan, item_ids=[1], dry_run=False)
        self.assertIn("Plan hash mismatch", str(ctx.exception))

    def test_short_name_alias_protected_path_refusal(self):
        """Case 7: Windows 8.3 short-name alias (e.g. C:\\PROGRA~1) of protected OS paths must be refused."""
        from disk_investigator.path_policy import is_protected_system_path
        self.assertTrue(is_protected_system_path(r"C:\PROGRA~1"))
        self.assertTrue(is_protected_system_path(r"C:\PROGRA~1\subapp\cache"))

        alias_item = PlanItem(
            item_id=1,
            path=r"C:\PROGRA~1\victim.tmp",
            expected_kind="file",
            candidate_bytes=100,
            expected_mtime=time.time(),
            risk=RiskLevel.LOW,
            disposition=Disposition.CLEANABLE,
            action_type=ActionType.RECYCLE_PATH,
            description="Short name bypass attempt",
            immediate_reclaimable_bytes=0,
            recycle_bin_bytes=100,
            potential_reclaim_bytes=100,
        )
        plan = CleanupPlan(
            plan_id="plan_alias83",
            target_root=r"C:\PROGRA~1",
            created_at=time.ctime(),
            total_items=1,
            total_candidate_bytes=100,
            total_immediate_reclaimable_bytes=0,
            total_recycle_bin_bytes=100,
            total_potential_reclaim_bytes=100,
            items=[alias_item],
        )
        executor = SafeExecutor()
        from disk_investigator.cleanup.plan_generator import compute_plan_hash
        plan.plan_hash = compute_plan_hash(
            plan.plan_id,
            plan.target_root,
            plan.created_at,
            plan.items,
            secret_key=executor.secret_key,
            total_items=1,
            total_candidate_bytes=100,
            total_immediate_reclaimable_bytes=0,
            total_recycle_bin_bytes=100,
            total_potential_reclaim_bytes=100,
        )
        res = executor.execute(plan=plan, item_ids=[1], dry_run=False)
        self.assertEqual(res.succeeded_count, 0)
        self.assertEqual(res.failed_count, 1)
        self.assertIn("SECURITY REFUSAL", res.failed_items[0]["error"])
        self.assertIn("protected Windows operating system boundary", res.failed_items[0]["error"])

    def test_all_user_profile_roots_blocked(self):
        """Case 8: All user profile roots (e.g. C:\\Users\\Alice, C:\\Users\\Administrator) must be blocked as critical boundaries."""
        from disk_investigator.path_policy import is_critical_boundary
        self.assertTrue(is_critical_boundary(r"C:\Users\Alice"))
        self.assertTrue(is_critical_boundary(r"C:\Users\Administrator"))
        self.assertTrue(is_critical_boundary(r"C:\Users\Public"))
        self.assertTrue(is_critical_boundary(r"D:\Users\Bob"))

    def test_duplicate_item_id_refusal(self):
        """Case 9: Duplicate item_id or schema mismatch must be refused before execution."""
        from disk_investigator.cleanup.safe_executor import PlanIntegrityError
        item_a = PlanItem(
            item_id=1, path=os.path.join(self.base, "a.tmp"), expected_kind="file", candidate_bytes=10,
            expected_mtime=time.time(), risk=RiskLevel.LOW, disposition=Disposition.CLEANABLE,
            action_type=ActionType.RECYCLE_PATH, description="Item A", immediate_reclaimable_bytes=0,
            recycle_bin_bytes=10, potential_reclaim_bytes=10,
        )
        item_b = PlanItem(
            item_id=1, path=os.path.join(self.base, "b.tmp"), expected_kind="file", candidate_bytes=10,
            expected_mtime=time.time(), risk=RiskLevel.LOW, disposition=Disposition.CLEANABLE,
            action_type=ActionType.RECYCLE_PATH, description="Item B with duplicate ID 1", immediate_reclaimable_bytes=0,
            recycle_bin_bytes=10, potential_reclaim_bytes=10,
        )
        plan = CleanupPlan(
            plan_id="plan_dup_ids", target_root=self.base, created_at=time.ctime(), total_items=2,
            total_candidate_bytes=20, total_immediate_reclaimable_bytes=0, total_recycle_bin_bytes=20,
            total_potential_reclaim_bytes=20, items=[item_a, item_b],
        )
        executor = SafeExecutor()
        from disk_investigator.cleanup.plan_generator import compute_plan_hash
        plan.plan_hash = compute_plan_hash(
            plan.plan_id, plan.target_root, plan.created_at, plan.items,
            secret_key=executor.secret_key,
            total_items=2, total_candidate_bytes=20, total_immediate_reclaimable_bytes=0,
            total_recycle_bin_bytes=20, total_potential_reclaim_bytes=20,
        )
        with self.assertRaises(ValueError) as ctx:
            executor.execute(plan=plan, item_ids=[1], dry_run=False)
        self.assertIn("Duplicate item_id", str(ctx.exception))

    def test_cloud_sync_short_alias_refusal(self):
        """Case 7b: Windows 8.3 short-name alias pointing to cloud sync folders must be refused."""
        from unittest.mock import patch
        from disk_investigator.path_policy import is_cloud_sync_path

        fake_alias = r"C:\Users\dell\ONEDRI~1\Documents\victim.tmp"
        resolved_fake = r"C:\Users\dell\OneDrive\Documents\victim.tmp"

        with patch("disk_investigator.path_policy.resolve_windows_aliases", return_value=resolved_fake):
            self.assertTrue(is_cloud_sync_path(fake_alias))

            alias_item = PlanItem(
                item_id=1,
                path=fake_alias,
                expected_kind="file",
                candidate_bytes=100,
                expected_mtime=time.time(),
                risk=RiskLevel.LOW,
                disposition=Disposition.CLEANABLE,
                action_type=ActionType.RECYCLE_PATH,
                description="Cloud sync short name attempt",
                immediate_reclaimable_bytes=0,
                recycle_bin_bytes=100,
                potential_reclaim_bytes=100,
            )
            executor = SafeExecutor()
            err = executor.preflight_check(alias_item)
            self.assertIsNotNone(err)
            self.assertIn("SECURITY REFUSAL", err)
            self.assertIn("cloud sync folder", err)

    def test_plan_generation_stat_failure_not_executable(self):
        """Case 10: If metadata (mtime) cannot be established at plan time, item is excluded from executable plan."""
        from unittest.mock import patch
        planner = PlanGenerator(cache_dir=os.path.join(self.base, "plans"))
        target_file = os.path.join(self.base, "unreadable_meta.tmp")
        with open(target_file, "wb") as f:
            f.write(b"DATA")

        with patch("os.path.getmtime", side_effect=PermissionError("Access denied to metadata")):
            plan = planner.generate_plan(
                target_root=self.base,
                candidates=[{
                "path": target_file,
                "artifact_type": "temporary",
                "logical_bytes": 4,
                "recommended_action": RecommendedAction.RECYCLE_KNOWN_CACHE,
                "user_data_probability": UserDataProbability.LOW,
            }],
            )
            self.assertEqual(plan.total_items, 0)
            self.assertEqual(len(plan.items), 0)

    def test_cross_volume_observed_delta(self):
        """Case 11: Free space delta is measured and attributed across all unique volumes."""
        target_file = os.path.join(self.base, "vol_test.tmp")
        with open(target_file, "wb") as f:
            f.write(b"DATA")

        planner = PlanGenerator(cache_dir=os.path.join(self.base, "plans"))
        plan = planner.generate_plan(
            target_root=self.base,
            candidates=[{
                "path": target_file,
                "artifact_type": "temporary",
                "logical_bytes": 4,
                "recommended_action": RecommendedAction.RECYCLE_KNOWN_CACHE,
                "user_data_probability": UserDataProbability.LOW,
            }],
        )

        executor = SafeExecutor(cache_dir=os.path.join(self.base, "plans"))
        res = executor.execute(plan=plan, item_ids=[1], dry_run=False)
        self.assertEqual(res.succeeded_count, 1)
        drive, _ = os.path.splitdrive(self.base)
        self.assertIn(f"{drive.upper()}\\", res.observed_volume_deltas)


if __name__ == "__main__":
    unittest.main()
