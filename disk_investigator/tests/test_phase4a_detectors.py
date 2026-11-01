"""
Unit tests for Phase 4A Detectors: System, Browser, Office, and DICOM Medical.
"""

import os
import tempfile
import time
import unittest

from disk_investigator.detectors.browser.chromium import ChromiumBrowserDetector
from disk_investigator.detectors.general.dicom import DicomMedicalDetector
from disk_investigator.detectors.office.office_cache import OfficeCacheDetector
from disk_investigator.detectors.office.outlook import OutlookStorageDetector
from disk_investigator.detectors.office.teams import TeamsCacheDetector
from disk_investigator.detectors.system.crash_dump import CrashDumpDetector
from disk_investigator.detectors.system.user_temp import UserTempDetector
from disk_investigator.models import (
    ArtifactCategory,
    ArtifactDomain,
    DetectionContext,
    RecommendedAction,
    RecoveryCost,
    Regenerability,
    UserDataProbability,
)


class TestPhase4ADetectors(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base = self.temp_dir.name

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_user_temp_detector(self):
        # Create temp files: one old (2 days ago), one fresh (now)
        old_file = os.path.join(self.base, "old_temp.tmp")
        with open(old_file, "w") as f:
            f.write("temporary junk")
        two_days_ago = time.time() - (48 * 3600)
        os.utime(old_file, (two_days_ago, two_days_ago))

        fresh_file = os.path.join(self.base, "fresh_temp.tmp")
        with open(fresh_file, "w") as f:
            f.write("fresh junk")

        det = UserTempDetector(min_age_hours=24.0)
        ctx = DetectionContext(target_path=self.base, env={"TEMP": self.base})
        artifacts = det.detect(ctx)

        self.assertEqual(len(artifacts), 1)
        self.assertEqual(artifacts[0].path, old_file)
        self.assertEqual(artifacts[0].category, ArtifactCategory.TEMPORARY)
        self.assertEqual(artifacts[0].recommended_action, RecommendedAction.RECYCLE_KNOWN_CACHE)

    def test_crash_dump_detector(self):
        dump_file = os.path.join(self.base, "app_crash.dmp")
        with open(dump_file, "wb") as f:
            f.write(b"MDMP\x00\x00\x00\x00")

        det = CrashDumpDetector()
        ctx = DetectionContext(target_path=self.base)
        artifacts = det.detect(ctx)

        self.assertEqual(len(artifacts), 1)
        self.assertEqual(artifacts[0].path, dump_file)
        self.assertEqual(artifacts[0].category, ArtifactCategory.CRASH_DUMP)
        self.assertEqual(artifacts[0].recommended_action, RecommendedAction.REVIEW_ONLY)
        self.assertEqual(artifacts[0].user_data_probability, UserDataProbability.HIGH)

    def test_chromium_browser_detector_cache_vs_user_data(self):
        # Setup mock Chrome profile directory structure
        chrome_dir = os.path.join(self.base, "Google", "Chrome", "User Data")
        default_profile = os.path.join(chrome_dir, "Default")
        cache_dir = os.path.join(default_profile, "Cache")
        code_cache_dir = os.path.join(default_profile, "Code Cache")
        os.makedirs(cache_dir)
        os.makedirs(code_cache_dir)

        # Write dummy cache files
        with open(os.path.join(cache_dir, "data_0"), "w") as f:
            f.write("cached http payload")

        # Write protected user database files
        history_file = os.path.join(default_profile, "History")
        with open(history_file, "w") as f:
            f.write("sqlite browser history")

        login_data = os.path.join(default_profile, "Login Data")
        with open(login_data, "w") as f:
            f.write("sqlite encrypted passwords")

        det = ChromiumBrowserDetector()
        ctx = DetectionContext(target_path=chrome_dir, env={"LOCALAPPDATA": self.base})
        artifacts = det.detect(ctx)

        actions_by_path = {a.path: a.recommended_action for a in artifacts}
        self.assertIn(cache_dir, actions_by_path)
        self.assertEqual(actions_by_path[cache_dir], RecommendedAction.TYPED_CLEANUP)

        self.assertIn(history_file, actions_by_path)
        self.assertEqual(actions_by_path[history_file], RecommendedAction.BLOCK)

        self.assertIn(login_data, actions_by_path)
        self.assertEqual(actions_by_path[login_data], RecommendedAction.BLOCK)

        # Verify safe attributes on blocked item
        history_art = next(a for a in artifacts if a.path == history_file)
        self.assertEqual(history_art.user_data_probability, UserDataProbability.HIGH)
        self.assertEqual(history_art.regenerability, Regenerability.NONE)
        self.assertEqual(history_art.recovery_cost, RecoveryCost.IMPOSSIBLE)

    def test_outlook_detector_pst_blocked_and_ost_review_only(self):
        outlook_dir = os.path.join(self.base, "Outlook")
        os.makedirs(outlook_dir)

        pst_file = os.path.join(outlook_dir, "archive_2024.pst")
        with open(pst_file, "wb") as f:
            f.write(b"!BDN\x00")

        ost_file = os.path.join(outlook_dir, "user@domain.com.ost")
        with open(ost_file, "wb") as f:
            f.write(b"!BDN\x00")

        det = OutlookStorageDetector()
        ctx = DetectionContext(target_path=outlook_dir)
        artifacts = det.detect(ctx)

        self.assertEqual(len(artifacts), 2)
        pst_art = next(a for a in artifacts if a.path == pst_file)
        ost_art = next(a for a in artifacts if a.path == ost_file)

        # Invariant: PST is strictly BLOCKED
        self.assertEqual(pst_art.recommended_action, RecommendedAction.BLOCK)
        self.assertEqual(pst_art.category, ArtifactCategory.EMAIL_ARCHIVE)
        self.assertEqual(pst_art.recovery_cost, RecoveryCost.IMPOSSIBLE)

        # Invariant: OST is strictly REVIEW_ONLY (never auto-cleaned)
        self.assertEqual(ost_art.recommended_action, RecommendedAction.REVIEW_ONLY)
        self.assertEqual(ost_art.recovery_cost, RecoveryCost.HIGH)

    def test_office_and_teams_cache_detectors(self):
        office_cache_dir = os.path.join(self.base, "OfficeFileCache")
        os.makedirs(office_cache_dir)
        with open(os.path.join(office_cache_dir, "doc.cache"), "w") as f:
            f.write("cached doc data")

        teams_cache_dir = os.path.join(self.base, "Teams", "Cache")
        os.makedirs(teams_cache_dir)
        with open(os.path.join(teams_cache_dir, "blob"), "w") as f:
            f.write("cached teams image")

        office_det = OfficeCacheDetector()
        office_artifacts = office_det.detect(DetectionContext(target_path=office_cache_dir))
        self.assertEqual(len(office_artifacts), 1)
        self.assertEqual(office_artifacts[0].recommended_action, RecommendedAction.TYPED_CLEANUP)

        teams_det = TeamsCacheDetector()
        teams_artifacts = teams_det.detect(DetectionContext(target_path=teams_cache_dir))
        self.assertEqual(len(teams_artifacts), 1)
        self.assertEqual(teams_artifacts[0].recommended_action, RecommendedAction.TYPED_CLEANUP)

    def test_dicom_medical_data_strictly_blocked(self):
        dicom_dir = os.path.join(self.base, "MedicalScans")
        os.makedirs(dicom_dir)

        # 1. File with .dcm extension
        dcm_file = os.path.join(dicom_dir, "scan_patient_001.dcm")
        with open(dcm_file, "wb") as f:
            f.write(b"\x00" * 128 + b"DICM" + b"\x00" * 100)

        # 2. File without extension but with DICM magic bytes at offset 128
        magic_file = os.path.join(dicom_dir, "unnamed_scan")
        with open(magic_file, "wb") as f:
            f.write(b"\x00" * 128 + b"DICM" + b"\x00" * 100)

        # 3. Regular non-dicom file
        other_file = os.path.join(dicom_dir, "notes.txt")
        with open(other_file, "w") as f:
            f.write("doctor notes")

        det = DicomMedicalDetector()
        ctx = DetectionContext(target_path=dicom_dir)
        artifacts = det.detect(ctx)

        self.assertEqual(len(artifacts), 2)
        paths = [a.path for a in artifacts]
        self.assertIn(dcm_file, paths)
        self.assertIn(magic_file, paths)
        self.assertNotIn(other_file, paths)

        for a in artifacts:
            self.assertEqual(a.recommended_action, RecommendedAction.BLOCK)
            self.assertEqual(a.category, ArtifactCategory.MEDICAL_DATA)
            self.assertEqual(a.user_data_probability, UserDataProbability.HIGH)
            self.assertEqual(a.recovery_cost, RecoveryCost.IMPOSSIBLE)
            self.assertEqual(a.regenerability, Regenerability.NONE)


if __name__ == "__main__":
    unittest.main()
