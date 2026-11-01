"""
Comprehensive False-Positive Hardening Test Suite.
Verifies all safety invariants defined in AC-01 through AC-20.
Guarantees that user documents, personal archives, creative footage, medical data,
and game installations are never falsely classified as cleanable.
"""

import os
import tempfile
import time
import unittest

from disk_investigator.classifiers.artifact_policy import ArtifactPolicyEngine
from disk_investigator.detectors.adapters import LargeFilesStorageDetector
from disk_investigator.detectors.browser.chromium import ChromiumBrowserDetector
from disk_investigator.detectors.creator.adobe import AdobeCreatorDetector
from disk_investigator.detectors.creator.davinci import DaVinciResolveDetector
from disk_investigator.detectors.gaming.steam import SteamGamingDetector
from disk_investigator.detectors.general.dicom import DicomMedicalDetector
from disk_investigator.detectors.office.outlook import OutlookStorageDetector
from disk_investigator.detectors.streaming.obs import OBSStudioDetector
from disk_investigator.models import (
    ArtifactCategory,
    ArtifactDomain,
    DetectionContext,
    RecommendedAction,
    RecoveryCost,
    Regenerability,
    StorageArtifact,
    UserDataProbability,
)
from disk_investigator.services.artifact_correlator import ArtifactCorrelator


class TestFalsePositives(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base = self.temp_dir.name

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_obs_recording_never_cleanable(self):
        # 1. OBS recording file (.mkv) in OBS folder
        obs_dir = os.path.join(self.base, "obs-studio")
        os.makedirs(obs_dir)
        recording = os.path.join(obs_dir, "2026-11-01_12-00-00.mkv")
        with open(recording, "wb") as f:
            f.write(b"\x1a\x45\xdf\xa3" + b"\x00" * 1024)

        det = OBSStudioDetector()
        ctx = DetectionContext(target_path=obs_dir)
        artifacts = det.detect(ctx)

        hardened = ArtifactPolicyEngine.evaluate_all(artifacts)
        rec_art = next(a for a in hardened if a.path == recording)

        self.assertEqual(rec_art.recommended_action, RecommendedAction.BLOCK)
        self.assertEqual(rec_art.category, ArtifactCategory.USER_MEDIA)
        self.assertEqual(rec_art.user_data_probability, UserDataProbability.HIGH)
        self.assertEqual(rec_art.recovery_cost, RecoveryCost.IMPOSSIBLE)

    def test_outlook_pst_blocked(self):
        # 2. Outlook .pst archive file
        outlook_dir = os.path.join(self.base, "Outlook")
        os.makedirs(outlook_dir)
        pst_file = os.path.join(outlook_dir, "archive.pst")
        with open(pst_file, "wb") as f:
            f.write(b"!BDN\x00" + b"\x00" * 1024)

        det = OutlookStorageDetector()
        ctx = DetectionContext(target_path=outlook_dir)
        artifacts = det.detect(ctx)

        hardened = ArtifactPolicyEngine.evaluate_all(artifacts)
        pst_art = next(a for a in hardened if a.path == pst_file)

        self.assertEqual(pst_art.recommended_action, RecommendedAction.BLOCK)
        self.assertEqual(pst_art.category, ArtifactCategory.EMAIL_ARCHIVE)
        self.assertEqual(pst_art.user_data_probability, UserDataProbability.HIGH)
        self.assertEqual(pst_art.recovery_cost, RecoveryCost.IMPOSSIBLE)

    def test_outlook_ost_review_only(self):
        # 3. Outlook .ost offline cache file
        outlook_dir = os.path.join(self.base, "Outlook")
        os.makedirs(outlook_dir)
        ost_file = os.path.join(outlook_dir, "mailbox.ost")
        with open(ost_file, "wb") as f:
            f.write(b"!BDN\x00" + b"\x00" * 1024)

        det = OutlookStorageDetector()
        ctx = DetectionContext(target_path=outlook_dir)
        artifacts = det.detect(ctx)

        hardened = ArtifactPolicyEngine.evaluate_all(artifacts)
        ost_art = next(a for a in hardened if a.path == ost_file)

        self.assertEqual(ost_art.recommended_action, RecommendedAction.REVIEW_ONLY)
        self.assertEqual(ost_art.recovery_cost, RecoveryCost.HIGH)

    def test_premiere_media_cache_vs_original_footage(self):
        # 4. Premiere Media Cache vs Original Footage
        proj_dir = os.path.join(self.base, "VideoProject")
        cache_dir = os.path.join(proj_dir, "Media Cache Files")
        os.makedirs(cache_dir)
        with open(os.path.join(cache_dir, "file.pek"), "w") as f:
            f.write("peaks")

        footage = os.path.join(proj_dir, "source_footage.mov")
        with open(footage, "wb") as f:
            f.write(b"\x00\x00\x00\x14ftypqt  " + b"\x00" * 2048)

        det = AdobeCreatorDetector()
        ctx = DetectionContext(target_path=proj_dir)
        artifacts = det.detect(ctx)

        hardened = ArtifactPolicyEngine.evaluate_all(artifacts)
        by_path = {a.path: a for a in hardened}

        self.assertEqual(by_path[cache_dir].recommended_action, RecommendedAction.TYPED_CLEANUP)
        self.assertEqual(by_path[footage].recommended_action, RecommendedAction.BLOCK)
        self.assertEqual(by_path[footage].user_data_probability, UserDataProbability.HIGH)

    def test_davinci_render_cache_vs_source_media(self):
        # 5. DaVinci CacheClip vs project database
        proj_dir = os.path.join(self.base, "DaVinci")
        cache_clip = os.path.join(proj_dir, "CacheClip")
        os.makedirs(cache_clip)
        with open(os.path.join(cache_clip, "render.mov"), "w") as f:
            f.write("render cache")

        proj_db = os.path.join(proj_dir, "project.resolve")
        with open(proj_db, "w") as f:
            f.write("resolve project")

        det = DaVinciResolveDetector()
        ctx = DetectionContext(target_path=proj_dir)
        artifacts = det.detect(ctx)

        hardened = ArtifactPolicyEngine.evaluate_all(artifacts)
        by_path = {a.path: a for a in hardened}

        self.assertEqual(by_path[cache_clip].recommended_action, RecommendedAction.TYPED_CLEANUP)
        self.assertEqual(by_path[proj_db].recommended_action, RecommendedAction.BLOCK)

    def test_steam_shader_cache_vs_game_install(self):
        # 6. Steam shader cache vs game installation
        steam_root = os.path.join(self.base, "Steam")
        steamapps = os.path.join(steam_root, "steamapps")
        shader_dir = os.path.join(steamapps, "shadercache")
        game_dir = os.path.join(steamapps, "common", "EldenRing")
        os.makedirs(shader_dir)
        os.makedirs(game_dir)

        with open(os.path.join(shader_dir, "vk.bin"), "w") as f:
            f.write("shader")
        with open(os.path.join(game_dir, "eldenring.exe"), "w") as f:
            f.write("game")

        det = SteamGamingDetector()
        ctx = DetectionContext(target_path=steam_root)
        artifacts = det.detect(ctx)

        hardened = ArtifactPolicyEngine.evaluate_all(artifacts)
        by_path = {a.path: a for a in hardened}

        self.assertEqual(by_path[shader_dir].recommended_action, RecommendedAction.TYPED_CLEANUP)
        self.assertEqual(by_path[game_dir].recommended_action, RecommendedAction.REVIEW_ONLY)
        self.assertEqual(by_path[game_dir].user_data_probability, UserDataProbability.HIGH)

    def test_dicom_blocked(self):
        # 7. Healthcare DICOM imaging data
        scan_dir = os.path.join(self.base, "Scans")
        os.makedirs(scan_dir)
        dcm_file = os.path.join(scan_dir, "mri_01.dcm")
        with open(dcm_file, "wb") as f:
            f.write(b"\x00" * 128 + b"DICM" + b"\x00" * 512)

        det = DicomMedicalDetector()
        ctx = DetectionContext(target_path=scan_dir)
        artifacts = det.detect(ctx)

        hardened = ArtifactPolicyEngine.evaluate_all(artifacts)
        self.assertEqual(len(hardened), 1)
        self.assertEqual(hardened[0].recommended_action, RecommendedAction.BLOCK)
        self.assertEqual(hardened[0].category, ArtifactCategory.MEDICAL_DATA)

    def test_large_video_is_not_cleanup_candidate(self):
        # 8. Standalone large video file must be REVIEW_ONLY, never TYPED_CLEANUP
        video_file = os.path.join(self.base, "family_vacation.mp4")
        with open(video_file, "wb") as f:
            f.write(b"0" * (1024 * 1024 * 2))  # 2MB

        det = LargeFilesStorageDetector(min_size_bytes=1024 * 1024)
        ctx = DetectionContext(target_path=self.base)
        artifacts = det.detect(ctx)

        hardened = ArtifactPolicyEngine.evaluate_all(artifacts)
        self.assertEqual(len(hardened), 1)
        # Invariant: Large user video is strictly NOT cleanable by default
        self.assertIn(
            hardened[0].recommended_action,
            (RecommendedAction.REVIEW_ONLY, RecommendedAction.BLOCK),
        )

    def test_unknown_artifact_review_only(self):
        # 9. Fail-closed: An unknown artifact must default to REVIEW_ONLY
        unknown_art = StorageArtifact(
            artifact_id="unk-1",
            path="C:\\Mystery\\Blob.dat",
            canonical_path="C:\\Mystery\\Blob.dat",
            domain=ArtifactDomain.GENERAL,
            category=ArtifactCategory.UNKNOWN,
            artifact_type="unknown",
            logical_bytes=5000,
            recommended_action=RecommendedAction.TYPED_CLEANUP,  # erroneously marked cleanable
        )

        hardened = ArtifactPolicyEngine.evaluate(unknown_art)
        self.assertEqual(hardened.recommended_action, RecommendedAction.REVIEW_ONLY)

    def test_chrome_cache_vs_history(self):
        # 10. Chrome Cache vs History SQLite
        user_data = os.path.join(self.base, "User Data")
        default = os.path.join(user_data, "Default")
        cache = os.path.join(default, "Cache")
        os.makedirs(cache)
        with open(os.path.join(cache, "f_0001"), "w") as f:
            f.write("cached data")

        history = os.path.join(default, "History")
        with open(history, "w") as f:
            f.write("sqlite history database")

        det = ChromiumBrowserDetector()
        ctx = DetectionContext(target_path=user_data)
        artifacts = det.detect(ctx)

        hardened = ArtifactPolicyEngine.evaluate_all(artifacts)
        by_path = {a.path: a for a in hardened}

        self.assertEqual(by_path[cache].recommended_action, RecommendedAction.TYPED_CLEANUP)
        self.assertEqual(by_path[history].recommended_action, RecommendedAction.BLOCK)

    def test_chrome_login_data_blocked(self):
        # 11. Chrome passwords database is strictly BLOCKED
        user_data = os.path.join(self.base, "User Data")
        default = os.path.join(user_data, "Default")
        os.makedirs(default)
        login_data = os.path.join(default, "Login Data")
        with open(login_data, "w") as f:
            f.write("passwords")

        det = ChromiumBrowserDetector()
        ctx = DetectionContext(target_path=user_data)
        artifacts = det.detect(ctx)

        hardened = ArtifactPolicyEngine.evaluate_all(artifacts)
        self.assertEqual(len(hardened), 1)
        self.assertEqual(hardened[0].recommended_action, RecommendedAction.BLOCK)
        self.assertEqual(hardened[0].user_data_probability, UserDataProbability.HIGH)
        self.assertEqual(hardened[0].recovery_cost, RecoveryCost.IMPOSSIBLE)

    def test_stale_user_file_does_not_become_cleanable(self):
        # 12. User files that haven't been touched in 2 years are NOT cleanable
        stale_doc = os.path.join(self.base, "tax_return_2022.pdf")
        with open(stale_doc, "w") as f:
            f.write("tax pdf content")
        two_years_ago = time.time() - (730 * 86400)
        os.utime(stale_doc, (two_years_ago, two_years_ago))

        # Even if a detector mistakenly flags it as TYPED_CLEANUP
        artifact = StorageArtifact(
            artifact_id="stale-doc",
            path=stale_doc,
            canonical_path=stale_doc,
            domain=ArtifactDomain.GENERAL,
            category=ArtifactCategory.USER_DOCUMENT,
            artifact_type="document",
            logical_bytes=10000,
            mtime=two_years_ago,
            recommended_action=RecommendedAction.TYPED_CLEANUP,
        )

        hardened = ArtifactPolicyEngine.evaluate(artifact)
        self.assertEqual(hardened.recommended_action, RecommendedAction.REVIEW_ONLY)

    def test_artifact_overlap_does_not_double_count(self):
        # 13. Parent & child overlapping artifacts
        parent = StorageArtifact(
            artifact_id="parent-dir",
            path="C:\\Users\\User\\AppData\\Local\\App",
            canonical_path="C:\\Users\\User\\AppData\\Local\\App",
            domain=ArtifactDomain.GENERAL,
            category=ArtifactCategory.CACHE,
            artifact_type="cache_dir",
            logical_bytes=10000000,  # 10 MB
        )
        child = StorageArtifact(
            artifact_id="child-dir",
            path="C:\\Users\\User\\AppData\\Local\\App\\Cache",
            canonical_path="C:\\Users\\User\\AppData\\Local\\App\\Cache",
            domain=ArtifactDomain.GENERAL,
            category=ArtifactCategory.CACHE,
            artifact_type="cache_dir",
            logical_bytes=6000000,   # 6 MB
        )

        correlated = ArtifactCorrelator.correlate([parent, child])
        net_bytes = ArtifactCorrelator.calculate_net_bytes(correlated)
        self.assertEqual(net_bytes, 10000000)  # Double-counting avoided!


if __name__ == "__main__":
    unittest.main()
