"""
Tests for General-Purpose Storage Investigator Domain Contracts (v2.2+).
Verifies StorageArtifact, Capability, Evidence, Enums, and fail-closed defaults.
"""

import unittest
from disk_investigator.models import (
    ArtifactCategory,
    ArtifactDomain,
    Confidence,
    Evidence,
    RecommendedAction,
    RecoveryCost,
    Regenerability,
    StorageArtifact,
    Capability,
    DetectionContext,
    UserDataProbability,
    generate_artifact_id,
)


class TestDomainModels(unittest.TestCase):
    def test_enums_completeness(self):
        # Verify all domains are present
        self.assertEqual(ArtifactDomain.SYSTEM.value, "system")
        self.assertEqual(ArtifactDomain.BROWSER.value, "browser")
        self.assertEqual(ArtifactDomain.OFFICE.value, "office")
        self.assertEqual(ArtifactDomain.CREATOR.value, "creator")
        self.assertEqual(ArtifactDomain.GAMING.value, "gaming")
        self.assertEqual(ArtifactDomain.STREAMING.value, "streaming")
        self.assertEqual(ArtifactDomain.DEVELOPER.value, "developer")
        self.assertEqual(ArtifactDomain.AI_ML.value, "ai_ml")
        self.assertEqual(ArtifactDomain.GENERAL.value, "general")

        # Verify key categories
        self.assertEqual(ArtifactCategory.RENDER_CACHE.value, "render_cache")
        self.assertEqual(ArtifactCategory.USER_MEDIA.value, "user_media")
        self.assertEqual(ArtifactCategory.EMAIL_ARCHIVE.value, "email_archive")
        self.assertEqual(ArtifactCategory.MEDICAL_DATA.value, "medical_data")
        self.assertEqual(ArtifactCategory.GAME_INSTALL.value, "game_install")
        self.assertEqual(ArtifactCategory.MODEL_CACHE.value, "model_cache")

    def test_storage_artifact_fail_closed_defaults(self):
        art_id = generate_artifact_id(r"C:\test\path", "unknown_type", "test_detector")
        art = StorageArtifact(
            artifact_id=art_id,
            path=r"C:\test\path",
            canonical_path=r"c:\test\path",
            domain=ArtifactDomain.GENERAL,
            category=ArtifactCategory.UNKNOWN,
            artifact_type="unknown_type",
        )
        # Fail-closed invariants check
        self.assertEqual(art.regenerability, Regenerability.NONE)
        self.assertEqual(art.user_data_probability, UserDataProbability.HIGH)
        self.assertEqual(art.recovery_cost, RecoveryCost.IMPOSSIBLE)
        self.assertEqual(art.recommended_action, RecommendedAction.REVIEW_ONLY)

    def test_storage_artifact_serialization_roundtrip(self):
        ev = Evidence(
            kind="filesystem_marker",
            source="test.config",
            value="present",
            message="Found test config file",
        )
        art = StorageArtifact(
            artifact_id="art-12345678",
            path=r"C:\Users\test\AppData\Local\Google\Chrome\User Data\Default\Cache",
            canonical_path=r"c:\users\test\appdata\local\google\chrome\user data\default\cache",
            domain=ArtifactDomain.BROWSER,
            category=ArtifactCategory.CACHE,
            artifact_type="chromium_cache",
            owner_app="google_chrome",
            capability_id="browser.chrome",
            source_detector="browser.chromium",
            logical_bytes=104857600,
            mtime=1700000000.0,
            regenerability=Regenerability.FULL,
            user_data_probability=UserDataProbability.LOW,
            recovery_cost=RecoveryCost.LOW,
            recommended_action=RecommendedAction.RECYCLE_KNOWN_CACHE,
            confidence=Confidence.HIGH,
            evidence=[ev],
        )

        d = art.to_dict()
        self.assertEqual(d["domain"], "browser")
        self.assertEqual(d["category"], "cache")
        self.assertEqual(d["regenerability"], "FULL")
        self.assertEqual(d["user_data_probability"], "LOW")
        self.assertEqual(d["recovery_cost"], "LOW")
        self.assertEqual(d["recommended_action"], "RECYCLE_KNOWN_CACHE")
        self.assertEqual(len(d["evidence"]), 1)
        self.assertEqual(d["evidence"][0]["kind"], "filesystem_marker")

        # Roundtrip back
        art2 = StorageArtifact.from_dict(d)
        self.assertEqual(art2.artifact_id, art.artifact_id)
        self.assertEqual(art2.domain, ArtifactDomain.BROWSER)
        self.assertEqual(art2.category, ArtifactCategory.CACHE)
        self.assertEqual(art2.regenerability, Regenerability.FULL)
        self.assertEqual(art2.user_data_probability, UserDataProbability.LOW)
        self.assertEqual(art2.recovery_cost, RecoveryCost.LOW)
        self.assertEqual(art2.recommended_action, RecommendedAction.RECYCLE_KNOWN_CACHE)
        self.assertEqual(len(art2.evidence), 1)
        self.assertEqual(art2.evidence[0].source, "test.config")

    def test_capability_serialization_roundtrip(self):
        ev = Evidence(kind="registry_install", source="HKLM", value="OBS Studio 30.2")
        cap = Capability(
            capability_id="streaming.obs_studio",
            detected=True,
            confidence=Confidence.HIGH,
            version="30.2.0",
            executable_paths=[r"C:\Program Files\obs-studio\bin\64bit\obs64.exe"],
            install_paths=[r"C:\Program Files\obs-studio"],
            data_roots=[r"C:\Users\test\AppData\Roaming\obs-studio"],
            evidence=[ev],
        )
        d = cap.to_dict()
        self.assertEqual(d["capability_id"], "streaming.obs_studio")
        self.assertTrue(d["detected"])
        self.assertEqual(d["version"], "30.2.0")

        cap2 = Capability.from_dict(d)
        self.assertEqual(cap2.capability_id, "streaming.obs_studio")
        self.assertTrue(cap2.detected)
        self.assertEqual(cap2.confidence, Confidence.HIGH)
        self.assertEqual(len(cap2.executable_paths), 1)
        self.assertEqual(len(cap2.evidence), 1)


if __name__ == "__main__":
    unittest.main()
