"""
Unit tests for Phase 4B Detectors: Creator, Streaming, and Gaming.
"""

import os
import tempfile
import unittest

from disk_investigator.detectors.creator.adobe import AdobeCreatorDetector
from disk_investigator.detectors.creator.capcut import CapCutDetector
from disk_investigator.detectors.creator.davinci import DaVinciResolveDetector
from disk_investigator.detectors.gaming.steam import SteamGamingDetector
from disk_investigator.detectors.streaming.obs import OBSStudioDetector
from disk_investigator.models import (
    ArtifactCategory,
    DetectionContext,
    RecommendedAction,
    RecoveryCost,
    Regenerability,
    UserDataProbability,
)


class TestPhase4BDetectors(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base = self.temp_dir.name

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_adobe_media_cache_vs_original_footage(self):
        adobe_root = os.path.join(self.base, "AdobeProject")
        os.makedirs(adobe_root)

        # Cache dir
        cache_dir = os.path.join(adobe_root, "Media Cache Files")
        os.makedirs(cache_dir)
        with open(os.path.join(cache_dir, "video.pek"), "w") as f:
            f.write("peak data")

        # Original footage and project files
        footage = os.path.join(adobe_root, "interview_raw.mp4")
        with open(footage, "wb") as f:
            f.write(b"\x00\x00\x00\x18ftypmp42" + b"\x00" * 1000)

        proj = os.path.join(adobe_root, "commercial.prproj")
        with open(proj, "w") as f:
            f.write("premiere xml")

        det = AdobeCreatorDetector()
        ctx = DetectionContext(target_path=adobe_root)
        artifacts = det.detect(ctx)

        actions = {a.path: a.recommended_action for a in artifacts}
        self.assertEqual(actions[cache_dir], RecommendedAction.TYPED_CLEANUP)
        self.assertEqual(actions[footage], RecommendedAction.BLOCK)
        self.assertEqual(actions[proj], RecommendedAction.BLOCK)

        # Safety attributes on original footage
        footage_art = next(a for a in artifacts if a.path == footage)
        self.assertEqual(footage_art.user_data_probability, UserDataProbability.HIGH)
        self.assertEqual(footage_art.recovery_cost, RecoveryCost.IMPOSSIBLE)
        self.assertEqual(footage_art.regenerability, Regenerability.NONE)

    def test_davinci_render_cache_vs_project_db(self):
        resolve_root = os.path.join(self.base, "ResolveWork")
        cache_clip = os.path.join(resolve_root, "CacheClip")
        os.makedirs(cache_clip)
        with open(os.path.join(cache_clip, "proxy.mov"), "w") as f:
            f.write("proxy render")

        proj_db = os.path.join(resolve_root, "project.resolve")
        with open(proj_db, "w") as f:
            f.write("resolve project header")

        det = DaVinciResolveDetector()
        ctx = DetectionContext(target_path=resolve_root)
        artifacts = det.detect(ctx)

        actions = {a.path: a.recommended_action for a in artifacts}
        self.assertEqual(actions[cache_clip], RecommendedAction.TYPED_CLEANUP)
        self.assertEqual(actions[proj_db], RecommendedAction.BLOCK)

    def test_capcut_cache_vs_projects(self):
        capcut_root = os.path.join(self.base, "CapCut", "User Data")
        cache_dir = os.path.join(capcut_root, "Cache")
        proj_dir = os.path.join(capcut_root, "Projects")
        os.makedirs(cache_dir)
        os.makedirs(proj_dir)

        det = CapCutDetector()
        ctx = DetectionContext(target_path=capcut_root)
        artifacts = det.detect(ctx)

        actions = {a.path: a.recommended_action for a in artifacts}
        self.assertEqual(actions[cache_dir], RecommendedAction.TYPED_CLEANUP)
        self.assertEqual(actions[proj_dir], RecommendedAction.BLOCK)

    def test_obs_logs_vs_recordings(self):
        obs_root = os.path.join(self.base, "obs-studio")
        logs_dir = os.path.join(obs_root, "logs")
        os.makedirs(logs_dir)
        with open(os.path.join(logs_dir, "2026-11-01.txt"), "w") as f:
            f.write("obs log line")

        recording_file = os.path.join(obs_root, "stream_highlight.mkv")
        with open(recording_file, "wb") as f:
            f.write(b"\x1a\x45\xdf\xa3" + b"\x00" * 500)

        det = OBSStudioDetector()
        ctx = DetectionContext(target_path=obs_root)
        artifacts = det.detect(ctx)

        actions = {a.path: a.recommended_action for a in artifacts}
        self.assertEqual(actions[logs_dir], RecommendedAction.RECYCLE_KNOWN_CACHE)
        self.assertEqual(actions[recording_file], RecommendedAction.BLOCK)

        rec_art = next(a for a in artifacts if a.path == recording_file)
        self.assertEqual(rec_art.category, ArtifactCategory.USER_MEDIA)
        self.assertEqual(rec_art.user_data_probability, UserDataProbability.HIGH)

    def test_steam_shader_cache_vs_game_install(self):
        steamapps = os.path.join(self.base, "Steam", "steamapps")
        shader_dir = os.path.join(steamapps, "shadercache")
        common_game = os.path.join(steamapps, "common", "CyberGame2077")
        os.makedirs(shader_dir)
        os.makedirs(common_game)

        with open(os.path.join(shader_dir, "dxvk.cache"), "w") as f:
            f.write("shader cache")
        with open(os.path.join(common_game, "game.exe"), "w") as f:
            f.write("executable")

        det = SteamGamingDetector()
        ctx = DetectionContext(target_path=os.path.join(self.base, "Steam"))
        artifacts = det.detect(ctx)

        actions = {a.path: a.recommended_action for a in artifacts}
        self.assertEqual(actions[shader_dir], RecommendedAction.TYPED_CLEANUP)
        self.assertEqual(actions[common_game], RecommendedAction.REVIEW_ONLY)

        game_art = next(a for a in artifacts if a.path == common_game)
        self.assertEqual(game_art.category, ArtifactCategory.GAME_INSTALL)
        self.assertEqual(game_art.user_data_probability, UserDataProbability.HIGH)
        self.assertEqual(game_art.recovery_cost, RecoveryCost.HIGH)


if __name__ == "__main__":
    unittest.main()
