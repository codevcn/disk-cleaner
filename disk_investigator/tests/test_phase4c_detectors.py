"""
Unit tests for Phase 4C Detectors: Developer and AI/ML.
"""

import os
import tempfile
import unittest

from disk_investigator.detectors.adapters import DeveloperStorageDetector, DockerStorageDetector
from disk_investigator.detectors.ai_ml.huggingface import HuggingFaceCacheDetector
from disk_investigator.detectors.ai_ml.ollama import OllamaModelDetector
from disk_investigator.models import (
    ArtifactCategory,
    ArtifactDomain,
    DetectionContext,
    RecommendedAction,
    RecoveryCost,
    Regenerability,
    UserDataProbability,
)


class TestPhase4CDetectors(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base = self.temp_dir.name

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_ollama_model_detector(self):
        ollama_root = os.path.join(self.base, ".ollama", "models")
        blobs_dir = os.path.join(ollama_root, "blobs")
        os.makedirs(blobs_dir)

        # Create dummy 10MB model blob
        blob_file = os.path.join(blobs_dir, "sha256-abcdef0123456789")
        with open(blob_file, "wb") as f:
            f.write(b"GGUF" + b"\x00" * 1024 * 100)

        det = OllamaModelDetector()
        ctx = DetectionContext(
            target_path=ollama_root,
            env={"USERPROFILE": self.base, "OLLAMA_MODELS": ollama_root},
        )
        artifacts = det.detect(ctx)

        self.assertEqual(len(artifacts), 1)
        art = artifacts[0]
        self.assertEqual(art.category, ArtifactCategory.MODEL_CACHE)
        self.assertEqual(art.domain, ArtifactDomain.AI_ML)
        self.assertEqual(art.recommended_action, RecommendedAction.REVIEW_ONLY)
        self.assertEqual(art.recovery_cost, RecoveryCost.HIGH)
        self.assertEqual(art.regenerability, Regenerability.FULL)
        self.assertEqual(art.user_data_probability, UserDataProbability.LOW)

    def test_huggingface_cache_detector(self):
        hf_home = os.path.join(self.base, ".cache", "huggingface")
        hub_dir = os.path.join(hf_home, "hub")
        os.makedirs(hub_dir)

        with open(os.path.join(hub_dir, "models--bert-base-uncased.bin"), "wb") as f:
            f.write(b"\x00" * 1024 * 50)

        det = HuggingFaceCacheDetector()
        ctx = DetectionContext(
            target_path=hub_dir,
            env={"USERPROFILE": self.base, "HF_HOME": hf_home},
        )
        artifacts = det.detect(ctx)

        self.assertEqual(len(artifacts), 1)
        art = artifacts[0]
        self.assertEqual(art.category, ArtifactCategory.MODEL_CACHE)
        self.assertEqual(art.domain, ArtifactDomain.AI_ML)
        self.assertEqual(art.recommended_action, RecommendedAction.REVIEW_ONLY)
        self.assertEqual(art.recovery_cost, RecoveryCost.HIGH)

    def test_developer_adapter_node_modules(self):
        proj = os.path.join(self.base, "my_node_app")
        os.makedirs(proj)
        with open(os.path.join(proj, "package.json"), "w") as f:
            f.write("{}")
        nm = os.path.join(proj, "node_modules")
        os.makedirs(nm)
        with open(os.path.join(nm, "lib.js"), "w") as f:
            f.write("console.log('test');")

        det = DeveloperStorageDetector()
        ctx = DetectionContext(target_path=proj)
        self.assertTrue(det.applicable(ctx))

        artifacts = det.detect(ctx)
        self.assertEqual(len(artifacts), 1)
        self.assertEqual(artifacts[0].artifact_type, "node_modules")
        self.assertEqual(artifacts[0].domain, ArtifactDomain.DEVELOPER)
        self.assertEqual(artifacts[0].recommended_action, RecommendedAction.TYPED_CLEANUP)

    def test_docker_adapter_vhdx_blocked(self):
        docker_dir = os.path.join(self.base, "Docker", "wsl", "data")
        os.makedirs(docker_dir)
        vhdx_file = os.path.join(docker_dir, "ext4.vhdx")
        with open(vhdx_file, "wb") as f:
            f.write(b"vhdx header")

        det = DockerStorageDetector()
        # Mock detector's internal local_app_data to point to our test base
        det.detector.local_app_data = self.base
        ctx = DetectionContext(target_path=docker_dir, env={"LOCALAPPDATA": self.base})
        artifacts = det.detect(ctx)

        self.assertEqual(len(artifacts), 1)
        self.assertEqual(artifacts[0].artifact_type, "docker_vhdx")
        self.assertEqual(artifacts[0].recommended_action, RecommendedAction.BLOCK)
        self.assertEqual(artifacts[0].user_data_probability, UserDataProbability.HIGH)


if __name__ == "__main__":
    unittest.main()
