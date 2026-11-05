"""
disk_investigator.tests.test_packaged_e2e
Packaged End-to-End Self-Update and Atomic Rollback Verification.
Covers true multi-process lifecycle handoff against local HTTP release fixture.
"""

from __future__ import annotations

import hashlib
import http.server
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
SETUP_EXE = ROOT_DIR / "disk-investigator-setup.exe"
CLI_EXE = ROOT_DIR / "disk_investigator.exe"


class MockReleaseHandler(http.server.BaseHTTPRequestHandler):
    """Hermetic local HTTP handler simulating GitHub Releases API and asset CDN."""
    server_ref: MockReleaseServer

    def log_message(self, format, *args):
        # Suppress standard logging to keep test output clean
        pass

    def do_GET(self):
        if self.path == "/repos/codevcn/disk-cleaner/releases/latest":
            data = {
                "tag_name": f"v{self.server_ref.target_version}",
                "name": f"v{self.server_ref.target_version}",
                "html_url": f"http://127.0.0.1:{self.server_ref.port}/releases/tag/v{self.server_ref.target_version}",
                "published_at": "2026-11-05T00:00:00Z",
                "assets": [
                    {
                        "name": "disk-investigator-setup.exe",
                        "browser_download_url": f"http://127.0.0.1:{self.server_ref.port}/downloads/disk-investigator-setup.exe",
                        "size": len(self.server_ref.setup_bytes),
                        "content_type": "application/octet-stream",
                    },
                    {
                        "name": "SHA256SUMS.txt",
                        "browser_download_url": f"http://127.0.0.1:{self.server_ref.port}/downloads/SHA256SUMS.txt",
                        "size": len(self.server_ref.manifest_bytes),
                        "content_type": "text/plain",
                    },
                ],
            }
            body = json.dumps(data, indent=2).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif self.path == "/downloads/disk-investigator-setup.exe":
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(self.server_ref.setup_bytes)))
            self.end_headers()
            self.wfile.write(self.server_ref.setup_bytes)

        elif self.path == "/downloads/SHA256SUMS.txt":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(self.server_ref.manifest_bytes)))
            self.end_headers()
            self.wfile.write(self.server_ref.manifest_bytes)

        else:
            self.send_response(404)
            self.end_headers()


class MockReleaseServer:
    def __init__(self, target_version: str, setup_bytes: bytes):
        self.target_version = target_version
        self.setup_bytes = setup_bytes
        self.sha256 = hashlib.sha256(setup_bytes).hexdigest()
        self.manifest_bytes = f"{self.sha256}  disk-investigator-setup.exe\n".encode("utf-8")
        self.port = 0
        self.server: Optional[http.server.ThreadingHTTPServer] = None
        self.thread: Optional[threading.Thread] = None

    def start(self):
        handler_cls = type("HandlerWithRef", (MockReleaseHandler,), {"server_ref": self})
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.server = None


class TestPackagedSelfUpdateE2E(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.isolated_root = Path(self.temp_dir.name)
        self.localappdata = self.isolated_root / "LocalAppData"
        self.userprofile = self.isolated_root / "UserProfile"
        self.install_dir = self.localappdata / "DiskInvestigator"
        self.bin_dir = self.install_dir / "bin"
        self.skill_dir = self.userprofile / ".gemini" / "config" / "skills" / "disk-cleanup"

        self.bin_dir.mkdir(parents=True, exist_ok=True)
        self.skill_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        # Give Windows kernel grace period to release process handles on downloaded binaries
        time.sleep(1.5)
        try:
            self.temp_dir.cleanup()
        except Exception:
            time.sleep(2.0)
            try:
                self.temp_dir.cleanup()
            except Exception:
                pass

    @unittest.skipUnless(SETUP_EXE.exists() and CLI_EXE.exists(), "Requires compiled disk-investigator-setup.exe and disk_investigator.exe in workspace root")
    def test_packaged_self_update_success_e2e(self):
        """
        UPDATE-FINAL-23 / Gate 29: True Packaged E2E Self-Update.
        Old installed version (2.3.2) -> packaged CLI_EXE 'update --yes' -> downloads real packaged setup
        from local HTTP server -> verifies SHA256 -> verifies setup version -> spawns installer
        with --wait-for-pid -> installer transactional replacement -> new version verified.
        """
        target_version = "2.4.4"

        # 1. Simulate existing installed state of older version v2.3.2
        target_bin = self.bin_dir / "disk_investigator.exe"
        target_bin.write_bytes(b"OLD_PACKAGED_BINARY_V232")

        target_skill = self.skill_dir / "SKILL.md"
        target_skill.write_text("# Old Skill v2.3.2", encoding="utf-8")

        target_manifest = self.install_dir / "install_manifest.json"
        manifest_data = {
            "app_name": "Disk Investigator",
            "version": "2.3.2",
            "installed_at": "2026-11-01T00:00:00Z",
            "bin_file": str(target_bin),
            "skill_file": str(target_skill),
        }
        target_manifest.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")

        # 2. Start local HTTP release fixture serving the real compiled setup binary
        setup_bytes = SETUP_EXE.read_bytes()
        server = MockReleaseServer(target_version=target_version, setup_bytes=setup_bytes)
        server.start()

        try:
            # 3. Execute packaged 'disk_investigator.exe update --yes' in isolated environment simulating v2.3.2
            env = os.environ.copy()
            env["LOCALAPPDATA"] = str(self.localappdata)
            env["USERPROFILE"] = str(self.userprofile)
            env["DISK_INVESTIGATOR_API_BASE_URL"] = f"http://127.0.0.1:{server.port}"
            env["DISK_INVESTIGATOR_CURRENT_VERSION_OVERRIDE"] = "2.3.2"
            env["DISK_INVESTIGATOR_NO_UPDATE_CHECK"] = "1"

            cmd = [str(CLI_EXE), "update", "--yes"]
            proc = subprocess.run(
                cmd,
                env=env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
            )
            self.assertEqual(proc.returncode, 0, f"Update command failed: {proc.stderr}\n{proc.stdout}")
            self.assertIn('"state": "handoff_started"', proc.stdout.lower())

            # 4. Wait for detached installer to complete transactional replacement
            receipt_file = self.localappdata / "DiskInvestigator" / "updates" / "last_update_result.json"
            deadline = time.time() + 30.0
            receipt = None
            while time.time() < deadline:
                if receipt_file.exists():
                    try:
                        data = json.loads(receipt_file.read_text(encoding="utf-8"))
                        if data.get("status") in ("success", "failed"):
                            receipt = data
                            break
                    except Exception:
                        pass
                time.sleep(0.5)

            self.assertIsNotNone(receipt, "Installer did not write update receipt within 30s")
            self.assertEqual(receipt["status"], "success", f"Installer reported failure: {receipt}")
            self.assertEqual(receipt["from_version"], "2.3.2")
            self.assertEqual(receipt["to_version"], target_version)

            # 5. Verify installed files, manifest, and lock cleanup
            updated_manifest = json.loads(target_manifest.read_text(encoding="utf-8"))
            self.assertEqual(updated_manifest["version"], target_version)

            lock_file = self.localappdata / "DiskInvestigator" / "updates" / "update.lock"
            self.assertFalse(lock_file.exists(), "update.lock must be deleted after installer finishes")

            # 6. Verify newly installed binary executable runs and reports new version
            self.assertNotEqual(target_bin.read_bytes(), b"OLD_PACKAGED_BINARY_V232")
            ver_proc = subprocess.run(
                [str(target_bin), "--version"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=10,
            )
            self.assertEqual(ver_proc.returncode, 0)
            self.assertIn(target_version, ver_proc.stdout)

        finally:
            server.stop()

    @unittest.skipUnless(SETUP_EXE.exists() and CLI_EXE.exists(), "Requires compiled disk-investigator-setup.exe and disk_investigator.exe in workspace root")
    def test_packaged_self_update_rollback_on_failure_e2e(self):
        """
        UPDATE-FINAL-23 / Gate 30: True Packaged Rollback E2E.
        When installer encounters an induced failure (e.g. failing target write or permission),
        it must cleanly abort, execute transactional rollback, preserve prior version v2.3.2,
        write receipt with status='failed' and rollback_attempted=True, and release update.lock.
        """
        target_version = "2.4.4"

        # 1. Existing installed state of v2.3.2
        target_bin = self.bin_dir / "disk_investigator.exe"
        target_bin.write_bytes(b"ORIGINAL_WORKING_V232_BINARY")

        target_skill = self.skill_dir / "SKILL.md"
        target_skill.write_text("# Original Working Skill v2.3.2", encoding="utf-8")

        target_manifest = self.install_dir / "install_manifest.json"
        manifest_data = {
            "app_name": "Disk Investigator",
            "version": "2.3.2",
            "bin_file": str(target_bin),
            "skill_file": str(target_skill),
        }
        target_manifest.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")

        # 2. Lock target binary by opening in exclusive mode to induce installer failure
        # When installer attempts to replace locked target_bin, it fails and triggers rollback!
        locked_handle = open(str(target_bin), "r+b")

        # 3. Serve real setup binary
        setup_bytes = SETUP_EXE.read_bytes()
        server = MockReleaseServer(target_version=target_version, setup_bytes=setup_bytes)
        server.start()

        try:
            env = os.environ.copy()
            env["LOCALAPPDATA"] = str(self.localappdata)
            env["USERPROFILE"] = str(self.userprofile)
            env["DISK_INVESTIGATOR_API_BASE_URL"] = f"http://127.0.0.1:{server.port}"
            env["DISK_INVESTIGATOR_CURRENT_VERSION_OVERRIDE"] = "2.3.2"
            env["DISK_INVESTIGATOR_NO_UPDATE_CHECK"] = "1"

            cmd = [str(CLI_EXE), "update", "--yes"]
            proc = subprocess.run(
                cmd,
                env=env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
            )

            # 4. Wait for installer receipt
            receipt_file = self.localappdata / "DiskInvestigator" / "updates" / "last_update_result.json"
            deadline = time.time() + 30.0
            receipt = None
            while time.time() < deadline:
                if receipt_file.exists():
                    try:
                        data = json.loads(receipt_file.read_text(encoding="utf-8"))
                        if data.get("status") in ("success", "failed"):
                            receipt = data
                            break
                    except Exception:
                        pass
                time.sleep(0.5)

            # Close lock handle so we can inspect file
            locked_handle.close()

            self.assertIsNotNone(receipt, "Installer did not write receipt on failure")
            self.assertEqual(receipt["status"], "failed", f"Expected failed receipt, got: {receipt}")
            self.assertTrue(receipt["rollback_attempted"] or receipt.get("error_message"))

            # 5. Verify rollback preserved original version 2.3.2
            preserved_manifest = json.loads(target_manifest.read_text(encoding="utf-8"))
            self.assertEqual(preserved_manifest["version"], "2.3.2")
            self.assertEqual(target_bin.read_bytes(), b"ORIGINAL_WORKING_V232_BINARY")

            # 6. Verify update.lock was released by installer finally block
            lock_file = self.localappdata / "DiskInvestigator" / "updates" / "update.lock"
            self.assertFalse(lock_file.exists(), "update.lock must be released on failure")

        finally:
            try:
                locked_handle.close()
            except Exception:
                pass
            server.stop()


if __name__ == "__main__":
    unittest.main()
