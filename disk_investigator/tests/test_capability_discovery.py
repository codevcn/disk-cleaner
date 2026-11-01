"""
Unit tests for Capability Discovery Engine.
Verifies hermetic discovery across Registry, Filesystem, and Executable probes.
"""

import unittest
from disk_investigator.discovery.capability_discovery import CapabilityDiscovery
from disk_investigator.discovery.probes import (
    MockExecutableProbe,
    MockFileSystemProbe,
    MockRegistryProbe,
    RegistryEntry,
)


class TestCapabilityDiscovery(unittest.TestCase):
    def test_zero_apps_detected(self):
        reg = MockRegistryProbe([])
        fs = MockFileSystemProbe([])
        exe = MockExecutableProbe({})
        disc = CapabilityDiscovery(reg, fs, exe)

        caps = disc.discover_all()
        self.assertEqual(len(caps), 0)

    def test_single_app_chrome_detected(self):
        reg = MockRegistryProbe([
            RegistryEntry("HKCU\\Software\\...\\Chrome", "Google Chrome", "125.0.0.0")
        ])
        fs = MockFileSystemProbe([
            r"C:\Users\testuser\AppData\Local\Google\Chrome\User Data"
        ])
        exe = MockExecutableProbe({"chrome": r"C:\Program Files\Google\Chrome\Application\chrome.exe"})
        disc = CapabilityDiscovery(reg, fs, exe)

        caps = disc.discover_all()
        self.assertIn("browser.chrome", caps)
        chrome = caps["browser.chrome"]
        self.assertTrue(chrome.detected)
        self.assertEqual(chrome.version, "125.0.0.0")
        self.assertIn(r"C:\Program Files\Google\Chrome\Application\chrome.exe", chrome.executable_paths)

    def test_multi_app_simultaneous_discovery(self):
        # A single system with Steam, OBS, Premiere, Docker, VS Code, and Ollama
        reg = MockRegistryProbe([
            RegistryEntry("HKLM\\...\\Steam", "Steam", "1.0", r"C:\Program Files (x86)\Steam"),
            RegistryEntry("HKLM\\...\\OBS", "OBS Studio", "30.1", r"C:\Program Files\obs-studio"),
            RegistryEntry("HKLM\\...\\Premiere", "Adobe Premiere Pro 2024", "24.0"),
            RegistryEntry("HKLM\\...\\Docker", "Docker Desktop", "4.30"),
            RegistryEntry("HKCU\\...\\Code", "Visual Studio Code", "1.89"),
        ])
        fs = MockFileSystemProbe([
            r"C:\Program Files (x86)\Steam",
            r"C:\Program Files (x86)\Steam\steam.exe",
            r"C:\Users\testuser\AppData\Roaming\obs-studio",
            r"C:\Users\testuser\AppData\Roaming\Adobe\Common",
            r"C:\Users\testuser\AppData\Local\Docker\wsl",
            r"C:\Users\testuser\AppData\Roaming\Code",
            r"C:\Users\testuser\.ollama\models",
        ])
        exe = MockExecutableProbe({
            "docker": r"C:\Program Files\Docker\Docker\resources\bin\docker.exe",
            "code": r"C:\Program Files\Microsoft VS Code\bin\code.cmd",
            "ollama": r"C:\Users\testuser\AppData\Local\Programs\Ollama\ollama.exe",
        })

        disc = CapabilityDiscovery(reg, fs, exe)
        caps = disc.discover_all()

        # All 6 domains should be discovered concurrently!
        self.assertIn("gaming.steam", caps)
        self.assertIn("streaming.obs_studio", caps)
        self.assertIn("creator.premiere", caps)
        self.assertIn("developer.docker", caps)
        self.assertIn("developer.vscode", caps)
        self.assertIn("ai_ml.ollama", caps)

    def test_registry_only_detection(self):
        reg = MockRegistryProbe([
            RegistryEntry("HKLM\\...\\CapCut", "CapCut", "3.0")
        ])
        fs = MockFileSystemProbe([])
        exe = MockExecutableProbe({})
        disc = CapabilityDiscovery(reg, fs, exe)

        caps = disc.discover_all()
        self.assertIn("creator.capcut", caps)

    def test_filesystem_only_detection(self):
        reg = MockRegistryProbe([])
        fs = MockFileSystemProbe([
            r"C:\Users\testuser\.cache\huggingface"
        ])
        exe = MockExecutableProbe({})
        disc = CapabilityDiscovery(reg, fs, exe)

        caps = disc.discover_all()
        self.assertIn("ai_ml.huggingface", caps)

    def test_executable_only_detection(self):
        reg = MockRegistryProbe([])
        fs = MockFileSystemProbe([])
        exe = MockExecutableProbe({"node": r"C:\nodejs\node.exe", "npm": r"C:\nodejs\npm.cmd"})
        disc = CapabilityDiscovery(reg, fs, exe)

        caps = disc.discover_all()
        self.assertIn("developer.node", caps)

    def test_permission_error_handling_fails_safely(self):
        reg = MockRegistryProbe([], raise_error=True)
        fs = MockFileSystemProbe([], raise_error=True)
        exe = MockExecutableProbe({}, raise_error=True)
        disc = CapabilityDiscovery(reg, fs, exe)

        # Must never raise unhandled exception, must return empty safely
        caps = disc.discover_all()
        self.assertEqual(len(caps), 0)


if __name__ == "__main__":
    unittest.main()
