"""
Capability Discovery Engine for General-Purpose Storage Investigator.
Discovers installed applications, development runtimes, creative suites,
browsers, games, and streaming tools via read-only Windows Registry,
standard filesystem paths, and PATH executable resolution.
"""

from __future__ import annotations

import os
from typing import Dict, List, Optional

from ..models import Capability, Confidence, Evidence
from .probes import (
    ExecutableProbe,
    FileSystemProbe,
    OSExecutableProbe,
    OSFileSystemProbe,
    RegistryProbe,
    WindowsRegistryProbe,
)


class CapabilityDiscovery:
    """Orchestrates non-invasive discovery of system application capabilities."""

    def __init__(
        self,
        registry_probe: Optional[RegistryProbe] = None,
        fs_probe: Optional[FileSystemProbe] = None,
        exe_probe: Optional[ExecutableProbe] = None,
    ):
        self.reg = registry_probe or WindowsRegistryProbe()
        self.fs = fs_probe or OSFileSystemProbe()
        self.exe = exe_probe or OSExecutableProbe()

    def discover_all(self) -> Dict[str, Capability]:
        """Runs all capability discovery probes and returns active capabilities."""
        caps: Dict[str, Capability] = {}

        discoverers = [
            self._discover_chrome,
            self._discover_edge,
            self._discover_outlook,
            self._discover_teams,
            self._discover_premiere,
            self._discover_after_effects,
            self._discover_davinci,
            self._discover_capcut,
            self._discover_obs_studio,
            self._discover_steam,
            self._discover_docker,
            self._discover_vscode,
            self._discover_jetbrains,
            self._discover_node,
            self._discover_python,
            self._discover_ollama,
            self._discover_huggingface,
        ]

        for fn in discoverers:
            try:
                cap = fn()
                if cap is not None and cap.detected:
                    caps[cap.capability_id] = cap
            except Exception as e:
                # Failure in one capability discovery must never crash the service
                continue

        return caps

    # --------------------------------------------------------------------------
    # Browsers
    # --------------------------------------------------------------------------

    def _discover_chrome(self) -> Optional[Capability]:
        evidence: List[Evidence] = []
        exe_paths: List[str] = []
        data_roots: List[str] = []
        version = None

        local_app = self.fs.get_env("LOCALAPPDATA")
        if local_app:
            user_data = os.path.join(local_app, "Google", "Chrome", "User Data")
            if self.fs.path_exists(user_data):
                data_roots.append(user_data)
                evidence.append(Evidence("filesystem_dir", "LOCALAPPDATA", user_data, "Chrome User Data found"))

        # Executable check
        c_exe = self.exe.find_executable("chrome") or self.exe.find_executable("chrome.exe")
        if c_exe:
            exe_paths.append(c_exe)
            evidence.append(Evidence("executable_lookup", "PATH", c_exe, "Chrome executable found on PATH"))

        # Program Files fallback
        for pf in [self.fs.get_env("PROGRAMFILES"), self.fs.get_env("PROGRAMFILES(X86)")]:
            if pf:
                cand = os.path.join(pf, "Google", "Chrome", "Application", "chrome.exe")
                if self.fs.path_exists(cand) and cand not in exe_paths:
                    exe_paths.append(cand)
                    evidence.append(Evidence("filesystem_file", "PROGRAMFILES", cand, "Chrome binary found"))

        # Registry check
        for reg in self.reg.find_installed_apps("Google Chrome"):
            if reg.display_version:
                version = reg.display_version
            evidence.append(Evidence("registry_install", reg.key, reg.display_name, "Registered in Windows Uninstall"))

        if data_roots or exe_paths:
            return Capability(
                capability_id="browser.chrome",
                detected=True,
                confidence=Confidence.HIGH,
                version=version,
                executable_paths=exe_paths,
                data_roots=data_roots,
                evidence=evidence,
            )
        return None

    def _discover_edge(self) -> Optional[Capability]:
        evidence: List[Evidence] = []
        exe_paths: List[str] = []
        data_roots: List[str] = []
        version = None

        local_app = self.fs.get_env("LOCALAPPDATA")
        if local_app:
            user_data = os.path.join(local_app, "Microsoft", "Edge", "User Data")
            if self.fs.path_exists(user_data):
                data_roots.append(user_data)
                evidence.append(Evidence("filesystem_dir", "LOCALAPPDATA", user_data, "Edge User Data found"))

        e_exe = self.exe.find_executable("msedge") or self.exe.find_executable("msedge.exe")
        if e_exe:
            exe_paths.append(e_exe)
            evidence.append(Evidence("executable_lookup", "PATH", e_exe, "Edge executable on PATH"))

        for pf in [self.fs.get_env("PROGRAMFILES"), self.fs.get_env("PROGRAMFILES(X86)")]:
            if pf:
                cand = os.path.join(pf, "Microsoft", "Edge", "Application", "msedge.exe")
                if self.fs.path_exists(cand) and cand not in exe_paths:
                    exe_paths.append(cand)
                    evidence.append(Evidence("filesystem_file", "PROGRAMFILES", cand, "Edge binary found"))

        for reg in self.reg.find_installed_apps("Microsoft Edge"):
            if reg.display_version:
                version = reg.display_version
            evidence.append(Evidence("registry_install", reg.key, reg.display_name, "Registered in Windows Uninstall"))

        if data_roots or exe_paths:
            return Capability(
                capability_id="browser.edge",
                detected=True,
                confidence=Confidence.HIGH,
                version=version,
                executable_paths=exe_paths,
                data_roots=data_roots,
                evidence=evidence,
            )
        return None

    # --------------------------------------------------------------------------
    # Office
    # --------------------------------------------------------------------------

    def _discover_outlook(self) -> Optional[Capability]:
        evidence: List[Evidence] = []
        exe_paths: List[str] = []
        data_roots: List[str] = []
        version = None

        local_app = self.fs.get_env("LOCALAPPDATA")
        if local_app:
            outlook_local = os.path.join(local_app, "Microsoft", "Outlook")
            if self.fs.path_exists(outlook_local):
                data_roots.append(outlook_local)
                evidence.append(Evidence("filesystem_dir", "LOCALAPPDATA", outlook_local, "Outlook data directory"))

        o_exe = self.exe.find_executable("outlook") or self.exe.find_executable("outlook.exe")
        if o_exe:
            exe_paths.append(o_exe)
            evidence.append(Evidence("executable_lookup", "PATH", o_exe, "Outlook on PATH"))

        for reg in self.reg.find_installed_apps("Microsoft Outlook") + self.reg.find_installed_apps("Microsoft 365"):
            if reg.display_version:
                version = reg.display_version
            evidence.append(Evidence("registry_install", reg.key, reg.display_name, "Office/Outlook registered"))

        if data_roots or exe_paths or evidence:
            return Capability(
                capability_id="office.outlook",
                detected=True,
                confidence=Confidence.HIGH if (data_roots or exe_paths) else Confidence.MEDIUM,
                version=version,
                executable_paths=exe_paths,
                data_roots=data_roots,
                evidence=evidence,
            )
        return None

    def _discover_teams(self) -> Optional[Capability]:
        evidence: List[Evidence] = []
        data_roots: List[str] = []
        local_app = self.fs.get_env("LOCALAPPDATA")
        app_data = self.fs.get_env("APPDATA")

        # Teams classic & Teams 2.0
        if app_data:
            t_classic = os.path.join(app_data, "Microsoft", "Teams")
            if self.fs.path_exists(t_classic):
                data_roots.append(t_classic)
                evidence.append(Evidence("filesystem_dir", "APPDATA", t_classic, "Teams classic root"))

        if local_app:
            t_new = os.path.join(local_app, "Packages", "MSTeams_8wekyb3d8bbwe", "LocalCache", "Microsoft", "MSTeams")
            if self.fs.path_exists(t_new):
                data_roots.append(t_new)
                evidence.append(Evidence("filesystem_dir", "LOCALAPPDATA", t_new, "Teams 2.0 root"))

        for reg in self.reg.find_installed_apps("Microsoft Teams"):
            evidence.append(Evidence("registry_install", reg.key, reg.display_name, "Teams registered"))

        if data_roots or evidence:
            return Capability(
                capability_id="office.teams",
                detected=True,
                confidence=Confidence.HIGH if data_roots else Confidence.MEDIUM,
                data_roots=data_roots,
                evidence=evidence,
            )
        return None

    # --------------------------------------------------------------------------
    # Creator
    # --------------------------------------------------------------------------

    def _discover_premiere(self) -> Optional[Capability]:
        evidence: List[Evidence] = []
        exe_paths: List[str] = []
        data_roots: List[str] = []
        version = None

        app_data = self.fs.get_env("APPDATA")
        if app_data:
            p_data = os.path.join(app_data, "Adobe", "Common")
            if self.fs.path_exists(p_data):
                data_roots.append(p_data)
                evidence.append(Evidence("filesystem_dir", "APPDATA", p_data, "Adobe Common media cache root"))

        for reg in self.reg.find_installed_apps("Adobe Premiere Pro"):
            if reg.display_version:
                version = reg.display_version
            evidence.append(Evidence("registry_install", reg.key, reg.display_name, "Adobe Premiere Pro installed"))

        if data_roots or evidence:
            return Capability(
                capability_id="creator.premiere",
                detected=True,
                confidence=Confidence.HIGH,
                version=version,
                executable_paths=exe_paths,
                data_roots=data_roots,
                evidence=evidence,
            )
        return None

    def _discover_after_effects(self) -> Optional[Capability]:
        evidence: List[Evidence] = []
        app_data = self.fs.get_env("APPDATA")
        data_roots = []
        if app_data:
            ae_root = os.path.join(app_data, "Adobe", "After Effects")
            if self.fs.path_exists(ae_root):
                data_roots.append(ae_root)
                evidence.append(Evidence("filesystem_dir", "APPDATA", ae_root, "After Effects root"))

        for reg in self.reg.find_installed_apps("After Effects"):
            evidence.append(Evidence("registry_install", reg.key, reg.display_name, "After Effects installed"))

        if data_roots or evidence:
            return Capability(
                capability_id="creator.after_effects",
                detected=True,
                confidence=Confidence.HIGH,
                data_roots=data_roots,
                evidence=evidence,
            )
        return None

    def _discover_davinci(self) -> Optional[Capability]:
        evidence: List[Evidence] = []
        app_data = self.fs.get_env("APPDATA")
        data_roots = []
        if app_data:
            dv = os.path.join(app_data, "Blackmagic Design", "DaVinci Resolve")
            if self.fs.path_exists(dv):
                data_roots.append(dv)
                evidence.append(Evidence("filesystem_dir", "APPDATA", dv, "DaVinci Resolve data root"))

        for reg in self.reg.find_installed_apps("DaVinci Resolve"):
            evidence.append(Evidence("registry_install", reg.key, reg.display_name, "DaVinci Resolve installed"))

        if data_roots or evidence:
            return Capability(
                capability_id="creator.davinci",
                detected=True,
                confidence=Confidence.HIGH,
                data_roots=data_roots,
                evidence=evidence,
            )
        return None

    def _discover_capcut(self) -> Optional[Capability]:
        evidence: List[Evidence] = []
        local_app = self.fs.get_env("LOCALAPPDATA")
        data_roots = []
        if local_app:
            cc = os.path.join(local_app, "CapCut")
            if self.fs.path_exists(cc):
                data_roots.append(cc)
                evidence.append(Evidence("filesystem_dir", "LOCALAPPDATA", cc, "CapCut local root"))

        for reg in self.reg.find_installed_apps("CapCut"):
            evidence.append(Evidence("registry_install", reg.key, reg.display_name, "CapCut installed"))

        if data_roots or evidence:
            return Capability(
                capability_id="creator.capcut",
                detected=True,
                confidence=Confidence.HIGH,
                data_roots=data_roots,
                evidence=evidence,
            )
        return None

    # --------------------------------------------------------------------------
    # Streaming & Gaming
    # --------------------------------------------------------------------------

    def _discover_obs_studio(self) -> Optional[Capability]:
        evidence: List[Evidence] = []
        exe_paths: List[str] = []
        data_roots: List[str] = []
        version = None

        app_data = self.fs.get_env("APPDATA")
        if app_data:
            obs_dir = os.path.join(app_data, "obs-studio")
            if self.fs.path_exists(obs_dir):
                data_roots.append(obs_dir)
                evidence.append(Evidence("filesystem_dir", "APPDATA", obs_dir, "OBS Studio settings/logs directory"))

        obs_exe = self.exe.find_executable("obs64") or self.exe.find_executable("obs32")
        if obs_exe:
            exe_paths.append(obs_exe)
            evidence.append(Evidence("executable_lookup", "PATH", obs_exe, "OBS Studio binary on PATH"))

        for reg in self.reg.find_installed_apps("OBS Studio"):
            if reg.display_version:
                version = reg.display_version
            if reg.install_location and self.fs.path_exists(reg.install_location):
                exe_cand = os.path.join(reg.install_location, "bin", "64bit", "obs64.exe")
                if self.fs.path_exists(exe_cand) and exe_cand not in exe_paths:
                    exe_paths.append(exe_cand)
            evidence.append(Evidence("registry_install", reg.key, reg.display_name, "OBS Studio registered"))

        if data_roots or exe_paths or evidence:
            return Capability(
                capability_id="streaming.obs_studio",
                detected=True,
                confidence=Confidence.HIGH,
                version=version,
                executable_paths=exe_paths,
                data_roots=data_roots,
                evidence=evidence,
            )
        return None

    def _discover_steam(self) -> Optional[Capability]:
        evidence: List[Evidence] = []
        exe_paths: List[str] = []
        install_paths: List[str] = []
        version = None

        for pf in [self.fs.get_env("PROGRAMFILES(X86)"), self.fs.get_env("PROGRAMFILES")]:
            if pf:
                cand = os.path.join(pf, "Steam")
                if self.fs.path_exists(cand):
                    install_paths.append(cand)
                    exe_file = os.path.join(cand, "steam.exe")
                    if self.fs.path_exists(exe_file):
                        exe_paths.append(exe_file)
                    evidence.append(Evidence("filesystem_dir", "PROGRAMFILES", cand, "Steam client installation directory"))

        for reg in self.reg.find_installed_apps("Steam"):
            if reg.display_version:
                version = reg.display_version
            if reg.install_location and self.fs.path_exists(reg.install_location) and reg.install_location not in install_paths:
                install_paths.append(reg.install_location)
            evidence.append(Evidence("registry_install", reg.key, reg.display_name, "Steam registered in Windows"))

        if install_paths or exe_paths or evidence:
            return Capability(
                capability_id="gaming.steam",
                detected=True,
                confidence=Confidence.HIGH,
                version=version,
                executable_paths=exe_paths,
                install_paths=install_paths,
                data_roots=install_paths,
                evidence=evidence,
            )
        return None

    # --------------------------------------------------------------------------
    # Developer & AI
    # --------------------------------------------------------------------------

    def _discover_docker(self) -> Optional[Capability]:
        evidence: List[Evidence] = []
        exe_paths: List[str] = []
        d_exe = self.exe.find_executable("docker") or self.exe.find_executable("docker.exe")
        if d_exe:
            exe_paths.append(d_exe)
            evidence.append(Evidence("executable_lookup", "PATH", d_exe, "Docker CLI available"))

        local_app = self.fs.get_env("LOCALAPPDATA")
        data_roots = []
        if local_app:
            docker_wsl = os.path.join(local_app, "Docker", "wsl")
            if self.fs.path_exists(docker_wsl):
                data_roots.append(docker_wsl)
                evidence.append(Evidence("filesystem_dir", "LOCALAPPDATA", docker_wsl, "Docker WSL disk container"))

        for reg in self.reg.find_installed_apps("Docker Desktop"):
            evidence.append(Evidence("registry_install", reg.key, reg.display_name, "Docker Desktop installed"))

        if exe_paths or data_roots or evidence:
            return Capability(
                capability_id="developer.docker",
                detected=True,
                confidence=Confidence.HIGH,
                executable_paths=exe_paths,
                data_roots=data_roots,
                evidence=evidence,
            )
        return None

    def _discover_vscode(self) -> Optional[Capability]:
        evidence: List[Evidence] = []
        exe_paths: List[str] = []
        code_exe = self.exe.find_executable("code") or self.exe.find_executable("code.cmd")
        if code_exe:
            exe_paths.append(code_exe)
            evidence.append(Evidence("executable_lookup", "PATH", code_exe, "VS Code on PATH"))

        app_data = self.fs.get_env("APPDATA")
        data_roots = []
        if app_data:
            code_dir = os.path.join(app_data, "Code")
            if self.fs.path_exists(code_dir):
                data_roots.append(code_dir)
                evidence.append(Evidence("filesystem_dir", "APPDATA", code_dir, "VS Code AppData directory"))

        for reg in self.reg.find_installed_apps("Visual Studio Code"):
            evidence.append(Evidence("registry_install", reg.key, reg.display_name, "VS Code registered"))

        if exe_paths or data_roots or evidence:
            return Capability(
                capability_id="developer.vscode",
                detected=True,
                confidence=Confidence.HIGH,
                executable_paths=exe_paths,
                data_roots=data_roots,
                evidence=evidence,
            )
        return None

    def _discover_jetbrains(self) -> Optional[Capability]:
        evidence: List[Evidence] = []
        local_app = self.fs.get_env("LOCALAPPDATA")
        data_roots = []
        if local_app:
            jb = os.path.join(local_app, "JetBrains")
            if self.fs.path_exists(jb):
                data_roots.append(jb)
                evidence.append(Evidence("filesystem_dir", "LOCALAPPDATA", jb, "JetBrains AppData directory"))

        if data_roots:
            return Capability(
                capability_id="developer.jetbrains",
                detected=True,
                confidence=Confidence.HIGH,
                data_roots=data_roots,
                evidence=evidence,
            )
        return None

    def _discover_node(self) -> Optional[Capability]:
        evidence: List[Evidence] = []
        exe_paths: List[str] = []
        node_exe = self.exe.find_executable("node") or self.exe.find_executable("node.exe")
        npm_exe = self.exe.find_executable("npm") or self.exe.find_executable("npm.cmd")
        if node_exe:
            exe_paths.append(node_exe)
            evidence.append(Evidence("executable_lookup", "PATH", node_exe, "Node runtime found"))
        if npm_exe:
            exe_paths.append(npm_exe)
            evidence.append(Evidence("executable_lookup", "PATH", npm_exe, "NPM CLI found"))

        if exe_paths:
            return Capability(
                capability_id="developer.node",
                detected=True,
                confidence=Confidence.HIGH,
                executable_paths=exe_paths,
                evidence=evidence,
            )
        return None

    def _discover_python(self) -> Optional[Capability]:
        evidence: List[Evidence] = []
        exe_paths: List[str] = []
        py_exe = self.exe.find_executable("python") or self.exe.find_executable("python.exe")
        if py_exe:
            exe_paths.append(py_exe)
            evidence.append(Evidence("executable_lookup", "PATH", py_exe, "Python runtime found"))

        if exe_paths:
            return Capability(
                capability_id="developer.python",
                detected=True,
                confidence=Confidence.HIGH,
                executable_paths=exe_paths,
                evidence=evidence,
            )
        return None

    def _discover_ollama(self) -> Optional[Capability]:
        evidence: List[Evidence] = []
        exe_paths: List[str] = []
        data_roots: List[str] = []

        ollama_exe = self.exe.find_executable("ollama") or self.exe.find_executable("ollama.exe")
        if ollama_exe:
            exe_paths.append(ollama_exe)
            evidence.append(Evidence("executable_lookup", "PATH", ollama_exe, "Ollama CLI on PATH"))

        user_profile = self.fs.get_env("USERPROFILE")
        if user_profile:
            m_dir = os.path.join(user_profile, ".ollama", "models")
            if self.fs.path_exists(m_dir):
                data_roots.append(m_dir)
                evidence.append(Evidence("filesystem_dir", "USERPROFILE", m_dir, "Ollama models directory"))

        if exe_paths or data_roots:
            return Capability(
                capability_id="ai_ml.ollama",
                detected=True,
                confidence=Confidence.HIGH,
                executable_paths=exe_paths,
                data_roots=data_roots,
                evidence=evidence,
            )
        return None

    def _discover_huggingface(self) -> Optional[Capability]:
        evidence: List[Evidence] = []
        data_roots: List[str] = []
        user_profile = self.fs.get_env("USERPROFILE")
        if user_profile:
            hf_cache = os.path.join(user_profile, ".cache", "huggingface")
            if self.fs.path_exists(hf_cache):
                data_roots.append(hf_cache)
                evidence.append(Evidence("filesystem_dir", "USERPROFILE", hf_cache, "Hugging Face hub cache"))

        if data_roots:
            return Capability(
                capability_id="ai_ml.huggingface",
                detected=True,
                confidence=Confidence.HIGH,
                data_roots=data_roots,
                evidence=evidence,
            )
        return None
