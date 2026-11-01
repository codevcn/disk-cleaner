"""
Probes for Capability Discovery on Windows.
Abstracts Registry, FileSystem, and Executable lookups to enable unit testing and mock injection.
Adheres strictly to read-only semantics. Never writes, modifies, deletes, or executes apps.
"""

from __future__ import annotations

import os
import shutil
from typing import Dict, List, Optional, Protocol, Tuple


class RegistryEntry:
    def __init__(self, key: str, display_name: str, display_version: Optional[str] = None, install_location: Optional[str] = None):
        self.key = key
        self.display_name = display_name
        self.display_version = display_version
        self.install_location = install_location


class RegistryProbe(Protocol):
    def find_installed_apps(self, query: str) -> List[RegistryEntry]:
        """Find applications matching query in Windows Uninstall registry."""
        ...


class FileSystemProbe(Protocol):
    def path_exists(self, path: str) -> bool:
        ...

    def is_dir(self, path: str) -> bool:
        ...

    def list_dir(self, path: str) -> List[str]:
        ...

    def get_env(self, var_name: str) -> Optional[str]:
        ...


class ExecutableProbe(Protocol):
    def find_executable(self, name: str) -> Optional[str]:
        ...


# ==============================================================================
# OS Real Implementations (Windows)
# ==============================================================================


class WindowsRegistryProbe:
    """Read-only Windows Registry probe for Installed Applications."""

    UNINSTALL_PATHS = [
        r"Software\Microsoft\Windows\CurrentVersion\Uninstall",
        r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    ]

    def find_installed_apps(self, query: str) -> List[RegistryEntry]:
        results: List[RegistryEntry] = []
        try:
            import winreg
        except ImportError:
            return results

        q_lower = query.lower()
        hives = [winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE]

        for hive in hives:
            for subkey_path in self.UNINSTALL_PATHS:
                try:
                    with winreg.OpenKey(hive, subkey_path) as root_key:
                        num_subkeys = winreg.QueryInfoKey(root_key)[0]
                        for i in range(num_subkeys):
                            try:
                                subkey_name = winreg.EnumKey(root_key, i)
                                with winreg.OpenKey(root_key, subkey_name) as app_key:
                                    try:
                                        display_name = winreg.QueryValueEx(app_key, "DisplayName")[0]
                                    except OSError:
                                        continue

                                    if not display_name or q_lower not in display_name.lower():
                                        continue

                                    display_version = None
                                    try:
                                        display_version = winreg.QueryValueEx(app_key, "DisplayVersion")[0]
                                    except OSError:
                                        pass

                                    install_loc = None
                                    try:
                                        install_loc = winreg.QueryValueEx(app_key, "InstallLocation")[0]
                                    except OSError:
                                        pass

                                    results.append(
                                        RegistryEntry(
                                            key=f"{subkey_path}\\{subkey_name}",
                                            display_name=display_name,
                                            display_version=display_version,
                                            install_location=install_loc,
                                        )
                                    )
                            except OSError:
                                continue
                except OSError:
                    continue

        return results


class OSFileSystemProbe:
    """Real filesystem probe with environment variable lookups."""

    def path_exists(self, path: str) -> bool:
        try:
            return os.path.exists(path)
        except (OSError, PermissionError):
            return False

    def is_dir(self, path: str) -> bool:
        try:
            return os.path.isdir(path)
        except (OSError, PermissionError):
            return False

    def list_dir(self, path: str) -> List[str]:
        try:
            return os.listdir(path)
        except (OSError, PermissionError):
            return []

    def get_env(self, var_name: str) -> Optional[str]:
        return os.environ.get(var_name)


class OSExecutableProbe:
    """Real executable probe using PATH resolution."""

    def find_executable(self, name: str) -> Optional[str]:
        return shutil.which(name)


# ==============================================================================
# Mock Implementations for Hermetic Unit Testing
# ==============================================================================


class MockRegistryProbe:
    def __init__(self, entries: Optional[List[RegistryEntry]] = None, raise_error: bool = False):
        self.entries = entries or []
        self.raise_error = raise_error

    def find_installed_apps(self, query: str) -> List[RegistryEntry]:
        if self.raise_error:
            raise PermissionError("Access denied to registry")
        q = query.lower()
        return [e for e in self.entries if q in e.display_name.lower()]


class MockFileSystemProbe:
    def __init__(
        self,
        existing_paths: Optional[List[str]] = None,
        dirs: Optional[List[str]] = None,
        env: Optional[Dict[str, str]] = None,
        raise_error: bool = False,
    ):
        self.existing_paths = set(p.lower() for p in (existing_paths or []))
        self.dirs = set(p.lower() for p in (dirs or []))
        self.env = env or {
            "USERPROFILE": r"C:\Users\testuser",
            "LOCALAPPDATA": r"C:\Users\testuser\AppData\Local",
            "APPDATA": r"C:\Users\testuser\AppData\Roaming",
            "PROGRAMFILES": r"C:\Program Files",
            "PROGRAMFILES(X86)": r"C:\Program Files (x86)",
            "TEMP": r"C:\Users\testuser\AppData\Local\Temp",
        }
        self.raise_error = raise_error

    def path_exists(self, path: str) -> bool:
        if self.raise_error:
            raise PermissionError("Access denied to filesystem")
        return path.lower() in self.existing_paths

    def is_dir(self, path: str) -> bool:
        if self.raise_error:
            raise PermissionError("Access denied to filesystem")
        return path.lower() in self.dirs

    def list_dir(self, path: str) -> List[str]:
        if self.raise_error:
            raise PermissionError("Access denied to filesystem")
        prefix = path.lower().rstrip("\\") + "\\"
        results = set()
        for p in self.existing_paths:
            if p.startswith(prefix):
                rel = p[len(prefix):]
                parts = rel.split("\\")
                if parts[0]:
                    results.add(parts[0])
        return list(results)

    def get_env(self, var_name: str) -> Optional[str]:
        return self.env.get(var_name)


class MockExecutableProbe:
    def __init__(self, executables: Optional[Dict[str, str]] = None, raise_error: bool = False):
        self.executables = executables or {}
        self.raise_error = raise_error

    def find_executable(self, name: str) -> Optional[str]:
        if self.raise_error:
            raise PermissionError("Access denied to PATH")
        return self.executables.get(name)
