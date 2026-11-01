"""
Discovery package for Windows applications, runtimes, and ecosystem capabilities.
"""

from .capability_discovery import CapabilityDiscovery
from .probes import (
    ExecutableProbe,
    FileSystemProbe,
    MockExecutableProbe,
    MockFileSystemProbe,
    MockRegistryProbe,
    OSExecutableProbe,
    OSFileSystemProbe,
    RegistryEntry,
    RegistryProbe,
    WindowsRegistryProbe,
)

__all__ = [
    "CapabilityDiscovery",
    "RegistryProbe",
    "FileSystemProbe",
    "ExecutableProbe",
    "RegistryEntry",
    "WindowsRegistryProbe",
    "OSFileSystemProbe",
    "OSExecutableProbe",
    "MockRegistryProbe",
    "MockFileSystemProbe",
    "MockExecutableProbe",
]
