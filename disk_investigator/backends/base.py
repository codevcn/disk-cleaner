"""
Base scanner backend interface for disk_investigator.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

from ..models import BackendKind, FileSystemNode


class ScannerBackend(ABC):
    """Abstract interface for filesystem scanning backends."""

    @property
    @abstractmethod
    def name(self) -> BackendKind:
        """Returns the BackendKind identifier."""
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Returns True if the backend is installed and executable."""
        pass

    @abstractmethod
    def scan(
        self,
        path: str,
        depth: int = 1,
        max_entries: Optional[int] = None,
        only_dir: bool = False,
        min_size_bytes: Optional[int] = None,
        collapse_node_modules: bool = True,
    ) -> FileSystemNode:
        """
        Performs a scoped filesystem scan starting at path.
        Returns the root FileSystemNode with child hierarchy.
        """
        pass
