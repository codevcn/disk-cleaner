"""
Action Registry and Typed Handlers for Cleanup Execution.
Enforces process running checks (never kills user apps) and dispatches typed cleanup actions.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Protocol, runtime_checkable

from enum import Enum

from .action_types import ActionType


class ProcessState(Enum):
    NOT_RUNNING = "NOT_RUNNING"
    RUNNING = "RUNNING"
    UNKNOWN = "UNKNOWN"


def check_process_state(exe_name: str) -> ProcessState:
    """
    Check if an executable is actively running on Windows without terminating it.
    Strict fail-closed: returns ProcessState.UNKNOWN on any error, timeout, or non-zero exit.
    """
    try:
        proc = subprocess.run(
            ["tasklist", "/FI", f"IMAGENAME eq {exe_name}", "/NH"],
            capture_output=True,
            text=True,
            timeout=3,
            shell=False,
        )
        if proc.returncode != 0:
            return ProcessState.UNKNOWN
        stdout = proc.stdout.lower()
        if exe_name.lower() in stdout:
            return ProcessState.RUNNING
        return ProcessState.NOT_RUNNING
    except Exception:
        return ProcessState.UNKNOWN


def is_process_running(exe_name: str) -> bool:
    """
    Check if an executable is actively running on Windows.
    Fails closed: returns True if running OR if process state cannot be confirmed.
    """
    return check_process_state(exe_name) != ProcessState.NOT_RUNNING


@runtime_checkable
class ActionHandler(Protocol):
    """Protocol for executing typed cleanup actions."""

    def can_handle(self, action_type: ActionType) -> bool:
        ...

    def execute(self, item: Any, dry_run: bool = False) -> Dict[str, Any]:
        ...


class BaseActionHandler(ABC):
    """Base class for typed action handlers."""

    @abstractmethod
    def can_handle(self, action_type: ActionType) -> bool:
        pass

    @abstractmethod
    def execute(self, item: Any, dry_run: bool = False) -> Dict[str, Any]:
        pass


class RecyclePathHandler(BaseActionHandler):
    """Default handler that sends paths safely to Windows Recycle Bin."""

    def can_handle(self, action_type: ActionType) -> bool:
        return action_type == ActionType.RECYCLE_PATH

    def execute(self, item: Any, dry_run: bool = False) -> Dict[str, Any]:
        from .safe_executor import send_to_recycle_bin

        if dry_run:
            return {"status": "DRY_RUN", "bytes_reclaimed": 0, "recycle_bin": True}

        send_to_recycle_bin(item.path)
        return {"status": "SUCCESS", "bytes_reclaimed": 0, "recycle_bin": True}


class NpmCacheHandler(BaseActionHandler):
    """Cleans npm global package cache using npm CLI."""

    def can_handle(self, action_type: ActionType) -> bool:
        return action_type == ActionType.NPM_CACHE_CLEAN

    def execute(self, item: Any, dry_run: bool = False) -> Dict[str, Any]:
        if dry_run:
            return {"status": "DRY_RUN", "bytes_reclaimed": item.immediate_reclaimable_bytes}

        npm_bin = shutil.which("npm.cmd") or shutil.which("npm")
        if not npm_bin:
            raise FileNotFoundError("npm executable not found in PATH")

        proc = subprocess.run([npm_bin, "cache", "clean", "--force"], capture_output=True, text=True, timeout=30, shell=False)
        if proc.returncode != 0:
            raise RuntimeError(f"npm cache clean failed: {proc.stderr.strip()}")

        return {"status": "SUCCESS", "bytes_reclaimed": item.immediate_reclaimable_bytes}


class PipCacheHandler(BaseActionHandler):
    """Purges Python pip cache using pip CLI."""

    def can_handle(self, action_type: ActionType) -> bool:
        return action_type == ActionType.PIP_CACHE_PURGE

    def execute(self, item: Any, dry_run: bool = False) -> Dict[str, Any]:
        if dry_run:
            return {"status": "DRY_RUN", "bytes_reclaimed": item.immediate_reclaimable_bytes}

        proc = subprocess.run([sys.executable, "-m", "pip", "cache", "purge"], capture_output=True, text=True, timeout=30, shell=False)
        if proc.returncode != 0:
            raise RuntimeError(f"pip cache purge failed: {proc.stderr.strip()}")

        return {"status": "SUCCESS", "bytes_reclaimed": item.immediate_reclaimable_bytes}


class DockerBuilderHandler(BaseActionHandler):
    """Prunes Docker builder cache using docker CLI."""

    def can_handle(self, action_type: ActionType) -> bool:
        return action_type == ActionType.DOCKER_BUILDER_PRUNE

    def execute(self, item: Any, dry_run: bool = False) -> Dict[str, Any]:
        if dry_run:
            return {"status": "DRY_RUN", "bytes_reclaimed": item.immediate_reclaimable_bytes}

        docker_bin = shutil.which("docker.exe") or shutil.which("docker")
        if not docker_bin:
            raise FileNotFoundError("docker executable not found in PATH")

        proc = subprocess.run([docker_bin, "builder", "prune", "-f"], capture_output=True, text=True, timeout=60, shell=False)
        if proc.returncode != 0:
            raise RuntimeError(f"docker builder prune failed: {proc.stderr.strip()}")

        return {"status": "SUCCESS", "bytes_reclaimed": item.immediate_reclaimable_bytes}


class BrowserCacheHandler(BaseActionHandler):
    """Safely clears browser caches while guaranteeing running browsers are never terminated."""

    BLOCKING_PROCESSES = ("chrome.exe", "msedge.exe", "brave.exe")

    def can_handle(self, action_type: ActionType) -> bool:
        return action_type == ActionType.BROWSER_CACHE_PURGE

    def execute(self, item: Any, dry_run: bool = False) -> Dict[str, Any]:
        for proc in self.BLOCKING_PROCESSES:
            state = check_process_state(proc)
            if state == ProcessState.RUNNING:
                return {
                    "status": "APP_RUNNING_SKIP",
                    "error": f"Browser process '{proc}' is running. Please close the browser before clearing cache.",
                    "bytes_reclaimed": 0,
                }
            if state == ProcessState.UNKNOWN:
                return {
                    "status": "APP_STATE_UNKNOWN_SKIP",
                    "error": f"Unable to verify process state for '{proc}' (tasklist error or timeout). Fail-closed skip.",
                    "bytes_reclaimed": 0,
                }

        from .safe_executor import send_to_recycle_bin

        if dry_run:
            return {"status": "DRY_RUN", "bytes_reclaimed": 0, "recycle_bin": True}

        send_to_recycle_bin(item.path)
        return {"status": "SUCCESS", "bytes_reclaimed": 0, "recycle_bin": True}


class OfficeCacheHandler(BaseActionHandler):
    """Safely clears Office caches while ensuring Office/Teams are closed."""

    BLOCKING_PROCESSES = ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "teams.exe", "ms-teams.exe")

    def can_handle(self, action_type: ActionType) -> bool:
        return action_type == ActionType.OFFICE_CACHE_PURGE

    def execute(self, item: Any, dry_run: bool = False) -> Dict[str, Any]:
        for proc in self.BLOCKING_PROCESSES:
            state = check_process_state(proc)
            if state == ProcessState.RUNNING:
                return {
                    "status": "APP_RUNNING_SKIP",
                    "error": f"Office application '{proc}' is running. Skipping cache cleanup.",
                    "bytes_reclaimed": 0,
                }
            if state == ProcessState.UNKNOWN:
                return {
                    "status": "APP_STATE_UNKNOWN_SKIP",
                    "error": f"Unable to verify process state for '{proc}' (tasklist error or timeout). Fail-closed skip.",
                    "bytes_reclaimed": 0,
                }

        from .safe_executor import send_to_recycle_bin

        if dry_run:
            return {"status": "DRY_RUN", "bytes_reclaimed": 0, "recycle_bin": True}

        send_to_recycle_bin(item.path)
        return {"status": "SUCCESS", "bytes_reclaimed": 0, "recycle_bin": True}


class CreatorCacheHandler(BaseActionHandler):
    """Safely clears Adobe/DaVinci/CapCut render caches without interrupting rendering."""

    BLOCKING_PROCESSES = (
        "Adobe Premiere Pro.exe",
        "AfterFX.exe",
        "Resolve.exe",
        "CapCut.exe",
    )

    def can_handle(self, action_type: ActionType) -> bool:
        return action_type == ActionType.CREATOR_CACHE_PURGE

    def execute(self, item: Any, dry_run: bool = False) -> Dict[str, Any]:
        for proc in self.BLOCKING_PROCESSES:
            state = check_process_state(proc)
            if state == ProcessState.RUNNING:
                return {
                    "status": "APP_RUNNING_SKIP",
                    "error": f"Creative application '{proc}' is active. Skipping render cache cleanup.",
                    "bytes_reclaimed": 0,
                }
            if state == ProcessState.UNKNOWN:
                return {
                    "status": "APP_STATE_UNKNOWN_SKIP",
                    "error": f"Unable to verify process state for '{proc}' (tasklist error or timeout). Fail-closed skip.",
                    "bytes_reclaimed": 0,
                }

        from .safe_executor import send_to_recycle_bin

        if dry_run:
            return {"status": "DRY_RUN", "bytes_reclaimed": 0, "recycle_bin": True}

        send_to_recycle_bin(item.path)
        return {"status": "SUCCESS", "bytes_reclaimed": 0, "recycle_bin": True}


class GamingCacheHandler(BaseActionHandler):
    """Safely purges Steam shader caches."""

    BLOCKING_PROCESSES = ("steam.exe",)

    def can_handle(self, action_type: ActionType) -> bool:
        return action_type == ActionType.GAMING_CACHE_PURGE

    def execute(self, item: Any, dry_run: bool = False) -> Dict[str, Any]:
        for proc in self.BLOCKING_PROCESSES:
            state = check_process_state(proc)
            if state == ProcessState.RUNNING:
                return {
                    "status": "APP_RUNNING_SKIP",
                    "error": f"Gaming client '{proc}' is running. Skipping shader cache cleanup.",
                    "bytes_reclaimed": 0,
                }
            if state == ProcessState.UNKNOWN:
                return {
                    "status": "APP_STATE_UNKNOWN_SKIP",
                    "error": f"Unable to verify process state for '{proc}' (tasklist error or timeout). Fail-closed skip.",
                    "bytes_reclaimed": 0,
                }

        from .safe_executor import send_to_recycle_bin

        if dry_run:
            return {"status": "DRY_RUN", "bytes_reclaimed": 0, "recycle_bin": True}

        send_to_recycle_bin(item.path)
        return {"status": "SUCCESS", "bytes_reclaimed": 0, "recycle_bin": True}


class StreamingLogsHandler(BaseActionHandler):
    """Safely purges OBS ephemeral logs and crash dumps."""

    BLOCKING_PROCESSES = ("obs64.exe", "obs32.exe")

    def can_handle(self, action_type: ActionType) -> bool:
        return action_type == ActionType.STREAMING_LOGS_PURGE

    def execute(self, item: Any, dry_run: bool = False) -> Dict[str, Any]:
        for proc in self.BLOCKING_PROCESSES:
            state = check_process_state(proc)
            if state == ProcessState.RUNNING:
                return {
                    "status": "APP_RUNNING_SKIP",
                    "error": f"OBS Studio ('{proc}') is currently active. Skipping logs cleanup.",
                    "bytes_reclaimed": 0,
                }
            if state == ProcessState.UNKNOWN:
                return {
                    "status": "APP_STATE_UNKNOWN_SKIP",
                    "error": f"Unable to verify process state for '{proc}' (tasklist error or timeout). Fail-closed skip.",
                    "bytes_reclaimed": 0,
                }

        from .safe_executor import send_to_recycle_bin

        if dry_run:
            return {"status": "DRY_RUN", "bytes_reclaimed": 0, "recycle_bin": True}

        send_to_recycle_bin(item.path)
        return {"status": "SUCCESS", "bytes_reclaimed": 0, "recycle_bin": True}


class ActionRegistry:
    """Manages registration and dispatching of typed cleanup action handlers."""

    def __init__(self) -> None:
        self._handlers: List[ActionHandler] = []

    def register(self, handler: ActionHandler) -> None:
        self._handlers.append(handler)

    def get_handler(self, action_type: ActionType) -> Optional[ActionHandler]:
        for h in self._handlers:
            if h.can_handle(action_type):
                return h
        return None

    def execute_action(self, item: Any, dry_run: bool = False) -> Dict[str, Any]:
        handler = self.get_handler(item.action_type)
        if not handler:
            raise NotImplementedError(f"No registered handler for action type '{item.action_type}'")
        return handler.execute(item, dry_run=dry_run)


def create_default_action_registry() -> ActionRegistry:
    """Build an ActionRegistry with all default typed handlers registered."""
    registry = ActionRegistry()
    registry.register(RecyclePathHandler())
    registry.register(NpmCacheHandler())
    registry.register(PipCacheHandler())
    registry.register(DockerBuilderHandler())
    registry.register(BrowserCacheHandler())
    registry.register(OfficeCacheHandler())
    registry.register(CreatorCacheHandler())
    registry.register(GamingCacheHandler())
    registry.register(StreamingLogsHandler())
    return registry
