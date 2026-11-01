"""
Cleanup planning and safe execution package for disk_investigator.
"""

from .action_registry import (
    ActionHandler,
    ActionRegistry,
    create_default_action_registry,
    is_process_running,
)
from .action_types import ActionType
from .plan_generator import CleanupPlan, PlanGenerator, PlanItem
from .safe_executor import ExecutionResult, SafeExecutor, send_to_recycle_bin

__all__ = [
    "ActionType",
    "ActionHandler",
    "ActionRegistry",
    "create_default_action_registry",
    "is_process_running",
    "CleanupPlan",
    "PlanGenerator",
    "PlanItem",
    "ExecutionResult",
    "SafeExecutor",
    "send_to_recycle_bin",
]
