"""Read-only action-planning boundary; no filesystem executor exists."""

from .planning import build_action_plan
from .executor import QuarantineError, execute_quarantine, load_action_plan, restore_quarantine

EXECUTOR_AVAILABLE = True

__all__ = [
    "EXECUTOR_AVAILABLE", "QuarantineError", "build_action_plan",
    "execute_quarantine", "load_action_plan", "restore_quarantine",
]
