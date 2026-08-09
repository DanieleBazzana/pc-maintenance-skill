"""Read-only action-planning boundary; no filesystem executor exists."""

from .planning import build_action_plan
from .executor import QuarantineError, execute_quarantine, execute_review_quarantine, list_quarantines, load_action_plan, preview_purge, preview_review_quarantine, purge_quarantine, restore_quarantine

EXECUTOR_AVAILABLE = True

__all__ = [
    "EXECUTOR_AVAILABLE", "QuarantineError", "build_action_plan",
    "execute_quarantine", "execute_review_quarantine", "list_quarantines", "load_action_plan", "preview_purge", "preview_review_quarantine", "purge_quarantine", "restore_quarantine",
]
