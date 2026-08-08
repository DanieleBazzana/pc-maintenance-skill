"""Read-only action-planning boundary; no filesystem executor exists."""

from .planning import build_action_plan

EXECUTOR_AVAILABLE = False

__all__ = ["EXECUTOR_AVAILABLE", "build_action_plan"]
