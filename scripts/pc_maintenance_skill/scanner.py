"""Compatibility adapter for the canonical scanning boundary."""

from .scanning import Entry, scan, stat_is_dir, stat_is_file

__all__ = ["Entry", "scan", "stat_is_dir", "stat_is_file"]
