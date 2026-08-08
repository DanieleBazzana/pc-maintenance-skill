"""Detector compatibility exports and the canonical coordinator boundary."""

from .cache import cache_detector
from .developer_cache import developer_cache_detector
from .installer import installer_detector
from .large import large_detector
from .log import log_detector
from .observation import _finding
from .rules import detail_for_protected as _detail_for_protected
from .temporary_detector import temporary_detector
from ..duplicates import duplicate_detector
from .coordinator import coordinate_detections


def detect_all(entries, max_hash_files=1000, large_threshold=500 * 1024 * 1024):
    findings, stats = coordinate_detections(
        entries,
        max_hash_files=max_hash_files,
        large_threshold=large_threshold,
    )
    detect_all.stats = stats
    return findings


detect_all.stats = {}

__all__ = [
    "cache_detector", "developer_cache_detector", "installer_detector",
    "large_detector", "log_detector", "temporary_detector",
    "duplicate_detector", "detect_all",
]
