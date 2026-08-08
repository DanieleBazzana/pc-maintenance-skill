from typing import Iterable, List

from .base import DetectorSpec
from .cache import cache_detector
from .developer_cache import developer_cache_detector
from .installer import installer_detector
from .large import large_detector
from .log import log_detector
from .temporary_detector import temporary_detector
from ..duplicates import duplicate_detector


_DETECTOR_SPECS = (
    DetectorSpec("cache", cache_detector),
    DetectorSpec("developer_cache", developer_cache_detector),
    DetectorSpec("log", log_detector),
    DetectorSpec("installer", installer_detector),
    DetectorSpec("temporary", temporary_detector),
    DetectorSpec("large", large_detector),
    DetectorSpec("duplicates", duplicate_detector),
)


def detector_registry() -> List[DetectorSpec]:
    return list(_DETECTOR_SPECS)


def run_registered_detectors(
    entries: Iterable,
    *,
    max_hash_files: int = 1000,
    large_threshold: int = 500 * 1024 * 1024,
):
    entries = list(entries)
    findings = []
    for spec in detector_registry():
        findings.extend(spec.run(entries, max_hash_files=max_hash_files, large_threshold=large_threshold))
    return findings
