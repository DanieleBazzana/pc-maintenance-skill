from typing import Iterable, List

from ..domain.models import Classification, Finding
from .observation import _finding


def detect(entries: Iterable) -> List[Finding]:
    result = []
    for entry in entries:
        suffix = getattr(entry, "suffix_lower", entry.path.suffix.lower())
        path_lower = getattr(entry, "path_lower", str(entry.path).lower())
        if entry.is_file and (suffix in (".log", ".trace") or "/logs/" in path_lower):
            result.append(_finding(entry, "log", "log may be rotated or no longer needed", "log extension or logs directory", Classification.REVIEW))
    return result


log_detector = detect
