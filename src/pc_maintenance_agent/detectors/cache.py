from typing import Iterable, List

from ..domain.models import Classification, Finding
from .observation import _finding
from .rules import cache_context, entry_parts


def detect(entries: Iterable) -> List[Finding]:
    result = []
    for entry in entries:
        parts = entry_parts(entry)
        suffix = getattr(entry, "suffix_lower", entry.path.suffix.lower())
        if entry.is_file and (("cache" in parts or "caches" in parts) or suffix in (".cache", ".cached")):
            result.append(_finding(entry, "cache", "regenerable application/browser cache candidate", "cache path or extension", Classification.SAFE, context=cache_context(entry)))
    return result


cache_detector = detect
