from typing import Iterable, List

from ..domain.models import Classification, Finding
from .observation import _finding
from .rules import large_evidence


def detect(entries: Iterable, threshold: int = 500 * 1024 * 1024) -> List[Finding]:
    return [
        _finding(entry, "large", "large file requires review; size alone is not evidence of expendability", large_evidence(entry), Classification.REVIEW)
        for entry in entries if entry.is_file and entry.size >= threshold
    ]


large_detector = detect
