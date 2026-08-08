from typing import Iterable, List

from ..domain.models import Classification, Finding
from .observation import _finding
from .rules import temporary_candidate


def detect(entries: Iterable) -> List[Finding]:
    return [
        _finding(entry, "temporary", "temporary or incomplete-file naming pattern", "strong temporary suffix or contextual temporary prefix", Classification.REVIEW)
        for entry in entries if temporary_candidate(entry)
    ]


temporary_detector = detect
