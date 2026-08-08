from typing import Iterable, List

from ..domain.models import Classification, Finding
from .observation import _finding
from .rules import installer_candidate


def detect(entries: Iterable) -> List[Finding]:
    return [
        _finding(entry, "installer", "installer/archive candidate requires user review", "contextual installer evidence; not a generic library archive", Classification.REVIEW)
        for entry in entries if installer_candidate(entry)
    ]


installer_detector = detect
