from typing import Iterable, List

from ..domain.models import Classification, Finding
from .observation import _finding
from .rules import developer_context, entry_parts


def detect(entries: Iterable) -> List[Finding]:
    result = []
    for entry in entries:
        parts = entry_parts(entry)
        if entry.is_file and (parts & {"node_modules", ".npm", ".yarn", ".pnpm", ".cache", ".vscode", "__pycache__", "deriveddata", "venv", ".venv", "virtualenv", "site-packages", "sdk", "sdks", "toolchain", "toolchains"}):
            result.append(_finding(entry, "developer_cache", "developer artifact may be regenerable but can belong to an active project", "developer path marker", Classification.REVIEW, context=developer_context(entry)))
    return result


developer_cache_detector = detect
