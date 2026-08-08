import os
import stat
from pathlib import Path
from typing import List
from uuid import uuid4

from ..domain.models import FileRecord, ScanScope
from ..safety import evaluate_path


Entry = FileRecord


def scan(root: Path, allowed_root: Path = None, scope: ScanScope = None, diagnostics: dict = None, scan_id: str = None) -> List[FileRecord]:
    root = Path(root).expanduser()
    allowed = Path(allowed_root or root).expanduser()
    scan_id = scan_id or uuid4().hex
    excluded = set(scope.excluded_names if scope else ["reports", "__pycache__"])
    diagnostics = diagnostics if diagnostics is not None else {}
    diagnostics.setdefault("skipped", [])
    diagnostics.setdefault("errors", [])
    entries: List[FileRecord] = []
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as iterator:
                children = list(iterator)
        except (OSError, PermissionError) as exc:
            diagnostics["skipped"].append(str(current))
            diagnostics["errors"].append(f"{current}: {type(exc).__name__}")
            continue
        for item in children:
            if item.name in excluded and item.is_dir(follow_symlinks=False):
                continue
            path = Path(item.path)
            try:
                st = item.stat(follow_symlinks=False)
                is_link = item.is_symlink()
                is_dir = stat_is_dir(st.st_mode) and not is_link
                is_file = stat_is_file(st.st_mode) and not is_link
            except (OSError, PermissionError) as exc:
                diagnostics["skipped"].append(str(path))
                diagnostics["errors"].append(f"{path}: {type(exc).__name__}")
                continue
            decision = evaluate_path(path, allowed, known_is_symlink=is_link, known_stat=st)
            symlink_target = ""
            metadata_quality = "COMPLETE"
            if is_link:
                try:
                    symlink_target = os.readlink(path)
                except OSError:
                    metadata_quality = "PARTIAL"
            required_attrs = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid")
            if any(not hasattr(st, attr) for attr in required_attrs):
                metadata_quality = "PARTIAL"
            entries.append(FileRecord(
                path, st.st_size, st.st_mtime, is_dir, is_file, is_link,
                decision.classification, decision.reason, decision.evidence,
                path.name.lower(), path.suffix.lower(), tuple(part.lower() for part in path.parts), str(path).lower(),
                getattr(st, "st_dev", 0), getattr(st, "st_ino", 0), stat.S_IMODE(st.st_mode),
                getattr(st, "st_uid", 0), getattr(st, "st_gid", 0), symlink_target, scan_id,
                metadata_quality, decision,
            ))
            if is_dir:
                stack.append(path)
    return entries


def stat_is_dir(mode: int) -> bool:
    return (mode & 0o170000) == 0o040000


def stat_is_file(mode: int) -> bool:
    return (mode & 0o170000) == 0o100000
