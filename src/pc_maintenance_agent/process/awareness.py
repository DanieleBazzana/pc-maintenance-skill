import subprocess
from pathlib import Path
from typing import Dict, Iterable

from ..domain.models import ProcessStatus


def check_many(paths: Iterable[Path], timeout: float = 60.0) -> Dict[Path, ProcessStatus]:
    """Read-only process check using one lsof inventory and path intersection."""
    unique = list(dict.fromkeys(Path(p) for p in paths))
    statuses = {path: ProcessStatus.UNKNOWN for path in unique}
    if not unique:
        return statuses
    try:
        result = subprocess.run(
            ["lsof", "-Fpn"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (FileNotFoundError, PermissionError, subprocess.TimeoutExpired, OSError):
        return statuses
    if result.returncode == 1:
        return {path: ProcessStatus.NOT_IN_USE for path in unique}
    if result.returncode != 0:
        return statuses
    wanted = {str(path): path for path in unique}
    open_paths = set()
    for line in result.stdout.splitlines():
        if line.startswith("n"):
            path = wanted.get(line[1:])
            if path is not None:
                open_paths.add(path)
    return {path: (ProcessStatus.IN_USE if path in open_paths else ProcessStatus.NOT_IN_USE) for path in unique}


def check_in_use(path: Path, timeout: float = 1.5) -> ProcessStatus:
    return check_many([path], timeout=timeout).get(Path(path), ProcessStatus.UNKNOWN)
