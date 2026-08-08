import hashlib
from typing import Iterable, List

from ..domain.models import Classification, Finding
from ..detectors.observation import _finding


LAST_STATS = {"hash_files": 0, "hash_limit_reached": False}


def detect(entries: Iterable, max_hash_files: int = 1000) -> List[Finding]:
    LAST_STATS.clear()
    LAST_STATS.update({"hash_files": 0, "hash_limit_reached": False})
    groups = {}
    for entry in entries:
        if entry.is_file and entry.policy_classification != Classification.PROTECTED:
            groups.setdefault(entry.size, []).append(entry)
    result = []
    hashed = 0
    for size, group in groups.items():
        if len(group) < 2:
            continue
        if max_hash_files <= 0:
            entry = group[0]
            LAST_STATS["hash_limit_reached"] = True
            finding = _finding(entry, "duplicate_candidate", "same-size duplicate group; content hashing disabled", f"size={size}; group_size={len(group)}; hashing disabled", Classification.REVIEW, process=False)
            finding.hash_limit_reached = True
            result.append(finding)
            continue
        hashes = {}
        for entry in group:
            if hashed >= max_hash_files:
                LAST_STATS["hash_limit_reached"] = True
                finding = _finding(entry, "duplicate_candidate", "same-size duplicate candidate not fully hashed", f"size={size}; hash limit reached", Classification.REVIEW, process=False)
                finding.hash_limit_reached = True
                result.append(finding)
                continue
            try:
                digest = hashlib.sha256()
                with open(entry.path, "rb") as stream:
                    for block in iter(lambda: stream.read(1024 * 1024), b""):
                        digest.update(block)
                value = digest.hexdigest()
                hashed += 1
                hashes.setdefault(value, []).append(entry)
            except (OSError, PermissionError) as exc:
                result.append(_finding(entry, "duplicate_candidate", "candidate could not be hashed; fail closed", type(exc).__name__, Classification.REVIEW, process=False))
        for digest, same in hashes.items():
            if len(same) > 1:
                for entry in same:
                    finding = _finding(entry, "duplicate_candidate", "same SHA-256 and size as another file; review required", f"sha256={digest}; size={size}", Classification.REVIEW, process=False)
                    finding.sha256 = digest
                    result.append(finding)
    LAST_STATS["hash_files"] = hashed
    return result


duplicate_detector = detect
