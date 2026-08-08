from pathlib import Path
from typing import Iterable, List

from ..domain.models import Classification, MAX_REPORT_FINDINGS_PER_CATEGORY, ProcessAssessment, ProcessStatus
from ..process import check_many
from ..duplicates.engine import LAST_STATS as DUPLICATE_STATS
from .registry import run_registered_detectors
from .observation import _finding
from .rules import detail_for_protected


def coordinate_detections(
    entries: Iterable,
    *,
    max_hash_files: int = 1000,
    large_threshold: int = 500 * 1024 * 1024,
):
    entries = list(entries)
    raw_findings = run_registered_detectors(
        entries,
        max_hash_files=max_hash_files,
        large_threshold=large_threshold,
    )
    findings = []
    stats = {
        "category_totals": {},
        "truncated_details": {},
        "candidate_paths": {},
        "hash_files": 0,
        "hash_limit_reached": False,
    }
    seen = set()
    detail_counts = {}

    def add(finding):
        category = finding.category
        if finding.sha256:
            key = (category, "sha256", finding.sha256)
        elif finding.hash_limit_reached:
            key = (category, "hash_limit", finding.evidence)
        else:
            key = (category, str(finding.path))
        if key in seen:
            return
        seen.add(key)
        total = stats["category_totals"].setdefault(category, {"count": 0, "bytes": 0})
        total["count"] += 1
        total["bytes"] += finding.size
        if finding.policy_classification != Classification.PROTECTED:
            stats["candidate_paths"][str(finding.path)] = finding.size
        if detail_counts.get(category, 0) >= MAX_REPORT_FINDINGS_PER_CATEGORY:
            stats["truncated_details"][category] = stats["truncated_details"].get(category, 0) + 1
            return
        detail_counts[category] = detail_counts.get(category, 0) + 1
        findings.append(finding)

    for finding in raw_findings:
        add(finding)
        if finding.hash_limit_reached:
            stats["hash_limit_reached"] = True

    for entry in entries:
        if entry.policy_classification == Classification.PROTECTED and detail_for_protected(entry):
            add(_finding(entry, "protected", entry.policy_reason, entry.policy_evidence, Classification.PROTECTED, process=False))

    stats["hash_files"] = DUPLICATE_STATS.get("hash_files", 0)
    stats["hash_limit_reached"] = bool(stats["hash_limit_reached"] or DUPLICATE_STATS.get("hash_limit_reached", False))

    stats["candidate_count"] = len(stats["candidate_paths"])
    stats["candidate_bytes"] = sum(stats["candidate_paths"].values())
    detailed_paths = {str(f.path) for f in findings if f.policy_classification != Classification.PROTECTED}
    candidate_paths = [Path(path) for path in stats["candidate_paths"] if path in detailed_paths]
    process_states = check_many(candidate_paths)
    for finding in findings:
        if finding.policy_classification != Classification.PROTECTED:
            finding.process_status = process_states.get(finding.path, ProcessStatus.UNKNOWN)
            finding.process_assessment = ProcessAssessment(finding.process_status, source="lsof")
    return findings, stats
