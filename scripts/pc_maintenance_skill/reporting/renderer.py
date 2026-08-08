import json
import shutil
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from ..domain.models import Classification, MAX_REPORT_FINDINGS_PER_CATEGORY, ProcessStatus, Report

_CLASS_RANK = {
    Classification.SAFE.value: 1,
    Classification.REVIEW.value: 2,
    Classification.PROTECTED.value: 3,
}


def _classification(value):
    return value.value if hasattr(value, "value") else str(value)


def _aggregate_findings(findings):
    category_totals = defaultdict(lambda: {"count": 0, "bytes": 0})
    category_seen = set()
    path_classification = {}
    path_size = {}
    details = []
    truncated = Counter()
    detail_counts = Counter()
    in_use = unknown = 0
    for finding in findings:
        item = finding.as_dict() if hasattr(finding, "as_dict") else dict(finding)
        path = item["path"]
        category = item["category"]
        key = (category, path)
        if key not in category_seen:
            category_seen.add(key)
            category_totals[category]["count"] += 1
            category_totals[category]["bytes"] += item["size"]
        current = path_classification.get(path)
        if current is None or _CLASS_RANK[item["classification"]] > _CLASS_RANK[current]:
            path_classification[path] = item["classification"]
        path_size[path] = max(path_size.get(path, 0), item["size"])
        if item["process_status"] == ProcessStatus.IN_USE.value:
            in_use += 1
        elif item["process_status"] == ProcessStatus.UNKNOWN.value:
            unknown += 1
        if detail_counts[category] < MAX_REPORT_FINDINGS_PER_CATEGORY:
            details.append(item)
            detail_counts[category] += 1
        else:
            truncated[category] += 1
    return category_totals, path_classification, path_size, details, truncated, in_use, unknown


def build_report(root, entries, findings, skipped, errors, warnings, detection_stats=None, action_plan=None):
    try:
        usage = shutil.disk_usage(root)
        total, free = usage.total, usage.free
    except OSError as exc:
        total = free = 0
        errors = list(errors) + [f"disk usage unavailable: {exc}"]

    category_totals, path_classification, path_size, details, truncated, in_use, unknown = _aggregate_findings(findings)
    stats = detection_stats or {}
    if stats.get("category_totals"):
        category_totals = stats["category_totals"]
    for category, count in (stats.get("truncated_details") or {}).items():
        truncated[category] = max(truncated[category], count)

    protected_entries = [entry for entry in entries if getattr(entry, "policy_classification", None) == Classification.PROTECTED]
    protected_summary = {"count": len(protected_entries), "bytes": sum(getattr(entry, "size", 0) for entry in protected_entries)}
    candidate_bytes = stats.get("candidate_bytes")
    if candidate_bytes is None:
        candidate_bytes = sum(size for path, size in path_size.items() if path_classification.get(path) in (Classification.SAFE.value, Classification.REVIEW.value))

    by_classification = Counter(path_classification.values())
    data = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "root": str(root),
        "read_only": True,
        "filesystem_changes_performed": False,
        "total_space": total,
        "free_space": free,
        "potentially_recoverable_space_upper_bound": candidate_bytes,
        "scanned_entries": len(entries),
        "counts": {
            "total": len(findings), "detailed": len(details),
            "unique_paths": len(path_classification), "by_classification": dict(by_classification),
            "by_category": {key: value["count"] for key, value in category_totals.items()},
        },
        "category_totals": dict(category_totals),
        "protected_summary": protected_summary,
        "truncated_details": dict(truncated),
        "process_status_counts": {"IN_USE": in_use, "UNKNOWN": unknown},
        "hash_files": stats.get("hash_files", 0),
        "hash_limit_reached": bool(stats.get("hash_limit_reached", False)),
        "findings": details,
        "skipped_paths": list(skipped), "errors": list(errors), "warnings": list(warnings),
        "safety_statement": "NO FILESYSTEM CHANGES PERFORMED",
    }
    if action_plan is not None:
        data["action_plan"] = action_plan.as_dict()
    if truncated:
        data["warnings"].append("Detailed findings were truncated by category; aggregate totals remain complete.")
    return Report(data)


def render_text(report: Report) -> str:
    d = report.as_dict()
    lines = [
        "## PC MAINTENANCE SKILL - READ-ONLY AUDIT", "", f"Root: {d['root']}",
        f"Scanned entries: {d['scanned_entries']}", f"Total space: {d['total_space']} bytes",
        f"Free space: {d['free_space']} bytes", f"Potential upper bound: {d['potentially_recoverable_space_upper_bound']} bytes",
        f"Protected total: {d['protected_summary']['count']} entries / {d['protected_summary']['bytes']} bytes", "",
        "Counts: " + json.dumps(d["counts"], sort_keys=True),
        "Category totals: " + json.dumps(d["category_totals"], sort_keys=True),
        "Process status: " + json.dumps(d["process_status_counts"], sort_keys=True),
    ]
    plan = d.get("action_plan")
    if plan:
        lines.extend([
            "",
            "Sorting and action plan (read-only): " + json.dumps(plan["bucket_counts"], sort_keys=True),
            f"Eligible candidate bytes: {plan['candidate_bytes']}",
            "No action was executed; eligible items require revalidation and explicit confirmation.",
        ])
        if not plan["complete"]:
            lines.append("WARNING: action-plan details are incomplete because findings were truncated: " + json.dumps(plan["truncated_categories"], sort_keys=True))
    for classification, label in (("SAFE", "🟢 SAFE"), ("REVIEW", "🟡 REVIEW"), ("PROTECTED", "🔴 PROTECTED")):
        lines.extend(["", label])
        lines.extend(f"- {item['path']} | {item['size']} bytes | {item['category']} | {item['simulated_operation']} | {item['reason']} | process={item['process_status']}" for item in d["findings"] if item["classification"] == classification)
    if d["truncated_details"]:
        lines.extend(["", "Truncated details:"] + [f"- {key}: {value}" for key, value in sorted(d["truncated_details"].items())])
    if d["skipped_paths"]:
        lines.extend(["", "Skipped paths:"] + [f"- {x}" for x in d["skipped_paths"]])
    if d["errors"]:
        lines.extend(["", "Errors:"] + [f"- {x}" for x in d["errors"]])
    if d["warnings"]:
        lines.extend(["", "Warnings:"] + [f"- {x}" for x in d["warnings"]])
    if d["hash_limit_reached"]:
        lines.extend(["", "WARNING: duplicate hashing limit reached; duplicate results are incomplete."])
    lines.extend(["", "NO FILESYSTEM CHANGES PERFORMED"])
    return "\n".join(lines) + "\n"


def write_report(report: Report, output_dir: Path, stem: str = "audit"):
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / f"{stem}.json"
    text_path = output_dir / f"{stem}.txt"
    json_path.write_text(json.dumps(report.as_dict(), indent=2, sort_keys=True), encoding="utf-8")
    text_path.write_text(render_text(report), encoding="utf-8")
    return text_path, json_path


__all__ = ["build_report", "render_text", "write_report"]
