import argparse
from pathlib import Path

from ..actions import build_action_plan
from ..logging import append_records
from ..classification import classify_findings
from ..detectors import detect_all
from ..reporting import build_report, render_text, write_report
from ..scanning import scan


def main(argv=None):
    parser = argparse.ArgumentParser(description="Read-only PC maintenance Skill")
    parser.add_argument("mode", choices=("audit", "dry-run", "plan"))
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--large-threshold", type=int, default=500 * 1024 * 1024)
    parser.add_argument("--max-hash-files", type=int, default=1000)
    args = parser.parse_args(argv)

    root = args.root.expanduser().resolve(strict=False)
    output_dir = args.output_dir.expanduser().resolve(strict=False)
    diagnostics = {}
    entries = scan(root, allowed_root=root, diagnostics=diagnostics)
    findings = classify_findings(detect_all(entries, max_hash_files=args.max_hash_files, large_threshold=args.large_threshold))
    detection_stats = getattr(detect_all, "stats", {})
    action_plan = build_action_plan(root, findings, truncated_categories=detection_stats.get("truncated_details"))
    report = build_report(
        root,
        entries,
        findings,
        skipped=diagnostics["skipped"],
        errors=diagnostics["errors"],
        warnings=["This Skill has no filesystem mutation executor."],
        detection_stats=detection_stats,
        action_plan=action_plan,
    )
    text_path, json_path = write_report(report, output_dir, stem=args.mode)
    log_path = output_dir / "operations.jsonl"
    operation_id = append_records(log_path, findings)
    print(render_text(report))
    print(f"Text report: {text_path}")
    print(f"JSON report: {json_path}")
    print(f"Audit log: {log_path}")
    print(f"Operation ID: {operation_id}")
    print(f"Plan ID: {action_plan.operation_id}")
    return 0


__all__ = ["main"]
