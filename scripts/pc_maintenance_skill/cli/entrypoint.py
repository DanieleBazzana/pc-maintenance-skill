import argparse
import json
from pathlib import Path

from ..actions import QuarantineError, build_action_plan, execute_quarantine, list_quarantines, load_action_plan, restore_quarantine
from ..logging import append_records
from ..classification import classify_findings
from ..detectors import detect_all
from ..reporting import build_report, render_text, write_report
from ..scanning import scan
from ..preferences import PreferencesError, load_preferences


def _require(parser, value, option):
    if value is None:
        parser.error(f"{option} is required for this mode")


def main(argv=None):
    parser = argparse.ArgumentParser(description="PC maintenance Skill")
    parser.add_argument("mode", choices=("audit", "dry-run", "plan", "quarantine", "restore", "list-quarantines"))
    parser.add_argument("--root", type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--large-threshold", type=int)
    parser.add_argument("--max-hash-files", type=int)
    parser.add_argument("--config", type=Path, help="optional JSON preferences that can only narrow audit scope")
    parser.add_argument("--plan-json", type=Path)
    parser.add_argument("--quarantine-dir", type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--confirm-plan")
    parser.add_argument("--confirm-restore")
    args = parser.parse_args(argv)

    if args.mode == "list-quarantines":
        _require(parser, args.quarantine_dir, "--quarantine-dir")
        try:
            operations = list_quarantines(args.quarantine_dir)
        except QuarantineError as exc:
            parser.error(str(exc))
        for operation in operations:
            print(json.dumps(operation, sort_keys=True))
        print(f"Quarantine operations: {len(operations)}")
        return 0

    if args.mode == "quarantine":
        _require(parser, args.plan_json, "--plan-json")
        _require(parser, args.quarantine_dir, "--quarantine-dir")
        _require(parser, args.confirm_plan, "--confirm-plan")
        try:
            plan = load_action_plan(args.plan_json)
            if args.root is not None and args.root.expanduser().resolve(strict=False) != plan.root.expanduser().resolve(strict=False):
                parser.error("--root does not match the action-plan root")
            manifest_path, manifest = execute_quarantine(plan, args.quarantine_dir, args.confirm_plan)
        except QuarantineError as exc:
            parser.error(str(exc))
        print(f"Quarantine manifest: {manifest_path}")
        print(f"State: {manifest['state']}")
        print(f"Operation ID: {plan.operation_id}")
        return 0

    if args.mode == "restore":
        _require(parser, args.manifest, "--manifest")
        _require(parser, args.confirm_restore, "--confirm-restore")
        try:
            restored, manifest = restore_quarantine(args.manifest, args.confirm_restore)
        except QuarantineError as exc:
            parser.error(str(exc))
        print(f"Restored entries: {restored}")
        print(f"State: {manifest['state']}")
        print(f"Operation ID: {manifest['operation_id']}")
        return 0

    _require(parser, args.root, "--root")
    _require(parser, args.output_dir, "--output-dir")

    root = args.root.expanduser().resolve(strict=False)
    output_dir = args.output_dir.expanduser().resolve(strict=False)
    preferences = {}
    if args.config:
        try:
            preferences = load_preferences(args.config)
        except PreferencesError as exc:
            parser.error(str(exc))
        allowed_roots = preferences["audit_roots"]
        if allowed_roots and not any(root == allowed or root.is_relative_to(allowed) for allowed in allowed_roots):
            parser.error("--root is outside the audit_roots allowed by --config")
    large_threshold = args.large_threshold or preferences.get("large_threshold", 500 * 1024 * 1024)
    max_hash_files = args.max_hash_files or preferences.get("max_hash_files", 1000)
    diagnostics = {}
    entries = scan(root, allowed_root=root, diagnostics=diagnostics)
    findings = classify_findings(detect_all(entries, max_hash_files=max_hash_files, large_threshold=large_threshold))
    detection_stats = getattr(detect_all, "stats", {})
    action_plan = build_action_plan(
        root,
        findings,
        truncated_categories=detection_stats.get("truncated_details"),
        entries=entries,
    )
    report = build_report(
        root,
        entries,
        findings,
        skipped=diagnostics["skipped"],
        errors=diagnostics["errors"],
        warnings=["Audit, dry-run, and plan modes perform no filesystem changes."],
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
