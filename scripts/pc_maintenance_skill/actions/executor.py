"""Explicit, reversible quarantine executor for complete action plans."""

import json
import os
import stat
from datetime import datetime, timezone
from pathlib import Path

from ..domain.models import ActionPlan, ActionPlanItem, Classification, ProcessStatus, ProposedAction, SortingBucket
from ..process import check_many
from ..safety import evaluate_path


class QuarantineError(RuntimeError):
    """Raised when a plan or quarantine operation fails a safety precondition."""


def _now():
    return datetime.now(timezone.utc).isoformat()


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _item_from_dict(data):
    return ActionPlanItem(
        path=Path(data["path"]),
        size=int(data["size"]),
        category=data["category"],
        bucket=SortingBucket(data["bucket"]),
        proposed_action=ProposedAction(data["proposed_action"]),
        eligible=bool(data["eligible"]),
        requires_confirmation=bool(data["requires_confirmation"]),
        reason=data["reason"],
        process_status=ProcessStatus(data["process_status"]),
        classification=Classification(data["classification"]),
        sha256=data.get("sha256"),
        expected_mtime_ns=data.get("expected_mtime_ns"),
        expected_device=data.get("expected_device"),
        expected_inode=data.get("expected_inode"),
    )


def load_action_plan(path: Path) -> ActionPlan:
    """Load an action plan from either a report JSON file or a plan JSON object."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError) as exc:
        raise QuarantineError(f"cannot read action plan: {type(exc).__name__}") from exc
    plan_data = data.get("action_plan", data)
    required = {"operation_id", "root", "items", "complete"}
    if not required.issubset(plan_data):
        raise QuarantineError("action plan has missing required fields")
    return ActionPlan(
        operation_id=str(plan_data["operation_id"]),
        root=Path(plan_data["root"]),
        items=[_item_from_dict(item) for item in plan_data["items"]],
        truncated_categories=dict(plan_data.get("truncated_categories") or {}),
    )


def _verify_item(item: ActionPlanItem, root: Path, process_states):
    if not item.eligible or item.proposed_action != ProposedAction.QUARANTINE:
        raise QuarantineError(f"{item.path}: plan item is not eligible for quarantine")
    if item.bucket != SortingBucket.CLEANUP_CANDIDATE:
        raise QuarantineError(f"{item.path}: unexpected plan bucket")
    if None in (item.expected_mtime_ns, item.expected_device, item.expected_inode):
        raise QuarantineError(f"{item.path}: plan is missing a revalidation fingerprint")
    path = Path(item.path)
    try:
        st = path.lstat()
    except OSError as exc:
        raise QuarantineError(f"{path}: cannot read metadata ({type(exc).__name__})") from exc
    if not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode):
        raise QuarantineError(f"{path}: only regular, non-symlink files can be quarantined")
    if not _inside(path.resolve(strict=False), root):
        raise QuarantineError(f"{path}: path is outside the plan root")
    # Resolve the root and candidate through the same policy path. On macOS,
    # /var and /tmp are aliases under /private, so mixed normalization would
    # otherwise produce a false "outside allowed root" result.
    decision = evaluate_path(path, root)
    if decision.classification == Classification.PROTECTED:
        raise QuarantineError(f"{path}: policy now protects this path")
    if (st.st_size, st.st_mtime_ns, st.st_dev, st.st_ino) != (
        item.size, item.expected_mtime_ns, item.expected_device, item.expected_inode,
    ):
        raise QuarantineError(f"{path}: file changed after the plan was created")
    if process_states.get(path, ProcessStatus.UNKNOWN) != ProcessStatus.NOT_IN_USE:
        raise QuarantineError(f"{path}: process state is no longer NOT_IN_USE")
    return st


def _write_manifest(path: Path, manifest):
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")


def execute_quarantine(plan: ActionPlan, quarantine_dir: Path, confirmation: str):
    """Move eligible plan items atomically into a same-device, reversible quarantine."""
    if confirmation != plan.operation_id:
        raise QuarantineError("confirmation must exactly match the action-plan ID")
    if plan.truncated_categories:
        raise QuarantineError("incomplete action plans cannot be executed")
    root = Path(plan.root).expanduser().resolve(strict=False)
    if not root.is_dir():
        raise QuarantineError("plan root is unavailable")
    quarantine_base = Path(quarantine_dir).expanduser().resolve(strict=False)
    if _inside(quarantine_base, root):
        raise QuarantineError("quarantine directory must be outside the plan root")
    eligible = [item for item in plan.items if item.eligible]
    if not eligible:
        raise QuarantineError("action plan has no eligible quarantine candidates")
    process_states = check_many([Path(item.path) for item in eligible])
    verified = [(item, _verify_item(item, root, process_states)) for item in eligible]

    try:
        quarantine_base.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise QuarantineError(f"cannot create quarantine directory: {type(exc).__name__}") from exc
    operation_dir = quarantine_base / plan.operation_id
    if operation_dir.exists():
        raise QuarantineError("a quarantine operation with this ID already exists")
    try:
        operation_dir.mkdir(mode=0o700)
    except OSError as exc:
        raise QuarantineError(f"cannot create quarantine operation: {type(exc).__name__}") from exc
    if operation_dir.stat().st_dev != root.stat().st_dev:
        raise QuarantineError("quarantine directory must be on the same filesystem as the plan root")

    manifest_path = operation_dir / "manifest.json"
    manifest = {
        "schema_version": 1,
        "operation_id": plan.operation_id,
        "root": str(root),
        "quarantine_dir": str(operation_dir),
        "created_at": _now(),
        "state": "RUNNING",
        "entries": [],
    }
    _write_manifest(manifest_path, manifest)
    for item, _st in verified:
        source = Path(item.path)
        relative = source.resolve(strict=False).relative_to(root)
        destination = operation_dir / "files" / relative
        entry = {
            "source": str(source),
            "destination": str(destination),
            "size": item.size,
            "mtime_ns": item.expected_mtime_ns,
            "device": item.expected_device,
            "inode": item.expected_inode,
            "status": "PENDING",
        }
        manifest["entries"].append(entry)
        try:
            # Revalidate immediately before mutation to reduce the plan/action race window.
            _verify_item(item, root, check_many([source]))
            destination.parent.mkdir(parents=True, exist_ok=True)
            if destination.exists() or destination.is_symlink():
                raise QuarantineError("quarantine destination already exists")
            os.replace(source, destination)
            entry["status"] = "QUARANTINED"
            entry["quarantined_at"] = _now()
        except (OSError, QuarantineError) as exc:
            entry["status"] = "ERROR"
            entry["error"] = f"{type(exc).__name__}: {exc}"
        _write_manifest(manifest_path, manifest)
    manifest["state"] = "COMPLETED" if all(item["status"] == "QUARANTINED" for item in manifest["entries"]) else "PARTIAL"
    manifest["completed_at"] = _now()
    _write_manifest(manifest_path, manifest)
    return manifest_path, manifest


def restore_quarantine(manifest_path: Path, confirmation: str):
    """Restore quarantined files only when the exact operation ID is confirmed."""
    try:
        manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError) as exc:
        raise QuarantineError(f"cannot read quarantine manifest: {type(exc).__name__}") from exc
    operation_id = manifest.get("operation_id")
    if not operation_id or confirmation != operation_id:
        raise QuarantineError("confirmation must exactly match the quarantine operation ID")
    operation_dir = Path(manifest.get("quarantine_dir", "")).resolve(strict=False)
    root = Path(manifest.get("root", "")).resolve(strict=False)
    if not operation_dir.is_dir() or not root.is_dir() or Path(manifest_path).resolve(strict=False) != operation_dir / "manifest.json":
        raise QuarantineError("manifest location is invalid")
    restored = 0
    for entry in manifest.get("entries", []):
        if entry.get("status") != "QUARANTINED":
            continue
        source = Path(entry["destination"])
        destination = Path(entry["source"])
        try:
            st = source.lstat()
            if not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode):
                raise QuarantineError("quarantined entry is not a regular file")
            if (st.st_size, st.st_mtime_ns, st.st_dev, st.st_ino) != (
                entry["size"], entry["mtime_ns"], entry["device"], entry["inode"],
            ):
                raise QuarantineError("quarantined entry changed after the operation")
            if not _inside(source.resolve(strict=False), operation_dir):
                raise QuarantineError("quarantined entry is outside its operation directory")
            if not _inside(destination.resolve(strict=False), root):
                raise QuarantineError("restore destination is outside the original root")
            if destination.exists() or destination.is_symlink():
                raise QuarantineError("restore destination already exists")
            if source.stat().st_dev != root.stat().st_dev:
                raise QuarantineError("restore requires the original filesystem")
            destination.parent.mkdir(parents=True, exist_ok=True)
            os.replace(source, destination)
            entry["status"] = "RESTORED"
            entry["restored_at"] = _now()
            restored += 1
        except (OSError, QuarantineError) as exc:
            entry["restore_error"] = f"{type(exc).__name__}: {exc}"
        _write_manifest(Path(manifest_path), manifest)
    manifest["state"] = "RESTORED" if all(item.get("status") == "RESTORED" for item in manifest.get("entries", [])) else "PARTIAL_RESTORE"
    manifest["restored_at"] = _now()
    _write_manifest(Path(manifest_path), manifest)
    return restored, manifest


__all__ = ["QuarantineError", "execute_quarantine", "load_action_plan", "restore_quarantine"]
