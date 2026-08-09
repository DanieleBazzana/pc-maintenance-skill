"""Explicit, reversible quarantine executor for complete action plans."""

import json
import os
import stat
import tempfile
import hashlib
from datetime import datetime, timezone
from pathlib import Path

from ..classification import classify_findings
from ..detectors import detect_all
from ..domain.models import ActionPlan, ActionPlanItem, Classification, ProcessStatus, ProposedAction, SortingBucket
from ..process import check_many
from ..scanning import scan
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


def _integrity_digest(plan_data):
    payload = dict(plan_data)
    payload.pop("integrity_sha256", None)
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def load_action_plan(path: Path) -> ActionPlan:
    """Load an action plan from either a report JSON file or a plan JSON object."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError) as exc:
        raise QuarantineError(f"cannot read action plan: {type(exc).__name__}") from exc
    plan_data = data.get("action_plan", data)
    required = {"schema_version", "operation_id", "root", "items", "complete", "integrity_sha256"}
    if not required.issubset(plan_data):
        raise QuarantineError("action plan has missing required fields")
    if plan_data.get("schema_version") != 2:
        raise QuarantineError("action plan schema is unsupported")
    if not isinstance(plan_data.get("integrity_sha256"), str) or plan_data["integrity_sha256"] != _integrity_digest(plan_data):
        raise QuarantineError("action plan integrity check failed")
    if not plan_data.get("read_only") or not plan_data.get("executor_available"):
        raise QuarantineError("action plan is not executable")
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
    """Durably replace the manifest so an interrupted update keeps a valid copy."""
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent, prefix=".manifest-", suffix=".json", delete=False,
        ) as stream:
            json.dump(manifest, stream, indent=2, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
            temporary_path = Path(stream.name)
        os.replace(temporary_path, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError as exc:
        raise QuarantineError(f"cannot update quarantine manifest: {type(exc).__name__}") from exc


def _same_fingerprint(left: ActionPlanItem, right: ActionPlanItem) -> bool:
    return (
        left.size, left.expected_mtime_ns, left.expected_device, left.expected_inode,
    ) == (
        right.size, right.expected_mtime_ns, right.expected_device, right.expected_inode,
    )


def _current_cache_candidates(root: Path):
    """Detect current cache candidates without trusting fields in the saved plan."""
    diagnostics = {}
    entries = scan(root, allowed_root=root, diagnostics=diagnostics)
    findings = classify_findings(detect_all(entries))
    stats = getattr(detect_all, "stats", {})
    if stats.get("truncated_details"):
        raise QuarantineError("current scan is incomplete; quarantine is refused")
    records = {Path(entry.path).resolve(strict=False): entry for entry in entries}
    candidates = {}
    for finding in findings:
        path = Path(finding.path).resolve(strict=False)
        record = records.get(path)
        if (
            record is not None
            and finding.category == "cache"
            and finding.policy_classification != Classification.PROTECTED
            and finding.process_status == ProcessStatus.NOT_IN_USE
        ):
            candidates[path] = record
    return candidates


def _revalidate_plan_eligibility(plan: ActionPlan, root: Path):
    """Return current plan items only if each requested item remains independently eligible."""
    requested = [item for item in plan.items if item.eligible]
    if not requested:
        raise QuarantineError("action plan has no eligible quarantine candidates")
    current_by_path = _current_cache_candidates(root)
    verified = []
    for requested_item in requested:
        key = Path(requested_item.path).resolve(strict=False)
        record = current_by_path.get(key)
        if (
            record is None
            or (record.size, record.mtime_ns, record.device, record.inode)
            != (requested_item.size, requested_item.expected_mtime_ns, requested_item.expected_device, requested_item.expected_inode)
        ):
            raise QuarantineError(f"{requested_item.path}: no longer independently eligible for quarantine")
        verified.append(requested_item)
    return verified


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
    eligible = _revalidate_plan_eligibility(plan, root)
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


_MANUAL_REVIEW_CATEGORIES = {"installer", "large"}


def _review_selection_token(operation_id, items):
    selected = "\n".join(sorted(str(Path(item.path).resolve(strict=False)) for item in items))
    digest = hashlib.sha256(selected.encode("utf-8")).hexdigest()[:16]
    return f"REVIEW_QUARANTINE:{operation_id}:{digest}"


def _verify_review_item(item: ActionPlanItem, root: Path, process_states):
    if item.bucket != SortingBucket.REVIEW_REQUIRED or item.category not in _MANUAL_REVIEW_CATEGORIES:
        raise QuarantineError(f"{item.path}: only installer and large-file review entries are allowed")
    if item.classification != Classification.REVIEW:
        raise QuarantineError(f"{item.path}: review classification is required")
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
    if evaluate_path(path, root).classification == Classification.PROTECTED:
        raise QuarantineError(f"{path}: policy now protects this path")
    if (st.st_size, st.st_mtime_ns, st.st_dev, st.st_ino) != (
        item.size, item.expected_mtime_ns, item.expected_device, item.expected_inode,
    ):
        raise QuarantineError(f"{path}: file changed after the plan was created")
    if process_states.get(path, ProcessStatus.UNKNOWN) != ProcessStatus.NOT_IN_USE:
        raise QuarantineError(f"{path}: process state is no longer NOT_IN_USE")
    return st


def _current_review_candidates(root: Path):
    diagnostics = {}
    entries = scan(root, allowed_root=root, diagnostics=diagnostics)
    findings = classify_findings(detect_all(entries))
    stats = getattr(detect_all, "stats", {})
    if stats.get("truncated_details"):
        raise QuarantineError("current scan is incomplete; review quarantine is refused")
    records = {Path(entry.path).resolve(strict=False): entry for entry in entries}
    candidates = {}
    for finding in findings:
        path = Path(finding.path).resolve(strict=False)
        if (
            finding.category in _MANUAL_REVIEW_CATEGORIES
            and finding.classification == Classification.REVIEW
            and finding.policy_classification != Classification.PROTECTED
            and finding.process_status == ProcessStatus.NOT_IN_USE
            and path in records
        ):
            candidates[(path, finding.category)] = records[path]
    return candidates


def preview_review_quarantine(plan: ActionPlan, selected_paths):
    """Create a read-only, token-bound preview for explicitly selected review entries."""
    if plan.truncated_categories:
        raise QuarantineError("incomplete action plans cannot be used for review quarantine")
    root = Path(plan.root).expanduser().resolve(strict=False)
    if not root.is_dir():
        raise QuarantineError("plan root is unavailable")
    requested = {Path(path).expanduser().resolve(strict=False) for path in selected_paths}
    if not requested:
        raise QuarantineError("at least one explicit --entry is required")
    by_path = {Path(item.path).resolve(strict=False): item for item in plan.items}
    selected = []
    for path in requested:
        item = by_path.get(path)
        if item is None:
            raise QuarantineError(f"{path}: path is not present in the action plan")
        _verify_review_item(item, root, check_many([Path(item.path)]))
        selected.append(item)
    current = _current_review_candidates(root)
    for item in selected:
        key = (Path(item.path).resolve(strict=False), item.category)
        record = current.get(key)
        if record is None or (record.size, record.mtime_ns, record.device, record.inode) != (
            item.size, item.expected_mtime_ns, item.expected_device, item.expected_inode,
        ):
            raise QuarantineError(f"{item.path}: no longer independently matches the selected review category")
    return {
        "plan_id": plan.operation_id,
        "entries": [{"path": str(item.path), "size": item.size, "category": item.category, "reason": item.reason} for item in selected],
        "selection_token": _review_selection_token(plan.operation_id, selected),
    }


def execute_review_quarantine(plan: ActionPlan, quarantine_dir: Path, selected_paths, confirmation: str, token: str):
    """Atomically quarantine only user-selected, independently revalidated review entries."""
    if confirmation != plan.operation_id:
        raise QuarantineError("confirmation must exactly match the action-plan ID")
    preview = preview_review_quarantine(plan, selected_paths)
    if token != preview["selection_token"]:
        raise QuarantineError("review-quarantine token does not match the current selection")
    root = Path(plan.root).expanduser().resolve(strict=False)
    quarantine_base = Path(quarantine_dir).expanduser().resolve(strict=False)
    if _inside(quarantine_base, root):
        raise QuarantineError("quarantine directory must be outside the plan root")
    try:
        quarantine_base.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise QuarantineError(f"cannot create quarantine directory: {type(exc).__name__}") from exc
    operation_id = f"review-{plan.operation_id}"
    operation_dir = quarantine_base / operation_id
    if operation_dir.exists():
        raise QuarantineError("a review-quarantine operation with this ID already exists")
    try:
        operation_dir.mkdir(mode=0o700)
    except OSError as exc:
        raise QuarantineError(f"cannot create quarantine operation: {type(exc).__name__}") from exc
    if operation_dir.stat().st_dev != root.stat().st_dev:
        raise QuarantineError("quarantine directory must be on the same filesystem as the plan root")
    selected_by_path = {Path(item["path"]).resolve(strict=False) for item in preview["entries"]}
    items = [item for item in plan.items if Path(item.path).resolve(strict=False) in selected_by_path]
    manifest_path = operation_dir / "manifest.json"
    manifest = {"schema_version": 2, "operation_id": operation_id, "plan_id": plan.operation_id,
                "action_type": "EXPLICIT_REVIEW_QUARANTINE", "root": str(root), "quarantine_dir": str(operation_dir),
                "created_at": _now(), "state": "RUNNING", "entries": []}
    _write_manifest(manifest_path, manifest)
    for item in items:
        source = Path(item.path)
        destination = operation_dir / "files" / source.resolve(strict=False).relative_to(root)
        entry = {"source": str(source), "destination": str(destination), "size": item.size,
                 "mtime_ns": item.expected_mtime_ns, "device": item.expected_device, "inode": item.expected_inode,
                 "category": item.category, "status": "PENDING"}
        manifest["entries"].append(entry)
        try:
            _verify_review_item(item, root, check_many([source]))
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
    manifest["state"] = "COMPLETED" if all(entry["status"] == "QUARANTINED" for entry in manifest["entries"]) else "PARTIAL"
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


def list_quarantines(quarantine_dir: Path):
    """Read a quarantine base directory without changing manifests or files."""
    base = Path(quarantine_dir).expanduser().resolve(strict=False)
    if not base.is_dir():
        raise QuarantineError("quarantine directory is unavailable")
    operations = []
    for operation_dir in sorted(base.iterdir(), key=lambda item: item.name):
        manifest_path = operation_dir / "manifest.json"
        if not operation_dir.is_dir() or not manifest_path.is_file():
            continue
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            entries = manifest.get("entries", [])
            if not isinstance(entries, list) or not manifest.get("operation_id"):
                raise ValueError("invalid manifest")
        except (OSError, TypeError, ValueError):
            operations.append({"directory": str(operation_dir), "state": "INVALID_MANIFEST"})
            continue
        operations.append({
            "operation_id": manifest["operation_id"], "state": manifest.get("state", "UNKNOWN"),
            "created_at": manifest.get("created_at"), "entries": len(entries),
            "quarantined": sum(entry.get("status") == "QUARANTINED" for entry in entries),
            "manifest": str(manifest_path),
        })
    return operations


_PURGE_RETENTION_HOURS = 72


def _load_quarantine_manifest(manifest_path: Path):
    try:
        manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    except (OSError, TypeError, ValueError) as exc:
        raise QuarantineError(f"cannot read quarantine manifest: {type(exc).__name__}") from exc
    operation_dir = Path(manifest.get("quarantine_dir", "")).resolve(strict=False)
    if not manifest.get("operation_id") or Path(manifest_path).resolve(strict=False) != operation_dir / "manifest.json":
        raise QuarantineError("manifest location is invalid")
    return manifest, operation_dir


def _purge_token(operation_id, entries):
    selected = "\n".join(sorted(str(entry["destination"]) for entry in entries))
    digest = hashlib.sha256(selected.encode("utf-8")).hexdigest()[:16]
    return f"PURGE:{operation_id}:{digest}"


def preview_purge(manifest_path: Path):
    """List mature, intact files eligible for a future irreversible purge."""
    manifest, operation_dir = _load_quarantine_manifest(manifest_path)
    now = datetime.now(timezone.utc)
    eligible = []
    for entry in manifest.get("entries", []):
        if entry.get("status") != "QUARANTINED" or not entry.get("quarantined_at"):
            continue
        try:
            age_hours = (now - datetime.fromisoformat(entry["quarantined_at"])).total_seconds() / 3600
            source = Path(entry["destination"])
            st = source.lstat()
        except (KeyError, OSError, TypeError, ValueError):
            continue
        if age_hours < _PURGE_RETENTION_HOURS or not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode):
            continue
        if not _inside(source.resolve(strict=False), operation_dir):
            continue
        if (st.st_size, st.st_mtime_ns, st.st_dev, st.st_ino) != (entry.get("size"), entry.get("mtime_ns"), entry.get("device"), entry.get("inode")):
            continue
        eligible.append(entry)
    entries = [
        {"destination": item["destination"], "size": item["size"],
         "confirmation_token": _purge_token(manifest["operation_id"], [item])}
        for item in eligible
    ]
    return {"operation_id": manifest["operation_id"], "retention_hours": _PURGE_RETENTION_HOURS, "entries": entries}


def purge_quarantine(manifest_path: Path, destinations, confirmation: str, token: str):
    """Irreversibly remove explicitly selected, mature, intact quarantine files only."""
    preview = preview_purge(manifest_path)
    if confirmation != preview["operation_id"]:
        raise QuarantineError("confirmation must exactly match the quarantine operation ID")
    requested = {str(Path(value).expanduser().resolve(strict=False)) for value in destinations}
    eligible = {str(Path(item["destination"]).resolve(strict=False)): item for item in preview["entries"]}
    if len(requested) != 1 or not requested.issubset(eligible):
        raise QuarantineError("purge requires exactly one path from the current preview")
    selected = eligible[next(iter(requested))]
    if token != selected["confirmation_token"]:
        raise QuarantineError("purge token does not match the selected entry")
    manifest, _operation_dir = _load_quarantine_manifest(manifest_path)
    deleted = 0
    for entry in manifest["entries"]:
        if str(Path(entry.get("destination", "")).resolve(strict=False)) not in requested:
            continue
        source = Path(entry["destination"])
        try:
            st = source.lstat()
            if not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode):
                raise QuarantineError("quarantined entry is not a regular file")
            if (st.st_size, st.st_mtime_ns, st.st_dev, st.st_ino) != (entry["size"], entry["mtime_ns"], entry["device"], entry["inode"]):
                raise QuarantineError("quarantined entry changed after preview")
            source.unlink()
            entry["status"] = "PURGED"
            entry["purged_at"] = _now()
            deleted += 1
        except (OSError, QuarantineError) as exc:
            entry["purge_error"] = f"{type(exc).__name__}: {exc}"
        _write_manifest(Path(manifest_path), manifest)
    manifest["state"] = "PURGED" if deleted == len(requested) else "PARTIAL_PURGE"
    manifest["purged_at"] = _now()
    _write_manifest(Path(manifest_path), manifest)
    return deleted, manifest


__all__ = ["QuarantineError", "execute_quarantine", "execute_review_quarantine", "list_quarantines", "load_action_plan", "preview_purge", "preview_review_quarantine", "purge_quarantine", "restore_quarantine"]
