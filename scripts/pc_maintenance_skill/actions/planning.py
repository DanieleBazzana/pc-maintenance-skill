"""Read-only conversion of classified findings into an explicit action plan."""

from pathlib import Path
from uuid import uuid4

from ..domain.models import (
    ActionEligibility,
    ActionPlan,
    ActionPlanItem,
    Classification,
    ProcessStatus,
    ProposedAction,
    SortingBucket,
)


_BUCKET_RANK = {
    SortingBucket.CLEANUP_CANDIDATE: 1,
    SortingBucket.REVIEW_REQUIRED: 2,
    SortingBucket.UNAVAILABLE: 3,
    SortingBucket.PROTECTED: 4,
}


def _fingerprint(record):
    if record is None:
        return None, None, None
    return (
        getattr(record, "mtime_ns", int(getattr(record, "mtime", 0) * 1_000_000_000)),
        getattr(record, "device", None),
        getattr(record, "inode", None),
    )


def _item_for(finding, record=None):
    expected_mtime_ns, expected_device, expected_inode = _fingerprint(record)
    if finding.policy_classification == Classification.PROTECTED or finding.classification == Classification.PROTECTED:
        return ActionPlanItem(
            finding.path, finding.size, finding.category, SortingBucket.PROTECTED,
            ProposedAction.NONE, False, False, finding.reason,
            finding.process_status, finding.classification, finding.sha256,
            expected_mtime_ns, expected_device, expected_inode,
        )
    if finding.process_status in (ProcessStatus.IN_USE, ProcessStatus.UNKNOWN):
        return ActionPlanItem(
            finding.path, finding.size, finding.category, SortingBucket.UNAVAILABLE,
            ProposedAction.NONE, False, False,
            f"{finding.reason}; process state is {finding.process_status.value}",
            finding.process_status, finding.classification, finding.sha256,
            expected_mtime_ns, expected_device, expected_inode,
        )
    if finding.classification == Classification.SAFE and finding.category == "cache":
        finding.action_eligibility = ActionEligibility(
            eligible=True,
            reason="read-only plan: regenerable cache candidate is not in use",
        )
        return ActionPlanItem(
            finding.path, finding.size, finding.category, SortingBucket.CLEANUP_CANDIDATE,
            ProposedAction.QUARANTINE, True, True,
            "regenerable cache candidate; revalidation and explicit confirmation required",
            finding.process_status, finding.classification, finding.sha256,
            expected_mtime_ns, expected_device, expected_inode,
        )
    if finding.category == "duplicate_candidate" and finding.sha256:
        reason = "duplicate content was confirmed, but the user must choose which copy to retain"
    else:
        reason = finding.reason
    return ActionPlanItem(
        finding.path, finding.size, finding.category, SortingBucket.REVIEW_REQUIRED,
        ProposedAction.NONE, False, True, reason,
        finding.process_status, finding.classification, finding.sha256,
        expected_mtime_ns, expected_device, expected_inode,
    )


def build_action_plan(root: Path, findings, operation_id: str = None, truncated_categories=None, entries=None) -> ActionPlan:
    """Build a read-only, per-path plan using the most conservative finding."""
    records = {item.path: item for item in (entries or [])}
    selected = {}
    for finding in findings:
        item = _item_for(finding, records.get(finding.path))
        previous = selected.get(item.path)
        if previous is None or _BUCKET_RANK[item.bucket] > _BUCKET_RANK[previous.bucket]:
            selected[item.path] = item
    return ActionPlan(
        operation_id=operation_id or uuid4().hex,
        root=Path(root),
        items=sorted(selected.values(), key=lambda item: str(item.path)),
        truncated_categories=dict(truncated_categories or {}),
    )


__all__ = ["build_action_plan"]
