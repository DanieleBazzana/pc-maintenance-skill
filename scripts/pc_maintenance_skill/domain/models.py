from dataclasses import dataclass, field
import hashlib
import json
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional


MAX_REPORT_FINDINGS_PER_CATEGORY = 500


__all__ = [
    "ActionEligibility", "ActionPlan", "ActionPlanItem", "Classification", "DecisionLayer",
    "DetectorObservation", "Disposition", "DuplicateGroup",
    "DuplicateVerification", "FileRecord", "Finding",
    "MAX_REPORT_FINDINGS_PER_CATEGORY", "PolicyDecision",
    "ProcessAssessment", "ProcessStatus", "ProposedAction", "ProtectionSource", "Report",
    "ScanScope", "UserPreferenceDecision", "apply_user_preference",
    "SortingBucket",
]


class Classification(str, Enum):
    SAFE = "SAFE"
    REVIEW = "REVIEW"
    PROTECTED = "PROTECTED"


class ProtectionSource(str, Enum):
    NONE = "NONE"
    POLICY = "POLICY"
    USER = "USER"


class Disposition(str, Enum):
    PROTECTED = "PROTECTED"
    REVIEW = "REVIEW"
    SAFE = "SAFE"


class DuplicateVerification(str, Enum):
    SAME_SIZE_ONLY = "SAME_SIZE_ONLY"
    PARTIAL_HASH_MATCH = "PARTIAL_HASH_MATCH"
    FULL_HASH_CONFIRMED = "FULL_HASH_CONFIRMED"
    HASH_SKIPPED = "HASH_SKIPPED"
    HASH_ERROR = "HASH_ERROR"


class DecisionLayer(str, Enum):
    POLICY_PROTECTED = "POLICY_PROTECTED"
    USER_PROTECTED = "USER_PROTECTED"
    REVIEW = "REVIEW"
    SAFE = "SAFE"


class ProcessStatus(str, Enum):
    IN_USE = "IN_USE"
    NOT_IN_USE = "NOT_IN_USE"
    UNKNOWN = "UNKNOWN"


class SortingBucket(str, Enum):
    CLEANUP_CANDIDATE = "CLEANUP_CANDIDATE"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    UNAVAILABLE = "UNAVAILABLE"
    PROTECTED = "PROTECTED"


class ProposedAction(str, Enum):
    NONE = "NONE"
    QUARANTINE = "QUARANTINE"


@dataclass(frozen=True)
class PolicyDecision:
    source: ProtectionSource
    disposition: Disposition
    reason: str
    evidence: str = ""
    rule_id: Optional[str] = None

    @property
    def classification(self) -> Classification:
        return Classification(self.disposition.value)


@dataclass(frozen=True)
class UserPreferenceDecision:
    protected: bool = False
    reason: str = ""
    rule_id: Optional[str] = None


@dataclass(frozen=True)
class ProcessAssessment:
    status: ProcessStatus
    source: str = ""
    reason: str = ""
    confidence: Optional[str] = None


@dataclass(frozen=True)
class DetectorObservation:
    category: str
    reason: str
    evidence: str = ""
    context: Optional[str] = None
    confidence: Optional[str] = None


@dataclass(frozen=True)
class ActionEligibility:
    eligible: bool = False
    reason: str = "Not eligible for the reversible quarantine executor"


@dataclass(frozen=True)
class ActionPlanItem:
    path: Path
    size: int
    category: str
    bucket: SortingBucket
    proposed_action: ProposedAction
    eligible: bool
    requires_confirmation: bool
    reason: str
    process_status: ProcessStatus
    classification: Classification
    sha256: Optional[str] = None
    expected_mtime_ns: Optional[int] = None
    expected_device: Optional[int] = None
    expected_inode: Optional[int] = None

    def as_dict(self) -> Dict[str, Any]:
        return {
            "path": str(self.path),
            "size": self.size,
            "category": self.category,
            "bucket": self.bucket.value,
            "proposed_action": self.proposed_action.value,
            "eligible": self.eligible,
            "requires_confirmation": self.requires_confirmation,
            "reason": self.reason,
            "process_status": self.process_status.value,
            "classification": self.classification.value,
            "sha256": self.sha256,
            "expected_mtime_ns": self.expected_mtime_ns,
            "expected_device": self.expected_device,
            "expected_inode": self.expected_inode,
        }


@dataclass(frozen=True)
class ActionPlan:
    operation_id: str
    root: Path
    items: List[ActionPlanItem] = field(default_factory=list)
    truncated_categories: Dict[str, int] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        bucket_counts: Dict[str, int] = {}
        bucket_bytes: Dict[str, int] = {}
        for item in self.items:
            key = item.bucket.value
            bucket_counts[key] = bucket_counts.get(key, 0) + 1
            bucket_bytes[key] = bucket_bytes.get(key, 0) + item.size
        candidate_bytes = sum(item.size for item in self.items if item.eligible)
        payload = {
            "schema_version": 2,
            "operation_id": self.operation_id,
            "root": str(self.root),
            "read_only": True,
            "executor_available": True,
            "complete": not bool(self.truncated_categories),
            "truncated_categories": dict(self.truncated_categories),
            "candidate_bytes": candidate_bytes,
            "bucket_counts": bucket_counts,
            "bucket_bytes": bucket_bytes,
            "items": [item.as_dict() for item in self.items],
        }
        # This digest detects accidental corruption or edits between planning and
        # execution.  It is intentionally not treated as an authorization token:
        # the executor independently rebuilds the eligible set from the filesystem.
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        payload["integrity_sha256"] = hashlib.sha256(encoded).hexdigest()
        return payload


@dataclass(frozen=True)
class DuplicateGroup:
    group_id: str
    verification_state: DuplicateVerification
    size: int
    members: List[Path] = field(default_factory=list)
    sha256: Optional[str] = None


def apply_user_preference(policy: PolicyDecision, preference: UserPreferenceDecision) -> PolicyDecision:
    if policy.source == ProtectionSource.POLICY:
        return policy
    if preference.protected:
        return PolicyDecision(
            ProtectionSource.USER,
            Disposition.PROTECTED,
            preference.reason or "protected by user preference",
            policy.evidence,
            preference.rule_id,
        )
    return policy


@dataclass
class FileRecord:
    path: Path
    size: int
    mtime: float
    is_dir: bool
    is_file: bool
    is_symlink: bool
    policy_classification: Classification
    policy_reason: str
    policy_evidence: str
    name_lower: str = ""
    suffix_lower: str = ""
    parts_lower: tuple = ()
    path_lower: str = ""
    device: int = 0
    inode: int = 0
    mode: int = 0
    uid: int = 0
    gid: int = 0
    symlink_target: str = ""
    scan_id: str = ""
    metadata_quality: str = "COMPLETE"
    policy_decision: Optional[PolicyDecision] = None
    mtime_ns: int = 0


@dataclass
class Finding:
    path: Path
    size: int
    mtime: float
    category: str
    reason: str
    evidence: str = ""
    policy_classification: Classification = Classification.REVIEW
    classification: Classification = Classification.REVIEW
    process_status: ProcessStatus = ProcessStatus.UNKNOWN
    hash_limit_reached: bool = False
    sha256: Optional[str] = None
    error: Optional[str] = None
    context: Optional[str] = None
    decision_layer: DecisionLayer = DecisionLayer.REVIEW
    detector_observation: Optional[DetectorObservation] = None
    policy_decision: Optional[PolicyDecision] = None
    process_assessment: Optional[ProcessAssessment] = None
    action_eligibility: ActionEligibility = field(default_factory=ActionEligibility)

    def __post_init__(self):
        if self.policy_decision is not None:
            self.policy_classification = self.policy_decision.classification
        if self.classification == Classification.REVIEW and self.policy_classification != Classification.REVIEW:
            self.classification = self.policy_classification
        if self.policy_decision is not None and self.policy_decision.source == ProtectionSource.USER and self.policy_classification == Classification.PROTECTED:
            self.decision_layer = DecisionLayer.USER_PROTECTED
        elif self.policy_classification == Classification.PROTECTED:
            self.decision_layer = DecisionLayer.POLICY_PROTECTED
        elif self.classification == Classification.SAFE:
            self.decision_layer = DecisionLayer.SAFE
        else:
            self.decision_layer = DecisionLayer.REVIEW

    @property
    def simulated_operation(self) -> str:
        if self.classification == Classification.SAFE:
            return "SIMULATED_DELETE"
        if self.classification == Classification.REVIEW:
            return "SIMULATED_QUARANTINE"
        return "PROTECTED"

    def as_dict(self) -> Dict[str, Any]:
        return {
            "path": str(self.path), "size": self.size, "mtime": self.mtime,
            "category": self.category, "reason": self.reason, "evidence": self.evidence,
            "classification": self.classification.value,
            "policy_classification": self.policy_classification.value,
            "process_status": self.process_status.value,
            "simulated_operation": self.simulated_operation,
            "hash_limit_reached": self.hash_limit_reached,
            "sha256": self.sha256, "error": self.error,
            "context": self.context,
            "decision_layer": self.decision_layer.value,
            "detector_observation": self.detector_observation.__dict__ if self.detector_observation else None,
            "policy_decision": {
                "source": self.policy_decision.source.value,
                "disposition": self.policy_decision.disposition.value,
                "reason": self.policy_decision.reason,
                "evidence": self.policy_decision.evidence,
                "rule_id": self.policy_decision.rule_id,
            } if self.policy_decision else None,
            "process_assessment": {
                "status": self.process_assessment.status.value,
                "source": self.process_assessment.source,
                "reason": self.process_assessment.reason,
                "confidence": self.process_assessment.confidence,
            } if self.process_assessment else None,
            "action_eligibility": {
                "eligible": self.action_eligibility.eligible,
                "reason": self.action_eligibility.reason,
            },
        }


@dataclass
class ScanScope:
    root: Path
    allowed_root: Path
    excluded_names: List[str] = field(default_factory=lambda: ["reports", "__pycache__"])


@dataclass
class Report:
    data: Dict[str, Any]

    def __getitem__(self, key):
        return self.data[key]

    def as_dict(self) -> Dict[str, Any]:
        return self.data
