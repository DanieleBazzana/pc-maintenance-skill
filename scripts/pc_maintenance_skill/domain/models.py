from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional


MAX_REPORT_FINDINGS_PER_CATEGORY = 500


__all__ = [
    "ActionEligibility", "Classification", "DecisionLayer",
    "DetectorObservation", "Disposition", "DuplicateGroup",
    "DuplicateVerification", "FileRecord", "Finding",
    "MAX_REPORT_FINDINGS_PER_CATEGORY", "PolicyDecision",
    "ProcessAssessment", "ProcessStatus", "ProtectionSource", "Report",
    "ScanScope", "UserPreferenceDecision", "apply_user_preference",
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
    reason: str = "No action executor is implemented"


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
