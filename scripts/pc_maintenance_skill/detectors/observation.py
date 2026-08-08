from ..domain.models import Classification, DetectorObservation, Finding, ProcessAssessment, ProcessStatus


def _finding(entry, category, reason, evidence, preferred=Classification.REVIEW, process=True, context=None):
    status = ProcessStatus.UNKNOWN
    classification = entry.policy_classification
    if classification != Classification.PROTECTED and preferred == Classification.SAFE:
        classification = Classification.SAFE
    elif classification != Classification.PROTECTED:
        classification = Classification.REVIEW
    observation = DetectorObservation(category, reason, evidence, context=context)
    policy_decision = getattr(entry, "policy_decision", None)
    return Finding(
        entry.path, entry.size, entry.mtime, category, reason, evidence,
        entry.policy_classification, classification, status, context=context,
        detector_observation=observation, policy_decision=policy_decision,
        process_assessment=ProcessAssessment(status, source="pending"),
    )
