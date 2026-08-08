from ..domain.models import Classification, DecisionLayer, ProcessAssessment, ProcessStatus


def classify_findings(findings):
    result = []
    for finding in findings:
        if finding.policy_classification == Classification.PROTECTED:
            finding.classification = Classification.PROTECTED
            finding.decision_layer = DecisionLayer.POLICY_PROTECTED
        elif finding.process_status in (ProcessStatus.IN_USE, ProcessStatus.UNKNOWN):
            finding.classification = Classification.REVIEW
            finding.decision_layer = DecisionLayer.REVIEW
            finding.process_assessment = ProcessAssessment(finding.process_status, source="classifier")
            if finding.process_status == ProcessStatus.IN_USE:
                finding.reason += "; active process detected"
            else:
                finding.reason += "; process state unknown"
        elif finding.policy_classification == Classification.SAFE and finding.classification == Classification.SAFE:
            finding.classification = Classification.SAFE
            finding.decision_layer = DecisionLayer.SAFE
        else:
            finding.classification = Classification.REVIEW
            finding.decision_layer = DecisionLayer.REVIEW
        result.append(finding)
    return result


__all__ = ["classify_findings"]
