import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4


def append_records(path: Path, findings, operation_id=None):
    operation_id = operation_id or uuid4().hex
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as stream:
        for finding in findings:
            record = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "operation_id": operation_id,
                "path": str(finding.path),
                "category": finding.category,
                "classification": finding.classification.value,
                "simulated_operation": finding.simulated_operation,
                "result": "SIMULATED",
                "error": finding.error,
                "reason": finding.reason,
            }
            stream.write(json.dumps(record, sort_keys=True) + "\n")
    return operation_id


__all__ = ["append_records"]
