from . import entrypoint as _entrypoint

append_records = _entrypoint.append_records
build_action_plan = _entrypoint.build_action_plan
execute_quarantine = _entrypoint.execute_quarantine
load_action_plan = _entrypoint.load_action_plan
restore_quarantine = _entrypoint.restore_quarantine
build_report = _entrypoint.build_report
classify_findings = _entrypoint.classify_findings
detect_all = _entrypoint.detect_all
render_text = _entrypoint.render_text
scan = _entrypoint.scan
write_report = _entrypoint.write_report


def main(argv=None):
    _entrypoint.append_records = append_records
    _entrypoint.build_action_plan = build_action_plan
    _entrypoint.execute_quarantine = execute_quarantine
    _entrypoint.load_action_plan = load_action_plan
    _entrypoint.restore_quarantine = restore_quarantine
    _entrypoint.build_report = build_report
    _entrypoint.classify_findings = classify_findings
    _entrypoint.detect_all = detect_all
    _entrypoint.render_text = render_text
    _entrypoint.scan = scan
    _entrypoint.write_report = write_report
    return _entrypoint.main(argv)


__all__ = [
    "append_records", "build_action_plan", "build_report", "classify_findings", "detect_all",
    "execute_quarantine", "load_action_plan", "main", "render_text", "restore_quarantine",
    "scan", "write_report",
]
