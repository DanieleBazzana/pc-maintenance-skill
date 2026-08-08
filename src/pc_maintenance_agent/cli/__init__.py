from . import entrypoint as _entrypoint

append_records = _entrypoint.append_records
build_report = _entrypoint.build_report
classify_findings = _entrypoint.classify_findings
detect_all = _entrypoint.detect_all
render_text = _entrypoint.render_text
scan = _entrypoint.scan
write_report = _entrypoint.write_report


def main(argv=None):
    _entrypoint.append_records = append_records
    _entrypoint.build_report = build_report
    _entrypoint.classify_findings = classify_findings
    _entrypoint.detect_all = detect_all
    _entrypoint.render_text = render_text
    _entrypoint.scan = scan
    _entrypoint.write_report = write_report
    return _entrypoint.main(argv)


__all__ = [
    "append_records", "build_report", "classify_findings", "detect_all",
    "main", "render_text", "scan", "write_report",
]
