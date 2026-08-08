# PC Maintenance Agent

Version 1 is intentionally read-only.

It scans a selected local directory, applies a fail-closed safety policy, classifies findings as SAFE, REVIEW, or PROTECTED, generates text/JSON reports, simulates future actions, and appends JSONL audit records.

This version has no delete, move, rename, permission, quarantine, daemon, launch-agent, network, or privilege-escalation implementation.

## Run

From the project root:

```sh
PYTHONPATH=src python3 -m pc_maintenance_agent.cli audit --root ./ --output-dir ./reports
PYTHONPATH=src python3 -m pc_maintenance_agent.cli dry-run --root ./ --output-dir ./reports
```

The project directory is the only real path used for the initial dry-run. Generated files are written under `reports/`.

## Safety

The policy fails closed for system paths, user data, projects, repositories, credentials, databases, backups, configuration, symlinks, external/network volumes, permission errors, and unknown process state. SAFE is only a future-cleanup candidate classification, not authorization.

## Testing

The test suite uses only Python's standard `unittest` module and temporary fixtures:

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

No global packages are required.
