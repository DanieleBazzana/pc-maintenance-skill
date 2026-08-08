# PC Maintenance Agent

The PC Maintenance Agent is currently a read-only macOS audit and dry-run engine. It scans a selected local directory, applies a fail-closed safety policy, identifies maintenance candidates, checks process usage, classifies findings as `SAFE`, `REVIEW`, or `PROTECTED`, generates reports, and appends JSONL audit records.

No filesystem mutation executor is implemented. This version does not delete, move, rename, change permissions, quarantine, start a daemon or launch agent, use the network, or escalate privileges.

The codebase is in a partial V1 → V2 architectural migration. The canonical domain, scanning, safety, detector, process, classification, reporting, logging, preferences, and action boundaries exist, while compatibility adapters and a few migration artifacts remain.

For the detailed architecture, migration state, safety invariants, known issues, and roadmap, see [PROJECT_STATUS.md](PROJECT_STATUS.md).

## Run

From the project root:

```sh
PYTHONPATH=src python3 -m pc_maintenance_agent.cli audit --root ./ --output-dir ./reports
PYTHONPATH=src python3 -m pc_maintenance_agent.cli dry-run --root ./ --output-dir ./reports
```

The project directory is the only real path used for the initial dry-run. Generated files are written under `reports/`. Reports are local generated artifacts and are ignored by Git because they can contain personal filesystem paths.

## Safety

The policy fails closed for system paths, user data, projects, repositories, credentials, databases, backups, configuration, symlinks, external/network volumes, permission errors, and unknown process state. `SAFE` is only a future-cleanup candidate classification, not authorization. `IN_USE` and `UNKNOWN` process states cannot remain `SAFE`.

## Testing

The test suite uses only Python's standard `unittest` module and temporary fixtures:

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

The documented `PYTHONPATH=src` workflow requires no runtime dependencies. The project can also be built and installed as a standard wheel; the build environment provides `setuptools` as an isolated build dependency.

For an installed command:

```sh
python3 -m pip install .
pc-maintenance-agent --help
```
