# PC Maintenance Skill

The PC Maintenance Skill is currently a read-only macOS audit, sorting, and action-planning engine. It scans a selected local directory, applies a fail-closed safety policy, identifies maintenance candidates, checks process usage, classifies findings as `SAFE`, `REVIEW`, or `PROTECTED`, sorts each finding into an operational bucket, generates a proposed action plan, writes reports, and appends JSONL audit records.

No filesystem mutation executor is implemented. This version does not delete, move, rename, change permissions, quarantine, start a daemon or launch agent, use the network, or escalate privileges.

The codebase is in a partial V1 → V2 architectural migration. The canonical domain, scanning, safety, detector, process, classification, reporting, logging, preferences, and action boundaries exist, while compatibility adapters and a few migration artifacts remain.

For the detailed architecture, migration state, safety invariants, known issues, and roadmap, see [PROJECT_STATUS.md](PROJECT_STATUS.md).

## Run

From the project root:

```sh
PYTHONPATH=scripts python3 -m pc_maintenance_skill.cli audit --root ./ --output-dir ./reports
PYTHONPATH=scripts python3 -m pc_maintenance_skill.cli dry-run --root ./ --output-dir ./reports
PYTHONPATH=scripts python3 -m pc_maintenance_skill.cli plan --root ./ --output-dir ./reports
```

The project directory is the only real path used for the initial dry-run. Generated files are written under `reports/`. Reports are local generated artifacts and are ignored by Git because they can contain personal filesystem paths.

## Safety

The policy fails closed for system paths, personal-data directories, projects, repositories, credentials, databases, backups, configuration, symlinks, external/network volumes, permission errors, and unknown process state. `SAFE` is only a future-cleanup candidate classification, not authorization. `IN_USE` and `UNKNOWN` process states cannot remain `SAFE`.

The `plan` mode adds four read-only sorting buckets: `CLEANUP_CANDIDATE`, `REVIEW_REQUIRED`, `UNAVAILABLE`, and `PROTECTED`. Only a regenerable cache classified `SAFE` and `NOT_IN_USE` becomes a `CLEANUP_CANDIDATE`; its proposed action is still a future quarantine and always requires revalidation and explicit confirmation.

Plans are explicitly marked incomplete whenever detailed findings were truncated, and incomplete plans must never be used as a future execution input.

## Testing

The test suite uses only Python's standard `unittest` module and temporary fixtures:

```sh
PYTHONPATH=scripts python3 -m unittest discover -s tests -v
```

The documented `PYTHONPATH=scripts` workflow requires no runtime dependencies. The project can also be built and installed as a standard wheel; the build environment provides `setuptools` as an isolated build dependency.

For an installed command:

```sh
python3 -m pip install .
pc-maintenance-skill --help
```
