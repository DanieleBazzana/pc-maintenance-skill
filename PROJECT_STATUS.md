# PC Maintenance Agent — Project Status

## Current baseline

- Version declared by the package: `1.0.0`.
- Current behavior: read-only audit and dry-run only.
- Git baseline: commit `4904f5b` (`chore: establish project baseline`).
- Test baseline: 33 tests passing with the standard-library `unittest` suite.
- Supported entry point:

  ```sh
  PYTHONPATH=src python3 -m pc_maintenance_agent.cli audit --root ./ --output-dir ./reports
  PYTHONPATH=src python3 -m pc_maintenance_agent.cli dry-run --root ./ --output-dir ./reports
  ```

Generated reports are intentionally ignored by Git because they can contain personal filesystem paths and local-environment information.

## Product intent

The project is intended to become a cautious macOS maintenance agent. Its current purpose is to inspect a selected local directory, identify possible maintenance candidates, explain why each candidate was found, and fail closed whenever an automatic decision would be unsafe.

The current implementation is an audit engine. It is not yet an autonomous cleanup tool.

## Current pipeline

```text
CLI input
  → metadata-only filesystem scan
  → fail-closed safety policy
  → detector registry
  → finding coordination and deduplication
  → process-awareness check via lsof
  → SAFE / REVIEW / PROTECTED classification
  → text and JSON reporting
  → JSONL audit log of simulated operations
```

No step in this pipeline mutates the filesystem.

## Implemented capabilities

### Scanning

`pc_maintenance_agent.scanning` scans a selected root using filesystem metadata. It records path, size, modification time, file type, symlink state, device, inode, mode, ownership metadata, scan ID, and metadata quality.

Sensitive file content is not opened by the scanner.

### Safety policy

`pc_maintenance_agent.safety` applies a fail-closed policy. It protects, among other things:

- system paths;
- personal-data directories;
- external, removable, and network-mounted paths;
- symlinks;
- paths outside the allowed root;
- credentials, secrets, environment files, key material, and keychains;
- databases and database sidecars;
- backups and archives;
- projects and repositories;
- paths whose metadata cannot be safely read.

The policy decision is kept separate from later classification decisions.

### Detectors

The detector registry currently contains seven detector families:

| Name | Purpose | Default posture |
| --- | --- | --- |
| `cache` | Application and browser cache candidates | `SAFE` candidate, subject to policy and process checks |
| `developer_cache` | Development artifacts such as `node_modules` and Python environments | `REVIEW` |
| `log` | Log files and log directories | `REVIEW` |
| `installer` | Installer and archive candidates in contextual locations | `REVIEW` |
| `temporary` | Strong temporary or incomplete-file patterns | `REVIEW` |
| `large` | Large files where size alone is not enough evidence | `REVIEW` |
| `duplicates` | Same-size and SHA-256 duplicate candidates | `REVIEW` |

Duplicate detection fails closed when hashing is disabled, limited, or unsuccessful. A same-size match is not treated as a confirmed duplicate.

### Process awareness

`pc_maintenance_agent.process` performs a read-only `lsof` inventory and intersects open paths with candidate paths. The process state is one of:

- `IN_USE`;
- `NOT_IN_USE`;
- `UNKNOWN`.

`IN_USE` and `UNKNOWN` candidates cannot remain `SAFE`; they are downgraded to `REVIEW`.

### Classification and domain model

The canonical domain model is in `pc_maintenance_agent.domain.models`. It includes:

- `FileRecord`;
- `Finding`;
- `PolicyDecision`;
- `UserPreferenceDecision`;
- `ProcessAssessment`;
- `DetectorObservation`;
- `ActionEligibility`;
- `DuplicateVerification`;
- `Report`.

The three main classifications are:

- `SAFE`: a future-cleanup candidate, not authorization;
- `REVIEW`: requires review or additional conditions;
- `PROTECTED`: no automatic action is allowed by policy.

Decision layers distinguish policy protection, user protection, review, and safe candidates. Policy protection has precedence over user preferences.

### Reporting and audit

The reporting boundary creates text and JSON reports containing aggregate totals, protected summaries, process state, truncated details, warnings, skipped paths, and errors.

The logging boundary appends JSONL records describing simulated operations. The records do not represent filesystem mutations.

## Migration status

### V1 — read-only audit

Status: implemented and covered by tests.

This includes scanning, safety checks, detectors, process awareness, classification, reporting, dry-run output, and audit logging.

### V2 / Phase 1 — architectural boundaries

Status: partially migrated and currently working.

The canonical boundaries now exist for:

- `domain`;
- `scanning`;
- `safety`;
- `detectors`;
- `duplicates`;
- `process`;
- `classification`;
- `preferences`;
- `reporting`;
- `logging`;
- `cli`;
- `actions`.

Several old top-level modules remain as compatibility adapters. They re-export or delegate to the canonical implementations so existing imports and tests continue to work.

### User preferences

Status: model boundary exists; application flow is not yet complete.

`UserPreferenceDecision` and `apply_user_preference` exist. The current tests verify that user protection can raise an unprotected finding to `PROTECTED`, but cannot override a policy-protected path. Persistent preferences and a user-facing preference workflow are not implemented.

### Action planning

Status: not yet formalized as a separate application stage.

The domain already exposes `ActionEligibility` and simulated operation labels, but the project does not yet produce a durable, explicit action plan separate from findings and reports.

### Action executor

Status: intentionally not implemented.

There is no delete, move, rename, permission change, quarantine, daemon, launch agent, network, or privilege-escalation implementation. `EXECUTOR_AVAILABLE` is false, and tests guard this boundary.

## Known issues and cleanup candidates

### Duplicate-looking package directory

The repository contains both:

```text
src/pc_maintenance_agent/
src/pc_maintenance-agent/
```

The underscore directory is the actual Python package. The hyphen directory contains only three small `__init__.py` files and is not a normal importable Python package. It is currently preserved in the baseline and should be investigated and removed in a dedicated cleanup commit if confirmed to be a stale migration artifact.

### Packaging

`pyproject.toml` currently declares:

```toml
[build-system]
requires = []
build-backend = "backend"
```

No local `backend` module is currently present. Running through `PYTHONPATH=src` works, but standard package installation has not yet been made reliable. Packaging should be fixed before distributing the tool.

### Documentation alignment

The README historically described only V1, while the code already contains V2 architectural boundaries. The README should remain user-focused; this document is the technical source of truth for the migration status.

### Reports

Reports are generated artifacts and are ignored by Git. Existing reports remain on disk for local inspection, but should not be committed by default.

## Safety invariants

These invariants must remain true in every future phase:

1. Policy-protected paths cannot be made eligible by user preference.
2. Symlinks are protected unless an explicit future design says otherwise.
3. Unknown process state cannot result in `SAFE`.
4. Same-size duplicate candidates are not confirmed without content verification.
5. Scanner and detector stages do not mutate the filesystem.
6. Any future action must revalidate the path and metadata immediately before execution.
7. Reports and audit logs must distinguish simulated operations from real operations.
8. Failures in metadata, permissions, process checks, hashing, and verification must fail closed.

## Proposed next milestones

### Milestone 3 — stabilization cleanup

1. Investigate and remove the hyphenated duplicate package directory if it is stale.
2. Fix the package build configuration.
3. Add a packaging/install verification test or documented supported installation path.
4. Keep all existing tests passing.

### Milestone 4 — decision and action planning

1. Make user preferences an explicit application input.
2. Separate observations, policy decisions, process assessments, classifications, and action plans.
3. Add machine-readable reasons for action eligibility and denial.
4. Keep the system read-only.

### Milestone 5 — reversible execution

Only after the decision model is reviewed should a reversible quarantine executor be considered. Permanent deletion should not be the first real action.

## Verification commands

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
PYTHONPATH=src python3 -m pc_maintenance_agent.cli --help
git status --short --branch
```
