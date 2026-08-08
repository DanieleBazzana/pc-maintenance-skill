---
name: pc-maintenance
description: Run safe, read-only macOS maintenance audits on a user-selected local directory. Use when the user asks to inspect disk usage, caches, logs, temporary files, installers, large files, duplicates, or possible cleanup candidates. Never delete, move, rename, quarantine, change permissions, access file contents unnecessarily, or perform any other filesystem mutation.
---

# PC Maintenance

Use this skill when Codex needs to inspect a local macOS directory and explain possible maintenance candidates without changing the filesystem.

The skill combines Codex's orchestration with a deterministic Python audit engine bundled in `scripts/pc_maintenance_skill/`. The engine performs metadata-only scanning, fail-closed safety checks, detector evaluation, process awareness, classification, reporting, and JSONL audit logging.

## Operating contract

- Read-only is mandatory.
- Ask for or confirm the exact root directory before auditing when it is not explicit.
- Do not broaden a requested root to the whole home directory without explicit user approval.
- Treat `SAFE` as a candidate classification, never as authorization.
- Treat `REVIEW` as requiring user review.
- Treat `PROTECTED` as ineligible for automatic cleanup.
- Unknown or active process state cannot remain `SAFE`.
- Do not open sensitive file contents just to classify a path.
- Do not use deletion, move, rename, quarantine, permission, privilege-escalation, network, daemon, or launch-agent operations.
- Preserve generated reports locally; do not expose secrets or personal paths unnecessarily.

## Workflow

### 1. Establish scope

Identify the requested local root. If the user has not provided one, ask for it. Confirm whether the user wants a normal audit or a dry-run report; both modes are read-only in this version.

Use an output directory inside the project or another user-approved local directory. Avoid writing reports into the scanned root when that would affect the scan scope.

### 2. Run the bundled audit engine

From the skill repository root, run:

```sh
PYTHONPATH=scripts python3 -m pc_maintenance_skill.cli audit \
  --root "/absolute/path/to/root" \
  --output-dir reports
```

For the explicitly requested dry-run mode:

```sh
PYTHONPATH=scripts python3 -m pc_maintenance_skill.cli dry-run \
  --root "/absolute/path/to/root" \
  --output-dir reports
```

Optional controls:

- `--large-threshold BYTES` changes the large-file threshold;
- `--max-hash-files COUNT` bounds duplicate hashing and must remain finite.

Do not bypass the bundled engine with ad-hoc destructive shell commands.

### 3. Inspect and explain the result

Read the generated text or JSON report and summarize:

1. scanned scope and entry count;
2. counts by classification;
3. counts and bytes by detector category;
4. protected paths and why they were protected;
5. active or unknown process state;
6. hashing limits, skipped paths, errors, and warnings;
7. the potential recoverable-space figure as an upper bound only.

Explain that the audit did not modify the filesystem. Do not describe `SIMULATED_DELETE` or `SIMULATED_QUARANTINE` as performed operations.

### 4. Handle uncertainty

If the report contains `UNKNOWN`, permission errors, incomplete hashing, metadata errors, or truncated details, say so explicitly. Prefer `REVIEW` or `PROTECTED` over optimistic conclusions.

If the user asks to clean up after an audit, explain that this version only reports candidates and cannot perform cleanup.

## Classification semantics

- `SAFE`: evidence suggests a possible future cleanup candidate, but no action is authorized.
- `REVIEW`: the item may be useful, active, ambiguous, incompletely verified, or context-dependent.
- `PROTECTED`: policy marks the path as sensitive, personal, project-related, external, outside scope, a symlink, or otherwise unsafe.

The safety policy has precedence over detector suggestions. User preferences are not part of the current Skill workflow and cannot override policy protection.

## Detector coverage

The bundled engine currently checks:

- application and browser caches;
- developer caches and artifacts;
- logs;
- installers and contextual archives;
- temporary or incomplete files;
- large files;
- duplicate candidates using bounded hashing.

Same-size duplicate candidates are not confirmed without content verification. A hashing limit or hashing error remains a review condition.

## Verification

After changing the bundled engine or Skill files, run:

```sh
PYTHONPATH=scripts python3 -m unittest discover -s tests -v
python3 /Users/danielebazzana/.codex/skills/.system/skill-creator/scripts/quick_validate.py .
```

The project must retain its read-only guarantees and pass the complete test suite.
