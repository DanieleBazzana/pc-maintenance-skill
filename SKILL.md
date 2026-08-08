---
name: pc-maintenance
description: Run safe, read-only macOS maintenance audits on a user-selected local directory. Use when the user asks to inspect disk usage, caches, logs, temporary files, installers, large files, duplicates, or possible cleanup candidates. Never delete, move, rename, quarantine, change permissions, access file contents unnecessarily, or perform any other filesystem mutation.
---

# PC Maintenance

Use this skill when Codex needs to inspect a local macOS directory and explain possible maintenance candidates without changing the filesystem.

The skill combines Codex's orchestration with a deterministic Python audit engine bundled in `scripts/pc_maintenance_skill/`. The engine performs metadata-only scanning, fail-closed safety checks, detector evaluation, process awareness, classification, sorting, read-only action planning, reporting, and JSONL audit logging.

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

Identify the requested local root. If the user has not provided one, ask for it. Confirm whether the user wants an audit, dry-run, or action-plan report; all modes are read-only in this version.

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

For a sorting and proposed-action report:

```sh
PYTHONPATH=scripts python3 -m pc_maintenance_skill.cli plan \
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
7. the potential recoverable-space figure as an upper bound only;
8. sorting buckets and eligible candidate bytes from the action plan.

Explain that the audit did not modify the filesystem. Do not describe `SIMULATED_DELETE` or `SIMULATED_QUARANTINE` as performed operations.

### 4. Explain the action plan

The action plan is not an executor. It sorts each unique path into one of these buckets:

- `CLEANUP_CANDIDATE`: currently limited to a regenerable `cache` finding that is `SAFE` and `NOT_IN_USE`; proposed action is `QUARANTINE`, but it still requires revalidation and explicit confirmation.
- `REVIEW_REQUIRED`: ambiguous items, installers, logs, temporary files, large files, and confirmed duplicates that require a user choice.
- `UNAVAILABLE`: a file currently in use or whose process state is unknown.
- `PROTECTED`: a policy-protected path, including personal-data directories even when they are selected as the audit root.

No action plan item authorizes deletion. A confirmed duplicate remains in `REVIEW_REQUIRED` until the user chooses which copy to retain.

If the report says the plan is incomplete, it is a summary rather than a complete candidate list. Do not use an incomplete plan as a future execution input.

### 5. Handle uncertainty

If the report contains `UNKNOWN`, permission errors, incomplete hashing, metadata errors, or truncated details, say so explicitly. Prefer `REVIEW` or `PROTECTED` over optimistic conclusions.

If the user asks to clean up after an audit, explain that this version can produce a verified plan but cannot perform cleanup yet.

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
