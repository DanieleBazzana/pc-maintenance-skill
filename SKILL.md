---
name: pc-maintenance
description: Audit a user-selected macOS directory, sort maintenance findings, and create a safe cleanup plan. Use for disk usage, caches, logs, temporary files, installers, large files, duplicates, or cleanup candidates. Audit, dry-run, plan, and purge-preview modes are read-only; quarantine and restore are reversible, while permanent purge is an optional, per-entry final action with 72-hour retention and exact confirmations.
---

# PC Maintenance

Use this skill when Codex needs to inspect a local macOS directory and explain possible maintenance candidates without changing the filesystem.

The skill combines Codex's orchestration with a deterministic Python audit engine bundled in `scripts/pc_maintenance_skill/`. The engine performs metadata-only scanning, fail-closed safety checks, detector evaluation, process awareness, classification, sorting, read-only action planning, reporting, and JSONL audit logging.

## Operating contract

- `audit`, `dry-run`, and `plan` are read-only.
- Ask for or confirm the exact root directory before auditing when it is not explicit.
- Do not broaden a requested root to the whole home directory without explicit user approval.
- Treat `SAFE` as a candidate classification, never as authorization.
- Treat `REVIEW` as requiring user review.
- Treat `PROTECTED` as ineligible for automatic cleanup.
- Unknown or active process state cannot remain `SAFE`.
- Do not open sensitive file contents just to classify a path.
- Never permanently delete files unless the user explicitly selects the final purge layer and provides every required confirmation; never change permissions, escalate privileges, use the network, or install daemons or launch agents.
- Quarantine is allowed only with a complete integrity-checked action plan, an explicit quarantine directory outside the plan root, and a confirmation string exactly equal to the plan ID.
- Restore is allowed only from the generated manifest and with a confirmation string exactly equal to the operation ID.
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

### 6. Quarantine and restore

Only proceed after the user explicitly requests the operation and has reviewed a complete plan. Do not infer confirmation from a generic request to clean up.

Quarantine requires a report JSON generated by `plan`, an explicit destination outside the plan root, and the exact plan ID shown by the command:

```sh
PYTHONPATH=scripts python3 -m pc_maintenance_skill.cli quarantine \
  --plan-json reports/plan.json \
  --quarantine-dir "/absolute/path/to/quarantine" \
  --confirm-plan "EXACT_PLAN_ID"
```

The executor checks the plan digest, independently re-scans the root to confirm every requested file is still an inactive cache candidate, then revalidates regular-file type, symlink state, policy, path scope, size, mtime, device, inode, and process state before moving a file. It only performs same-filesystem atomic moves and updates a durable manifest under the quarantine operation directory.

To restore a completed quarantine:

```sh
PYTHONPATH=scripts python3 -m pc_maintenance_skill.cli restore \
  --manifest "/absolute/path/to/quarantine/OPERATION_ID/manifest.json" \
  --confirm-restore "EXACT_OPERATION_ID"
```

Restore refuses an existing destination, an altered quarantined file, an invalid manifest location, or a different filesystem.

For a read-only overview of a quarantine base, run `list-quarantines --quarantine-dir "/absolute/path/to/quarantine"`. It emits one compact JSON record for each operation manifest and never modifies files.

### 7. Optional irreversible final layer

Do not use permanent deletion unless the user explicitly asks for it. First run `purge-preview --manifest "/absolute/path/to/quarantine/OPERATION_ID/manifest.json"`. It is read-only and lists only intact regular files that have remained quarantined for at least 72 hours. To permanently delete one selected listed entry, require all of: the manifest path, one exact `--entry` path, `--confirm-purge` equal to the operation ID, and the entry-specific `--purge-token` emitted by the current preview. Never accept a bulk selection, a lower retention period, a root path, or a directory.

### 8. Explicit review quarantine

Treat `installer` and `large` findings as `REVIEW_REQUIRED`, never as automatic cleanup. After the user reviews a complete targeted plan, run `review-quarantine-preview --plan-json PLAN --entry PATH` and show its token-bound selection. Only after explicit confirmation, run `review-quarantine` with the same plan, exact entries, the plan ID, and its selection token. It must independently redetect the allowed category and revalidate policy, file type, symlink state, process state, containment, and fingerprint before a same-filesystem atomic move. Use normal `restore` to undo it. Do not use this layer for protected paths, directories, duplicates, logs, or temporary files.

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
# Run the `quick_validate.py` script bundled with the Skill Creator package against this repository.
```

The project must keep audit/preview modes read-only, quarantine reversible, permanent purge limited to one mature quarantined file per invocation, and pass the complete test suite.
