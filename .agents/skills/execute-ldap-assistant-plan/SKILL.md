---
name: execute-ldap-assistant-plan
description: Explicit-invocation workflow for implementing exactly one bounded LDAP Assistant MCP audit-remediation task from docs/GLOBAL_AUDIT_AND_IMPROVEMENT_PLAN.md. Invoke with $execute-ldap-assistant-plan only when a specific task manifest or task ID is supplied and code changes are requested. Do not use for general repository work, explanation/audit/review-only requests, customer/SOS/389 DS incident diagnosis, creation of future customer-support Skills, whole-roadmap execution, release/publish/deploy work, test-only requests, or unscoped "fix everything" requests.
---

# Execute one LDAP Assistant plan task

Implement one admitted remediation task with reproducible evidence. Treat the task manifest as the scope contract, the ExecPlan as the living run record, and the repository as the source of current truth.

## Admit exactly one task

Require one explicit task ID such as `T001` or one path matching `docs/implementation/tasks/<TASK_ID>.json`.

If no task is named, more than one task is requested, the request says to execute the whole roadmap, or the desired outcome cannot be represented by one current manifest:

1. remain read-only;
2. inspect `docs/implementation/ROADMAP.json` only as needed;
3. state the missing or conflicting admission information;
4. suggest the smallest eligible task ID or a decomposition;
5. stop without editing, installing, syncing, testing through Docker, or changing Git state.

Do not infer the active task as permission to edit. Do not silently widen a narrow task. General code review, diagnosis, explanation, customer incident work, release work, and requests to design the later customer-facing Skills are outside this Skill.

## Load the minimum durable context

From the repository root, read in this order:

1. `AGENTS.md`;
2. `docs/implementation/ROADMAP.json`;
3. the named task manifest;
4. its named ExecPlan and `PLANS.md`;
5. only the audit sections referenced by the manifest;
6. current source and tests needed to establish behavior.

Do not load the entire global audit by default. Locate referenced IDs with `rg -n` and read the surrounding section. Verify the audit SHA-256 from the roadmap before relying on it.

Read these Skill references before implementation:

- `references/execution-protocol.md` for the run sequence and stop conditions;
- `references/task-contract.md` for roadmap, manifest, evidence, and state semantics;
- `references/quality-gates.md` for mandatory proof and safe commands.

Run:

```bash
.venv/bin/python .agents/skills/execute-ldap-assistant-plan/scripts/validate_execution_state.py --expected-contract-sha256 <ORIGINAL_ADMISSION_CONTRACT_SHA256>
```

Use the admission-contract SHA-256 supplied by the user's invocation or an externally retained planning transcript; never derive a replacement receipt from task files you are authorized to edit. Stop on validation errors. Report warnings and reconcile them in the ExecPlan.

## Reconcile before editing

Record repository root, branch, `HEAD`, upstream, complete dirty status, audit hash, active task, dependencies, environment, and delivery authority. Classify every dirty path as task-owned, pre-existing, or unknown. Preserve unrelated work.

Revalidate every cited path. Produce a concrete fail-before reproduction when feasible; otherwise record a precise source trace and why execution is unsafe or unavailable. Enumerate every repository-wide occurrence inside the admitted invariant. Confirm:

- one testable invariant;
- allowed paths and explicit non-goals;
- compatibility constraints;
- every acceptance criterion mapped to direct proof;
- mandatory gates, stop conditions, rollback, and delivery permissions.

If the finding is contradicted, target ownership is unknown, required evidence is inaccessible, a dependency is incomplete, or the task needs a materially broader contract, stop and request an explicit manifest amendment.

After reconciliation succeeds and before product/test edits, update both the roadmap summary and packet to `in_progress` with the same precise `state_reason`, rerun the validator, then create the packet's immutable pre-edit baseline:

```bash
.venv/bin/python .agents/skills/execute-ldap-assistant-plan/scripts/review_bundle.py baseline --task <TASK_ID> --expected-contract-sha256 <ORIGINAL_ADMISSION_CONTRACT_SHA256> --expected-head <ORIGINAL_ADMITTED_HEAD>
```

Before the state transition, confirm the externally supplied admission-contract SHA-256 equals `admission_contract_sha256` in packet and roadmap, surface the reconciled `HEAD` in conversation, and confirm it equals `admitted_head` in both files. Pass both external admission receipts to every artifact command. Immediately after baseline creation, surface its emitted SHA-256 before any product/test edit, record that exact value in `baseline_sha256` in both packet and roadmap, rerun the validator with all three external receipts, and run `verify-baseline`. Retain all three receipts for G0 and final review. Do not proceed if any identity differs.

Never overwrite an existing baseline. On resume, recover all three original receipts from the task transcript or read-only witness, first reconcile a `blocked` task back to `in_progress` only if its recorded blocker is demonstrably resolved, then verify and reuse the baseline:

```bash
.venv/bin/python .agents/skills/execute-ldap-assistant-plan/scripts/review_bundle.py verify-baseline --task <TASK_ID> --expected-contract-sha256 <ORIGINAL_ADMISSION_CONTRACT_SHA256> --expected-head <ORIGINAL_ADMITTED_HEAD> --expected-baseline-sha256 <ORIGINAL_BASELINE_SHA256>
```

If an `in_progress` run was interrupted before baseline creation, create it only when every material target is still clean. A baseline file without matching pins and all external receipts, or material edits without a verified baseline, requires a blocked re-admission, never a reconstructed before-state. If a mandatory stop occurs after this transition, persist `blocked` and the reason in both state files when safe; do not disguise the stop as completion.

## Use one writer and bounded read-only help

Keep the controller as the only writer. Delegate at most three independent read-only jobs at depth one, but first verify each child's effective runtime is read-only; parent live permission overrides can supersede role defaults. If enforcement is unavailable, keep reconnaissance in the controller and run final review in a separate read-only task:

- `evidence-explorer` for call paths and occurrences;
- `test-strategist` for acceptance-to-proof coverage;
- `risk-reviewer` only after the canonical review bundle is frozen and verified.

Never ask multiple agents to edit the shared worktree. Never let a subagent inspect ignored server configs, contact LDAP, mutate Docker, install dependencies, or perform Git delivery.

## Prove, implement, and verify

1. Add or capture regressions for every manifest `fail_before_cases` ID that fail for the intended reason.
2. Make the smallest sufficient change covering the complete admitted invariant.
3. Re-run the focused proof after each material milestone.
4. Widen through every gate required by the manifest.
5. Audit every acceptance ID against direct evidence; do not substitute aggregate pass counts.
6. Update the ExecPlan as discoveries and decisions occur.

Use `.venv/bin/...` or `uv run --no-sync`; never use plain `uv run` while the lock/test-path remediation remains open. Do not run fixed-name Docker scripts unless the manifest requires integration and resource ownership is explicit. Do not weaken tests or acceptance criteria to produce green output.

## Freeze and review

After implementation and required gates:

1. finish the structured evidence draft except for G7/final identity, then create the canonical review bundle; ordinary `git diff` is insufficient when any task-owned file is untracked;
2. record the emitted bundle SHA-256 as the immutable identity;
3. stop editing product, tests, task contract, and pre-review evidence;
4. assign `risk-reviewer` the manifest, ExecPlan, complete bundle, evidence, and all three original pre-edit receipts (admission-contract SHA-256, admitted `HEAD`, and baseline SHA-256); require independent bundle verification and at least one relevant passing test rerun;
5. resolve all critical/high findings and any acceptance failure;
6. if product, tests, task contract, or acceptance evidence changes materially, build a new bundle and obtain a new review.

Create and verify the bundle with:

```bash
.venv/bin/python .agents/skills/execute-ldap-assistant-plan/scripts/review_bundle.py freeze --task <TASK_ID> --expected-contract-sha256 <ORIGINAL_ADMISSION_CONTRACT_SHA256> --expected-head <ORIGINAL_ADMITTED_HEAD> --expected-baseline-sha256 <ORIGINAL_BASELINE_SHA256>
.venv/bin/python .agents/skills/execute-ldap-assistant-plan/scripts/review_bundle.py verify --task <TASK_ID> --expected-contract-sha256 <ORIGINAL_ADMISSION_CONTRACT_SHA256> --expected-head <ORIGINAL_ADMITTED_HEAD> --expected-baseline-sha256 <ORIGINAL_BASELINE_SHA256>
```

## Complete truthfully and stop

Mark a task complete only when all acceptance criteria and mandatory gates are explicitly passed in the structured evidence, acceptance/G1 evidence covers every declared fail-before case, G7 points to a distinct enforceably read-only reviewer task that independently recomputed the bundle, reran a relevant test, and attested all three original pre-edit receipts, the structured review approves every acceptance ID with zero mechanically recomputed unresolved critical/high finding, reviewed identities equal the verified bundle SHA-256, and all completion records exist at the manifest paths. Local JSON validates consistency but cannot prove a command ran or a reviewer was actually read-only; the outer Codex tool transcript and independently enforced reviewer task are mandatory witness evidence.

Immediately before transition, verify the current bundle with all three receipts. Update packet and roadmap together to `completed`, set both `completion_bundle_sha256` values to the reviewed bundle identity, set `active_task` to `null`, then rerun the state validator. Historical completed tasks validate from their self-contained artifacts and never consume a later active task's receipts. Never downgrade/reopen a completed task ID; create a corrective task.

Report behavior changed, exact verification and exit codes, reviewed bundle SHA-256 (and commit identity only when delivery was authorized), unverified protected/ignored paths, limitations, rollback, and the next planning candidate. Never claim that unread protected or ignored content was preserved; only an enforceable write-denial boundary can prove that. Do not start the next candidate. If this task did not authorize commit/integration, later implementation is blocked until a separately authorized delivery step integrates the reviewed change and provides a clean admitted worktree.

Do not stage, commit, branch, push, open a pull request, publish, deploy, tag, release, or contact external systems unless both the user and manifest explicitly authorize that exact action.
