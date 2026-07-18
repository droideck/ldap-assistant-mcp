# LDAP Assistant execution plans

An ExecPlan is a self-contained, living implementation specification for one bounded task. Use one for every audit-remediation task, security/privacy change, compatibility change, or multi-hour implementation.

The plan must let a fresh agent reconstruct scope and work state from the repository, task manifest, and ExecPlan. The only required external resume inputs are the admission-contract SHA-256, admitted-HEAD, and baseline-SHA receipts that were surfaced before edits; recover them from the task transcript or read-only witness. If they are unavailable, remain blocked rather than trusting writable local pins. Do not rely on any other chat history or unstated intent.

## Required properties

Every ExecPlan must:

- name exactly one task ID, one invariant, and one rollback boundary;
- distinguish current observed behavior from desired behavior;
- cite audit IDs and current source paths, but revalidate all locations;
- define scope and non-goals precisely;
- map every acceptance criterion to planned proof;
- remain current as discoveries, decisions, progress, and evidence change;
- produce demonstrably correct behavior, not merely a plausible diff;
- explain repository-specific terms a new contributor needs;
- preserve unrelated work and state delivery authority explicitly.

## Required sections

Use these sections in this order.

### Purpose and outcome

State the user-visible or support-engineer-visible result and why it matters. Describe what must be true when the task is complete.

### Authority and starting state

Record task manifest, audit references/hash, repository root, branch, base/admitted `HEAD`, upstream, dirty paths, environment, delivery authority, and all three externally surfaced/pinned pre-edit receipts once created. Classify dirty paths by ownership.

### Invariant, scope, and non-goals

Write the invariant in one testable sentence. List known occurrences, allowed paths/subsystems, compatibility constraints, forbidden changes, and explicit exclusions.

### Current behavior and reproduction

Describe the failure precisely. Include fail-before evidence or explain why a runtime reproduction is impossible and provide a source trace. Never store secrets or customer data.

### Acceptance-to-evidence matrix

For every acceptance ID, record the requirement, before proof, planned regression, after proof, and current status. No criterion may be closed by inference alone.

### Plan of work

Use independently verifiable milestones. Each milestone states files/areas, change intent, proof, and rollback point. Do not prescribe speculative line edits before source investigation.

### Progress

Maintain timestamped checkboxes. Split partial work so completed and remaining portions are explicit. Update this section whenever the run pauses.

### Surprises and discoveries

Record facts discovered during implementation, with evidence. Classify each as amend-current, follow-up, duplicate, or invalid. Do not silently expand scope.

### Decision log

Record material choices, alternatives, rationale, compatibility impact, and date. Include decisions not to change something.

### Verification plan and results

List mandatory gates, exact commands, expected behavior, actual exit codes/results, limitations, and artifacts. Confirm each test reaches the claimed failure path.

### Independent review

Record canonical review-bundle SHA-256 or reviewed commit, all three original pre-edit receipts, distinct reviewer task/effective read-only runtime, acceptance verdicts, findings, inspected/rerun tests, blind spots, and whether material edits forced a new bundle/review. Ordinary Git diff is insufficient when task-owned paths are untracked.

### Rollback and recovery

Define rollback triggers, exact method, compatibility/data/config implications, and post-rollback verification. Never restore an insecure default silently.

### Outcomes and handoff

Summarize achieved behavior, unresolved risks, evidence paths, roadmap transition, and next planning candidate. Do not begin it; state the separate integration/clean-worktree prerequisite for later implementation.

## Plan discipline

- Reconcile the plan with the repository at every resume; repository state wins when they disagree.
- Keep evidence concise and sanitized. Hash large temporary artifacts instead of copying logs into the plan.
- Mark a required gate pending when it cannot run. Do not rename “not run” to “not applicable” without a task-backed reason.
- Amend the task manifest before broadening scope.
- Freeze the canonical review bundle before independent review. Any material edit invalidates the previous bundle and verdict.
- A plan is complete only when all acceptance criteria and mandatory gates have direct evidence.
