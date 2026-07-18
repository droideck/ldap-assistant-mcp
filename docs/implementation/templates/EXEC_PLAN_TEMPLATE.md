# TXXX execution plan — replace with outcome

This is the living ExecPlan for `TXXX`. Maintain it according to root `PLANS.md`. Replace every instruction placeholder before promoting the task to `ready`.

### Purpose and outcome

Describe the observable customer/support-engineer result, why it matters, and what must be true at completion.

### Authority and starting state

Record packet/audit paths and hashes, repository root, branch, base/current/admitted `HEAD`, upstream, complete dirty state and ownership, environment, portability, explicit delivery authority, and all three external receipts once surfaced: admission-contract SHA-256, admitted HEAD, and baseline SHA-256.

### Invariant, scope, and non-goals

State one invariant. Enumerate revalidated occurrences, allowed paths, forbidden changes, compatibility constraints, and adjacent exclusions.

### Current behavior and reproduction

Describe observed behavior. Provide fail-before evidence or a precise source trace and explain any proof that remains unavailable.

### Acceptance-to-evidence matrix

| ID | Requirement | Before proof | Planned regression | After proof | Status |
|---|---|---|---|---|---|
| AC-01 | Replace | Pending | Replace | Pending | Not started |

### Plan of work

Define independently verifiable milestones. For each, name areas, intent, proof, and rollback point without prescribing speculative line edits.

### Progress

- [ ] Reconcile durable state and current repository behavior.
- [ ] Prove the failure and freeze the acceptance matrix.
- [ ] Implement the smallest complete correction.
- [ ] Run mandatory gates and map direct evidence.
- [ ] Freeze, independently review, record evidence/state, and stop.

### Surprises and discoveries

Add dated evidence and classify each discovery as `amend-current`, `follow-up`, `duplicate`, or `invalid`.

### Decision log

Record dated choices, alternatives, rationale, compatibility/safety impact, and important decisions not to change something.

### Verification plan and results

List gate IDs, exact commands, expected/actual results, exit codes, relevant versions, limitations, artifacts, and acceptance IDs exercised. Do not treat skips or aggregate pass counts as proof.

### Independent review

Record canonical bundle SHA-256 or reviewed commit, all three pre-edit receipts (admission-contract SHA-256, admitted HEAD, and baseline SHA-256), reviewer task/effective read-only runtime, verdict per acceptance ID, severity-ranked findings, inspected/rerun tests, blind spots, and re-review after material changes.

### Rollback and recovery

Define triggers, precise reversal, data/config/dependency/artifact implications, preservation of unrelated work, and post-rollback verification.

### Outcomes and handoff

Summarize achieved behavior, evidence/review paths, completion bundle tombstone, unresolved risks, roadmap transition, and the next planning candidate without beginning it. State that later implementation requires separately authorized integration and a clean admitted worktree.
