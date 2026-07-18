# Durable task contract

All control files use repository-relative paths and UTF-8. JSON is used for machine state so the validator requires only the Python standard library.

## Roadmap

`docs/implementation/ROADMAP.json` is the task index and scheduler, not an implementation narrative.

Required top-level fields:

- `schema_version`: currently `1`;
- `plan_revision`, `audit_path`, `audit_sha256`, and `audited_commit`;
- `portability`: whether a new local session or a separate worktree/cloud task can see the control plane;
- `required_workflow_files` and `protected_dirty_paths`;
- `active_task`: one task ID or `null`;
- `workstreams`: unique IDs and purposes;
- `tasks`: unique task summaries with dependencies, state, `state_reason`, packet, and ExecPlan paths.

Allowed task states are `planned`, `ready`, `in_progress`, `blocked`, and `completed`. Normal transitions are:

```text
planned -> ready -> in_progress -> completed
                      |     ^
                      v     |
                    blocked
```

Only one task may be `in_progress`, and it must equal `active_task`. A task becomes `ready` only after all dependencies are `completed` and its packet/ExecPlan are valid. After successful reconciliation, transition the packet and roadmap summary together to `in_progress` before product edits. A mandatory stop after that transition becomes `blocked` with a precise matching `state_reason`. Do not mark a task complete based on conversation text.

A fresh run may inspect a `blocked` task read-only. Resume only when the recorded blocker can be shown to be resolved; update packet and roadmap together back to `in_progress` with a precise new reason, rerun the state validator, and verify the immutable baseline before any further product/test edits. If the task was interrupted after transition but before baseline creation, creation is allowed only when every material target remains clean. If material edits exist without a baseline, leave the task blocked and request re-admission instead of inventing a before-state.

## Task packet

`docs/implementation/tasks/<TASK_ID>.json` is the admitted scope contract. It contains:

- identity, status, reconciled admitted `HEAD`, externally retained `admission_contract_sha256`, workstream, release intent, audit references, dependencies;
- one invariant and explicit customer/support value;
- known occurrences, allowed paths, non-goals, and compatibility constraints;
- acceptance criteria with stable IDs and explicit `fail_before_cases` IDs for every defect class that must fail before the fix;
- required gate IDs and integration policy;
- delivery permissions for commit, branch, push, pull request, publish, deploy, and release;
- baseline, review-bundle, evidence, review, ExecPlan, and rollback paths/requirements.

Changing the invariant, acceptance criteria, allowed subsystem, compatibility boundary, or mandatory gates is a material amendment. Record the reason in the ExecPlan before implementation continues. User authority cannot silently weaken a safety gate; the manifest cannot silently grant an external action the user did not request.

Create future packets from `docs/implementation/templates/TASK_TEMPLATE.json` and `EXEC_PLAN_TEMPLATE.md` in a separate product-code-read-only planning task. Revalidate the relevant audit sections and current source, obtain contract review, synchronize the candidate packet/roadmap summary, and compute the candidate receipt with `review_bundle.py fingerprint --task <TASK_ID> --json`. Surface that value in the planning transcript, pin it in both files, rerun the fingerprint command plus the validator with `--expected-contract-sha256`, and place the same literal in the implementation prompt. Set `ready` only when dependencies and proof design are complete. Do not use the execution Skill to invent its own scope while implementing.

## ExecPlan

The path named by `exec_plan_path` follows root `PLANS.md`. It is the living record. It must separate observed facts from intended behavior and retain dated progress, discoveries, decisions, exact verification, final review identity, rollback, and handoff.

## Baseline and review bundle

The packet and roadmap task summary declare the reconciled `admitted_head`, canonical `admission_contract_sha256`, and `baseline_sha256`, which is `null` while `ready` and until the first baseline is created. A product-code-read-only planning/admission step computes the contract hash over the exact packet contract while excluding state-only pins, reports it outside the writable worktree, and copies it into packet and roadmap. The implementation invocation must carry that externally retained value through `--expected-contract-sha256`; never replace it with a hash derived after the implementation controller begins. This binds invariant, allowed paths, acceptance criteria, gates, compatibility constraints, and delivery permissions against self-scoping.

Before transition, report `admitted_head` in conversation and retain it as the second external admission receipt. Every artifact command requires both admission values through `--expected-contract-sha256` and `--expected-head`, so neither a self-authorized contract expansion nor an unauthorized commit can become the before-state. The packet's `baseline_path` is generated once after transition to `in_progress` and before product/test edits. It records the base commit, task contract, controlled workflow hashes, task-owned path states, and only Git-reported status for protected paths. The control plane never directly opens or records metadata for protected content, although Git or a filesystem traversal may perform an `lstat` while discovering status.

Immediately after creation, report the emitted baseline SHA-256 in the task conversation (the third external receipt), copy it into `baseline_sha256` in both packet and roadmap, rerun the state validator with all three external arguments, and run `verify-baseline`. Do not begin product/test edits until the contract receipt equals packet, roadmap, and canonical projection; the HEAD receipt equals packet, roadmap, and repository; and the baseline receipt equals packet, roadmap, and actual bytes. A pre-edit read-only witness should retain all three receipts when enforceable delegation is available; the final reviewer must receive and attest the same values. Local files cannot cryptographically defend themselves from a deliberately malicious principal with unrestricted write access, so transcript/witness retention is part of the trust boundary.

On every resume, recover all three original receipts from the task transcript/witness and run `review_bundle.py verify-baseline --task <TASK_ID> --expected-contract-sha256 <ORIGINAL_ADMISSION_CONTRACT_SHA256> --expected-head <ORIGINAL_ADMITTED_HEAD> --expected-baseline-sha256 <ORIGINAL_BASELINE_SHA256>`. Pass the same external arguments to the state validator and later `freeze`/`verify` commands. Verification checks the externally supplied and locally pinned admission/baseline identities, immutable task contract, base `HEAD`, branch/upstream, roadmap projection, material before-state against `HEAD`, controlled files, staged state, Git index hiding flags, and out-of-scope/protected dirty inventory. Reuse the baseline only when that command and all three external receipts agree; it never creates or overwrites an artifact.

The packet's `review_bundle_path` is created after product/test changes and pre-review evidence are frozen. Its SHA-256 is the only review identity for an uncommitted task. It contains the tracked binary patch, full content/hashes for changed task-owned untracked paths, and contract/state projections. The generator refuses to overwrite either artifact. A material correction requires recording invalidation in the ExecPlan, deliberately removing the old task-owned bundle, then creating and reviewing a new one.

Before freeze, every acceptance ID and every required gate except G7 must already be `passed`; G7 remains `pending`, final state remains `in_progress`, and reviewed identity is `null`. State-only finalization may add the review, set G7/final identity/state, and update designated ExecPlan sections. Any product/test/contract or pre-review evidence change requires a new bundle and review.

## Evidence record

On completion write the manifest's `evidence_path` as structured sanitized JSON based on the repository template containing:

- task ID, final state, admitted contract/HEAD receipts, base and final `HEAD`, pinned baseline identity, and reviewed bundle identity;
- acceptance ID to direct evidence mapping;
- exact commands, working directory, exit codes, concise results, and relevant tool versions;
- limitations, environment facts, and sanitized artifact hashes; required gates cannot be pending or skipped at completion;
- explicitly unverified protected paths and rollback verification.

Never include credentials, bind DNs, customer identifiers, raw logs, ignored config content, or secrets.

Every manifest acceptance ID and required gate must be present with `status: passed` and non-empty direct evidence. The reviewed identity must equal the actual bundle SHA-256.

Each proof/evidence item has exact machine fields. Commands must be `passed` with integer exit code `0`; tests may also record a nonzero `expected_failure` for fail-before proof; artifacts and reviews carry the verified SHA-256; source traces carry neither exit code nor digest. Free text cannot override those fields.

```json
{
  "kind": "command | test | artifact | source_trace | review",
  "reference": "exact command or repository-relative artifact/reference",
  "result": "PASS: the precise behavior proved",
  "outcome": "passed | expected_failure | verified | approved",
  "exit_code": 0,
  "sha256": null,
  "case_id": null
}
```

The result prefix is fixed by outcome: `PASS:`, `EXPECTED_FAIL:`, `VERIFIED:`, or `APPROVED:`. This prevents a human-readable failure from being paired with a machine `passed` label.

Every acceptance criterion and every non-review gate needs at least one passed executable command/test item. Each acceptance proof and G1 must contain exactly the manifest's expected-failure `case_id` set; this prevents one fail-before example from standing in for several admitted failure classes. G7 is one approved review item tied to the actual bundle hash and structured reviewer provenance. The reviewer must record both a successful independent bundle-verification command and at least one independently passing relevant test rerun.

## Review record

The manifest's `review_path` is structured JSON recording the immutable bundle identity; reviewer task ID, enforced read-only runtime, independently recomputed bundle hash, and all three original pre-edit receipts; `approved` status and checked evidence per acceptance ID; overall `approve`; severity-ranked findings and disposition; tests independently inspected/rerun; blind spots; zero mechanically recomputed unresolved critical/high findings; and `material_changes_after_review: false`. A material product/test/contract edit after that identity was computed invalidates the review. Review provenance is an explicit attestation, not a cryptographic identity; if effective read-only execution and all receipts cannot be evidenced, G7 remains pending.

The local schemas prove internal consistency, not physical execution. A writable principal can fabricate a plausible command exit code, test result, reviewer task ID, or read-only attestation. Therefore the outer Codex tool transcript is the execution witness, and G7 requires a genuinely separate reviewer whose write denial is enforced outside these files. If either witness is unavailable, do not complete the task. Protected and Git-ignored content is intentionally not opened or directly metadata-inspected by the control plane, though Git/filesystem traversal may observe path metadata. Its preservation is outside the local attestation and must be reported as unverified unless the runtime enforces write denial.

## Completion truth

A task may transition to `completed` only when:

1. every acceptance ID has direct pass evidence;
2. every mandatory gate passed rather than being skipped or inferred;
3. the current verified bundle has a passing independent review and its actual SHA-256 matches both structured records;
4. evidence and review records exist and match the manifest;
5. the ExecPlan outcomes and rollback are current;
6. the roadmap validator passes after the transition.

Immediately before transition, run current-worktree bundle verification with all three external receipts. Set `completion_bundle_sha256` in packet and roadmap to the reviewed bundle identity while transitioning to `completed`. Subsequent validators authenticate that task historically from its canonical baseline/bundle plus final evidence/review; they do not compare old material to a later task's `HEAD`, later protected-path additions, or consume the later active task's receipt set.

Completion is irreversible under the same task ID. Never clear the completion tombstone or downgrade a completed task to `blocked`; use a new corrective task. Surface the final bundle/tombstone SHA-256 in conversation so the transcript/witness retains the completion receipt. Like the pre-edit receipts, a writable local tombstone cannot cryptographically resist a deliberately malicious unrestricted writer who deletes every artifact and pin; the external receipt and later Git integration are the durable trust boundary. Completion is not delivery: if the manifest did not authorize a commit, integration requires a separate user-authorized step, and no later implementation may begin until that reviewed change is integrated and the admitted worktree is clean.

If any condition is absent, use `in_progress` or `blocked` with a precise reason. Never edit the roadmap merely to make validation green.
