# Execution protocol

Use this sequence for one admitted task. A later phase never cures a failed earlier phase.

## 1. Reconcile

- Confirm repository root, branch, `HEAD`, upstream, full dirty state, environment, audit hash, roadmap revision, task status, and delivery authority.
- Classify dirty paths as task-owned, pre-existing, or unknown. Preserve pre-existing paths byte-for-byte unless explicitly admitted.
- Revalidate audit references and manifest paths against the current tree.
- Record all facts in the ExecPlan. Repository state wins over stale prose; mismatches become discoveries, not silent assumptions.

Stop if a required workflow file is missing, the audit hash differs without an intentional revision, target ownership is unknown, or the named task is not admissible.

## 2. Admit

- Accept exactly one task ID.
- Verify status is `ready`, resumable `in_progress`, or `blocked` with a precise blocker that can now be re-evaluated. A blocked task remains read-only until reconciliation proves the blocker is resolved; then transition packet and roadmap together back to `in_progress` with the new reason and validate before continuing.
- Verify every dependency is `completed`.
- Restate the invariant, occurrences, allowed paths, non-goals, compatibility boundary, acceptance matrix, mandatory gates, rollback, and delivery permissions.
- Begin with the admission-contract SHA-256 supplied by the invocation/planning transcript; validate it with `--expected-contract-sha256 <ORIGINAL_ADMISSION_CONTRACT_SHA256>` and never recompute a replacement from locally editable scope files. Before transition, surface the reconciled `admitted_head` in conversation. Transition packet and roadmap together to `in_progress`, record a matching `state_reason`, and validate with both admission receipts. If no baseline exists, create it with both, surface its SHA-256, pin it in both state files, then pass all three externally retained values to the validator and `verify-baseline --expected-contract-sha256 <ORIGINAL_ADMISSION_CONTRACT_SHA256> --expected-head <ORIGINAL_ADMITTED_HEAD> --expected-baseline-sha256 <ORIGINAL_BASELINE_SHA256>` before product/test edits. If it exists, recover all three original external receipts and verify/reuse it with the same arguments; never overwrite or silently repin it. An `in_progress` task interrupted between transition and baseline creation may create the baseline only while every material target is still clean. An unpinned baseline artifact without the external receipts is a re-admission stop, not permission to derive a new receipt.

Stop for a manifest amendment if the implementation would need an unlisted subsystem, breaking contract change, dependency change, migration, unrelated cleanup, or another roadmap invariant.

## 3. Prove current behavior

- Trace each cited path in current source.
- Search for all in-scope occurrences; do not patch only the example named by the audit.
- Prefer a deterministic failure-injection regression that fails before the implementation for the expected semantic reason.
- If execution is unsafe or unavailable, record a source trace, limitation, and the proof still required before completion.

An exception observed is not enough: prove the public result violates the task invariant.

## 4. Implement with one writer

- The controller is the sole writer.
- Scouts may explore in parallel only after their effective runtime is verified read-only. If writable parent permissions override role defaults, do not use them in the shared worktree.
- Keep changes inside allowed paths and the smallest sufficient compatibility-preserving design.
- Update the ExecPlan after each milestone and when discoveries change the plan.
- Do not mix later roadmap abstractions into a hotfix unless the task explicitly requires them.

## 5. Verify by widening gates

- Run targeted fail-before/pass-after regressions first.
- Run subsystem and non-live suites next.
- Run integration, package, security, or release gates only when required and safe.
- Record exact command, working directory, exit code, result, limitations, and why the assertions exercise the criterion.
- Map evidence to each acceptance ID. A large pass count does not close an unmapped criterion.

## 6. Freeze and review

- Finish implementation and required evidence before review.
- Create the canonical review bundle from the pre-edit baseline. It must contain the tracked binary patch plus full bytes/hashes for task-owned untracked changes and a task-contract snapshot. Compute SHA-256 and stop editing.
- Give a fresh reviewer the verified canonical bundle, manifest/ExecPlan context, proof, and all three receipts retained before product edits: admission-contract SHA-256, admitted `HEAD`, and baseline SHA-256.
- Require a verdict per acceptance ID plus correctness, compatibility, security/privacy, error handling, and test-adequacy findings.
- Resolve critical/high findings and review again after every material edit.

## 7. Handoff and state transition

- Write structured, sanitized evidence and review records whose acceptance/gate verdicts and reviewed identity can be validated mechanically. Independently rerun at least one relevant test as well as bundle verification.
- Verify the current bundle with all three external receipts immediately before transition. Update ExecPlan outcomes, then set the bundle SHA-256 as `completion_bundle_sha256` in packet/roadmap and transition both to `completed`.
- Rerun the validator after the state transition. Completed tasks use self-contained historical bundle validation and do not consume the active task's receipts. Completion is irreversible under that task ID; corrective work gets a new task.
- Report protected/ignored paths as unverified, plus limitations, rollback, and the next planning candidate. Never infer content preservation from unchanged Git status. A later implementation may start only after the completed local change is integrated under separate user authority and the new admitted worktree is clean.
- Stop. Never start the next task in the same run.

## Mandatory stops and approvals

Stop and ask the user when any of these applies:

- the request names no task, multiple tasks, or the whole roadmap;
- user authority and manifest delivery permissions disagree;
- a required file, audit reference, dependency, or proof is missing;
- a target file contains unknown or overlapping work;
- the finding is contradicted or the invariant needs a material rewrite;
- a required gate needs network, production-looking LDAP, ignored configuration, secrets, Docker resources of unproven ownership, publishing, or other external mutation;
- completion would require a breaking public contract, dependency migration, or release action not admitted by the manifest.

Do not convert a stop into `not_applicable`. Pending proof means the task remains incomplete.

When a stop occurs after the task entered `in_progress`, transition it to `blocked` with a precise reason in both durable state files if those paths are safe to update. Admission failures before a task starts do not mutate roadmap state.
