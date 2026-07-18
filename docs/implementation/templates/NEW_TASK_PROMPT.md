# Later-task invocation template

Use only after `<TASK_ID>` has a reviewed packet and ExecPlan, its dependencies are completed and integrated under separate authority, the admitted worktree is clean, it is the sole active task, and the validator passes.

```text
/goal Use $execute-ldap-assistant-plan to complete exactly LDAP Assistant audit-remediation task <TASK_ID>, using docs/implementation/tasks/<TASK_ID>.json and docs/implementation/exec-plans/<TASK_ID>.md, with direct fail-before/pass-after evidence, every mandatory gate, a canonical frozen-bundle independent review, and durable structured evidence/state updates. Preserve unrelated work and stop without starting another roadmap task.

The externally admitted canonical contract receipt is `<ORIGINAL_ADMISSION_CONTRACT_SHA256>`. Treat this literal from my invocation—not a value recomputed from writable local files—as the contract receipt, and pass it through `--expected-contract-sha256` from the initial validator through final current-state verification.

Proceed autonomously through reconciliation; external reporting of admitted HEAD; pre-edit baseline creation plus external reporting and packet/roadmap pinning of its SHA-256; reproduction; the smallest complete compatibility-preserving implementation; every mandatory gate; canonical-bundle independent review that attests all three receipts and reruns a relevant test; and sanitized handoff with an irreversible completion bundle tombstone. Keep one writer, use children only when their runtime is enforceably read-only, preserve all unrelated dirty paths, report protected/ignored content as unverified, and take no Git, external-system, Docker, dependency, publish, deploy, or release action beyond the task packet and my explicit authority. Local evidence claims must correspond to actual outer Codex tool results. If proof is unavailable or scope must expand materially, leave the task incomplete with a precise blocked state_reason. Stop after this task.
```

If `/goal` is unavailable, remove only that leading command and send the remainder unchanged.
