# Quality gates

The task manifest lists required gate IDs. Run only commands appropriate to the current repository and environment; record exact commands and exit codes in the ExecPlan.

| Gate | Purpose | Minimum proof |
|---|---|---|
| G0 | Hygiene and state | Validator passes; root/branch/HEAD/upstream/dirty paths/audit hash recorded; syntax/static checks for touched files. |
| G1 | Targeted invariant | Every manifest `fail_before_cases` ID has deterministic nonzero expected-failure evidence and every acceptance has passed executable proof after the fix. |
| G2 | Subsystem regression | All directly affected module/unit tests pass. |
| G3 | Non-live repository | Complete `not live` suite passes with no unexplained skip or deselection. |
| G4 | Mode/integration | Relevant live/offline/STDIO/HTTP/Docker matrix passes, or the task remains incomplete. Resource ownership must be explicit. |
| G5 | Package/contract | Build, install, schemas, public response compatibility, lock consistency, and clean-environment smoke tests pass as applicable. |
| G6 | Adversarial | Permission denial, exceptions, empty/partial data, timeouts, malicious strings, privacy canaries, and boundary inputs required by the invariant pass. |
| G7 | Independent review | Fresh enforceably read-only review of the verified canonical bundle attests all three pre-edit receipts, approves every acceptance ID, independently reruns bundle verification and at least one relevant test, and has no unresolved critical/high finding. |
| G8 | CI/delivery | Required remote checks run against the exact delivered commit/artifact; publication consumes the tested artifact. |

## Safe current commands

Prefer the existing environment so validation cannot silently rewrite dependencies:

```bash
.venv/bin/ruff check src tests
.venv/bin/pytest <targeted-node-or-file> -q
.venv/bin/pytest tests/dirsrv_mcp -q
.venv/bin/pytest -m "not live" -q
uv lock --check
```

Until the dependency/test-runner remediation is complete, never use plain `uv run`; use `.venv/bin/...` or `uv run --no-sync`. Record tool versions when they matter.

## Docker and live tests

Current integration scripts use fixed resource names and have ownership/exit-propagation defects tracked by the roadmap. Before T005 is complete:

- do not run them merely because a checklist mentions integration;
- prove every container, volume, port, and project is owned by the current run;
- require explicit task and user authority for creation, reuse, cleanup, LDAP access, or network access;
- never inspect ignored real server configuration to make a test work;
- if a required integration gate cannot run safely, leave it pending and keep the task incomplete.

## Risk-specific proof

- False-success changes require injected denial/exception/empty/partial evidence for every required probe and a negative assertion that no healthy/success conclusion is emitted.
- Privacy/security changes require versioned canary corpora and checks of content, structured output, errors, metadata, resources/prompts, logs, and stderr as admitted.
- Contract changes require old/new shape comparison, consumer fixtures, migration notes, and explicit versioning authority.
- Release changes require tests/security/build on the exact tag SHA, artifact hashes, and proof that publication uses those identical artifacts.
- Test-infrastructure changes require deliberate failure injection proving install/test exit codes propagate and cleanup cannot affect unowned resources.

Passing tests are evidence only when their assertions reach the claimed boundary. Skipped, timed-out, deselected, flaky, or unavailable gates must be named exactly and cannot support completion.
