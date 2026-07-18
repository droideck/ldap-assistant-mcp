#!/usr/bin/env python3
"""Validate the durable LDAP Assistant execution control plane."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True

from review_bundle import (
    BundleError,
    assert_no_index_hiding,
    canonical_json,
    contract_projection,
    sha256_bytes,
    verify_historical_bundle,
)


SCHEMA_VERSION = 1
MAX_CONTROL_FILE_BYTES = 4 * 1024 * 1024
MAX_JSON_DEPTH = 64
MAX_JSON_NODES = 100_000
ALLOWED_STATUSES = {"planned", "ready", "in_progress", "blocked", "completed"}
ALLOWED_GATES = {f"G{number}" for number in range(9)}
ALLOWED_FINDING_SEVERITIES = {"critical", "high", "medium", "low", "info"}
ALLOWED_EVIDENCE_KINDS = {"command", "test", "artifact", "source_trace", "review"}
ALLOWED_FINDING_STATUSES = {"open", "resolved", "dismissed"}
TASK_ID_RE = re.compile(r"T[0-9]{3,}")
ACCEPTANCE_ID_RE = re.compile(r"AC-[0-9]{2,}")
FAILURE_CASE_RE = re.compile(r"[a-z][a-z0-9_]*")
AUDIT_ID_RE = re.compile(r"(?:TB|P0|P1|P2|COR|LOG|SEC|REL)-[0-9]+")
SHA40_RE = re.compile(r"[0-9a-f]{40}")
SHA64_RE = re.compile(r"[0-9a-f]{64}")
REQUIRED_PLAN_HEADINGS = (
    "### Purpose and outcome",
    "### Authority and starting state",
    "### Invariant, scope, and non-goals",
    "### Current behavior and reproduction",
    "### Acceptance-to-evidence matrix",
    "### Plan of work",
    "### Progress",
    "### Surprises and discoveries",
    "### Decision log",
    "### Verification plan and results",
    "### Independent review",
    "### Rollback and recovery",
    "### Outcomes and handoff",
)
MANDATORY_WORKFLOW_FILES = frozenset(
    {
        "AGENTS.md",
        "PLANS.md",
        ".codex/config.toml",
        ".codex/agents/evidence-explorer.toml",
        ".codex/agents/test-strategist.toml",
        ".codex/agents/risk-reviewer.toml",
        ".agents/skills/execute-ldap-assistant-plan/SKILL.md",
        ".agents/skills/execute-ldap-assistant-plan/agents/openai.yaml",
        ".agents/skills/execute-ldap-assistant-plan/references/execution-protocol.md",
        ".agents/skills/execute-ldap-assistant-plan/references/quality-gates.md",
        ".agents/skills/execute-ldap-assistant-plan/references/task-contract.md",
        ".agents/skills/execute-ldap-assistant-plan/scripts/validate_execution_state.py",
        ".agents/skills/execute-ldap-assistant-plan/scripts/review_bundle.py",
        "docs/implementation/START_HERE.md",
        "docs/implementation/FIRST_TASK_PROMPT.md",
        "docs/implementation/templates/TASK_TEMPLATE.json",
        "docs/implementation/templates/EXEC_PLAN_TEMPLATE.md",
        "docs/implementation/templates/EVIDENCE_TEMPLATE.json",
        "docs/implementation/templates/REVIEW_TEMPLATE.json",
        "docs/implementation/templates/NEW_TASK_PROMPT.md",
        "docs/implementation/evidence/README.md",
        "docs/implementation/reviews/README.md",
    }
)
REQUIRED_MANIFEST_KEYS = frozenset(
    {
        "schema_version",
        "task_id",
        "title",
        "status",
        "state_reason",
        "admitted_head",
        "admission_contract_sha256",
        "workstream",
        "release_intent",
        "audit_references",
        "dependencies",
        "invariant",
        "customer_support_value",
        "known_occurrences",
        "allowed_paths",
        "non_goals",
        "compatibility_constraints",
        "acceptance_criteria",
        "required_gates",
        "integration_policy",
        "delivery_permissions",
        "exec_plan_path",
        "baseline_path",
        "baseline_sha256",
        "completion_bundle_sha256",
        "review_bundle_path",
        "evidence_path",
        "review_path",
        "rollback",
    }
)
DELIVERY_KEYS = frozenset(
    {"commit", "branch", "push", "pull_request", "publish", "deploy", "release"}
)
ROADMAP_KEYS = frozenset(
    {
        "schema_version",
        "plan_revision",
        "audit_path",
        "audit_sha256",
        "audited_commit",
        "portability",
        "required_workflow_files",
        "protected_dirty_paths",
        "workstreams",
        "active_task",
        "tasks",
    }
)
EVIDENCE_KEYS = frozenset(
    {
        "schema_version",
        "task_id",
        "final_state",
        "admitted_head",
        "admission_contract_sha256",
        "base_head",
        "final_head",
        "baseline_sha256",
        "review_bundle_path",
        "reviewed_identity",
        "acceptance",
        "gates",
        "limitations",
        "unverified_protected_paths",
        "rollback_verification",
    }
)
REVIEW_KEYS = frozenset(
    {
        "schema_version",
        "task_id",
        "reviewed_identity",
        "reviewed_at_utc",
        "reviewer_provenance",
        "acceptance",
        "verdict",
        "findings",
        "unresolved_critical_high",
        "tests_inspected",
        "tests_rerun",
        "blind_spots",
        "material_changes_after_review",
    }
)


class Validation:
    def __init__(self) -> None:
        self.errors: list[str] = []
        self.warnings: list[str] = []

    def error(self, message: str) -> None:
        self.errors.append(message)

    def warn(self, message: str) -> None:
        self.warnings.append(message)


def reject_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON constant is forbidden: {value}")


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def find_repo_root(start: Path) -> Path:
    for candidate in (start, *start.parents):
        if (candidate / "AGENTS.md").is_file() and (
            candidate / "docs/implementation/ROADMAP.json"
        ).is_file():
            return candidate.resolve()
    raise FileNotFoundError(
        "repository root containing AGENTS.md and docs/implementation/ROADMAP.json was not found"
    )


def normalized_relative(raw: Any, label: str, validation: Validation) -> str | None:
    if not isinstance(raw, str) or not raw.strip() or raw != raw.strip():
        validation.error(f"{label} must be a non-empty normalized repository-relative path")
        return None
    if "\x00" in raw:
        validation.error(f"{label} contains a NUL byte")
        return None
    if "\\" in raw:
        validation.error(f"{label} must use forward slashes")
        return None
    try:
        path = Path(raw)
    except (TypeError, ValueError):
        validation.error(f"{label} is not a valid path")
        return None
    if path.is_absolute() or path == Path(".") or ".." in path.parts:
        validation.error(f"{label} must name one exact path inside the repository: {raw!r}")
        return None
    if path.as_posix() != raw:
        validation.error(f"{label} must use its exact canonical repository-relative spelling")
        return None
    if path.parts and path.parts[0] == ".git":
        validation.error(f"{label} must not name Git internals")
        return None
    return path.as_posix()


def repo_path(
    root: Path,
    raw: Any,
    label: str,
    validation: Validation,
    *,
    must_exist: bool = False,
    regular_file: bool = False,
) -> Path | None:
    normalized = normalized_relative(raw, label, validation)
    if normalized is None:
        return None
    relative = Path(normalized)
    candidate = root / relative
    cursor = root
    try:
        for part in relative.parts:
            cursor = cursor / part
            if cursor.is_symlink():
                validation.error(f"{label} contains a symlink component: {normalized}")
                return None
        if not candidate.resolve(strict=False).is_relative_to(root.resolve(strict=True)):
            validation.error(f"{label} resolves outside the repository: {normalized}")
            return None
    except (OSError, RuntimeError, ValueError) as exc:
        validation.error(f"{label} cannot be resolved safely: {type(exc).__name__}")
        return None
    if must_exist and not candidate.exists():
        validation.error(f"{label} is missing: {normalized}")
        return None
    if candidate.exists() and regular_file and not candidate.is_file():
        validation.error(f"{label} must be a regular file: {normalized}")
        return None
    return candidate


def read_control_file(
    root: Path, raw: Any, label: str, validation: Validation
) -> bytes | None:
    path = repo_path(
        root, raw, label, validation, must_exist=True, regular_file=True
    )
    if path is None:
        return None
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        validation.error(f"{label} cannot be opened safely: {type(exc).__name__}")
        return None
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            validation.error(f"{label} must be a single-link regular file")
            return None
        if before.st_size > MAX_CONTROL_FILE_BYTES:
            validation.error(f"{label} exceeds {MAX_CONTROL_FILE_BYTES} bytes")
            return None
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        after = os.fstat(descriptor)
        if (
            len(data) != before.st_size
            or before.st_ino != after.st_ino
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
        ):
            validation.error(f"{label} changed while it was read")
            return None
        return data
    except OSError as exc:
        validation.error(f"{label} cannot be read safely: {type(exc).__name__}")
        return None
    finally:
        os.close(descriptor)


def parse_strict_json(
    data: bytes, label: str, validation: Validation
) -> dict[str, Any] | None:
    try:
        value = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        validation.error(f"{label} is not strict JSON: {exc}")
        return None
    if not isinstance(value, dict):
        validation.error(f"{label} JSON root must be an object")
        return None
    stack: list[tuple[Any, int]] = [(value, 1)]
    nodes = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES:
            validation.error(f"{label} exceeds the {MAX_JSON_NODES}-node JSON limit")
            return None
        if depth > MAX_JSON_DEPTH:
            validation.error(f"{label} exceeds the {MAX_JSON_DEPTH}-level JSON depth limit")
            return None
        if isinstance(item, float):
            validation.error(f"{label} must not contain floating-point values")
            return None
        if isinstance(item, dict):
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
    return value


def load_repo_json(
    root: Path, raw: Any, label: str, validation: Validation
) -> tuple[dict[str, Any] | None, bytes | None]:
    data = read_control_file(root, raw, label, validation)
    if data is None:
        return None, None
    return parse_strict_json(data, label, validation), data


def nonempty_string(
    obj: dict[str, Any], key: str, label: str, validation: Validation
) -> str | None:
    value = obj.get(key)
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        validation.error(f"{label}.{key} must be a non-empty normalized string")
        return None
    return value


def string_list(
    obj: dict[str, Any],
    key: str,
    label: str,
    validation: Validation,
    *,
    nonempty: bool = True,
) -> list[str]:
    value = obj.get(key)
    if not isinstance(value, list):
        validation.error(f"{label}.{key} must be a list")
        return []
    result: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item.strip() or item != item.strip():
            validation.error(f"{label}.{key}[{index}] must be a non-empty normalized string")
        else:
            result.append(item)
    if nonempty and not result:
        validation.error(f"{label}.{key} must not be empty")
    if len(result) != len(set(result)):
        validation.error(f"{label}.{key} contains duplicates")
    return result


def audit_reference_exists(audit_text: str, reference: str) -> bool:
    if AUDIT_ID_RE.fullmatch(reference):
        return re.search(rf"(?<![A-Z0-9-]){re.escape(reference)}(?![A-Z0-9-])", audit_text) is not None
    if len(reference) < 8:
        return False
    return any(reference in line for line in audit_text.splitlines())


def paths_overlap(left: str, right: str) -> bool:
    left_parts = Path(left).parts
    right_parts = Path(right).parts
    shortest = min(len(left_parts), len(right_parts))
    return left_parts[:shortest] == right_parts[:shortest]


def git_run(root: Path, args: list[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", *args],
        cwd=root,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={**os.environ, "GIT_OPTIONAL_LOCKS": "0", "LC_ALL": "C"},
    )


def git_head(root: Path) -> str | None:
    result = git_run(root, ["rev-parse", "HEAD"])
    if result.returncode != 0:
        return None
    value = result.stdout.decode("ascii", errors="ignore").strip()
    return value if SHA40_RE.fullmatch(value) else None


def git_ignored(root: Path, raw: str) -> bool | None:
    result = git_run(root, ["check-ignore", "--no-index", "--quiet", "--", raw])
    if result.returncode == 0:
        return True
    if result.returncode == 1:
        return False
    return None


def validate_exec_plan(
    root: Path,
    raw: str,
    task_id: str,
    criterion_ids: list[str],
    status: str,
    validation: Validation,
) -> None:
    data = read_control_file(root, raw, f"task {task_id} ExecPlan", validation)
    if data is None:
        return
    try:
        text = data.decode("utf-8")
    except UnicodeError:
        validation.error(f"task {task_id} ExecPlan is not UTF-8")
        return
    if task_id not in text:
        validation.error(f"task {task_id} ExecPlan does not name the task")
    positions: list[tuple[str, int]] = []
    for heading in REQUIRED_PLAN_HEADINGS:
        matches = list(re.finditer(rf"(?m)^{re.escape(heading)}[ \t]*$", text))
        if not matches:
            validation.error(f"task {task_id} ExecPlan is missing heading: {heading}")
        elif len(matches) > 1:
            validation.error(
                f"task {task_id} ExecPlan repeats required heading: {heading}"
            )
        else:
            positions.append((heading, matches[0].start()))
    if len(positions) == len(REQUIRED_PLAN_HEADINGS):
        offsets = [offset for _, offset in positions]
        if offsets != sorted(offsets):
            validation.error(f"task {task_id} ExecPlan headings are out of order")
        for index, (heading, offset) in enumerate(positions):
            body_start = text.find("\n", offset) + 1
            body_end = positions[index + 1][1] if index + 1 < len(positions) else len(text)
            if len(text[body_start:body_end].strip()) < 20:
                validation.error(f"task {task_id} ExecPlan section is empty: {heading}")
    for criterion_id in criterion_ids:
        if criterion_id not in text:
            validation.error(f"task {task_id} ExecPlan omits acceptance ID {criterion_id}")
    for marker in ("Delivery authority", "Invariant:", "Audit"):
        if marker not in text:
            validation.error(f"task {task_id} ExecPlan omits required authority marker: {marker}")
    if status == "completed" and "Not complete" in text:
        validation.error(f"completed task {task_id} ExecPlan still says Not complete")


def validate_evidence_item(item: Any, label: str, validation: Validation) -> None:
    required = {
        "kind",
        "reference",
        "result",
        "outcome",
        "exit_code",
        "sha256",
        "case_id",
    }
    if not isinstance(item, dict) or set(item) != required:
        validation.error(
            f"{label} must contain exactly kind/reference/result/outcome/exit_code/sha256/case_id"
        )
        return
    kind = item.get("kind")
    if kind not in ALLOWED_EVIDENCE_KINDS:
        validation.error(f"{label}.kind is not an allowed evidence kind")
    for key in ("reference", "result"):
        value = nonempty_string(item, key, label, validation)
        if value is not None and value != value.strip():
            validation.error(f"{label}.{key} must be normalized")
    outcome = item.get("outcome")
    exit_code = item.get("exit_code")
    digest = item.get("sha256")
    case_id = item.get("case_id")
    expected_prefix = {
        "passed": "PASS: ",
        "expected_failure": "EXPECTED_FAIL: ",
        "verified": "VERIFIED: ",
        "approved": "APPROVED: ",
    }.get(outcome)
    if expected_prefix is None or not item.get("result", "").startswith(expected_prefix):
        validation.error(f"{label}.result does not match its machine outcome")
    if kind == "command":
        if (
            outcome != "passed"
            or type(exit_code) is not int
            or exit_code != 0
            or digest is not None
            or case_id is not None
        ):
            validation.error(f"{label} command must record passed with integer exit_code 0")
    elif kind == "test":
        if outcome not in {"passed", "expected_failure"} or type(exit_code) is not int:
            validation.error(f"{label} test outcome/exit_code is invalid")
        elif (outcome == "passed" and exit_code != 0) or (
            outcome == "expected_failure" and exit_code == 0
        ):
            validation.error(f"{label} test outcome contradicts exit_code")
        if digest is not None:
            validation.error(f"{label} test sha256 must be null")
        if outcome == "expected_failure" and (
            not isinstance(case_id, str) or FAILURE_CASE_RE.fullmatch(case_id) is None
        ):
            validation.error(f"{label} expected-failure test needs a stable case_id")
        if outcome == "passed" and case_id is not None and (
            not isinstance(case_id, str) or FAILURE_CASE_RE.fullmatch(case_id) is None
        ):
            validation.error(f"{label} passed test case_id is invalid")
    elif kind == "artifact":
        if (
            outcome != "verified"
            or exit_code is not None
            or not isinstance(digest, str)
            or SHA64_RE.fullmatch(digest) is None
            or case_id is not None
        ):
            validation.error(f"{label} artifact needs verified outcome and SHA-256")
    elif kind == "source_trace":
        if (
            outcome != "verified"
            or exit_code is not None
            or digest is not None
            or case_id is not None
        ):
            validation.error(f"{label} source trace machine fields are invalid")
    elif kind == "review":
        if (
            outcome != "approved"
            or exit_code is not None
            or not isinstance(digest, str)
            or SHA64_RE.fullmatch(digest) is None
            or case_id is not None
        ):
            validation.error(f"{label} review needs approved outcome and bundle SHA-256")


def validate_completion(
    root: Path,
    manifest: dict[str, Any],
    criterion_ids: list[str],
    required_gates: list[str],
    validation: Validation,
) -> None:
    task_id = manifest.get("task_id")
    if not isinstance(task_id, str) or TASK_ID_RE.fullmatch(task_id) is None:
        validation.error("completed task packet has no valid task_id")
        return
    evidence, _ = load_repo_json(
        root, manifest["evidence_path"], f"task {task_id} evidence", validation
    )
    review, _ = load_repo_json(
        root, manifest["review_path"], f"task {task_id} review", validation
    )
    if evidence is None or review is None:
        return
    try:
        bundle_result = verify_historical_bundle(root, task_id)
    except (
        BundleError,
        KeyError,
        OSError,
        RecursionError,
        RuntimeError,
        TypeError,
        UnicodeError,
        ValueError,
    ) as exc:
        validation.error(f"task {task_id} review bundle verification failed: {exc}")
        return
    identity = bundle_result.get("sha256")
    if not isinstance(identity, str) or SHA64_RE.fullmatch(identity) is None:
        validation.error(f"task {task_id} review bundle did not produce a valid identity")
        return
    if manifest.get("completion_bundle_sha256") != identity:
        validation.error(
            f"task {task_id} completion bundle tombstone does not match reviewed identity"
        )
    baseline_identity = bundle_result.get("baseline_sha256")
    if not isinstance(baseline_identity, str) or SHA64_RE.fullmatch(baseline_identity) is None:
        validation.error(f"task {task_id} review bundle did not return its baseline identity")
        return

    provenance = review.get("reviewer_provenance")
    reviewer_task_id: str | None = None
    if not isinstance(provenance, dict):
        validation.error(f"task {task_id} review.reviewer_provenance must be an object")
    else:
        expected_provenance_keys = {
            "role",
            "independent_task_id",
            "effective_runtime",
            "bundle_sha256_recomputed",
            "admitted_head_observed_pre_edit",
            "admission_contract_sha256_observed_pre_edit",
            "baseline_sha256_observed_pre_edit",
            "attestation",
        }
        if set(provenance) != expected_provenance_keys:
            validation.error(
                f"task {task_id} review.reviewer_provenance has an invalid schema"
            )
        if provenance.get("role") != "risk-reviewer":
            validation.error(f"task {task_id} review role must be risk-reviewer")
        reviewer_task_id = nonempty_string(
            provenance,
            "independent_task_id",
            f"task {task_id} review provenance",
            validation,
        )
        if reviewer_task_id is not None and (
            len(reviewer_task_id) < 8
            or reviewer_task_id.lower() in {"none", "unknown", "self", "same-task"}
            or reviewer_task_id == task_id
        ):
            validation.error(
                f"task {task_id} review needs a distinct concrete reviewer task ID"
            )
        if provenance.get("effective_runtime") != "enforced_read_only":
            validation.error(
                f"task {task_id} review must attest an enforced_read_only runtime"
            )
        if provenance.get("bundle_sha256_recomputed") != identity:
            validation.error(
                f"task {task_id} reviewer did not independently recompute the bundle identity"
            )
        if provenance.get("admitted_head_observed_pre_edit") != manifest.get(
            "admitted_head"
        ):
            validation.error(
                f"task {task_id} reviewer admitted HEAD differs from the external admission receipt"
            )
        if provenance.get(
            "admission_contract_sha256_observed_pre_edit"
        ) != manifest.get("admission_contract_sha256"):
            validation.error(
                f"task {task_id} reviewer contract receipt differs from the external admission receipt"
            )
        if provenance.get("baseline_sha256_observed_pre_edit") != baseline_identity:
            validation.error(
                f"task {task_id} reviewer baseline receipt differs from the frozen baseline"
            )
        nonempty_string(
            provenance,
            "attestation",
            f"task {task_id} review provenance",
            validation,
        )

    if set(evidence) != EVIDENCE_KEYS:
        validation.error(f"task {task_id} evidence has an invalid top-level schema")
    if type(evidence.get("schema_version")) is not int or evidence.get(
        "schema_version"
    ) != SCHEMA_VERSION:
        validation.error(f"task {task_id} evidence schema_version must be 1")
    if evidence.get("task_id") != task_id or evidence.get("final_state") != "completed":
        validation.error(f"task {task_id} evidence identity/final_state is invalid")
    for key in ("base_head", "final_head"):
        if not isinstance(evidence.get(key), str) or SHA40_RE.fullmatch(evidence[key]) is None:
            validation.error(f"task {task_id} evidence.{key} must be a full Git SHA")
    if evidence.get("final_head") != bundle_result.get("base_head"):
        validation.error(f"task {task_id} evidence.final_head does not match reviewed HEAD")
    if evidence.get("reviewed_identity") != identity:
        validation.error(f"task {task_id} evidence reviewed_identity does not match bundle")
    if evidence.get("baseline_sha256") != baseline_identity:
        validation.error(f"task {task_id} evidence baseline_sha256 does not match bundle")
    if evidence.get("admitted_head") != manifest.get("admitted_head"):
        validation.error(f"task {task_id} evidence admitted_head does not match packet")
    if evidence.get("admission_contract_sha256") != manifest.get(
        "admission_contract_sha256"
    ):
        validation.error(
            f"task {task_id} evidence admission contract receipt does not match packet"
        )
    if evidence.get("base_head") != bundle_result.get("base_head"):
        validation.error(f"task {task_id} evidence.base_head does not match bundle")
    if evidence.get("review_bundle_path") != manifest.get("review_bundle_path"):
        validation.error(f"task {task_id} evidence review_bundle_path does not match packet")

    acceptance = evidence.get("acceptance")
    if not isinstance(acceptance, dict) or set(acceptance) != set(criterion_ids):
        validation.error(f"task {task_id} evidence must contain exactly every acceptance ID")
    else:
        for criterion_id in criterion_ids:
            criterion = next(
                item
                for item in manifest["acceptance_criteria"]
                if isinstance(item, dict) and item.get("id") == criterion_id
            )
            expected_cases = set(criterion.get("fail_before_cases", []))
            record = acceptance.get(criterion_id)
            if not isinstance(record, dict) or record.get("status") != "passed":
                validation.error(f"task {task_id} acceptance is not passed: {criterion_id}")
                continue
            proof = record.get("proof")
            if not isinstance(proof, list) or not proof:
                validation.error(f"task {task_id} acceptance lacks proof: {criterion_id}")
            else:
                for index, item in enumerate(proof):
                    validate_evidence_item(
                        item, f"task {task_id} acceptance {criterion_id} proof[{index}]", validation
                    )
                    if isinstance(item, dict) and item.get("kind") == "review":
                        validation.error(
                            f"task {task_id} acceptance {criterion_id} uses review as implementation proof"
                        )
                if not any(
                    isinstance(item, dict)
                    and item.get("kind") in {"command", "test"}
                    and item.get("outcome") == "passed"
                    and item.get("exit_code") == 0
                    for item in proof
                ):
                    validation.error(
                        f"task {task_id} acceptance {criterion_id} lacks passed executable proof"
                    )
                actual_cases = {
                    item.get("case_id")
                    for item in proof
                    if isinstance(item, dict)
                    and item.get("outcome") == "expected_failure"
                }
                if actual_cases != expected_cases:
                    validation.error(
                        f"task {task_id} acceptance {criterion_id} fail-before case coverage differs from manifest"
                    )

    gates = evidence.get("gates")
    if not isinstance(gates, dict) or not set(required_gates).issubset(gates):
        validation.error(f"task {task_id} evidence omits a required gate")
    else:
        for gate in required_gates:
            record = gates.get(gate)
            if not isinstance(record, dict) or record.get("status") != "passed":
                validation.error(f"task {task_id} required gate is not passed: {gate}")
                continue
            items = record.get("evidence")
            if not isinstance(items, list) or not items:
                validation.error(f"task {task_id} required gate lacks evidence: {gate}")
            else:
                for index, item in enumerate(items):
                    validate_evidence_item(
                        item, f"task {task_id} gate {gate} evidence[{index}]", validation
                    )
                    if gate != "G7" and isinstance(item, dict) and item.get("kind") == "review":
                        validation.error(
                            f"task {task_id} gate {gate} cannot use review evidence"
                        )
                if gate != "G7" and not any(
                    isinstance(item, dict)
                    and item.get("kind") in {"command", "test"}
                    and item.get("outcome") == "passed"
                    and item.get("exit_code") == 0
                    for item in items
                ):
                    validation.error(
                        f"task {task_id} gate {gate} lacks passed executable proof"
                    )
                if gate == "G1" and not any(
                    isinstance(item, dict)
                    and item.get("kind") == "test"
                    and item.get("outcome") == "expected_failure"
                    and type(item.get("exit_code")) is int
                    and item.get("exit_code") != 0
                    for item in items
                ):
                    validation.error(f"task {task_id} G1 lacks fail-before evidence")
                if gate == "G1":
                    expected_gate_cases = {
                        case_id
                        for criterion in manifest["acceptance_criteria"]
                        if isinstance(criterion, dict)
                        for case_id in criterion.get("fail_before_cases", [])
                    }
                    actual_gate_cases = {
                        item.get("case_id")
                        for item in items
                        if isinstance(item, dict)
                        and item.get("outcome") == "expected_failure"
                    }
                    if actual_gate_cases != expected_gate_cases:
                        validation.error(
                            f"task {task_id} G1 fail-before case coverage differs from manifest"
                        )
                if gate == "G0" and not any(
                    isinstance(item, dict)
                    and item.get("kind") == "command"
                    and "validate_execution_state.py" in item.get("reference", "")
                    and item.get("outcome") == "passed"
                    and item.get("exit_code") == 0
                    for item in items
                ):
                    validation.error(
                        f"task {task_id} G0 lacks a passed state-validator command"
                    )
            if gate == "G7" and isinstance(items, list):
                expected_result = (
                    f"APPROVED: bundle_sha256={identity}; "
                    f"reviewer_task_id={reviewer_task_id}; unresolved_critical_high=0"
                )
                if items != [
                    {
                        "kind": "review",
                        "reference": manifest["review_path"],
                        "result": expected_result,
                        "outcome": "approved",
                        "exit_code": None,
                        "sha256": identity,
                        "case_id": None,
                    }
                ]:
                    validation.error(
                        f"task {task_id} G7 evidence does not match the independent review attestation"
                    )
    if not isinstance(evidence.get("limitations"), list):
        validation.error(f"task {task_id} evidence.limitations must be a list")
    if not isinstance(evidence.get("unverified_protected_paths"), list):
        validation.error(
            f"task {task_id} evidence.unverified_protected_paths must be a list"
        )
    rollback = evidence.get("rollback_verification")
    if not isinstance(rollback, str) or not rollback.strip():
        validation.error(f"task {task_id} evidence.rollback_verification must be non-empty")

    if set(review) != REVIEW_KEYS:
        validation.error(f"task {task_id} review has an invalid top-level schema")
    if (
        type(review.get("schema_version")) is not int
        or review.get("schema_version") != SCHEMA_VERSION
        or review.get("task_id") != task_id
    ):
        validation.error(f"task {task_id} review schema/identity is invalid")
    if review.get("reviewed_identity") != identity or review.get("verdict") != "approve":
        validation.error(f"task {task_id} review identity/verdict is invalid")
    if review.get("material_changes_after_review") is not False:
        validation.error(f"task {task_id} review must confirm no material post-review changes")
    unresolved_value = review.get("unresolved_critical_high")
    if type(unresolved_value) is not int or unresolved_value != 0:
        validation.error(f"task {task_id} review has unresolved critical/high findings")
    reviewed_at = review.get("reviewed_at_utc")
    if not isinstance(reviewed_at, str) or re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", reviewed_at
    ) is None:
        validation.error(f"task {task_id} review.reviewed_at_utc must be an RFC3339 UTC second")
    review_acceptance = review.get("acceptance")
    if not isinstance(review_acceptance, dict) or set(review_acceptance) != set(criterion_ids):
        validation.error(f"task {task_id} review must contain exactly every acceptance ID")
    else:
        for criterion_id in criterion_ids:
            record = review_acceptance.get(criterion_id)
            if not isinstance(record, dict) or record.get("status") != "approved":
                validation.error(f"task {task_id} review did not approve {criterion_id}")
                continue
            checked = record.get("evidence_checked")
            if not isinstance(checked, list) or not checked or any(
                not isinstance(item, str) or not item.strip() for item in checked
            ):
                validation.error(f"task {task_id} review lacks checked evidence for {criterion_id}")
            nonempty_string(record, "reason", f"task {task_id} review {criterion_id}", validation)
    findings = review.get("findings")
    computed_unresolved = 0
    if not isinstance(findings, list):
        validation.error(f"task {task_id} review.findings must be a list")
    else:
        for index, finding in enumerate(findings):
            if not isinstance(finding, dict):
                validation.error(f"task {task_id} review finding {index} must be an object")
                continue
            severity = finding.get("severity")
            if severity not in ALLOWED_FINDING_SEVERITIES:
                validation.error(f"task {task_id} review finding {index} severity is invalid")
            status = finding.get("status")
            if status not in ALLOWED_FINDING_STATUSES:
                validation.error(f"task {task_id} review finding {index} status is invalid")
            for key in ("id", "summary", "evidence"):
                nonempty_string(
                    finding, key, f"task {task_id} review finding {index}", validation
                )
            resolution = finding.get("resolution")
            if status in {"resolved", "dismissed"} and (
                not isinstance(resolution, str) or not resolution.strip()
            ):
                validation.error(
                    f"task {task_id} review finding {index} needs a resolution rationale"
                )
            if severity in {"critical", "high"} and status == "open":
                computed_unresolved += 1
    if type(unresolved_value) is int and unresolved_value != computed_unresolved:
        validation.error(
            f"task {task_id} unresolved_critical_high disagrees with findings"
        )
    tests_inspected = review.get("tests_inspected")
    if not isinstance(tests_inspected, list) or not tests_inspected or any(
        not isinstance(item, str) or not item.strip() for item in tests_inspected
    ):
        validation.error(f"task {task_id} review.tests_inspected must be a non-empty string list")
    tests_rerun = review.get("tests_rerun")
    if not isinstance(tests_rerun, list) or not tests_rerun:
        validation.error(f"task {task_id} review.tests_rerun must be a non-empty list")
    else:
        for index, item in enumerate(tests_rerun):
            validate_evidence_item(
                item, f"task {task_id} review tests_rerun[{index}]", validation
            )
        if not any(
            isinstance(item, dict)
            and item.get("kind") in {"command", "test"}
            and item.get("outcome") == "passed"
            and item.get("exit_code") == 0
            for item in tests_rerun
        ):
            validation.error(
                f"task {task_id} review.tests_rerun lacks passed executable evidence"
            )
        if not any(
            isinstance(item, dict)
            and item.get("kind") == "command"
            and "review_bundle.py verify" in item.get("reference", "")
            and item.get("outcome") == "passed"
            and item.get("exit_code") == 0
            for item in tests_rerun
        ):
            validation.error(
                f"task {task_id} reviewer did not record an independent bundle verification"
            )
        if not any(
            isinstance(item, dict)
            and item.get("kind") == "test"
            and item.get("outcome") == "passed"
            and item.get("exit_code") == 0
            for item in tests_rerun
        ):
            validation.error(
                f"task {task_id} reviewer did not record an independently passing test rerun"
            )
    blind_spots = review.get("blind_spots")
    if not isinstance(blind_spots, list) or any(
        not isinstance(item, str) or not item.strip() for item in blind_spots
    ):
        validation.error(f"task {task_id} review.blind_spots must be a string list")


def validate_manifest(
    root: Path,
    task: dict[str, Any],
    audit_text: str,
    workstream_ids: set[str],
    expected_baseline_sha256: str | None,
    expected_head: str | None,
    expected_contract_sha256: str | None,
    is_active: bool,
    validation: Validation,
) -> dict[str, Any]:
    task_id = task["task_id"]
    packet_raw = task.get("packet_path")
    manifest, _ = load_repo_json(root, packet_raw, f"task {task_id} packet", validation)
    if manifest is None:
        return {"allowed_paths": set(), "criterion_ids": [], "required_gates": []}
    if set(manifest) != REQUIRED_MANIFEST_KEYS:
        missing = sorted(REQUIRED_MANIFEST_KEYS - manifest.keys())
        unexpected = sorted(manifest.keys() - REQUIRED_MANIFEST_KEYS)
        details: list[str] = []
        if missing:
            details.append("missing: " + ", ".join(missing))
        if unexpected:
            details.append("unexpected: " + ", ".join(unexpected))
        validation.error(
            f"task {task_id} packet has an invalid top-level schema ({'; '.join(details)})"
        )
        return {"allowed_paths": set(), "criterion_ids": [], "required_gates": []}
    if type(manifest.get("schema_version")) is not int or manifest.get(
        "schema_version"
    ) != SCHEMA_VERSION:
        validation.error(f"task {task_id} packet schema_version must be 1")
    expected_packet = f"docs/implementation/tasks/{task_id}.json"
    if packet_raw != expected_packet:
        validation.error(f"task {task_id} packet_path must be {expected_packet}")
    for key in (
        "task_id",
        "title",
        "status",
        "state_reason",
        "admitted_head",
        "admission_contract_sha256",
        "workstream",
        "release_intent",
        "audit_references",
        "dependencies",
        "baseline_sha256",
        "completion_bundle_sha256",
    ):
        if manifest.get(key) != task.get(key):
            validation.error(f"task {task_id} packet.{key} does not match roadmap")
    for key in ("title", "state_reason", "release_intent", "invariant", "customer_support_value"):
        nonempty_string(manifest, key, f"task {task_id} packet", validation)
    if manifest.get("workstream") not in workstream_ids:
        validation.error(f"task {task_id} packet names an unknown workstream")

    list_fields: dict[str, list[str]] = {}
    for key in (
        "audit_references",
        "known_occurrences",
        "allowed_paths",
        "non_goals",
        "compatibility_constraints",
        "required_gates",
    ):
        list_fields[key] = string_list(manifest, key, f"task {task_id} packet", validation)
    for reference in list_fields["audit_references"]:
        if not audit_reference_exists(audit_text, reference):
            validation.error(f"task {task_id} packet audit reference is not exact: {reference}")

    allowed_paths: set[str] = set()
    for index, raw in enumerate(list_fields["allowed_paths"]):
        normalized = normalized_relative(
            raw, f"task {task_id} allowed_paths[{index}]", validation
        )
        if normalized is None:
            continue
        path = repo_path(root, normalized, f"task {task_id} allowed path", validation)
        if path is not None and path.exists() and path.is_dir():
            validation.error(f"task {task_id} allowed path must be an exact file: {normalized}")
        ignored = git_ignored(root, normalized)
        if ignored is True:
            validation.error(f"task {task_id} allowed path is Git-ignored and unsafe to read: {normalized}")
        elif ignored is None:
            validation.error(f"task {task_id} allowed path ignore status could not be verified")
        allowed_paths.add(normalized)

    required_paths = {
        "docs/implementation/ROADMAP.json",
        expected_packet,
        f"docs/implementation/exec-plans/{task_id}.md",
        f"docs/implementation/evidence/{task_id}-baseline.json",
        f"docs/implementation/evidence/{task_id}-review-bundle.json",
        f"docs/implementation/evidence/{task_id}.json",
        f"docs/implementation/reviews/{task_id}.json",
    }
    missing_allowed = sorted(required_paths - allowed_paths)
    if missing_allowed:
        validation.error(
            f"task {task_id} allowed_paths omits required state files: {', '.join(missing_allowed)}"
        )

    required_gates = list_fields["required_gates"]
    invalid_gates = sorted(set(required_gates) - ALLOWED_GATES)
    if invalid_gates:
        validation.error(f"task {task_id} has invalid gates: {', '.join(invalid_gates)}")
    core_missing = sorted({"G0", "G1", "G7"} - set(required_gates))
    if core_missing:
        validation.error(f"task {task_id} lacks core gates: {', '.join(core_missing)}")

    criteria = manifest.get("acceptance_criteria")
    criterion_ids: list[str] = []
    failure_case_ids: list[str] = []
    if not isinstance(criteria, list) or not criteria:
        validation.error(f"task {task_id} acceptance_criteria must be a non-empty list")
    else:
        for index, criterion in enumerate(criteria):
            if not isinstance(criterion, dict):
                validation.error(f"task {task_id} acceptance criterion {index} must be an object")
                continue
            criterion_id = criterion.get("id")
            if not isinstance(criterion_id, str) or ACCEPTANCE_ID_RE.fullmatch(criterion_id) is None:
                validation.error(f"task {task_id} acceptance criterion {index} has invalid id")
            else:
                criterion_ids.append(criterion_id)
            nonempty_string(
                criterion, "requirement", f"task {task_id} acceptance {criterion_id}", validation
            )
            fail_cases = string_list(
                criterion,
                "fail_before_cases",
                f"task {task_id} acceptance {criterion_id}",
                validation,
                nonempty=False,
            )
            for case_id in fail_cases:
                if FAILURE_CASE_RE.fullmatch(case_id) is None:
                    validation.error(
                        f"task {task_id} acceptance {criterion_id} has invalid failure case {case_id}"
                    )
            failure_case_ids.extend(fail_cases)
            string_list(
                criterion,
                "required_proof",
                f"task {task_id} acceptance {criterion_id}",
                validation,
            )
        if len(criterion_ids) != len(set(criterion_ids)):
            validation.error(f"task {task_id} acceptance IDs contain duplicates")
        if len(failure_case_ids) != len(set(failure_case_ids)):
            validation.error(f"task {task_id} fail-before case IDs must be globally unique")

    integration = manifest.get("integration_policy")
    if not isinstance(integration, dict):
        validation.error(f"task {task_id} integration_policy must be an object")
    else:
        g4_required = integration.get("g4_required")
        if not isinstance(g4_required, bool):
            validation.error(f"task {task_id} integration_policy.g4_required must be boolean")
        elif g4_required != ("G4" in required_gates):
            validation.error(f"task {task_id} G4 gate and integration policy disagree")
        nonempty_string(integration, "rationale", f"task {task_id} integration_policy", validation)
        nonempty_string(
            integration, "optional_proof", f"task {task_id} integration_policy", validation
        )
        string_list(
            integration,
            "prohibited_by_default",
            f"task {task_id} integration_policy",
            validation,
        )

    permissions = manifest.get("delivery_permissions")
    if not isinstance(permissions, dict):
        validation.error(f"task {task_id} delivery_permissions must be an object")
    else:
        missing_permissions = sorted(DELIVERY_KEYS - permissions.keys())
        if missing_permissions:
            validation.error(
                f"task {task_id} delivery permissions missing: {', '.join(missing_permissions)}"
            )
        for key in DELIVERY_KEYS:
            if key in permissions and not isinstance(permissions[key], bool):
                validation.error(f"task {task_id} delivery permission {key} must be boolean")

    rollback = manifest.get("rollback")
    if not isinstance(rollback, dict):
        validation.error(f"task {task_id} rollback must be an object")
    else:
        string_list(rollback, "triggers", f"task {task_id} rollback", validation)
        nonempty_string(rollback, "method", f"task {task_id} rollback", validation)
        nonempty_string(
            rollback, "data_config_impact", f"task {task_id} rollback", validation
        )

    canonical_paths = {
        "exec_plan_path": f"docs/implementation/exec-plans/{task_id}.md",
        "baseline_path": f"docs/implementation/evidence/{task_id}-baseline.json",
        "review_bundle_path": f"docs/implementation/evidence/{task_id}-review-bundle.json",
        "evidence_path": f"docs/implementation/evidence/{task_id}.json",
        "review_path": f"docs/implementation/reviews/{task_id}.json",
    }
    for key, expected in canonical_paths.items():
        if manifest.get(key) != expected:
            validation.error(f"task {task_id} {key} must be {expected}")
    if task.get("exec_plan_path") != canonical_paths["exec_plan_path"]:
        validation.error(f"task {task_id} roadmap ExecPlan path is not canonical")
    validate_exec_plan(
        root,
        canonical_paths["exec_plan_path"],
        task_id,
        criterion_ids,
        task.get("status", ""),
        validation,
    )

    baseline = repo_path(
        root, canonical_paths["baseline_path"], f"task {task_id} baseline", validation
    )
    raw_status = task.get("status")
    status = raw_status if isinstance(raw_status, str) else "invalid"
    contract_fingerprint = sha256_bytes(canonical_json(contract_projection(manifest)))
    contract_pin = manifest.get("admission_contract_sha256")
    if (
        not isinstance(contract_pin, str)
        or SHA64_RE.fullmatch(contract_pin) is None
        or contract_pin != contract_fingerprint
    ):
        validation.error(
            f"task {task_id} admission_contract_sha256 must match its canonical contract"
        )
    if is_active and status in {"ready", "in_progress", "blocked"}:
        if expected_contract_sha256 is None:
            validation.error(
                f"task {task_id} requires --expected-contract-sha256 from the external admission receipt"
            )
        elif expected_contract_sha256 != contract_fingerprint:
            validation.error(
                f"task {task_id} external admission contract receipt differs from packet/roadmap"
            )
    admitted_head = manifest.get("admitted_head")
    if not isinstance(admitted_head, str) or SHA40_RE.fullmatch(admitted_head) is None:
        validation.error(f"task {task_id} admitted_head must be a full lowercase Git SHA")
    else:
        current_head = git_head(root)
        if (status == "in_progress" or (status == "blocked" and is_active)) and current_head != admitted_head:
            validation.error(f"task {task_id} HEAD differs from admitted_head")
        elif status == "ready" and current_head != admitted_head:
            validation.warn(
                f"ready task {task_id} HEAD differs from admitted_head; product-code-read-only re-admission is required before transition"
            )
        if is_active and expected_head is not None and expected_head != admitted_head:
            validation.error(
                f"task {task_id} external admitted HEAD differs from packet/roadmap"
            )
    if (status == "in_progress" or (status == "blocked" and is_active)) and expected_head is None:
        validation.error(
            f"task {task_id} requires --expected-head from the external admission receipt"
        )
    baseline_pin = manifest.get("baseline_sha256")
    completion_pin = manifest.get("completion_bundle_sha256")
    if status == "completed":
        if not isinstance(completion_pin, str) or SHA64_RE.fullmatch(completion_pin) is None:
            validation.error(
                f"completed task {task_id} requires a completion bundle tombstone"
            )
    elif completion_pin is not None:
        validation.error(
            f"non-completed task {task_id} must have null completion_bundle_sha256"
        )
    if baseline_pin is not None and (
        not isinstance(baseline_pin, str) or SHA64_RE.fullmatch(baseline_pin) is None
    ):
        validation.error(f"task {task_id} baseline_sha256 must be null or lowercase SHA-256")
    if status == "ready" and baseline is not None and baseline.exists():
        validation.error(f"ready task {task_id} has a stale pre-edit baseline")
    if status == "ready" and baseline_pin is not None:
        validation.error(f"ready task {task_id} must have null baseline_sha256")
    if status == "in_progress" and baseline is not None and not baseline.exists():
        validation.warn(
            f"in_progress task {task_id} has no baseline yet; only baseline generation is admitted"
        )
        if baseline_pin is not None:
            validation.error(f"task {task_id} pins a missing baseline")
    if status == "blocked" and baseline is not None and not baseline.is_file():
        validation.warn(f"blocked task {task_id} stopped before baseline creation")
        if baseline_pin is not None:
            validation.error(f"task {task_id} pins a missing baseline")
    if status == "completed" and baseline is not None and not baseline.is_file():
        validation.error(f"completed task {task_id} requires its baseline artifact")
    if status in {"planned", "ready", "blocked"}:
        evidence_path = repo_path(
            root,
            canonical_paths["evidence_path"],
            f"task {task_id} evidence",
            validation,
        )
        if evidence_path is not None and evidence_path.is_file():
            prior_evidence, _ = load_repo_json(
                root,
                canonical_paths["evidence_path"],
                f"task {task_id} evidence",
                validation,
            )
            if prior_evidence is not None and prior_evidence.get("final_state") == "completed":
                validation.error(
                    f"task {task_id} cannot downgrade after completed evidence exists; use a new task ID"
                )
        review_path = repo_path(
            root,
            canonical_paths["review_path"],
            f"task {task_id} review",
            validation,
        )
        if review_path is not None and review_path.is_file():
            prior_review, _ = load_repo_json(
                root,
                canonical_paths["review_path"],
                f"task {task_id} review",
                validation,
            )
            if prior_review is not None and prior_review.get("verdict") == "approve":
                validation.error(
                    f"task {task_id} cannot downgrade after an approved review exists; use a new task ID"
                )
    if (
        status in {"in_progress", "blocked", "completed"}
        and baseline is not None
        and baseline.is_file()
    ):
        if not isinstance(baseline_pin, str) or SHA64_RE.fullmatch(baseline_pin) is None:
            validation.error(f"task {task_id} existing baseline requires its SHA-256 pin")
        else:
            baseline_bytes = read_control_file(
                root, canonical_paths["baseline_path"], f"task {task_id} baseline", validation
            )
            if baseline_bytes is not None and hashlib.sha256(baseline_bytes).hexdigest() != baseline_pin:
                validation.error(f"task {task_id} baseline bytes differ from baseline_sha256")
            if (
                (status == "in_progress" or (status == "blocked" and is_active))
                and expected_baseline_sha256 is None
            ):
                validation.error(
                    f"task {task_id} requires --expected-baseline-sha256 from the external receipt"
                )
            elif (
                (status == "in_progress" or (status == "blocked" and is_active))
                and expected_baseline_sha256 != baseline_pin
            ):
                validation.error(
                    f"task {task_id} external baseline receipt differs from packet/roadmap pin"
                )
    if status == "completed":
        validate_completion(
            root,
            manifest,
            criterion_ids,
            required_gates,
            validation,
        )

    return {
        "allowed_paths": allowed_paths,
        "criterion_ids": criterion_ids,
        "required_gates": required_gates,
    }


def validate(
    root: Path,
    expected_baseline_sha256: str | None = None,
    expected_head: str | None = None,
    expected_contract_sha256: str | None = None,
) -> Validation:
    validation = Validation()
    if expected_baseline_sha256 is not None and SHA64_RE.fullmatch(
        expected_baseline_sha256
    ) is None:
        validation.error("--expected-baseline-sha256 must be 64 lowercase hexadecimal characters")
    if expected_head is not None and SHA40_RE.fullmatch(expected_head) is None:
        validation.error("--expected-head must be a full lowercase Git SHA")
    if expected_contract_sha256 is not None and SHA64_RE.fullmatch(
        expected_contract_sha256
    ) is None:
        validation.error(
            "--expected-contract-sha256 must be 64 lowercase hexadecimal characters"
        )
    try:
        assert_no_index_hiding(root)
    except (BundleError, OSError, UnicodeError, ValueError) as exc:
        validation.error(f"Git index hiding flags are not admitted: {exc}")
    roadmap_raw = "docs/implementation/ROADMAP.json"
    roadmap, _ = load_repo_json(root, roadmap_raw, "ROADMAP.json", validation)
    if roadmap is None:
        return validation
    if set(roadmap) != ROADMAP_KEYS:
        missing = sorted(ROADMAP_KEYS - roadmap.keys())
        unexpected = sorted(roadmap.keys() - ROADMAP_KEYS)
        details: list[str] = []
        if missing:
            details.append("missing: " + ", ".join(missing))
        if unexpected:
            details.append("unexpected: " + ", ".join(unexpected))
        validation.error(
            "ROADMAP.json has an invalid top-level schema (" + "; ".join(details) + ")"
        )
        return validation
    if type(roadmap.get("schema_version")) is not int or roadmap.get(
        "schema_version"
    ) != SCHEMA_VERSION:
        validation.error("ROADMAP.json schema_version must be 1")
    for key in ("plan_revision", "audit_path", "audit_sha256", "audited_commit"):
        nonempty_string(roadmap, key, "roadmap", validation)
    if roadmap.get("audit_path") != "docs/GLOBAL_AUDIT_AND_IMPROVEMENT_PLAN.md":
        validation.error("roadmap.audit_path must be docs/GLOBAL_AUDIT_AND_IMPROVEMENT_PLAN.md")
    expected_audit_hash = roadmap.get("audit_sha256")
    if not isinstance(expected_audit_hash, str) or SHA64_RE.fullmatch(expected_audit_hash) is None:
        validation.error("roadmap.audit_sha256 must be 64 lowercase hexadecimal characters")
    audited_commit = roadmap.get("audited_commit")
    if not isinstance(audited_commit, str) or SHA40_RE.fullmatch(audited_commit) is None:
        validation.error("roadmap.audited_commit must be a full lowercase Git SHA")
    elif git_run(root, ["cat-file", "-e", f"{audited_commit}^{{commit}}"]).returncode != 0:
        validation.error("roadmap.audited_commit does not exist in this repository")

    audit_bytes = read_control_file(root, roadmap.get("audit_path"), "global audit", validation)
    audit_text = ""
    if audit_bytes is not None:
        actual_hash = hashlib.sha256(audit_bytes).hexdigest()
        if actual_hash != expected_audit_hash:
            validation.error(
                f"global audit SHA-256 mismatch: expected {expected_audit_hash!r}, got {actual_hash}"
            )
        try:
            audit_text = audit_bytes.decode("utf-8")
        except UnicodeError:
            validation.error("global audit is not UTF-8")

    required_files = string_list(
        roadmap, "required_workflow_files", "roadmap", validation
    )
    missing_mandatory = sorted(MANDATORY_WORKFLOW_FILES - set(required_files))
    if missing_mandatory:
        validation.error(
            "roadmap.required_workflow_files omits code-required files: "
            + ", ".join(missing_mandatory)
        )
    permitted_task_file = re.compile(
        r"docs/implementation/(?:tasks/T[0-9]{3,}\.json|exec-plans/T[0-9]{3,}\.md)"
    )
    unsafe_extras = sorted(
        raw
        for raw in set(required_files) - MANDATORY_WORKFLOW_FILES
        if permitted_task_file.fullmatch(raw) is None
    )
    if unsafe_extras:
        validation.error(
            "roadmap.required_workflow_files contains non-canonical extras: "
            + ", ".join(unsafe_extras)
        )
    for index, raw in enumerate(required_files):
        repo_path(
            root,
            raw,
            f"required_workflow_files[{index}]",
            validation,
            must_exist=True,
            regular_file=True,
        )

    protected_paths = string_list(
        roadmap, "protected_dirty_paths", "roadmap", validation, nonempty=False
    )
    normalized_protected: set[str] = set()
    for index, raw in enumerate(protected_paths):
        normalized = normalized_relative(raw, f"protected_dirty_paths[{index}]", validation)
        if normalized is not None:
            normalized_protected.add(normalized)

    workstreams = roadmap.get("workstreams")
    workstream_ids: set[str] = set()
    if not isinstance(workstreams, list) or not workstreams:
        validation.error("roadmap.workstreams must be a non-empty list")
    else:
        for index, workstream in enumerate(workstreams):
            if not isinstance(workstream, dict):
                validation.error(f"workstream {index} must be an object")
                continue
            workstream_id = nonempty_string(
                workstream, "id", f"workstream {index}", validation
            )
            nonempty_string(workstream, "purpose", f"workstream {index}", validation)
            if workstream_id:
                if workstream_id in workstream_ids:
                    validation.error(f"duplicate workstream ID: {workstream_id}")
                workstream_ids.add(workstream_id)

    tasks = roadmap.get("tasks")
    if not isinstance(tasks, list) or not tasks:
        validation.error("roadmap.tasks must be a non-empty list")
        return validation
    declared_active = roadmap.get("active_task")
    task_by_id: dict[str, dict[str, Any]] = {}
    dependencies_by_id: dict[str, list[str]] = {}
    in_progress: list[str] = []
    manifest_info: dict[str, dict[str, Any]] = {}
    for index, task in enumerate(tasks):
        if not isinstance(task, dict):
            validation.error(f"task {index} must be an object")
            continue
        task_id = task.get("task_id")
        if not isinstance(task_id, str) or TASK_ID_RE.fullmatch(task_id) is None:
            validation.error(f"task {index} has an invalid task_id")
            continue
        if task_id in task_by_id:
            validation.error(f"duplicate task_id: {task_id}")
            continue
        task_by_id[task_id] = task
        for key in ("title", "workstream", "release_intent"):
            nonempty_string(task, key, f"task {task_id}", validation)
        status = task.get("status")
        if not isinstance(status, str) or status not in ALLOWED_STATUSES:
            validation.error(f"task {task_id} has invalid status")
            status = "invalid"
        if status == "in_progress":
            in_progress.append(task_id)
        if status in {"ready", "in_progress", "blocked", "completed"}:
            nonempty_string(task, "state_reason", f"task {task_id}", validation)
        dependencies = string_list(
            task, "dependencies", f"task {task_id}", validation, nonempty=False
        )
        dependencies_by_id[task_id] = dependencies
        workstream = task.get("workstream")
        if not isinstance(workstream, str) or workstream not in workstream_ids:
            validation.error(f"task {task_id} names an unknown workstream")
        references = string_list(
            task, "audit_references", f"task {task_id}", validation
        )
        for reference in references:
            if not audit_reference_exists(audit_text, reference):
                validation.error(f"task {task_id} audit reference is not exact: {reference}")

        packet_raw = task.get("packet_path")
        plan_raw = task.get("exec_plan_path")
        packet_valid_type = packet_raw is None or (
            isinstance(packet_raw, str) and bool(packet_raw.strip()) and packet_raw == packet_raw.strip()
        )
        plan_valid_type = plan_raw is None or (
            isinstance(plan_raw, str) and bool(plan_raw.strip()) and plan_raw == plan_raw.strip()
        )
        if not packet_valid_type or not plan_valid_type:
            validation.error(f"task {task_id} packet/ExecPlan paths must be null or strings")
        has_packet = isinstance(packet_raw, str) and bool(packet_raw)
        has_plan = isinstance(plan_raw, str) and bool(plan_raw)
        if has_packet != has_plan:
            validation.error(f"task {task_id} must declare packet and ExecPlan together")
        if status in {"ready", "in_progress", "blocked", "completed"} and not (
            has_packet and has_plan
        ):
            validation.error(f"task {task_id} status {status} requires packet and ExecPlan")
        elif has_packet and has_plan:
            manifest_info[task_id] = validate_manifest(
                root,
                task,
                audit_text,
                workstream_ids,
                expected_baseline_sha256,
                expected_head,
                expected_contract_sha256,
                task_id == declared_active,
                validation,
            )

    if len(in_progress) > 1:
        validation.error("more than one task is in_progress: " + ", ".join(in_progress))
    for task_id, dependencies in dependencies_by_id.items():
        raw_status = task_by_id[task_id].get("status")
        status = raw_status if isinstance(raw_status, str) else "invalid"
        for dependency in dependencies:
            if dependency not in task_by_id:
                validation.error(f"task {task_id} has unknown dependency {dependency}")
            elif dependency == task_id:
                validation.error(f"task {task_id} depends on itself")
            elif status in {"ready", "in_progress", "blocked", "completed"} and task_by_id[
                dependency
            ].get("status") != "completed":
                validation.error(f"task {task_id} has incomplete dependency {dependency}")

    remaining = {
        task_id: {dep for dep in dependencies if dep in task_by_id}
        for task_id, dependencies in dependencies_by_id.items()
    }
    while remaining:
        leaves = {task_id for task_id, dependencies in remaining.items() if not dependencies}
        if not leaves:
            validation.error(
                "task dependency cycle detected among: " + ", ".join(sorted(remaining))
            )
            break
        for leaf in leaves:
            remaining.pop(leaf, None)
        for dependencies in remaining.values():
            dependencies.difference_update(leaves)

    if "active_task" not in roadmap:
        validation.error("roadmap.active_task key is required; use explicit null when none is active")
        active_id: Any = None
    else:
        active_id = roadmap.get("active_task")
    if active_id is None:
        if in_progress:
            validation.error("active_task is null while a task is in_progress")
        ready = sorted(
            task_id for task_id, task in task_by_id.items() if task.get("status") == "ready"
        )
        if ready:
            validation.warn("active_task is null while ready tasks exist: " + ", ".join(ready))
    elif not isinstance(active_id, str):
        validation.error("roadmap.active_task must be a task ID string or null")
    elif active_id not in task_by_id:
        validation.error(f"roadmap.active_task names an unknown task: {active_id}")
    else:
        active_status = task_by_id[active_id].get("status")
        if not isinstance(active_status, str) or active_status not in {
            "ready",
            "in_progress",
            "blocked",
        }:
            validation.error(f"active task {active_id} has non-executable status {active_status}")
        if in_progress and in_progress[0] != active_id:
            validation.error("active_task does not match the in_progress task")

    for task_id, info in manifest_info.items():
        if task_by_id[task_id].get("status") == "completed":
            continue
        for allowed in info["allowed_paths"]:
            for protected in normalized_protected:
                if paths_overlap(allowed, protected):
                    validation.error(
                        f"task {task_id} allowed path overlaps protected path: {allowed} / {protected}"
                    )

    portability = roadmap.get("portability")
    if not isinstance(portability, dict):
        validation.error("roadmap.portability must be an object")
    else:
        state = portability.get("state")
        if state == "local_only_until_committed":
            validation.warn(
                "workflow control files are local-only; use this worktree or commit them intentionally"
            )
        elif state == "portable":
            tracked_result = git_run(root, ["ls-files", "-z"])
            if tracked_result.returncode != 0:
                validation.error("portable state cannot verify tracked workflow files")
            else:
                tracked = {
                    item.decode("utf-8", errors="strict")
                    for item in tracked_result.stdout.split(b"\0")
                    if item
                }
                portable_required = set(required_files)
                portable_required.add("docs/GLOBAL_AUDIT_AND_IMPROVEMENT_PLAN.md")
                for task in task_by_id.values():
                    for key in ("packet_path", "exec_plan_path"):
                        if isinstance(task.get(key), str):
                            portable_required.add(task[key])
                untracked = sorted(portable_required - tracked)
                if untracked:
                    validation.error(
                        "portable state has untracked control files: " + ", ".join(untracked)
                    )
        else:
            validation.error(f"roadmap.portability.state is invalid: {state!r}")

    return validation


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, help="repository root (auto-detected by default)")
    parser.add_argument(
        "--expected-baseline-sha256",
        help="external pre-edit receipt required for the active in-progress/blocked task",
    )
    parser.add_argument(
        "--expected-head",
        help="external admitted HEAD receipt required for the active in-progress/blocked task",
    )
    parser.add_argument(
        "--expected-contract-sha256",
        help="external admission contract receipt required for the active executable task",
    )
    parser.add_argument("--json", action="store_true", help="emit machine-readable output")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        root = args.root.resolve() if args.root else find_repo_root(Path.cwd().resolve())
        validation = validate(
            root,
            args.expected_baseline_sha256,
            args.expected_head,
            args.expected_contract_sha256,
        )
    except (
        KeyError,
        OSError,
        FileNotFoundError,
        OverflowError,
        RecursionError,
        RuntimeError,
        StopIteration,
        TypeError,
        ValueError,
    ) as exc:
        result = {
            "ok": False,
            "root": ".",
            "errors": [f"validator could not process repository state: {type(exc).__name__}: {exc}"],
            "warnings": [],
        }
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print(f"ERROR: {result['errors'][0]}", file=sys.stderr)
        return 2

    result = {
        "ok": not validation.errors,
        "root": ".",
        "errors": validation.errors,
        "warnings": validation.warnings,
    }
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        for warning in validation.warnings:
            print(f"WARNING: {warning}")
        for error in validation.errors:
            print(f"ERROR: {error}", file=sys.stderr)
        if not validation.errors:
            suffix = f" with {len(validation.warnings)} warning(s)" if validation.warnings else ""
            print(f"Execution state is valid{suffix}: .")
    return 1 if validation.errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
