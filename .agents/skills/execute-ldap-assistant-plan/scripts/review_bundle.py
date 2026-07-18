#!/usr/bin/env python3
"""Create and verify immutable baselines and review bundles for one admitted task."""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1
BASELINE_KIND = "ldap-assistant-task-baseline"
BUNDLE_KIND = "ldap-assistant-task-review-bundle"
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_JSON_DEPTH = 64
MAX_JSON_NODES = 100_000
ALLOWED_EVIDENCE_KINDS = {"command", "test", "artifact", "source_trace", "review"}
STATE_ONLY_MANIFEST_KEYS = {
    "status",
    "state_reason",
    "admission_contract_sha256",
    "baseline_sha256",
    "completion_bundle_sha256",
}
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
BASELINE_KEYS = frozenset(
    {
        "schema_version",
        "kind",
        "task_id",
        "base_head",
        "branch",
        "upstream",
        "audit_sha256",
        "allowed_paths",
        "state_paths",
        "material_paths",
        "contract_fingerprint",
        "roadmap_fingerprint",
        "controlled_files",
        "workspace",
        "protected_paths",
    }
)
BUNDLE_KEYS = frozenset(
    {
        "schema_version",
        "kind",
        "task_id",
        "base_head",
        "current_head",
        "branch",
        "upstream",
        "baseline_path",
        "baseline_sha256",
        "baseline_content_base64",
        "self_path",
        "contract",
        "contract_fingerprint",
        "roadmap_fingerprint",
        "manifest_pre_review_base64",
        "manifest_pre_review_sha256",
        "roadmap_pre_review_base64",
        "roadmap_pre_review_sha256",
        "exec_plan_pre_review_base64",
        "exec_plan_pre_review_sha256",
        "exec_plan_immutable_sha256",
        "evidence_pre_review_base64",
        "evidence_pre_review_sha256",
        "evidence_projection",
        "evidence_projection_sha256",
        "allowed_paths",
        "state_paths",
        "material_paths",
        "final_snapshot",
        "material_snapshot",
        "changed_paths",
        "changed_material_paths",
        "changed_files",
        "material_tracked_patch_base64",
        "material_tracked_patch_sha256",
        "whole_tracked_changed_paths",
        "whole_tracked_patch_base64",
        "whole_tracked_patch_sha256",
        "review_identity_rule",
        "post_review_mutability",
    }
)
STATE_PATH_KEYS = {
    "exec_plan_path",
    "baseline_path",
    "review_bundle_path",
    "evidence_path",
    "review_path",
}
EXEC_PLAN_HEADINGS = (
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


class BundleError(RuntimeError):
    """Raised when review identity cannot be constructed safely."""


def reject_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON constant is forbidden: {value}")


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def json_load_bytes(data: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise BundleError(f"{label} is not strict JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise BundleError(f"{label} JSON root must be an object")
    stack: list[tuple[Any, int]] = [(value, 1)]
    nodes = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES:
            raise BundleError(f"{label} exceeds the {MAX_JSON_NODES}-node JSON limit")
        if depth > MAX_JSON_DEPTH:
            raise BundleError(f"{label} exceeds the {MAX_JSON_DEPTH}-level JSON depth limit")
        if isinstance(item, float):
            raise BundleError(f"{label} must not contain floating-point values")
        if isinstance(item, dict):
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
    return value


def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("ascii")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def find_repo_root(start: Path) -> Path:
    for candidate in (start, *start.parents):
        if (candidate / "AGENTS.md").is_file() and (
            candidate / "docs/implementation/ROADMAP.json"
        ).is_file():
            return candidate.resolve()
    raise BundleError("repository root with AGENTS.md and ROADMAP.json was not found")


def canonical_relative(raw: Any, label: str) -> Path:
    if not isinstance(raw, str) or not raw.strip() or raw != raw.strip():
        raise BundleError(f"{label} must be a non-empty normalized relative path")
    if "\x00" in raw:
        raise BundleError(f"{label} contains a NUL byte")
    if "\\" in raw:
        raise BundleError(f"{label} must use forward slashes")
    try:
        relative = Path(raw)
    except (TypeError, ValueError) as exc:
        raise BundleError(f"{label} is not a valid path") from exc
    if relative.is_absolute() or relative == Path(".") or ".." in relative.parts:
        raise BundleError(f"{label} must name one exact file inside the repository")
    if relative.as_posix() != raw:
        raise BundleError(f"{label} must use its exact canonical repository-relative spelling")
    if relative.parts and relative.parts[0] == ".git":
        raise BundleError(f"{label} must not name Git internals")
    return relative


def safe_path(root: Path, raw: Any, label: str, *, allow_missing: bool = True) -> Path:
    relative = canonical_relative(raw, label)
    candidate = root / relative
    cursor = root
    for part in relative.parts:
        cursor = cursor / part
        try:
            if cursor.is_symlink():
                raise BundleError(f"{label} contains a symlink component: {raw}")
        except OSError as exc:
            raise BundleError(f"{label} cannot be inspected safely") from exc
    try:
        if not candidate.resolve(strict=False).is_relative_to(root.resolve(strict=True)):
            raise BundleError(f"{label} resolves outside the repository")
    except (OSError, RuntimeError) as exc:
        raise BundleError(f"{label} cannot be resolved safely") from exc
    if not allow_missing and not candidate.is_file():
        raise BundleError(f"{label} is missing or not a regular file: {raw}")
    if candidate.exists() and not candidate.is_file():
        raise BundleError(f"{label} must name a regular file: {raw}")
    return candidate


def read_bounded(path: Path, label: str) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise BundleError(f"cannot open {label} safely") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise BundleError(f"{label} must be a single-link regular file")
        if before.st_size > MAX_FILE_BYTES:
            raise BundleError(f"{label} exceeds {MAX_FILE_BYTES} bytes")
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
            raise BundleError(f"{label} changed while it was read")
        return data
    finally:
        os.close(descriptor)


def load_repo_json(root: Path, raw: str, label: str) -> tuple[dict[str, Any], bytes]:
    path = safe_path(root, raw, label, allow_missing=False)
    data = read_bounded(path, label)
    return json_load_bytes(data, label), data


def run_git(root: Path, args: list[str]) -> bytes:
    result = subprocess.run(
        ["git", *args],
        cwd=root,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={
            **os.environ,
            "GIT_OPTIONAL_LOCKS": "0",
            "LC_ALL": "C",
            "GIT_PAGER": "cat",
        },
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise BundleError(f"git {' '.join(args)} failed: {detail or 'unknown error'}")
    return result.stdout


def assert_not_ignored(root: Path, raw: str, label: str) -> None:
    result = subprocess.run(
        ["git", "check-ignore", "--no-index", "--quiet", "--", raw],
        cwd=root,
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        env={**os.environ, "GIT_OPTIONAL_LOCKS": "0", "LC_ALL": "C"},
    )
    if result.returncode == 0:
        raise BundleError(f"{label} is Git-ignored and must not be opened: {raw}")
    if result.returncode != 1:
        raise BundleError(f"ignore status could not be verified for {label}")


def git_head(root: Path) -> str:
    value = run_git(root, ["rev-parse", "HEAD"]).decode("ascii", errors="strict").strip()
    if len(value) != 40:
        raise BundleError("git HEAD is not a full commit identity")
    return value


def git_branch(root: Path) -> str:
    value = run_git(root, ["branch", "--show-current"]).decode("utf-8", errors="strict").strip()
    if not value:
        raise BundleError("detached HEAD is not admitted for this workflow")
    return value


def git_upstream(root: Path) -> str:
    value = run_git(
        root, ["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{upstream}"]
    ).decode("utf-8", errors="strict").strip()
    if not value:
        raise BundleError("current branch has no upstream")
    return value


def assert_no_staged_changes(root: Path) -> None:
    result = subprocess.run(
        ["git", "diff", "--cached", "--quiet", "--exit-code", "--"],
        cwd=root,
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        env={**os.environ, "GIT_OPTIONAL_LOCKS": "0", "LC_ALL": "C"},
    )
    if result.returncode == 1:
        raise BundleError("staged changes are not authorized for this local-edit task")
    if result.returncode != 0:
        raise BundleError("could not verify that the Git index is unchanged")


def assert_no_index_hiding(root: Path) -> None:
    """Reject Git index flags that can hide tracked worktree changes."""
    verbose = run_git(root, ["ls-files", "-v", "-z"])
    for entry in verbose.split(b"\0"):
        if entry and entry[:1].isalpha() and entry[:1].islower():
            raw = entry[2:].decode("utf-8", errors="replace")
            raise BundleError(f"tracked path has assume-unchanged set: {raw}")
    tagged = run_git(root, ["ls-files", "-t", "-z"])
    for entry in tagged.split(b"\0"):
        if entry.startswith(b"S "):
            raw = entry[2:].decode("utf-8", errors="replace")
            raise BundleError(f"tracked path has skip-worktree set: {raw}")


def tracked_paths(root: Path) -> set[str]:
    data = run_git(root, ["ls-files", "-z"])
    return {
        item.decode("utf-8", errors="strict")
        for item in data.split(b"\0")
        if item
    }


def git_status(root: Path) -> dict[str, str]:
    data = run_git(root, ["status", "--porcelain=v1", "-z", "--untracked-files=all"])
    parts = data.split(b"\0")
    result: dict[str, str] = {}
    index = 0
    while index < len(parts):
        record = parts[index]
        index += 1
        if not record:
            continue
        if len(record) < 4 or record[2:3] != b" ":
            raise BundleError("git status returned an unsupported record")
        status_code = record[:2].decode("ascii", errors="strict")
        path = record[3:].decode("utf-8", errors="strict")
        if "R" in status_code or "C" in status_code:
            if index >= len(parts) or not parts[index]:
                raise BundleError("git status rename/copy record is incomplete")
            old_path = parts[index].decode("utf-8", errors="strict")
            index += 1
            result[old_path] = f"{status_code}:source"
        result[path] = status_code
    return result


def protected_metadata(_root: Path, raw: str) -> dict[str, Any]:
    canonical_relative(raw, "protected path")
    return {
        "content_read_by_control_plane": False,
        "direct_metadata_read_by_control_plane": False,
        "git_status_only": True,
    }


def file_record(root: Path, raw: str, tracked: set[str]) -> dict[str, Any]:
    path = safe_path(root, raw, f"file {raw}")
    if not path.exists():
        return {"state": "missing", "tracked": raw in tracked}
    data = read_bounded(path, f"file {raw}")
    metadata = path.stat()
    return {
        "state": "file",
        "tracked": raw in tracked,
        "size": len(data),
        "mode": stat.S_IMODE(metadata.st_mode),
        "sha256": sha256_bytes(data),
    }


def file_record_with_content(root: Path, raw: str, tracked: set[str]) -> dict[str, Any]:
    record = file_record(root, raw, tracked)
    if record["state"] == "file":
        data = read_bounded(root / raw, f"file {raw}")
        if len(data) != record["size"] or sha256_bytes(data) != record["sha256"]:
            raise BundleError(f"file changed while content was captured: {raw}")
        record["content_base64"] = base64.b64encode(data).decode("ascii")
    return record


def contract_projection(manifest: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in manifest.items()
        if key not in STATE_ONLY_MANIFEST_KEYS
    }


def roadmap_projection(roadmap: dict[str, Any], task_id: str) -> dict[str, Any]:
    projected = copy.deepcopy(roadmap)
    projected.pop("active_task", None)
    tasks = projected.get("tasks")
    if isinstance(tasks, list):
        for task in tasks:
            if isinstance(task, dict) and task.get("task_id") == task_id:
                task.pop("status", None)
                task.pop("state_reason", None)
                task.pop("admission_contract_sha256", None)
                task.pop("baseline_sha256", None)
                task.pop("completion_bundle_sha256", None)
    return projected


def exec_plan_immutable_projection(text: str) -> str:
    mutable = {
        "### Progress",
        "### Verification plan and results",
        "### Independent review",
        "### Outcomes and handoff",
    }
    positions: list[tuple[str, int, int]] = []
    for heading in EXEC_PLAN_HEADINGS:
        matches = list(re.finditer(rf"(?m)^{re.escape(heading)}[ \t]*$", text))
        if len(matches) != 1:
            raise BundleError(f"ExecPlan must contain exactly one heading: {heading}")
        positions.append((heading, matches[0].start(), matches[0].end()))
    offsets = [start for _, start, _ in positions]
    if offsets != sorted(offsets):
        raise BundleError("ExecPlan required headings are out of order")

    output = [text[: positions[0][1]]]
    for index, (heading, start, heading_end) in enumerate(positions):
        section_end = positions[index + 1][1] if index + 1 < len(positions) else len(text)
        newline_end = text.find("\n", heading_end)
        body_start = section_end if newline_end < 0 or newline_end >= section_end else newline_end + 1
        output.append(text[start:body_start])
        if heading in mutable:
            output.append("<STATE-ONLY-FINALIZATION>\n")
        else:
            output.append(text[body_start:section_end])
    return "".join(output)


def evidence_projection(evidence: dict[str, Any]) -> dict[str, Any]:
    projected = copy.deepcopy(evidence)
    projected.pop("final_state", None)
    projected.pop("reviewed_identity", None)
    gates = projected.get("gates")
    if isinstance(gates, dict):
        gates.pop("G7", None)
    return projected


def post_review_policy(ctx: dict[str, Any], task_id: str) -> dict[str, Any]:
    return {
        "manifest_fields": ["status", "state_reason", "completion_bundle_sha256"],
        "roadmap_fields": [
            "active_task",
            f"tasks[{task_id}].status",
            f"tasks[{task_id}].state_reason",
            f"tasks[{task_id}].completion_bundle_sha256",
        ],
        "evidence_fields": ["final_state", "reviewed_identity", "gates.G7"],
        "exec_plan_sections": [
            "Progress",
            "Verification plan and results",
            "Independent review",
            "Outcomes and handoff",
        ],
        "new_review_path": ctx["manifest"]["review_path"],
    }


def decode_bundle_blob(bundle: dict[str, Any], prefix: str, label: str) -> bytes:
    encoded = bundle.get(f"{prefix}_base64")
    digest = bundle.get(f"{prefix}_sha256")
    if not isinstance(encoded, str) or not isinstance(digest, str):
        raise BundleError(f"review bundle {label} content/hash is missing")
    try:
        data = base64.b64decode(encoded, validate=True)
    except ValueError as exc:
        raise BundleError(f"review bundle {label} base64 is invalid") from exc
    if sha256_bytes(data) != digest:
        raise BundleError(f"review bundle {label} content/hash disagree")
    return data


def require_evidence_item(item: Any, label: str, *, allow_review: bool) -> None:
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
        raise BundleError(
            f"{label} must contain exactly kind/reference/result/outcome/exit_code/sha256/case_id"
        )
    kind = item.get("kind")
    if kind not in ALLOWED_EVIDENCE_KINDS or (kind == "review" and not allow_review):
        raise BundleError(f"{label} has an inadmissible evidence kind")
    for key in ("reference", "result"):
        value = item.get(key)
        if not isinstance(value, str) or not value.strip() or value != value.strip():
            raise BundleError(f"{label}.{key} must be a normalized non-empty string")
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
    if expected_prefix is None or not item["result"].startswith(expected_prefix):
        raise BundleError(f"{label} result does not match its machine outcome")
    if kind == "command":
        if (
            outcome != "passed"
            or type(exit_code) is not int
            or exit_code != 0
            or digest is not None
            or case_id is not None
        ):
            raise BundleError(f"{label} command evidence must record passed/exit_code 0")
    elif kind == "test":
        if outcome not in {"passed", "expected_failure"} or type(exit_code) is not int:
            raise BundleError(f"{label} test evidence has invalid outcome/exit_code")
        if (outcome == "passed" and exit_code != 0) or (
            outcome == "expected_failure" and exit_code == 0
        ):
            raise BundleError(f"{label} test outcome contradicts exit_code")
        if digest is not None:
            raise BundleError(f"{label} test evidence sha256 must be null")
        if outcome == "expected_failure" and (
            not isinstance(case_id, str)
            or not case_id
            or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789_" for character in case_id)
        ):
            raise BundleError(f"{label} expected-failure test needs a stable case_id")
        if outcome == "passed" and case_id is not None and (
            not isinstance(case_id, str)
            or not case_id
            or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789_" for character in case_id)
        ):
            raise BundleError(f"{label} passed test case_id is invalid")
    elif kind == "artifact":
        if (
            outcome != "verified"
            or exit_code is not None
            or not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            or case_id is not None
        ):
            raise BundleError(f"{label} artifact evidence needs a verified SHA-256")
    elif kind == "source_trace":
        if (
            outcome != "verified"
            or exit_code is not None
            or digest is not None
            or case_id is not None
        ):
            raise BundleError(f"{label} source trace evidence has invalid machine fields")
    elif kind == "review":
        if (
            outcome != "approved"
            or exit_code is not None
            or not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            or case_id is not None
        ):
            raise BundleError(f"{label} review evidence needs the approved bundle SHA-256")


def validate_pre_review_evidence_value(
    ctx: dict[str, Any],
    evidence: dict[str, Any],
    *,
    protected_paths: list[str] | None = None,
) -> None:
    if set(evidence) != EVIDENCE_KEYS:
        raise BundleError("pre-review evidence has an invalid top-level schema")
    if type(evidence.get("schema_version")) is not int or evidence.get(
        "schema_version"
    ) != SCHEMA_VERSION:
        raise BundleError("pre-review evidence schema_version must be 1")
    if evidence.get("task_id") != ctx["manifest"].get("task_id"):
        raise BundleError("pre-review evidence task ID does not match")
    if evidence.get("final_state") != "in_progress" or evidence.get("reviewed_identity") is not None:
        raise BundleError("pre-review evidence must be in_progress with null reviewed_identity")
    if evidence.get("baseline_sha256") != ctx["manifest"].get("baseline_sha256"):
        raise BundleError("pre-review evidence baseline_sha256 does not match packet pin")
    if evidence.get("admitted_head") != ctx["manifest"].get("admitted_head"):
        raise BundleError("pre-review evidence admitted_head does not match packet")
    if evidence.get("admission_contract_sha256") != ctx["contract_fingerprint"]:
        raise BundleError("pre-review evidence admission contract receipt does not match")
    criterion_ids = [
        item.get("id")
        for item in ctx["manifest"].get("acceptance_criteria", [])
        if isinstance(item, dict)
    ]
    acceptance = evidence.get("acceptance")
    if not isinstance(acceptance, dict) or set(acceptance) != set(criterion_ids):
        raise BundleError("pre-review evidence must contain exactly every acceptance ID")
    for criterion_id in criterion_ids:
        criterion = next(
            item
            for item in ctx["manifest"]["acceptance_criteria"]
            if isinstance(item, dict) and item.get("id") == criterion_id
        )
        expected_cases = criterion.get("fail_before_cases")
        if not isinstance(expected_cases, list) or any(
            not isinstance(case_id, str) for case_id in expected_cases
        ):
            raise BundleError(f"acceptance {criterion_id} fail_before_cases is invalid")
        record = acceptance.get(criterion_id)
        if not isinstance(record, dict) or record.get("status") != "passed":
            raise BundleError(f"pre-review acceptance is not passed: {criterion_id}")
        proof = record.get("proof")
        if not isinstance(proof, list) or not proof:
            raise BundleError(f"pre-review acceptance lacks direct proof: {criterion_id}")
        for index, item in enumerate(proof):
            require_evidence_item(
                item,
                f"pre-review acceptance {criterion_id} proof[{index}]",
                allow_review=False,
            )
        if not any(
            isinstance(item, dict)
            and item.get("kind") in {"command", "test"}
            and item.get("outcome") == "passed"
            and item.get("exit_code") == 0
            for item in proof
        ):
            raise BundleError(
                f"pre-review acceptance lacks passed executable proof: {criterion_id}"
            )
        actual_cases = {
            item.get("case_id")
            for item in proof
            if isinstance(item, dict) and item.get("outcome") == "expected_failure"
        }
        if actual_cases != set(expected_cases):
            raise BundleError(
                f"pre-review acceptance fail-before case coverage differs: {criterion_id}"
            )
    required_gates = ctx["manifest"].get("required_gates", [])
    gates = evidence.get("gates")
    if not isinstance(gates, dict) or not set(required_gates).issubset(gates):
        raise BundleError("pre-review evidence omits a required gate")
    for gate in required_gates:
        record = gates.get(gate)
        if not isinstance(record, dict):
            raise BundleError(f"pre-review gate record is invalid: {gate}")
        expected_status = "pending" if gate == "G7" else "passed"
        if record.get("status") != expected_status:
            raise BundleError(f"pre-review gate {gate} must be {expected_status}")
        evidence_items = record.get("evidence")
        if gate == "G7":
            if evidence_items != []:
                raise BundleError("pre-review G7 evidence must be empty while pending")
        elif not isinstance(evidence_items, list) or not evidence_items:
            raise BundleError(f"pre-review gate {gate} lacks evidence")
        else:
            for index, item in enumerate(evidence_items):
                require_evidence_item(
                    item,
                    f"pre-review gate {gate} evidence[{index}]",
                    allow_review=False,
                )
            if not any(
                isinstance(item, dict)
                and item.get("kind") in {"command", "test"}
                and item.get("outcome") == "passed"
                and item.get("exit_code") == 0
                for item in evidence_items
            ):
                raise BundleError(f"pre-review gate {gate} lacks a passed executable proof")
            if gate == "G1" and not any(
                isinstance(item, dict)
                and item.get("kind") == "test"
                and item.get("outcome") == "expected_failure"
                and type(item.get("exit_code")) is int
                and item.get("exit_code") != 0
                for item in evidence_items
            ):
                raise BundleError("pre-review G1 lacks fail-before expected-failure evidence")
            if gate == "G1":
                expected_gate_cases = {
                    case_id
                    for criterion in ctx["manifest"]["acceptance_criteria"]
                    if isinstance(criterion, dict)
                    for case_id in criterion.get("fail_before_cases", [])
                }
                actual_gate_cases = {
                    item.get("case_id")
                    for item in evidence_items
                    if isinstance(item, dict)
                    and item.get("outcome") == "expected_failure"
                }
                if actual_gate_cases != expected_gate_cases:
                    raise BundleError(
                        "pre-review G1 fail-before case coverage differs from the manifest"
                    )
            if gate == "G0" and not any(
                isinstance(item, dict)
                and item.get("kind") == "command"
                and "validate_execution_state.py" in item.get("reference", "")
                and item.get("outcome") == "passed"
                and item.get("exit_code") == 0
                for item in evidence_items
            ):
                raise BundleError("pre-review G0 lacks a passed state-validator command")
    admitted_head = ctx["manifest"].get("admitted_head")
    if evidence.get("base_head") != admitted_head or evidence.get("final_head") != admitted_head:
        raise BundleError("pre-review evidence base_head/final_head must match admitted HEAD")
    if evidence.get("review_bundle_path") != ctx["manifest"].get("review_bundle_path"):
        raise BundleError("pre-review evidence review_bundle_path does not match packet")
    for key in ("limitations", "unverified_protected_paths"):
        value = evidence.get(key)
        if not isinstance(value, list) or any(
            not isinstance(item, str) or not item.strip() or item != item.strip()
            for item in value
        ):
            raise BundleError(f"pre-review evidence {key} must be a normalized string list")
    required_protected = ctx["protected_paths"] if protected_paths is None else protected_paths
    if not set(required_protected).issubset(
        evidence.get("unverified_protected_paths", [])
    ):
        raise BundleError("pre-review evidence omits an unverified protected path")
    rollback = evidence.get("rollback_verification")
    if not isinstance(rollback, str) or not rollback.strip():
        raise BundleError("pre-review evidence rollback_verification must be non-empty")


def validate_pre_review_evidence(ctx: dict[str, Any]) -> tuple[dict[str, Any], bytes]:
    raw = ctx["manifest"]["evidence_path"]
    evidence, evidence_bytes = load_repo_json(ctx["root"], raw, "pre-review evidence")
    validate_pre_review_evidence_value(ctx, evidence)
    return evidence, evidence_bytes


def context(
    root: Path, task_id: str, *, require_contract_pin: bool = True
) -> dict[str, Any]:
    roadmap, roadmap_bytes = load_repo_json(
        root, "docs/implementation/ROADMAP.json", "ROADMAP.json"
    )
    if set(roadmap) != ROADMAP_KEYS:
        raise BundleError("ROADMAP.json has an invalid top-level schema")
    if type(roadmap.get("schema_version")) is not int or roadmap.get(
        "schema_version"
    ) != SCHEMA_VERSION:
        raise BundleError("ROADMAP.json schema_version must be integer 1")
    tasks = roadmap.get("tasks")
    if not isinstance(tasks, list):
        raise BundleError("ROADMAP.json tasks must be a list")
    matches = [task for task in tasks if isinstance(task, dict) and task.get("task_id") == task_id]
    if len(matches) != 1:
        raise BundleError(f"roadmap must contain exactly one task {task_id}")
    task = matches[0]
    packet_raw = task.get("packet_path")
    if not isinstance(packet_raw, str):
        raise BundleError(f"task {task_id} has no packet path")
    manifest, manifest_bytes = load_repo_json(root, packet_raw, f"task {task_id} packet")
    if set(manifest) != REQUIRED_MANIFEST_KEYS:
        raise BundleError("task packet has an invalid top-level schema")
    if type(manifest.get("schema_version")) is not int or manifest.get(
        "schema_version"
    ) != SCHEMA_VERSION:
        raise BundleError("task packet schema_version must be integer 1")
    if manifest.get("task_id") != task_id:
        raise BundleError("roadmap and task packet identity do not match")
    for key in (
        "status",
        "state_reason",
        "admitted_head",
        "admission_contract_sha256",
        "baseline_sha256",
        "completion_bundle_sha256",
    ):
        if manifest.get(key) != task.get(key):
            raise BundleError(f"roadmap and task packet {key} do not match")
    if manifest.get("state_reason") != task.get("state_reason") or not isinstance(
        manifest.get("state_reason"), str
    ) or not manifest.get("state_reason", "").strip():
        raise BundleError("roadmap and task packet state_reason must be equal and non-empty")
    allowed = manifest.get("allowed_paths")
    protected = roadmap.get("protected_dirty_paths")
    required = roadmap.get("required_workflow_files")
    if not isinstance(allowed, list) or not all(isinstance(item, str) for item in allowed):
        raise BundleError("manifest allowed_paths must be a string list")
    if not isinstance(protected, list) or not all(isinstance(item, str) for item in protected):
        raise BundleError("roadmap protected_dirty_paths must be a string list")
    if not isinstance(required, list) or not all(isinstance(item, str) for item in required):
        raise BundleError("roadmap required_workflow_files must be a string list")
    allowed_set = set(allowed)
    if len(allowed) != len(allowed_set):
        raise BundleError("manifest allowed_paths contains duplicates")
    if len(protected) != len(set(protected)):
        raise BundleError("roadmap protected_dirty_paths contains duplicates")
    for raw in allowed:
        safe_path(root, raw, f"allowed path {raw}")
        assert_not_ignored(root, raw, f"allowed path {raw}")
    for raw in protected:
        canonical_relative(raw, f"protected path {raw}")
    state_paths = {"docs/implementation/ROADMAP.json", packet_raw}
    for key in STATE_PATH_KEYS:
        raw = manifest.get(key)
        if not isinstance(raw, str):
            raise BundleError(f"manifest {key} must be a path")
        state_paths.add(raw)
    if not state_paths.issubset(allowed_set):
        missing = ", ".join(sorted(state_paths - allowed_set))
        raise BundleError(f"state path(s) are not admitted by allowed_paths: {missing}")
    material_paths = allowed_set - state_paths
    projection = contract_projection(manifest)
    fingerprint = sha256_bytes(canonical_json(projection))
    packet_contract_pin = manifest.get("admission_contract_sha256")
    roadmap_contract_pin = task.get("admission_contract_sha256")
    if packet_contract_pin != roadmap_contract_pin:
        raise BundleError("packet/roadmap admission_contract_sha256 values differ")
    if require_contract_pin and packet_contract_pin != fingerprint:
        raise BundleError(
            "packet/roadmap admission_contract_sha256 does not match the canonical task contract"
        )
    return {
        "root": root,
        "roadmap": roadmap,
        "roadmap_bytes": roadmap_bytes,
        "task": task,
        "packet_path": packet_raw,
        "manifest": manifest,
        "manifest_bytes": manifest_bytes,
        "allowed_paths": sorted(allowed_set),
        "protected_paths": sorted(set(protected)),
        "required_files": sorted(set(required)),
        "state_paths": sorted(state_paths),
        "material_paths": sorted(material_paths),
        "contract": projection,
        "contract_fingerprint": fingerprint,
        "roadmap_projection": roadmap_projection(roadmap, task_id),
        "roadmap_fingerprint": sha256_bytes(
            canonical_json(roadmap_projection(roadmap, task_id))
        ),
    }


def fingerprint_task_contract(root: Path, task_id: str) -> dict[str, Any]:
    """Compute a candidate receipt during a separate planning/admission task."""
    ctx = context(root, task_id, require_contract_pin=False)
    return {
        "path": ctx["packet_path"],
        "sha256": ctx["contract_fingerprint"],
    }


def workspace_snapshot(
    root: Path,
    status_map: dict[str, str],
    protected: set[str],
    tracked: set[str],
    readable: set[str],
) -> dict[str, Any]:
    snapshot: dict[str, Any] = {}
    for raw, status_code in sorted(status_map.items()):
        if raw in protected:
            snapshot[raw] = {
                "git_status": status_code,
                "protected_observation": protected_metadata(root, raw),
            }
        else:
            if raw not in readable:
                raise BundleError(
                    f"unexpected dirty path is outside the baseline policy; content was not read: {raw}"
                )
            snapshot[raw] = {
                "git_status": status_code,
                "file": file_record(root, raw, tracked),
            }
    return snapshot


def controlled_paths(ctx: dict[str, Any]) -> list[str]:
    values = set(ctx["required_files"])
    values.update(ctx["allowed_paths"])
    values.add(ctx["roadmap"].get("audit_path"))
    values.discard(None)
    return sorted(value for value in values if isinstance(value, str))


def readable_paths(ctx: dict[str, Any]) -> set[str]:
    return set(controlled_paths(ctx))


def require_external_admitted_head(
    root: Path, ctx: dict[str, Any], expected_head: str
) -> str:
    packet_head = ctx["manifest"].get("admitted_head")
    roadmap_head = ctx["task"].get("admitted_head")
    if packet_head != roadmap_head:
        raise BundleError("packet and roadmap admitted_head identities differ")
    if (
        not isinstance(expected_head, str)
        or len(expected_head) != 40
        or any(character not in "0123456789abcdef" for character in expected_head)
    ):
        raise BundleError("an external expected admitted HEAD receipt is required")
    if packet_head != expected_head:
        raise BundleError("external admitted HEAD differs from packet/roadmap admission")
    current = git_head(root)
    if current != expected_head:
        raise BundleError("HEAD changed after admission; task must be re-admitted")
    return current


def require_external_contract(ctx: dict[str, Any], expected_contract_sha256: str) -> str:
    if (
        not isinstance(expected_contract_sha256, str)
        or len(expected_contract_sha256) != 64
        or any(
            character not in "0123456789abcdef"
            for character in expected_contract_sha256
        )
    ):
        raise BundleError("an external expected admission contract SHA-256 receipt is required")
    if expected_contract_sha256 != ctx["contract_fingerprint"]:
        raise BundleError("external admission contract receipt differs from the task contract")
    return expected_contract_sha256


def exclusive_atomic_create(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(
        mode="wb", dir=path.parent, prefix=f".{path.name}.", delete=False
    )
    temp_path = Path(handle.name)
    try:
        with handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temp_path, path)
        except FileExistsError as exc:
            raise BundleError(f"artifact already exists and will not be overwritten: {path.name}") from exc
        temp_path.unlink()
    except Exception:
        try:
            temp_path.unlink()
        except OSError:
            pass
        raise


def assert_out_of_scope_unchanged(
    ctx: dict[str, Any], baseline: dict[str, Any], current_workspace: dict[str, Any]
) -> None:
    allowed = set(ctx["allowed_paths"])
    before_workspace = baseline.get("workspace")
    if not isinstance(before_workspace, dict):
        raise BundleError("baseline workspace snapshot is missing")
    before_outside = {key: value for key, value in before_workspace.items() if key not in allowed}
    current_outside = {key: value for key, value in current_workspace.items() if key not in allowed}
    if before_outside != current_outside:
        changed = sorted(set(before_outside) ^ set(current_outside))
        if not changed:
            changed = sorted(
                key for key in before_outside if before_outside[key] != current_outside.get(key)
            )
        raise BundleError(
            "out-of-scope/protected workspace state changed since baseline: "
            + ", ".join(changed)
        )


def make_baseline(
    root: Path,
    task_id: str,
    expected_head: str,
    expected_contract_sha256: str,
) -> dict[str, Any]:
    ctx = context(root, task_id)
    if ctx["manifest"].get("status") != "in_progress":
        raise BundleError("baseline requires packet and roadmap status in_progress")
    if ctx["manifest"].get("baseline_sha256") is not None or ctx["task"].get(
        "baseline_sha256"
    ) is not None:
        raise BundleError("new baseline requires null packet/roadmap baseline_sha256 pins")
    if ctx["manifest"].get("completion_bundle_sha256") is not None or ctx["task"].get(
        "completion_bundle_sha256"
    ) is not None:
        raise BundleError("new baseline requires null completion bundle pins")
    require_external_contract(ctx, expected_contract_sha256)
    admitted_head = require_external_admitted_head(root, ctx, expected_head)
    baseline_raw = ctx["manifest"]["baseline_path"]
    baseline_path = safe_path(root, baseline_raw, "baseline_path")
    if baseline_path.exists():
        raise BundleError("baseline already exists and is immutable; verify/reuse it")

    assert_no_staged_changes(root)
    assert_no_index_hiding(root)
    tracked = tracked_paths(root)
    status_map = git_status(root)
    dirty_material = sorted(
        raw for raw in ctx["material_paths"] if raw in status_map
    )
    if dirty_material:
        raise BundleError(
            "material target paths were already dirty before baseline: "
            + ", ".join(dirty_material)
        )

    controlled = {
        raw: file_record(root, raw, tracked)
        for raw in controlled_paths(ctx)
    }
    protected = set(ctx["protected_paths"])
    baseline = {
        "schema_version": SCHEMA_VERSION,
        "kind": BASELINE_KIND,
        "task_id": task_id,
        "base_head": admitted_head,
        "branch": git_branch(root),
        "upstream": git_upstream(root),
        "audit_sha256": ctx["roadmap"].get("audit_sha256"),
        "allowed_paths": ctx["allowed_paths"],
        "state_paths": ctx["state_paths"],
        "material_paths": ctx["material_paths"],
        "contract_fingerprint": ctx["contract_fingerprint"],
        "roadmap_fingerprint": ctx["roadmap_fingerprint"],
        "controlled_files": controlled,
        "workspace": workspace_snapshot(
            root, status_map, protected, tracked, readable_paths(ctx)
        ),
        "protected_paths": ctx["protected_paths"],
    }
    if git_status(root) != status_map:
        raise BundleError("workspace changed while the baseline was being constructed")
    data = canonical_json(baseline)
    exclusive_atomic_create(baseline_path, data)
    return {"path": baseline_raw, "sha256": sha256_bytes(data), "base_head": baseline["base_head"]}


def load_baseline(root: Path, ctx: dict[str, Any]) -> tuple[dict[str, Any], bytes]:
    raw = ctx["manifest"]["baseline_path"]
    baseline, data = load_repo_json(root, raw, "task baseline")
    if set(baseline) != BASELINE_KEYS:
        raise BundleError("baseline has an invalid top-level schema")
    if (
        type(baseline.get("schema_version")) is not int
        or baseline.get("schema_version") != SCHEMA_VERSION
        or baseline.get("kind") != BASELINE_KIND
    ):
        raise BundleError("baseline schema/kind is invalid")
    if baseline.get("task_id") != ctx["manifest"].get("task_id"):
        raise BundleError("baseline task ID does not match packet")
    if baseline.get("allowed_paths") != ctx["allowed_paths"]:
        raise BundleError("allowed_paths changed after baseline")
    if baseline.get("contract_fingerprint") != ctx["contract_fingerprint"]:
        raise BundleError("task contract changed after baseline; re-admission is required")
    return baseline, data


def head_file_record(root: Path, raw: str, tracked: set[str]) -> dict[str, Any]:
    """Return the immutable HEAD-side record for one admitted material path."""
    if raw not in tracked:
        return {"state": "missing", "tracked": False}
    tree = run_git(root, ["ls-tree", "-z", "HEAD", "--", raw])
    entries = [entry for entry in tree.split(b"\0") if entry]
    if len(entries) != 1 or b"\t" not in entries[0]:
        raise BundleError(f"cannot resolve one HEAD file for admitted path: {raw}")
    metadata, encoded_path = entries[0].split(b"\t", 1)
    try:
        mode_raw, object_type, object_id = metadata.decode("ascii").split(" ")
        tree_path = encoded_path.decode("utf-8", errors="strict")
    except (UnicodeError, ValueError) as exc:
        raise BundleError(f"HEAD metadata is malformed for admitted path: {raw}") from exc
    if tree_path != raw or object_type != "blob" or mode_raw not in {"100644", "100755"}:
        raise BundleError(f"admitted material path is not a regular HEAD file: {raw}")
    data = run_git(root, ["cat-file", "blob", object_id])
    return {
        "state": "file",
        "tracked": True,
        "size": len(data),
        "mode": 0o755 if mode_raw == "100755" else 0o644,
        "sha256": sha256_bytes(data),
    }


def verify_loaded_baseline(
    root: Path,
    ctx: dict[str, Any],
    baseline: dict[str, Any],
    baseline_bytes: bytes,
    expected_sha256: str,
    expected_head: str,
    expected_contract_sha256: str,
) -> dict[str, Any]:
    status = ctx["manifest"].get("status")
    if status not in {"in_progress", "blocked", "completed"}:
        raise BundleError(
            "baseline verification requires in_progress, blocked, or completed state"
        )
    require_external_contract(ctx, expected_contract_sha256)
    admitted_head = require_external_admitted_head(root, ctx, expected_head)
    identity = sha256_bytes(baseline_bytes)
    if (
        not isinstance(expected_sha256, str)
        or len(expected_sha256) != 64
        or any(character not in "0123456789abcdef" for character in expected_sha256)
    ):
        raise BundleError("an external expected baseline SHA-256 receipt is required")
    if expected_sha256 != identity:
        raise BundleError("baseline bytes differ from the external pre-edit receipt")
    packet_pin = ctx["manifest"].get("baseline_sha256")
    roadmap_pin = ctx["task"].get("baseline_sha256")
    if packet_pin != roadmap_pin:
        raise BundleError("packet and roadmap baseline_sha256 pins differ")
    if (
        not isinstance(packet_pin, str)
        or len(packet_pin) != 64
        or any(character not in "0123456789abcdef" for character in packet_pin)
    ):
        raise BundleError("baseline_sha256 must be a pinned lowercase SHA-256 identity")
    if packet_pin != identity:
        raise BundleError("current baseline bytes differ from the pinned baseline_sha256")
    expected_lists = {
        "state_paths": ctx["state_paths"],
        "material_paths": ctx["material_paths"],
        "protected_paths": ctx["protected_paths"],
    }
    for key, expected in expected_lists.items():
        if baseline.get(key) != expected:
            raise BundleError(f"baseline {key} differs from the current admitted contract")
    if baseline.get("audit_sha256") != ctx["roadmap"].get("audit_sha256"):
        raise BundleError("baseline audit identity differs from the current roadmap")
    if baseline.get("roadmap_fingerprint") != ctx["roadmap_fingerprint"]:
        raise BundleError("roadmap material changed after baseline")
    if admitted_head != baseline.get("base_head"):
        raise BundleError("HEAD changed after baseline; this local-edit task must be re-admitted")
    if git_branch(root) != baseline.get("branch") or git_upstream(root) != baseline.get(
        "upstream"
    ):
        raise BundleError("branch or upstream changed after baseline")

    controlled = baseline.get("controlled_files")
    expected_controlled = controlled_paths(ctx)
    if not isinstance(controlled, dict) or set(controlled) != set(expected_controlled):
        raise BundleError("baseline controlled-file inventory is incomplete or stale")
    tracked = tracked_paths(root)
    for raw in ctx["material_paths"]:
        if controlled.get(raw) != head_file_record(root, raw, tracked):
            raise BundleError(f"baseline material record does not match HEAD: {raw}")

    assert_no_staged_changes(root)
    assert_no_index_hiding(root)
    status_map = git_status(root)
    current_workspace = workspace_snapshot(
        root,
        status_map,
        set(ctx["protected_paths"]),
        tracked,
        readable_paths(ctx),
    )
    assert_out_of_scope_unchanged(ctx, baseline, current_workspace)
    allowed = set(ctx["allowed_paths"])
    for raw, before in controlled.items():
        if not isinstance(before, dict):
            raise BundleError(f"baseline file record is invalid: {raw}")
        if raw not in allowed and file_record(root, raw, tracked) != before:
            raise BundleError(f"out-of-scope controlled file changed after baseline: {raw}")
    if git_status(root) != status_map:
        raise BundleError("workspace changed while the baseline was being verified")
    return {
        "path": ctx["manifest"]["baseline_path"],
        "sha256": identity,
        "base_head": baseline["base_head"],
    }


def verify_baseline(
    root: Path,
    task_id: str,
    expected_sha256: str,
    expected_head: str,
    expected_contract_sha256: str,
) -> dict[str, Any]:
    ctx = context(root, task_id)
    baseline, baseline_bytes = load_baseline(root, ctx)
    return verify_loaded_baseline(
        root,
        ctx,
        baseline,
        baseline_bytes,
        expected_sha256,
        expected_head,
        expected_contract_sha256,
    )


def material_patch(root: Path, material_paths: list[str], tracked: set[str]) -> bytes:
    tracked_material = [raw for raw in material_paths if raw in tracked]
    if not tracked_material:
        return b""
    return run_git(
        root,
        [
            "diff",
            "HEAD",
            "--binary",
            "--full-index",
            "--no-renames",
            "--no-ext-diff",
            "--no-textconv",
            "--no-color",
            "--",
            *tracked_material,
        ],
    )


def whole_tracked_patch(root: Path, allowed_paths: set[str]) -> tuple[bytes, list[str]]:
    names = run_git(
        root,
        ["diff", "HEAD", "--name-only", "-z", "--no-renames", "--"],
    )
    changed = sorted(
        item.decode("utf-8", errors="strict")
        for item in names.split(b"\0")
        if item
    )
    outside = sorted(set(changed) - allowed_paths)
    if outside:
        raise BundleError("tracked out-of-scope paths changed: " + ", ".join(outside))
    patch = run_git(
        root,
        [
            "diff",
            "HEAD",
            "--binary",
            "--full-index",
            "--no-renames",
            "--no-ext-diff",
            "--no-textconv",
            "--no-color",
            "--",
        ],
    )
    return patch, changed


def freeze_bundle(
    root: Path,
    task_id: str,
    expected_baseline_sha256: str,
    expected_head: str,
    expected_contract_sha256: str,
) -> dict[str, Any]:
    ctx = context(root, task_id)
    if ctx["manifest"].get("status") != "in_progress":
        raise BundleError("freeze requires packet and roadmap status in_progress")
    if ctx["manifest"].get("completion_bundle_sha256") is not None or ctx["task"].get(
        "completion_bundle_sha256"
    ) is not None:
        raise BundleError("freeze requires null completion bundle pins")
    baseline, baseline_bytes = load_baseline(root, ctx)
    verify_loaded_baseline(
        root,
        ctx,
        baseline,
        baseline_bytes,
        expected_baseline_sha256,
        expected_head,
        expected_contract_sha256,
    )

    evidence, evidence_bytes = validate_pre_review_evidence(ctx)
    review_path = safe_path(root, ctx["manifest"]["review_path"], "review_path")
    if review_path.exists():
        raise BundleError("review record must not exist before the bundle is frozen")
    exec_plan_raw = ctx["manifest"]["exec_plan_path"]
    exec_plan_path = safe_path(root, exec_plan_raw, "exec_plan_path", allow_missing=False)
    exec_plan_bytes = read_bounded(exec_plan_path, "ExecPlan")
    try:
        exec_plan_text = exec_plan_bytes.decode("utf-8")
    except UnicodeError as exc:
        raise BundleError("ExecPlan is not UTF-8") from exc

    assert_no_staged_changes(root)
    tracked = tracked_paths(root)
    status_map = git_status(root)
    current_workspace = workspace_snapshot(
        root,
        status_map,
        set(ctx["protected_paths"]),
        tracked,
        readable_paths(ctx),
    )
    assert_out_of_scope_unchanged(ctx, baseline, current_workspace)

    baseline_controlled = baseline.get("controlled_files")
    if not isinstance(baseline_controlled, dict):
        raise BundleError("baseline controlled_files is missing")
    allowed = set(ctx["allowed_paths"])
    for raw, before in baseline_controlled.items():
        if raw not in allowed and file_record(root, raw, tracked) != before:
            raise BundleError(f"out-of-scope controlled file changed after baseline: {raw}")

    bundle_raw = ctx["manifest"]["review_bundle_path"]
    changed_files: dict[str, Any] = {}
    final_records: dict[str, Any] = {}
    for raw in ctx["allowed_paths"]:
        if raw == bundle_raw:
            continue
        final = file_record(root, raw, tracked)
        before = baseline_controlled.get(raw, {"state": "missing", "tracked": raw in tracked})
        final_records[raw] = final
        if final != before:
            changed_files[raw] = {
                "baseline": before,
                "final": file_record_with_content(root, raw, tracked),
            }

    changed_material = sorted(set(changed_files) & set(ctx["material_paths"]))
    if not changed_material:
        raise BundleError("no admitted material product/test path changed since baseline")

    patch = material_patch(root, ctx["material_paths"], tracked)
    whole_patch, tracked_changed_paths = whole_tracked_patch(root, allowed)
    bundle = {
        "schema_version": SCHEMA_VERSION,
        "kind": BUNDLE_KIND,
        "task_id": task_id,
        "base_head": baseline["base_head"],
        "current_head": git_head(root),
        "branch": git_branch(root),
        "upstream": git_upstream(root),
        "baseline_path": ctx["manifest"]["baseline_path"],
        "baseline_sha256": sha256_bytes(baseline_bytes),
        "baseline_content_base64": base64.b64encode(baseline_bytes).decode("ascii"),
        "self_path": bundle_raw,
        "contract": ctx["contract"],
        "contract_fingerprint": ctx["contract_fingerprint"],
        "roadmap_fingerprint": ctx["roadmap_fingerprint"],
        "manifest_pre_review_base64": base64.b64encode(ctx["manifest_bytes"]).decode(
            "ascii"
        ),
        "manifest_pre_review_sha256": sha256_bytes(ctx["manifest_bytes"]),
        "roadmap_pre_review_base64": base64.b64encode(ctx["roadmap_bytes"]).decode(
            "ascii"
        ),
        "roadmap_pre_review_sha256": sha256_bytes(ctx["roadmap_bytes"]),
        "exec_plan_pre_review_base64": base64.b64encode(exec_plan_bytes).decode("ascii"),
        "exec_plan_pre_review_sha256": sha256_bytes(exec_plan_bytes),
        "exec_plan_immutable_sha256": sha256_bytes(
            exec_plan_immutable_projection(exec_plan_text).encode("utf-8")
        ),
        "evidence_pre_review_base64": base64.b64encode(evidence_bytes).decode("ascii"),
        "evidence_projection": evidence_projection(evidence),
        "evidence_projection_sha256": sha256_bytes(
            canonical_json(evidence_projection(evidence))
        ),
        "evidence_pre_review_sha256": sha256_bytes(evidence_bytes),
        "allowed_paths": ctx["allowed_paths"],
        "state_paths": ctx["state_paths"],
        "material_paths": ctx["material_paths"],
        "final_snapshot": final_records,
        "material_snapshot": {
            raw: final_records[raw] for raw in ctx["material_paths"]
        },
        "changed_paths": sorted(changed_files),
        "changed_material_paths": changed_material,
        "changed_files": changed_files,
        "material_tracked_patch_base64": base64.b64encode(patch).decode("ascii"),
        "material_tracked_patch_sha256": sha256_bytes(patch),
        "whole_tracked_changed_paths": tracked_changed_paths,
        "whole_tracked_patch_base64": base64.b64encode(whole_patch).decode("ascii"),
        "whole_tracked_patch_sha256": sha256_bytes(whole_patch),
        "review_identity_rule": "SHA-256 of the exact canonical bundle file bytes; no embedded self-hash",
        "post_review_mutability": post_review_policy(ctx, task_id),
    }
    current_manifest = read_bounded(
        safe_path(root, ctx["packet_path"], "task packet", allow_missing=False),
        "task packet",
    )
    current_roadmap = read_bounded(
        safe_path(
            root,
            "docs/implementation/ROADMAP.json",
            "ROADMAP.json",
            allow_missing=False,
        ),
        "ROADMAP.json",
    )
    if (
        current_manifest != ctx["manifest_bytes"]
        or current_roadmap != ctx["roadmap_bytes"]
        or read_bounded(exec_plan_path, "ExecPlan") != exec_plan_bytes
        or read_bounded(
            safe_path(
                root,
                ctx["manifest"]["evidence_path"],
                "pre-review evidence",
                allow_missing=False,
            ),
            "pre-review evidence",
        )
        != evidence_bytes
    ):
        raise BundleError("pre-review state changed while the bundle was being constructed")
    if git_status(root) != status_map:
        raise BundleError("workspace changed while the review bundle was being constructed")
    data = canonical_json(bundle)
    output = safe_path(root, bundle_raw, "review_bundle_path")
    exclusive_atomic_create(output, data)
    return {
        "path": bundle_raw,
        "sha256": sha256_bytes(data),
        "changed_paths": bundle["changed_paths"],
        "changed_material_paths": changed_material,
    }


def strict_json_equal(left: Any, right: Any) -> bool:
    return canonical_json(left) == canonical_json(right)


def validate_snapshot_record(
    record: Any, label: str, *, content_required: bool = False
) -> bytes | None:
    if not isinstance(record, dict):
        raise BundleError(f"{label} must be an object")
    state = record.get("state")
    if state == "missing":
        if set(record) != {"state", "tracked"} or type(record.get("tracked")) is not bool:
            raise BundleError(f"{label} missing record schema is invalid")
        return None
    expected = {"state", "tracked", "size", "mode", "sha256"}
    if content_required:
        expected.add("content_base64")
    if state != "file" or set(record) != expected:
        raise BundleError(f"{label} file record schema is invalid")
    if type(record.get("tracked")) is not bool:
        raise BundleError(f"{label}.tracked must be boolean")
    if type(record.get("size")) is not int or record["size"] < 0:
        raise BundleError(f"{label}.size must be a non-negative integer")
    if (
        type(record.get("mode")) is not int
        or record["mode"] < 0
        or record["mode"] > 0o777
    ):
        raise BundleError(f"{label}.mode must be a permission-bit integer")
    digest = record.get("sha256")
    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
    ):
        raise BundleError(f"{label}.sha256 is invalid")
    if not content_required:
        return None
    encoded = record.get("content_base64")
    if not isinstance(encoded, str):
        raise BundleError(f"{label}.content_base64 is missing")
    try:
        data = base64.b64decode(encoded, validate=True)
    except ValueError as exc:
        raise BundleError(f"{label}.content_base64 is invalid") from exc
    if len(data) != record["size"] or sha256_bytes(data) != digest:
        raise BundleError(f"{label} content/size/hash disagree")
    return data


def record_for_bytes(template: dict[str, Any], data: bytes) -> dict[str, Any]:
    return {
        "state": "file",
        "tracked": template.get("tracked"),
        "size": len(data),
        "mode": template.get("mode"),
        "sha256": sha256_bytes(data),
    }


def verify_bundle(
    root: Path,
    task_id: str,
    expected_baseline_sha256: str | None,
    expected_head: str | None,
    expected_contract_sha256: str | None,
    *,
    historical: bool = False,
) -> dict[str, Any]:
    ctx = context(root, task_id)
    baseline, baseline_bytes = load_baseline(root, ctx)
    baseline_identity = sha256_bytes(baseline_bytes)
    if baseline_bytes != canonical_json(baseline):
        raise BundleError("task baseline is not canonical JSON")
    if historical:
        if (
            ctx["manifest"].get("baseline_sha256") != baseline_identity
            or ctx["task"].get("baseline_sha256") != baseline_identity
        ):
            raise BundleError("historical baseline bytes differ from packet/roadmap pin")
    else:
        verify_loaded_baseline(
            root,
            ctx,
            baseline,
            baseline_bytes,
            expected_baseline_sha256,
            expected_head,
            expected_contract_sha256,
        )

    bundle_raw = ctx["manifest"]["review_bundle_path"]
    bundle, bundle_bytes = load_repo_json(root, bundle_raw, "review bundle")
    if bundle_bytes != canonical_json(bundle):
        raise BundleError("review bundle is not canonical JSON")
    if set(bundle) != BUNDLE_KEYS:
        raise BundleError("review bundle has an invalid top-level schema")
    if (
        type(bundle.get("schema_version")) is not int
        or bundle.get("schema_version") != SCHEMA_VERSION
        or bundle.get("kind") != BUNDLE_KIND
    ):
        raise BundleError("review bundle schema/kind is invalid")
    if bundle.get("task_id") != task_id or bundle.get("self_path") != bundle_raw:
        raise BundleError("review bundle identity/path does not match task packet")
    if bundle.get("baseline_path") != ctx["manifest"]["baseline_path"]:
        raise BundleError("review bundle baseline_path differs from the packet")
    if bundle.get("baseline_sha256") != baseline_identity or bundle.get(
        "baseline_content_base64"
    ) != base64.b64encode(baseline_bytes).decode("ascii"):
        raise BundleError("review bundle baseline content/hash disagree")
    if bundle.get("base_head") != baseline.get("base_head") or bundle.get(
        "current_head"
    ) != baseline.get("base_head"):
        raise BundleError("review bundle HEAD identity differs from the baseline")
    if bundle.get("branch") != baseline.get("branch") or bundle.get(
        "upstream"
    ) != baseline.get("upstream"):
        raise BundleError("review bundle branch/upstream differs from the baseline")
    if bundle.get("contract_fingerprint") != ctx["contract_fingerprint"] or not strict_json_equal(
        bundle.get("contract"), ctx["contract"]
    ):
        raise BundleError("task contract differs from the reviewed bundle")
    if bundle.get("allowed_paths") != ctx["allowed_paths"]:
        raise BundleError("allowed_paths differ from the reviewed bundle")
    if bundle.get("state_paths") != ctx["state_paths"] or bundle.get(
        "material_paths"
    ) != ctx["material_paths"]:
        raise BundleError("review bundle state/material path inventories differ from packet")
    if bundle.get("review_identity_rule") != (
        "SHA-256 of the exact canonical bundle file bytes; no embedded self-hash"
    ):
        raise BundleError("review bundle identity rule is invalid")
    if not strict_json_equal(
        bundle.get("post_review_mutability"), post_review_policy(ctx, task_id)
    ):
        raise BundleError("review bundle post-review mutability policy is invalid")

    manifest_pre_bytes = decode_bundle_blob(
        bundle, "manifest_pre_review", "pre-review manifest"
    )
    roadmap_pre_bytes = decode_bundle_blob(
        bundle, "roadmap_pre_review", "pre-review roadmap"
    )
    exec_plan_pre_bytes = decode_bundle_blob(
        bundle, "exec_plan_pre_review", "pre-review ExecPlan"
    )
    evidence_pre_bytes = decode_bundle_blob(
        bundle, "evidence_pre_review", "pre-review evidence"
    )
    manifest_pre = json_load_bytes(manifest_pre_bytes, "bundled pre-review manifest")
    roadmap_pre = json_load_bytes(roadmap_pre_bytes, "bundled pre-review roadmap")
    evidence_pre = json_load_bytes(evidence_pre_bytes, "bundled pre-review evidence")
    if (
        manifest_pre.get("task_id") != task_id
        or manifest_pre.get("status") != "in_progress"
        or manifest_pre.get("completion_bundle_sha256") is not None
    ):
        raise BundleError("bundled pre-review manifest identity/state is invalid")
    if manifest_pre.get("baseline_sha256") != baseline_identity or manifest_pre.get(
        "admitted_head"
    ) != baseline.get("base_head"):
        raise BundleError("bundled pre-review manifest receipt identities are invalid")
    if not strict_json_equal(contract_projection(manifest_pre), bundle.get("contract")):
        raise BundleError("bundled pre-review manifest differs from contract snapshot")
    pre_projection = roadmap_projection(roadmap_pre, task_id)
    if bundle.get("roadmap_fingerprint") != sha256_bytes(canonical_json(pre_projection)):
        raise BundleError("bundled pre-review roadmap fingerprint is invalid")
    pre_tasks = roadmap_pre.get("tasks")
    pre_matches = (
        [item for item in pre_tasks if isinstance(item, dict) and item.get("task_id") == task_id]
        if isinstance(pre_tasks, list)
        else []
    )
    if (
        len(pre_matches) != 1
        or pre_matches[0].get("status") != "in_progress"
        or pre_matches[0].get("baseline_sha256") != baseline_identity
        or pre_matches[0].get("completion_bundle_sha256") is not None
        or pre_matches[0].get("admitted_head") != baseline.get("base_head")
        or roadmap_pre.get("active_task") != task_id
    ):
        raise BundleError("bundled pre-review roadmap task state is invalid")
    try:
        exec_plan_pre_text = exec_plan_pre_bytes.decode("utf-8")
    except UnicodeError as exc:
        raise BundleError("bundled pre-review ExecPlan is not UTF-8") from exc
    if bundle.get("exec_plan_immutable_sha256") != sha256_bytes(
        exec_plan_immutable_projection(exec_plan_pre_text).encode("utf-8")
    ):
        raise BundleError("bundled pre-review ExecPlan projection is invalid")
    historical_protected = roadmap_pre.get("protected_dirty_paths")
    if not isinstance(historical_protected, list) or historical_protected != baseline.get(
        "protected_paths"
    ):
        raise BundleError(
            "bundled pre-review protected paths differ from the immutable baseline"
        )
    validate_pre_review_evidence_value(
        ctx, evidence_pre, protected_paths=historical_protected
    )
    pre_evidence_projection = evidence_projection(evidence_pre)
    if not strict_json_equal(bundle.get("evidence_projection"), pre_evidence_projection) or bundle.get(
        "evidence_projection_sha256"
    ) != sha256_bytes(canonical_json(pre_evidence_projection)):
        raise BundleError("bundled pre-review evidence projection is invalid")

    baseline_controlled = baseline.get("controlled_files")
    if not isinstance(baseline_controlled, dict):
        raise BundleError("baseline controlled_files is missing")
    final_snapshot = bundle.get("final_snapshot")
    snapshot_paths = set(ctx["allowed_paths"]) - {bundle_raw}
    if not snapshot_paths.issubset(baseline_controlled):
        raise BundleError("baseline omits an allowed pre-review path")
    for raw in snapshot_paths:
        validate_snapshot_record(
            baseline_controlled[raw], f"baseline controlled_files[{raw}]"
        )
    if not isinstance(final_snapshot, dict) or set(final_snapshot) != snapshot_paths:
        raise BundleError("review bundle final_snapshot inventory is incomplete or stale")
    for raw, record in final_snapshot.items():
        validate_snapshot_record(record, f"final_snapshot[{raw}]")
    material_snapshot = bundle.get("material_snapshot")
    expected_material_snapshot = {
        raw: final_snapshot[raw] for raw in ctx["material_paths"]
    }
    if not isinstance(material_snapshot, dict) or not strict_json_equal(
        material_snapshot, expected_material_snapshot
    ):
        raise BundleError("review bundle material_snapshot is invalid")
    expected_changed = sorted(
        raw
        for raw, final in final_snapshot.items()
        if not strict_json_equal(
            final,
            baseline_controlled[raw],
        )
    )
    expected_changed_material = sorted(set(expected_changed) & set(ctx["material_paths"]))
    if not expected_changed_material:
        raise BundleError("review bundle contains no admitted material product/test change")
    if bundle.get("changed_paths") != expected_changed or bundle.get(
        "changed_material_paths"
    ) != expected_changed_material:
        raise BundleError("review bundle changed path inventories are incomplete or stale")
    changed_files = bundle.get("changed_files")
    if not isinstance(changed_files, dict) or set(changed_files) != set(expected_changed):
        raise BundleError("review bundle changed_files inventory is incomplete or stale")
    for raw in expected_changed:
        record = changed_files.get(raw)
        if not isinstance(record, dict) or set(record) != {"baseline", "final"}:
            raise BundleError(f"changed file record schema is invalid: {raw}")
        expected_before = baseline_controlled[raw]
        if not strict_json_equal(record["baseline"], expected_before):
            raise BundleError(f"changed file baseline record disagrees: {raw}")
        validate_snapshot_record(record["baseline"], f"changed_files[{raw}].baseline")
        content = validate_snapshot_record(
            record["final"], f"changed_files[{raw}].final", content_required=True
        )
        final_without_content = {
            key: value for key, value in record["final"].items() if key != "content_base64"
        }
        if not strict_json_equal(final_without_content, final_snapshot[raw]):
            raise BundleError(f"changed file final record disagrees with snapshot: {raw}")
        if content is not None and not strict_json_equal(
            record_for_bytes(final_snapshot[raw], content), final_snapshot[raw]
        ):
            raise BundleError(f"changed file bytes disagree with final snapshot: {raw}")

    explicit_state_bytes = {
        ctx["packet_path"]: manifest_pre_bytes,
        "docs/implementation/ROADMAP.json": roadmap_pre_bytes,
        ctx["manifest"]["exec_plan_path"]: exec_plan_pre_bytes,
        ctx["manifest"]["evidence_path"]: evidence_pre_bytes,
        ctx["manifest"]["baseline_path"]: baseline_bytes,
    }
    for raw, data in explicit_state_bytes.items():
        snapshot = final_snapshot.get(raw)
        if not isinstance(snapshot, dict) or not strict_json_equal(
            record_for_bytes(snapshot, data), snapshot
        ):
            raise BundleError(f"explicit bundled state bytes disagree with snapshot: {raw}")

    material_patch_bytes = decode_bundle_blob(
        bundle, "material_tracked_patch", "tracked material patch"
    )
    whole_patch_bytes = decode_bundle_blob(bundle, "whole_tracked_patch", "whole tracked patch")
    tracked_changed_paths = bundle.get("whole_tracked_changed_paths")
    if not isinstance(tracked_changed_paths, list) or any(
        not isinstance(raw, str) or raw not in ctx["allowed_paths"]
        for raw in tracked_changed_paths
    ):
        raise BundleError("review bundle whole tracked path inventory is invalid")

    current_exec_plan = read_bounded(
        safe_path(
            root,
            ctx["manifest"]["exec_plan_path"],
            "ExecPlan",
            allow_missing=False,
        ),
        "ExecPlan",
    ).decode("utf-8")
    if sha256_bytes(exec_plan_immutable_projection(current_exec_plan).encode("utf-8")) != bundle.get(
        "exec_plan_immutable_sha256"
    ):
        raise BundleError("immutable ExecPlan sections changed after review freeze")
    current_evidence, _ = load_repo_json(
        root, ctx["manifest"]["evidence_path"], "task evidence"
    )
    if not strict_json_equal(
        evidence_projection(current_evidence), pre_evidence_projection
    ):
        raise BundleError("pre-review acceptance/gate evidence changed after freeze")

    if not historical:
        if git_head(root) != bundle.get("current_head") or git_branch(root) != bundle.get(
            "branch"
        ) or git_upstream(root) != bundle.get("upstream"):
            raise BundleError("current repository identity differs from the review freeze")
        tracked = tracked_paths(root)
        assert_no_staged_changes(root)
        assert_no_index_hiding(root)
        status_map = git_status(root)
        current_workspace = workspace_snapshot(
            root,
            status_map,
            set(ctx["protected_paths"]),
            tracked,
            readable_paths(ctx),
        )
        assert_out_of_scope_unchanged(ctx, baseline, current_workspace)
        current_material = {
            raw: file_record(root, raw, tracked) for raw in ctx["material_paths"]
        }
        if not strict_json_equal(current_material, expected_material_snapshot):
            raise BundleError("material paths changed after review freeze")
        if material_patch(root, ctx["material_paths"], tracked) != material_patch_bytes:
            raise BundleError("tracked material patch changed after review freeze")
        review_exists = safe_path(
            root, ctx["manifest"]["review_path"], "review_path"
        ).is_file()
        if ctx["manifest"].get("status") == "in_progress" and not review_exists:
            current_snapshot = {
                raw: file_record(root, raw, tracked) for raw in snapshot_paths
            }
            if not strict_json_equal(current_snapshot, final_snapshot):
                raise BundleError("allowed state/material files differ from review freeze")
            whole_patch, current_changed = whole_tracked_patch(
                root, set(ctx["allowed_paths"])
            )
            if whole_patch != whole_patch_bytes or current_changed != tracked_changed_paths:
                raise BundleError("whole tracked patch/inventory differs from review freeze")

    identity = sha256_bytes(bundle_bytes)
    for key in ("evidence_path", "review_path"):
        raw = ctx["manifest"][key]
        path = safe_path(root, raw, key)
        if not path.exists():
            continue
        record, _ = load_repo_json(root, raw, key)
        recorded = record.get("reviewed_identity")
        if recorded is not None and recorded != identity:
            raise BundleError(f"{key} reviewed_identity does not match bundle SHA-256")

    return {
        "path": bundle_raw,
        "sha256": identity,
        "baseline_sha256": baseline_identity,
        "base_head": bundle.get("base_head"),
        "changed_paths": bundle.get("changed_paths", []),
        "changed_material_paths": bundle.get("changed_material_paths", []),
    }


def verify_historical_bundle(root: Path, task_id: str) -> dict[str, Any]:
    return verify_bundle(root, task_id, None, None, None, historical=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command",
        choices=("fingerprint", "baseline", "verify-baseline", "freeze", "verify"),
    )
    parser.add_argument("--task", required=True, help="one admitted task ID, for example T001")
    parser.add_argument(
        "--expected-baseline-sha256",
        help="external pre-edit baseline receipt (required after baseline creation)",
    )
    parser.add_argument(
        "--expected-head",
        help="external admitted HEAD receipt (required for every artifact command)",
    )
    parser.add_argument(
        "--expected-contract-sha256",
        help="external admission contract receipt (required for every artifact command)",
    )
    parser.add_argument("--root", type=Path, help="repository root (auto-detected by default)")
    parser.add_argument("--json", action="store_true", help="emit machine-readable output")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        root = args.root.resolve() if args.root else find_repo_root(Path.cwd().resolve())
        if args.command == "fingerprint":
            if any(
                value is not None
                for value in (
                    args.expected_baseline_sha256,
                    args.expected_head,
                    args.expected_contract_sha256,
                )
            ):
                raise BundleError("fingerprint does not accept external receipt arguments")
            result = fingerprint_task_contract(root, args.task)
        elif args.command == "baseline":
            if args.expected_baseline_sha256 is not None:
                raise BundleError("baseline creation does not accept an expected receipt")
            result = make_baseline(
                root,
                args.task,
                args.expected_head,
                args.expected_contract_sha256,
            )
        elif args.command == "verify-baseline":
            result = verify_baseline(
                root,
                args.task,
                args.expected_baseline_sha256,
                args.expected_head,
                args.expected_contract_sha256,
            )
        elif args.command == "freeze":
            result = freeze_bundle(
                root,
                args.task,
                args.expected_baseline_sha256,
                args.expected_head,
                args.expected_contract_sha256,
            )
        else:
            result = verify_bundle(
                root,
                args.task,
                args.expected_baseline_sha256,
                args.expected_head,
                args.expected_contract_sha256,
            )
    except (
        BundleError,
        KeyError,
        OSError,
        OverflowError,
        RecursionError,
        RuntimeError,
        TypeError,
        UnicodeError,
        ValueError,
    ) as exc:
        failure = {"ok": False, "command": args.command, "task_id": args.task, "errors": [str(exc)]}
        if args.json:
            print(json.dumps(failure, indent=2, sort_keys=True))
        else:
            print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    output = {"ok": True, "command": args.command, "task_id": args.task, **result}
    if args.json:
        print(json.dumps(output, indent=2, sort_keys=True))
    else:
        print(f"{args.command} OK for {args.task}: {result['sha256']}")
        if "changed_paths" in result:
            print("Changed paths: " + ", ".join(result["changed_paths"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
