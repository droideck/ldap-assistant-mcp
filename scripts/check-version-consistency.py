#!/usr/bin/env python3
"""Check that every version declaration in the repo agrees.

Compared (all must match):
  - pyproject.toml   [project].version  (baseline when no --tag is given)
  - uv.lock          the "ldap-assistant-mcp" package entry
  - server.json      top-level "version" AND every packages[*].version
  - CHANGELOG.md     the first release heading of the form "## [X.Y.Z] - ..."
  - the git tag      when --tag vX.Y.Z is passed (CI passes $GITHUB_REF_NAME)

Also compares (warning only, never fatal): the fastmcp constraint in
fastmcp.json vs pyproject.toml — these are allowed to differ but drift is
worth seeing at release time.

Usage:
  python3 scripts/check-version-consistency.py [--tag vX.Y.Z]

Exit status: 0 when all versions agree, 1 otherwise (every mismatched file
is named). Dependency-free: needs only Python 3.11+ (tomllib is stdlib).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PROJECT_NAME = "ldap-assistant-mcp"


def read_pyproject_version() -> str | None:
    path = REPO_ROOT / "pyproject.toml"
    with open(path, "rb") as f:
        data = tomllib.load(f)
    return data.get("project", {}).get("version")


def read_uv_lock_version() -> str | None:
    path = REPO_ROOT / "uv.lock"
    with open(path, "rb") as f:
        data = tomllib.load(f)
    for pkg in data.get("package", []):
        if pkg.get("name") == PROJECT_NAME:
            return pkg.get("version")
    return None


def read_server_json_versions() -> list[tuple[str, str | None]]:
    path = REPO_ROOT / "server.json"
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    found: list[tuple[str, str | None]] = [
        ("server.json .version", data.get("version")),
    ]
    for i, pkg in enumerate(data.get("packages", [])):
        found.append((f"server.json .packages[{i}].version", pkg.get("version")))
    return found


def read_changelog_version() -> str | None:
    path = REPO_ROOT / "CHANGELOG.md"
    text = path.read_text(encoding="utf-8")
    # First "## [<something>]" heading whose content starts with a digit
    # (skips an optional "[Unreleased]" section at the top).
    for match in re.finditer(r"^##\s*\[([^\]]+)\]", text, flags=re.MULTILINE):
        candidate = match.group(1).strip()
        if candidate and candidate[0].isdigit():
            return candidate
    return None


def fastmcp_constraint_from_pyproject() -> str | None:
    with open(REPO_ROOT / "pyproject.toml", "rb") as f:
        data = tomllib.load(f)
    for dep in data.get("project", {}).get("dependencies", []):
        if re.match(r"^fastmcp\b", dep.strip()):
            return dep.strip()
    return None


def fastmcp_constraint_from_fastmcp_json() -> str | None:
    path = REPO_ROOT / "fastmcp.json"
    if not path.is_file():
        return None
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    for dep in data.get("environment", {}).get("dependencies", []):
        if re.match(r"^fastmcp\b", str(dep).strip()):
            return str(dep).strip()
    return None


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify all repo version declarations agree."
    )
    parser.add_argument(
        "--tag",
        help="Git tag to validate against, e.g. v0.5.0 "
        "(in CI, pass \"$GITHUB_REF_NAME\")",
    )
    args = parser.parse_args()

    findings: list[tuple[str, str | None]] = []
    errors: list[str] = []

    tag_version: str | None = None
    if args.tag:
        m = re.fullmatch(r"v(\d.*)", args.tag.strip())
        if not m:
            print(
                f"ERROR: tag {args.tag!r} does not look like vX.Y.Z "
                "(must be 'v' followed by a version starting with a digit)",
                file=sys.stderr,
            )
            return 1
        tag_version = m.group(1)
        findings.append((f"git tag {args.tag}", tag_version))

    try:
        findings.append(("pyproject.toml [project].version", read_pyproject_version()))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        errors.append(f"pyproject.toml unreadable: {exc}")

    try:
        findings.append((f"uv.lock package {PROJECT_NAME!r}", read_uv_lock_version()))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        errors.append(f"uv.lock unreadable: {exc}")

    try:
        findings.extend(read_server_json_versions())
    except (OSError, json.JSONDecodeError) as exc:
        errors.append(f"server.json unreadable: {exc}")

    try:
        findings.append(("CHANGELOG.md top release heading", read_changelog_version()))
    except OSError as exc:
        errors.append(f"CHANGELOG.md unreadable: {exc}")

    pyproject_version = next(
        (v for label, v in findings if label.startswith("pyproject.toml")), None
    )
    expected = tag_version or pyproject_version
    if expected is None:
        errors.append(
            "could not determine an expected version "
            "(no --tag given and pyproject.toml has no [project].version)"
        )

    baseline = f"tag {args.tag}" if tag_version else "pyproject.toml"
    print(f"Version consistency check — expected {expected!r} (from {baseline})")

    mismatches: list[str] = []
    for label, value in findings:
        if value is None:
            mismatches.append(f"{label}: version NOT FOUND")
            print(f"  MISSING   {label}")
        elif expected is not None and value != expected:
            mismatches.append(f"{label}: {value} (expected {expected})")
            print(f"  MISMATCH  {label} = {value}")
        else:
            print(f"  OK        {label} = {value}")

    # Advisory only: fastmcp constraint drift between fastmcp.json and
    # pyproject.toml. Allowed to differ, but should be a conscious choice.
    py_fastmcp = fastmcp_constraint_from_pyproject()
    fj_fastmcp = fastmcp_constraint_from_fastmcp_json()
    if fj_fastmcp is not None and py_fastmcp != fj_fastmcp:
        print(
            f"  WARNING   fastmcp constraint drift (not fatal): "
            f"pyproject.toml has {py_fastmcp!r}, fastmcp.json has {fj_fastmcp!r}"
        )

    if errors or mismatches:
        print("", file=sys.stderr)
        for err in errors:
            print(f"ERROR: {err}", file=sys.stderr)
        if mismatches:
            print(
                f"ERROR: {len(mismatches)} version declaration(s) disagree "
                f"with {expected!r}:",
                file=sys.stderr,
            )
            for m_ in mismatches:
                print(f"  - {m_}", file=sys.stderr)
            print(
                "Fix the files above (and regenerate uv.lock with 'uv lock' "
                "if pyproject.toml changed) before tagging a release.",
                file=sys.stderr,
            )
        return 1

    print("All version declarations agree.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
