"""Parse dsctl healthcheck output from SOS reports.

SOS reports may include ``sos_commands/dirsrv/dsctl_<inst>_healthcheck``
containing the output of ``dsctl <instance> healthcheck``.  This module
parses that output into a structured format compatible with the health
check findings model.

The text report format is produced by ``lib389.cli_ctl.health`` (see
``_format_check_output`` and ``_run``) and consists of multi-line blocks::

    [1] DS Lint Error: DSBLE0002
    --------------------------------------------------------------------------------
    Severity: HIGH
    Check: backends:userroot:search
    Affects:
     -- dc=example,dc=com

    Details:
    -----------
    Unable to query the backend.  LDAP error (Operations error)

    Resolution:
    -----------
    Check the server's error and access logs for more information.

    ===== End Of Report (1 Issue found) =====

A clean run instead prints the explicit phrase ``No issues found.``.
When ``dsctl`` is invoked with ``--json``, the output is a JSON array of
lint result dicts (``dsle``/``severity``/``check``/``items``/``detail``/
``fix``); that format is detected and parsed as well.

Content that is neither a recognizable report nor an explicit pass phrase
is reported with ``parse_status="unknown"`` and ``passed=False`` — never
as a passing healthcheck.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

# Finding header emitted by lib389.cli_ctl.health._format_check_output:
#   [1] DS Lint Error: DSBLE0002
_HEADER_RE = re.compile(r"^\[\d+\] DS Lint Error:\s*(?P<code>\S+)\s*$")

# Trailing summary:  ===== End Of Report (2 Issues found) =====
_END_OF_REPORT_RE = re.compile(r"^=+\s*End Of Report.*$")

# Count line printed before the report:  2 Issues found!  Generating report ...
_ISSUES_FOUND_RE = re.compile(r"^\d+\s+Issues?\s+found!", re.IGNORECASE)

# Dashed rule under "Details:" / "Resolution:" section headers (and the
# 80-dash rule under the finding header).
_RULE_RE = re.compile(r"^-{3,}$")

# Exact phrase printed by lib389.cli_ctl.health._run on a clean report:
#   "No issues found."
_PASS_PHRASES = ("no issues found",)


def parse_healthcheck_output(content: Optional[str]) -> Dict[str, Any]:
    """Parse the output of ``dsctl <instance> healthcheck``.

    Returns a dict with:
      - ``passed`` (bool): True only when the output contains an explicit
        pass phrase (or an empty ``--json`` report) and no findings.
      - ``parse_status`` (str): ``"passed"``, ``"findings"``, ``"empty"``,
        or ``"unknown"``.  Unrecognized content is reported as
        ``"unknown"``, never as passing.
      - ``findings`` (list[dict]): Each finding has ``code``, ``severity``,
        and ``description``, plus optional ``check``, ``affects``,
        ``details``, and ``resolution``.
      - ``total_findings`` (int): Number of findings.
      - ``raw_output`` (str): The original text.
    """
    if not content or not content.strip():
        return _result([], passed=False, status="empty", raw="")

    stripped = content.strip()

    json_findings = _parse_json_report(stripped)
    if json_findings is not None:
        if json_findings:
            return _result(json_findings, passed=False, status="findings", raw=stripped)
        # An empty JSON report ("[]") is only printed on a clean run.
        return _result([], passed=True, status="passed", raw=stripped)

    lines = stripped.splitlines()
    findings = _parse_text_findings(lines)
    if findings:
        return _result(findings, passed=False, status="findings", raw=stripped)

    # The report claimed issues ("N Issues found!") but no finding blocks
    # could be parsed (e.g. truncated output) — treat as a parse failure.
    if any(_ISSUES_FOUND_RE.match(line.strip()) for line in lines):
        return _result([], passed=False, status="unknown", raw=stripped)

    if any(_is_pass_line(line) for line in lines):
        return _result([], passed=True, status="passed", raw=stripped)

    # No findings and no explicit pass phrase: do not report success.
    return _result([], passed=False, status="unknown", raw=stripped)


def _result(
    findings: List[Dict[str, Any]], *, passed: bool, status: str, raw: str
) -> Dict[str, Any]:
    return {
        "passed": passed,
        "parse_status": status,
        "findings": findings,
        "total_findings": len(findings),
        "raw_output": raw,
    }


def _is_pass_line(line: str) -> bool:
    """Return True if the line is an explicit clean-healthcheck phrase."""
    lower = line.strip().lower()
    return any(phrase in lower for phrase in _PASS_PHRASES)


def _parse_json_report(stripped: str) -> Optional[List[Dict[str, Any]]]:
    """Parse ``dsctl --json healthcheck`` output (a JSON array of results).

    Returns None when the content is not a JSON healthcheck report (the
    caller then falls back to the text format).
    """
    if not stripped.startswith(("[", "{")):
        return None
    # The text report's finding header also starts with "[", so only
    # accept content that actually parses as JSON.
    try:
        parsed = json.loads(stripped)
    except ValueError:
        return None
    if not isinstance(parsed, list):
        return None
    if not all(
        isinstance(item, dict) and "dsle" in item and "severity" in item
        for item in parsed
    ):
        return None

    findings: List[Dict[str, Any]] = []
    for item in parsed:
        finding: Dict[str, Any] = {
            "code": str(item["dsle"]),
            "severity": str(item["severity"]).upper(),
        }
        check = item.get("check")
        if check:
            finding["check"] = str(check)
        items = item.get("items")
        if isinstance(items, list) and items:
            finding["affects"] = [str(i) for i in items]
        detail = item.get("detail")
        if detail:
            finding["details"] = str(detail).strip()
        fix = item.get("fix")
        if fix:
            finding["resolution"] = str(fix).strip()
        finding["description"] = _build_description(finding)
        findings.append(finding)
    return findings


def _parse_text_findings(lines: List[str]) -> List[Dict[str, Any]]:
    """Extract findings from the multi-line text report format."""
    header_indexes = [
        i for i, line in enumerate(lines) if _HEADER_RE.match(line.strip())
    ]
    findings: List[Dict[str, Any]] = []
    for n, start in enumerate(header_indexes):
        end = header_indexes[n + 1] if n + 1 < len(header_indexes) else len(lines)
        finding = _parse_finding_block(lines[start:end])
        if finding is not None:
            findings.append(finding)
    return findings


def _parse_finding_block(block: List[str]) -> Optional[Dict[str, Any]]:
    """Parse one ``[N] DS Lint Error: CODE`` block into a finding dict."""
    m = _HEADER_RE.match(block[0].strip())
    if not m:
        return None
    code = m.group("code")
    severity: Optional[str] = None
    check: Optional[str] = None
    affects: List[str] = []
    details_lines: List[str] = []
    resolution_lines: List[str] = []

    section = "head"
    expect_rule = False
    for raw in block[1:]:
        line = raw.rstrip()
        text = line.strip()
        if _END_OF_REPORT_RE.match(text):
            break
        if section in ("head", "affects"):
            if text.startswith("Severity:"):
                severity = text[len("Severity:"):].strip().upper()
                section = "head"
            elif text.startswith("Check:"):
                check = text[len("Check:"):].strip()
                section = "head"
            elif text == "Affects:":
                section = "affects"
            elif text == "Details:":
                section = "details"
                expect_rule = True
            elif section == "affects" and text.startswith("--"):
                affects.append(text[2:].strip())
            # Anything else in the head (the dashed rule under the header,
            # blank lines) is ignored.
        elif section == "details":
            if text == "Resolution:":
                section = "resolution"
                expect_rule = True
            elif expect_rule and _RULE_RE.match(text):
                expect_rule = False
            else:
                expect_rule = False
                details_lines.append(line)
        elif section == "resolution":
            if expect_rule and _RULE_RE.match(text):
                expect_rule = False
            else:
                expect_rule = False
                resolution_lines.append(line)

    finding: Dict[str, Any] = {
        "code": code,
        "severity": severity or "UNKNOWN",
    }
    if check:
        finding["check"] = check
    if affects:
        finding["affects"] = affects
    details = _join_block(details_lines)
    if details:
        finding["details"] = details
    resolution = _join_block(resolution_lines)
    if resolution:
        finding["resolution"] = resolution
    finding["description"] = _build_description(finding)
    return finding


def _join_block(lines: List[str]) -> Optional[str]:
    """Join section lines, trimming leading/trailing blank lines."""
    text = "\n".join(lines).strip()
    return text or None


def _build_description(finding: Dict[str, Any]) -> str:
    """Build a one-line description for backward compatibility.

    Prefers the first line of the detail text, then the check name,
    then the lint code.
    """
    details = finding.get("details")
    if details:
        first_line = details.splitlines()[0].strip()
        if first_line:
            return first_line
    check = finding.get("check")
    if check:
        return f"Check: {check}"
    return finding["code"]
