"""Parse dsctl healthcheck text output from SOS reports.

SOS reports may include ``sos_commands/dirsrv/dsctl_<inst>_healthcheck``
containing the text output of ``dsctl <instance> healthcheck``.  This
module parses that output into a structured format compatible with the
health check findings model.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

# Matches lines like:  DSBLE0001 : HIGH : Backend Backup : ...
_FINDING_RE = re.compile(
    r"^(?P<code>[A-Z]{2,10}\d{4})\s*:\s*(?P<severity>\w+)\s*:\s*(?P<description>.+)$"
)

_KNOWN_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "WARNING"}


def parse_healthcheck_output(content: str) -> Dict[str, Any]:
    """Parse the text output of ``dsctl <instance> healthcheck``.

    Returns a dict with:
      - ``passed`` (bool): True when no issues were found.
      - ``findings`` (list[dict]): Each finding has ``code``, ``severity``,
        ``description``, and optional ``details``.
      - ``raw_output`` (str): The original text.
    """
    if not content or not content.strip():
        return {"passed": True, "findings": [], "raw_output": ""}

    stripped = content.strip()
    findings: List[Dict[str, Any]] = []
    lines = stripped.splitlines()

    i = 0
    while i < len(lines):
        line = lines[i].strip()

        # Check for "no issues" / "passed" messages
        if _is_pass_line(line):
            i += 1
            continue

        m = _FINDING_RE.match(line)
        if m:
            raw_severity = m.group("severity").upper()
            severity = raw_severity if raw_severity in _KNOWN_SEVERITIES else "INFO"
            finding: Dict[str, Any] = {
                "code": m.group("code"),
                "severity": severity,
                "description": m.group("description").strip(),
            }
            # Collect multi-line detail block that follows
            detail_lines: List[str] = []
            i += 1
            while i < len(lines):
                detail = lines[i]
                # Stop at the next finding line or blank separator
                if _FINDING_RE.match(detail.strip()):
                    break
                if detail.strip():
                    detail_lines.append(detail.strip())
                else:
                    # Empty line may separate findings
                    # Peek ahead to see if next non-empty is a new finding
                    j = i + 1
                    while j < len(lines) and not lines[j].strip():
                        j += 1
                    if j < len(lines) and _FINDING_RE.match(lines[j].strip()):
                        i = j
                        break
                    if detail_lines:
                        detail_lines.append("")
                i += 1
            if detail_lines:
                # Strip trailing empty lines
                while detail_lines and not detail_lines[-1]:
                    detail_lines.pop()
                finding["details"] = "\n".join(detail_lines)
            findings.append(finding)
        else:
            i += 1

    passed = len(findings) == 0
    return {
        "passed": passed,
        "findings": findings,
        "raw_output": stripped,
    }


def _is_pass_line(line: str) -> bool:
    """Return True if the line indicates a clean healthcheck."""
    lower = line.lower()
    return any(phrase in lower for phrase in (
        "no issues found",
        "health check passed",
        "healthcheck passed",
        "no problems found",
        "all checks passed",
    ))
