"""Unit tests for lib/result_formatter.py (IMPROVEMENT-PLAN 1.5.5)."""

from __future__ import annotations

from ldap_assistant_mcp.lib.result_formatter import Severity, format_finding


def test_severity_values():
    assert Severity.CRITICAL.value == "critical"
    assert Severity.HIGH.value == "high"
    assert Severity.MEDIUM.value == "medium"
    assert Severity.LOW.value == "low"
    assert Severity.INFO.value == "info"


def test_format_finding_required_fields():
    finding = format_finding(
        title="Replication Agreement Down",
        severity=Severity.CRITICAL,
        impact="Data is not replicating",
        details="Agreement down for 3 hours",
        remediation="Check connectivity",
    )
    assert finding == {
        "title": "Replication Agreement Down",
        "severity": "critical",
        "impact": "Data is not replicating",
        "details": "Agreement down for 3 hours",
        "remediation": "Check connectivity",
    }


def test_format_finding_severity_serialized_as_string():
    finding = format_finding(
        title="t", severity=Severity.LOW, impact="i", details="d", remediation="r"
    )
    assert isinstance(finding["severity"], str)
    assert finding["severity"] == "low"


def test_format_finding_with_server():
    finding = format_finding(
        title="t", severity=Severity.INFO, impact="i", details="d",
        remediation="r", server="ds-1",
    )
    assert finding["server"] == "ds-1"


def test_format_finding_omits_absent_optionals():
    finding = format_finding(
        title="t", severity=Severity.INFO, impact="i", details="d", remediation="r"
    )
    assert "server" not in finding
    assert "metadata" not in finding


def test_format_finding_with_metadata():
    meta = {"hit_ratio": 42.5, "tries": 10}
    finding = format_finding(
        title="t", severity=Severity.MEDIUM, impact="i", details="d",
        remediation="r", metadata=meta,
    )
    assert finding["metadata"] == meta


def test_format_finding_empty_metadata_omitted():
    finding = format_finding(
        title="t", severity=Severity.MEDIUM, impact="i", details="d",
        remediation="r", metadata={},
    )
    assert "metadata" not in finding
