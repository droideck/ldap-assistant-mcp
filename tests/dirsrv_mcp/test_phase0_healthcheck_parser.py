"""Phase 0 tests for the SOS healthcheck parser.

The parser previously matched a single-line ``CODE : SEVERITY : desc``
format that ``dsctl <inst> healthcheck`` never emits, so real findings
parsed as ``passed=True``.  These tests feed the REAL output format
produced by ``lib389.cli_ctl.health`` (``_run`` + ``_format_check_output``):

- multi-line ``[N] DS Lint Error: CODE`` blocks for findings,
- the explicit ``No issues found.`` phrase for a clean run,
- a JSON array of lint dicts in ``--json`` mode.

Unknown/garbage content must NOT be reported as passing.
"""

from __future__ import annotations

import json

from ldap_assistant_mcp.dirsrv_mcp.archive.healthcheck_parser import (
    parse_healthcheck_output,
)


# Fixture data — mirrors lib389.cli_ctl.health output byte-for-byte.

REAL_FINDINGS_OUTPUT = """\
Beginning lint report, this could take a while ...
Checking backends:userroot:mappingtree ...
Checking backends:userroot:search ...
Checking config:hr_timestamp ...
Healthcheck complete.
2 Issues found!  Generating report ...


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


[2] DS Lint Error: DSCLE0001
--------------------------------------------------------------------------------
Severity: LOW
Check: config:hr_timestamp
Affects:
 -- cn=config

Details:
-----------
nsslapd-logging-hr-timestamps-enabled changes the log format in directory server from

[07/Jun/2017:17:15:58 +1000]

to

[07/Jun/2017:17:15:58.716117312 +1000]

This actually provides a performance improvement.

Resolution:
-----------
Set nsslapd-logging-hr-timestamps-enabled to on.


===== End Of Report (2 Issues found) =====
"""

REAL_PASS_OUTPUT = """\
Beginning lint report, this could take a while ...
Checking backends:userroot:mappingtree ...
Checking backends:userroot:search ...
Checking config:hr_timestamp ...
Healthcheck complete.
No issues found.
"""

GARBAGE_OUTPUT = """\
Traceback (most recent call last):
  File "/usr/sbin/dsctl", line 42, in <module>
    instance.healthcheck()
ValueError: Failed to connect to Directory Server instance
"""

TRUNCATED_OUTPUT = """\
Beginning lint report, this could take a while ...
Checking backends:userroot:search ...
Healthcheck complete.
3 Issues found!  Generating report ...
"""

# Legacy single-line format the OLD parser was (wrongly) written for —
# dsctl never emits this.
LEGACY_SINGLE_LINE_OUTPUT = """\
Beginning lint report, this could take a while ...

DSBLE0001 : HIGH : Backend Backup : dc=example,dc=com
No backup has been taken for the backend 'userRoot'.
"""

JSON_FINDINGS_OUTPUT = json.dumps(
    [
        {
            "dsle": "DSBLE0002",
            "severity": "HIGH",
            "check": "backends:userroot:search",
            "items": ["dc=example,dc=com"],
            "detail": "Unable to query the backend.  LDAP error (Operations error)",
            "fix": "Check the server's error and access logs for more information.",
        },
        {
            "dsle": "DSCLE0001",
            "severity": "LOW",
            "items": ["cn=config"],
            "detail": "nsslapd-logging-hr-timestamps-enabled changes the log format.",
            "fix": "Set nsslapd-logging-hr-timestamps-enabled to on.",
        },
    ],
    indent=4,
)


class TestRealTextFindings:

    def test_findings_not_reported_as_passed(self):
        """Regression: real findings used to parse as passed=True."""
        result = parse_healthcheck_output(REAL_FINDINGS_OUTPUT)
        assert result["passed"] is False
        assert result["parse_status"] == "findings"
        assert result["total_findings"] == 2
        assert len(result["findings"]) == 2

    def test_first_finding_fields(self):
        result = parse_healthcheck_output(REAL_FINDINGS_OUTPUT)
        f = result["findings"][0]
        assert f["code"] == "DSBLE0002"
        assert f["severity"] == "HIGH"
        assert f["check"] == "backends:userroot:search"
        assert f["affects"] == ["dc=example,dc=com"]
        assert f["details"] == (
            "Unable to query the backend.  LDAP error (Operations error)"
        )
        assert f["resolution"] == (
            "Check the server's error and access logs for more information."
        )
        assert f["description"].startswith("Unable to query the backend")

    def test_second_finding_multiline_details(self):
        """Detail text with blank lines and bracketed timestamps survives."""
        result = parse_healthcheck_output(REAL_FINDINGS_OUTPUT)
        f = result["findings"][1]
        assert f["code"] == "DSCLE0001"
        assert f["severity"] == "LOW"
        assert f["check"] == "config:hr_timestamp"
        assert f["affects"] == ["cn=config"]
        assert "[07/Jun/2017:17:15:58 +1000]" in f["details"]
        assert "performance improvement" in f["details"]
        assert "End Of Report" not in f["details"]
        assert f["resolution"] == (
            "Set nsslapd-logging-hr-timestamps-enabled to on."
        )

    def test_resolution_excludes_end_of_report(self):
        result = parse_healthcheck_output(REAL_FINDINGS_OUTPUT)
        for f in result["findings"]:
            assert "End Of Report" not in f.get("resolution", "")
            assert "End Of Report" not in f.get("details", "")

    def test_raw_output_preserved(self):
        result = parse_healthcheck_output(REAL_FINDINGS_OUTPUT)
        assert result["raw_output"] == REAL_FINDINGS_OUTPUT.strip()

    def test_single_finding_without_check_line(self):
        """The Check: line is optional in _format_check_output."""
        content = (
            "[1] DS Lint Error: DSPERMLE0001\n"
            + "-" * 80
            + "\n"
            "Severity: MEDIUM\n"
            "Affects:\n"
            " -- /etc/dirsrv/slapd-inst/dse.ldif\n"
            "\n"
            "Details:\n"
            "-----------\n"
            "The file permissions are incorrect.\n"
            "\n"
            "Resolution:\n"
            "-----------\n"
            "Change the permissions to 600.\n"
        )
        result = parse_healthcheck_output(content)
        assert result["passed"] is False
        assert len(result["findings"]) == 1
        f = result["findings"][0]
        assert f["code"] == "DSPERMLE0001"
        assert f["severity"] == "MEDIUM"
        assert "check" not in f
        assert f["affects"] == ["/etc/dirsrv/slapd-inst/dse.ldif"]


class TestCleanRun:

    def test_no_issues_found_passes(self):
        result = parse_healthcheck_output(REAL_PASS_OUTPUT)
        assert result["passed"] is True
        assert result["parse_status"] == "passed"
        assert result["findings"] == []
        assert result["total_findings"] == 0

    def test_bare_pass_phrase(self):
        result = parse_healthcheck_output("No issues found.\n")
        assert result["passed"] is True
        assert result["parse_status"] == "passed"


class TestUnknownContent:

    def test_garbage_is_not_passed(self):
        result = parse_healthcheck_output(GARBAGE_OUTPUT)
        assert result["passed"] is False
        assert result["parse_status"] == "unknown"
        assert result["findings"] == []

    def test_legacy_single_line_format_is_not_passed(self):
        """The format the old parser expected is neither findings nor a pass."""
        result = parse_healthcheck_output(LEGACY_SINGLE_LINE_OUTPUT)
        assert result["passed"] is False
        assert result["parse_status"] == "unknown"
        assert result["findings"] == []

    def test_truncated_report_with_claimed_issues_is_not_passed(self):
        """'N Issues found!' with no parseable blocks is a parse failure."""
        result = parse_healthcheck_output(TRUNCATED_OUTPUT)
        assert result["passed"] is False
        assert result["parse_status"] == "unknown"
        assert result["findings"] == []

    def test_empty_content_is_not_passed(self):
        result = parse_healthcheck_output("")
        assert result["passed"] is False
        assert result["parse_status"] == "empty"
        assert result["findings"] == []
        assert result["raw_output"] == ""

    def test_none_content_is_not_passed(self):
        result = parse_healthcheck_output(None)
        assert result["passed"] is False
        assert result["parse_status"] == "empty"

    def test_whitespace_only_is_not_passed(self):
        result = parse_healthcheck_output("   \n  \n")
        assert result["passed"] is False
        assert result["parse_status"] == "empty"


class TestJsonMode:

    def test_json_findings(self):
        result = parse_healthcheck_output(JSON_FINDINGS_OUTPUT)
        assert result["passed"] is False
        assert result["parse_status"] == "findings"
        assert result["total_findings"] == 2
        f = result["findings"][0]
        assert f["code"] == "DSBLE0002"
        assert f["severity"] == "HIGH"
        assert f["check"] == "backends:userroot:search"
        assert f["affects"] == ["dc=example,dc=com"]
        assert "Unable to query the backend" in f["details"]
        assert "error and access logs" in f["resolution"]
        assert f["description"].startswith("Unable to query the backend")

    def test_json_finding_without_check(self):
        result = parse_healthcheck_output(JSON_FINDINGS_OUTPUT)
        f = result["findings"][1]
        assert f["code"] == "DSCLE0001"
        assert "check" not in f

    def test_empty_json_report_passes(self):
        """--json mode prints '[]' on a clean run — an explicit pass."""
        result = parse_healthcheck_output("[]")
        assert result["passed"] is True
        assert result["parse_status"] == "passed"
        assert result["findings"] == []

    def test_non_healthcheck_json_is_not_passed(self):
        """A JSON array that isn't lint results must not pass."""
        result = parse_healthcheck_output('[1, 2, 3]')
        assert result["passed"] is False
        assert result["parse_status"] == "unknown"

    def test_json_dicts_without_lint_keys_are_not_findings(self):
        result = parse_healthcheck_output('[{"foo": "bar"}]')
        assert result["passed"] is False
        assert result["parse_status"] == "unknown"
        assert result["findings"] == []

    def test_invalid_json_falls_back_to_unknown(self):
        result = parse_healthcheck_output("[not json at all")
        assert result["passed"] is False
        assert result["parse_status"] == "unknown"


class TestCallerCompatibility:
    """Result keys stay compatible with tools/archive.py consumers."""

    def test_result_keys_present(self):
        for content in (REAL_FINDINGS_OUTPUT, REAL_PASS_OUTPUT, GARBAGE_OUTPUT):
            result = parse_healthcheck_output(content)
            assert set(result.keys()) >= {
                "passed",
                "parse_status",
                "findings",
                "total_findings",
                "raw_output",
            }
            assert isinstance(result["passed"], bool)
            assert isinstance(result["findings"], list)

    def test_findings_have_sanitizer_keys(self):
        """_sanitize_archive_result reads code/severity/description/details."""
        result = parse_healthcheck_output(REAL_FINDINGS_OUTPUT)
        for f in result["findings"]:
            assert isinstance(f.get("code"), str)
            assert isinstance(f.get("severity"), str)
            assert isinstance(f.get("description"), str)
            # details is optional but present for real lib389 findings
            assert isinstance(f.get("details"), str)
