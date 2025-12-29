"""Tests for health check tools.

Following FastMCP testing patterns:
- Each test verifies exactly one behavior
- Tests are self-contained and can run in any order
- Use in-memory transport via Client(server) pattern
"""

from __future__ import annotations

import pytest
from fastmcp import Client

pytestmark = pytest.mark.asyncio


# ============================================================================
# list_healthcheck_errors tests
# ============================================================================


async def test_list_healthcheck_errors_returns_error_codes(dirsrv_server):
    """Test that list_healthcheck_errors returns known error codes."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("list_healthcheck_errors", {})
        data = result.data

        assert data["type"] == "healthcheck_errors", "Response type should be 'healthcheck_errors'"
        assert "errors" in data, "Response should contain 'errors'"
        assert "total_count" in data, "Response should contain 'total_count'"
        assert data["total_count"] > 0, "Should have at least one error code defined"


async def test_list_healthcheck_errors_includes_dsle_format(dirsrv_server):
    """Test that error codes follow DSLE format."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("list_healthcheck_errors", {})
        data = result.data

        errors = data["errors"]
        assert len(errors) > 0, "Should have error codes"

        # Check structure of first error
        first_error = errors[0]
        assert "code" in first_error, "Error should have 'code'"
        assert "severity" in first_error, "Error should have 'severity'"
        assert "description" in first_error, "Error should have 'description'"
        assert first_error["code"].startswith("DS"), "Error code should start with 'DS'"


async def test_list_healthcheck_errors_includes_known_codes(dirsrv_server):
    """Test that known error codes are present."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("list_healthcheck_errors", {})
        data = result.data

        codes = [e["code"] for e in data["errors"]]
        # Check for some known error codes
        assert "DSCLE0002" in codes, "Should include DSCLE0002 (weak password scheme)"
        assert "DSBLE0001" in codes, "Should include DSBLE0001 (mapping tree)"


# ============================================================================
# list_healthchecks tests
# ============================================================================


async def test_list_healthchecks_returns_available_checks(dirsrv_server):
    """Test that list_healthchecks returns available check list."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("list_healthchecks", {})
        data = result.data

        assert data["type"] == "healthcheck_list", "Response type should be 'healthcheck_list'"
        assert "checks" in data, "Response should contain 'checks'"
        assert "total_count" in data, "Response should contain 'total_count'"
        assert "categories" in data, "Response should contain 'categories'"


async def test_list_healthchecks_has_config_category(dirsrv_server):
    """Test that config category checks are available."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("list_healthchecks", {})
        data = result.data

        categories = data["categories"]
        assert "config" in categories, "Should have 'config' category"


async def test_list_healthchecks_check_format(dirsrv_server):
    """Test that checks have proper format (category:check_name)."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("list_healthchecks", {})
        data = result.data

        checks = data["checks"]
        assert len(checks) > 0, "Should have at least one check"

        # Verify structure
        first_check = checks[0]
        assert "name" in first_check, "Check should have 'name'"
        assert "category" in first_check, "Check should have 'category'"
        assert "check" in first_check, "Check should have 'check'"
        assert ":" in first_check["name"], "Check name should contain colon separator"


async def test_list_healthchecks_includes_server_name(dirsrv_server):
    """Test that response includes server name."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("list_healthchecks", {})
        data = result.data

        assert "server" in data, "Response should include 'server'"
        assert data["server"] is not None, "Server name should not be None"


# ============================================================================
# run_healthcheck tests
# ============================================================================


async def test_run_healthcheck_returns_structured_report(dirsrv_server):
    """Test that run_healthcheck returns a structured health report."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("run_healthcheck", {})
        data = result.data

        assert data["type"] == "healthcheck", "Response type should be 'healthcheck'"
        assert "summary" in data, "Response should contain 'summary'"
        assert "findings" in data, "Response should contain 'findings'"
        assert "checks_executed" in data, "Response should contain 'checks_executed'"


async def test_run_healthcheck_includes_severity_counts(dirsrv_server):
    """Test that run_healthcheck includes severity counts."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("run_healthcheck", {})
        data = result.data

        assert "critical_count" in data, "Should include critical_count"
        assert "high_count" in data, "Should include high_count"
        assert "medium_count" in data, "Should include medium_count"
        assert "low_count" in data, "Should include low_count"
        assert "info_count" in data, "Should include info_count"
        assert "total_issues" in data, "Should include total_issues"


async def test_run_healthcheck_executes_checks(dirsrv_server):
    """Test that run_healthcheck actually executes checks."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("run_healthcheck", {})
        data = result.data

        assert "checks_executed" in data, "Should include checks_executed"
        assert "total_checks_run" in data, "Should include total_checks_run"
        assert data["total_checks_run"] > 0, "Should execute at least one check"


async def test_run_healthcheck_with_specific_check(dirsrv_server):
    """Test run_healthcheck with specific check filter."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("run_healthcheck", {"checks": ["config:*"]})
        data = result.data

        assert data["type"] == "healthcheck", "Response type should be 'healthcheck'"
        checks_executed = data["checks_executed"]

        # All executed checks should be from config category
        for check in checks_executed:
            assert check.startswith("config:"), f"Check {check} should be from config category"


async def test_run_healthcheck_with_exclude(dirsrv_server):
    """Test run_healthcheck with exclude filter."""
    async with Client(dirsrv_server) as client:
        # First, run without exclude to see what we get
        result_full = await client.call_tool("run_healthcheck", {"checks": ["config:*"]})
        full_checks = set(result_full.data["checks_executed"])

        # Now run with exclude
        result = await client.call_tool(
            "run_healthcheck",
            {"checks": ["config:*"], "exclude_checks": ["config:passwordscheme"]},
        )
        data = result.data

        assert data["type"] == "healthcheck", "Response type should be 'healthcheck'"

        # Check that excluded check is not in executed list
        for check in data["checks_executed"]:
            assert check != "config:passwordscheme", "Excluded check should not be executed"

        # And should be in skipped list if it existed in full checks
        if "config:passwordscheme" in full_checks:
            assert "config:passwordscheme" in data["checks_skipped"], "Excluded check should be in skipped list"


async def test_run_healthcheck_findings_have_proper_structure(dirsrv_server):
    """Test that findings have the expected structure."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("run_healthcheck", {})
        data = result.data

        # If there are findings, verify their structure
        if data["findings"]:
            finding = data["findings"][0]
            assert "title" in finding, "Finding should have 'title'"
            assert "severity" in finding, "Finding should have 'severity'"
            assert "impact" in finding, "Finding should have 'impact'"
            assert "details" in finding, "Finding should have 'details'"
            assert "remediation" in finding, "Finding should have 'remediation'"


async def test_run_healthcheck_includes_server_name(dirsrv_server):
    """Test that response includes server name."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("run_healthcheck", {})
        data = result.data

        assert "server" in data, "Response should include 'server'"
        assert data["server"] is not None, "Server name should not be None"


# ============================================================================
# first_look tests (existing tool)
# ============================================================================


async def test_first_look_returns_overview(dirsrv_server):
    """Test that first_look returns a health overview."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("first_look", {})
        data = result.data

        assert data["type"] == "first_look", "Response type should be 'first_look'"
        assert "summary" in data, "Response should contain 'summary'"
        assert "findings" in data, "Response should contain 'findings'"
        assert "servers_checked" in data, "Response should contain 'servers_checked'"


async def test_first_look_includes_severity_counts(dirsrv_server):
    """Test that first_look includes severity counts."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("first_look", {})
        data = result.data

        assert "critical_count" in data, "Should include critical_count"
        assert "high_count" in data, "Should include high_count"
        assert "medium_count" in data, "Should include medium_count"
        assert "low_count" in data, "Should include low_count"
        assert "info_count" in data, "Should include info_count"


async def test_first_look_checks_server_connectivity(dirsrv_server):
    """Test that first_look verifies server connectivity."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("first_look", {})
        data = result.data

        # At minimum, we should have tried to check our configured server
        assert len(data["servers_checked"]) > 0 or len(data["servers_failed"]) > 0, (
            "Should have checked at least one server"
        )
