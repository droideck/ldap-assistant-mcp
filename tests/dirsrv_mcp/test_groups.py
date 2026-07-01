"""Tests for group management tools.

Following FastMCP testing patterns:
- Each test verifies exactly one behavior
- Tests are self-contained and can run in any order
- Use in-memory transport via Client(server) pattern
"""

from __future__ import annotations

import pytest
from fastmcp import Client

# Every test in this module drives live LDAP tools against a running DS
# instance — deselect without containers via `pytest -m "not live"`.
pytestmark = [pytest.mark.asyncio, pytest.mark.live]


async def test_list_all_groups_returns_group_list(dirsrv_server):
    """Test that list_all_groups returns a properly structured group list."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("list_all_groups", {"limit": 50})
        data = result.data

        assert data["type"] == "group_list", "Response type should be 'group_list'"
        assert "items" in data, "Response should contain 'items'"
        assert "total_returned" in data, "Response should contain 'total_returned'"
        assert "limit_applied" in data, "Response should contain 'limit_applied'"


async def test_list_all_groups_item_count_matches_total(dirsrv_server):
    """Test that list_all_groups item count matches total_returned."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("list_all_groups", {"limit": 50})
        data = result.data

        assert len(data["items"]) == data["total_returned"], (
            f"items count ({len(data['items'])}) should match "
            f"total_returned ({data['total_returned']})"
        )


async def test_list_all_groups_includes_expected_groups(dirsrv_server, expected_test_groups):
    """Test that list_all_groups includes all expected test groups."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("list_all_groups", {"limit": 50})
        data = result.data

        if data["total_returned"] == 0:
            pytest.skip("No groups configured in test environment")

        found_groups = _extract_group_names(data["items"])

        for expected_group in expected_test_groups:
            assert expected_group in found_groups, (
                f"Expected group '{expected_group}' not found in results. "
                f"Found groups: {found_groups}"
            )


async def test_list_all_groups_respects_limit(dirsrv_server):
    """Test that list_all_groups respects the limit parameter."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("list_all_groups", {"limit": 5})
        data = result.data

        assert data["limit_applied"] == 5, "Limit should be applied as specified"
        assert len(data["items"]) <= 5, f"Should return at most 5 groups, got {len(data['items'])}"


async def test_list_all_groups_uses_default_limit(dirsrv_server):
    """Test that list_all_groups uses default limit of 50 when none specified."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("list_all_groups", {})
        data = result.data

        assert data["limit_applied"] == 50, (
            f"Default limit should be 50, got {data['limit_applied']}"
        )


def _extract_group_names(items: list) -> list[str]:
    """Extract group names from a list of group items."""
    found_groups = []
    for item in items:
        attrs = item.get("attrs", {})
        cn_values = attrs.get("cn", [])
        if isinstance(cn_values, list) and cn_values:
            found_groups.append(cn_values[0])
        elif cn_values:
            found_groups.append(cn_values)
    return found_groups

