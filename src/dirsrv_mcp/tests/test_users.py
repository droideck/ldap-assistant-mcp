"""Tests for user management tools.

Following FastMCP testing patterns:
- Each test verifies exactly one behavior
- Tests are self-contained and can run in any order
- Use in-memory transport via Client(server) pattern
"""

from __future__ import annotations

import pytest
from fastmcp import Client

pytestmark = pytest.mark.asyncio


async def test_list_all_users_returns_user_list(dirsrv_server):
    """Test that list_all_users returns a properly structured user list."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("list_all_users", {"limit": 50})
        data = result.data

        assert data["type"] == "user_list", "Response type should be 'user_list'"
        assert "items" in data, "Response should contain 'items'"
        assert "total_returned" in data, "Response should contain 'total_returned'"
        assert "limit_applied" in data, "Response should contain 'limit_applied'"


async def test_list_all_users_includes_expected_users(dirsrv_server, expected_test_users):
    """Test that list_all_users includes all expected test users."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("list_all_users", {"limit": 50})
        data = result.data

        found_users = _extract_user_ids(data["items"])

        for expected_user in expected_test_users:
            assert expected_user in found_users, (
                f"Expected user '{expected_user}' not found in results. "
                f"Found users: {found_users}"
            )


async def test_list_all_users_respects_limit(dirsrv_server):
    """Test that list_all_users respects the limit parameter."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("list_all_users", {"limit": 2})
        data = result.data

        assert data["limit_applied"] == 2, "Limit should be applied as specified"
        assert len(data["items"]) <= 2, f"Should return at most 2 users, got {len(data['items'])}"


async def test_list_active_users_returns_only_active(dirsrv_server):
    """Test that list_active_users returns only users with active status."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("list_active_users", {"limit": 50})
        data = result.data

        assert data["type"] == "active_users", "Response type should be 'active_users'"

        for item in data["items"]:
            status = item.get("attrs", {}).get("computed_status", {})
            assert status.get("simple_status") == "active", (
                f"Found non-active user in active users list: {status}"
            )


async def test_list_active_users_excludes_locked_user(dirsrv_server):
    """Test that list_active_users does not include locked users."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("list_active_users", {"limit": 50})
        data = result.data

        found_users = _extract_user_ids(data["items"])

        assert "lockeduser" not in found_users, (
            "Locked user should not appear in active users list"
        )


async def test_list_locked_users_returns_only_locked(dirsrv_server):
    """Test that list_locked_users returns only users with locked status."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("list_locked_users", {"limit": 50})
        data = result.data

        assert data["type"] == "locked_users", "Response type should be 'locked_users'"
        assert data["locked_users_found"] == len(data["items"]), (
            "locked_users_found should match items count"
        )

        for item in data["items"]:
            status = item.get("attrs", {}).get("computed_status", {})
            assert status.get("simple_status") == "locked", (
                f"Found non-locked user in locked users list: {status}"
            )


async def test_list_locked_users_includes_locked_user(dirsrv_server):
    """Test that list_locked_users includes the expected locked user."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("list_locked_users", {"limit": 50})
        data = result.data

        found_users = _extract_user_ids(data["items"])

        assert "lockeduser" in found_users, (
            "Expected 'lockeduser' in locked users list"
        )


async def test_search_users_by_name_finds_exact_match(dirsrv_server):
    """Test that search_users_by_name finds users by exact name match."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("search_users_by_name", {"name": "testuser1", "limit": 50})
        data = result.data

        assert data["type"] == "user_search", "Response type should be 'user_search'"
        assert data["search_term"] == "testuser1", "Search term should be preserved"

        found_users = _extract_user_ids(data["items"])
        assert "testuser1" in found_users, "testuser1 should be found"


async def test_search_users_by_name_returns_search_metadata(dirsrv_server):
    """Test that search_users_by_name includes proper search metadata."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("search_users_by_name", {"name": "test", "limit": 10})
        data = result.data

        assert "filter_used" in data, "Response should include the filter used"
        assert "total_returned" in data, "Response should include total_returned"
        assert "limit_applied" in data, "Response should include limit_applied"


async def test_get_user_details_returns_user_info(dirsrv_server):
    """Test that get_user_details returns detailed information for a specific user."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("get_user_details", {"username": "testuser1"})
        data = result.data

        assert data["type"] == "user_details", "Response type should be 'user_details'"
        assert data["username"] == "testuser1", "Username should be preserved"
        assert "user" in data, "Response should contain user data"


async def test_get_user_details_includes_expected_attributes(dirsrv_server):
    """Test that get_user_details includes expected user attributes."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("get_user_details", {"username": "testuser1"})
        data = result.data

        user = data["user"]
        attrs = user.get("attrs", {})

        assert "dn" in user, "User should have a DN"
        assert "uid" in attrs, "User should have a uid attribute"
        assert "cn" in attrs, "User should have a cn attribute"
        assert "mail" in attrs, "User should have a mail attribute"
        assert "computed_status" in attrs, "User should have computed_status"


async def test_get_user_details_has_correct_uid(dirsrv_server):
    """Test that get_user_details returns the correct user by UID."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("get_user_details", {"username": "testuser1"})
        data = result.data

        uid_values = data["user"]["attrs"]["uid"]
        if isinstance(uid_values, list):
            assert "testuser1" in uid_values, "UID should be testuser1"
        else:
            assert uid_values == "testuser1", "UID should be testuser1"


async def test_search_users_by_attribute_finds_contractor(dirsrv_server):
    """Test that search_users_by_attribute can find users by employeeType."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool(
            "search_users_by_attribute",
            {"attribute": "employeeType", "value": "Contractor", "limit": 50},
        )
        data = result.data

        assert data["type"] == "attribute_search", "Response type should be 'attribute_search'"
        assert data["attribute"] == "employeeType", "Attribute should be preserved"
        assert data["value"] == "Contractor", "Value should be preserved"

        found_users = _extract_user_ids(data["items"])
        assert "contractor" in found_users, (
            "Expected 'contractor' user in search results"
        )


async def test_search_users_by_attribute_includes_filter_info(dirsrv_server):
    """Test that search_users_by_attribute includes filter metadata."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool(
            "search_users_by_attribute",
            {"attribute": "mail", "value": "test", "limit": 10},
        )
        data = result.data

        assert "filter_used" in data, "Response should include the filter used"
        assert data["filter_used"], "Filter should not be empty"


def _extract_user_ids(items: list) -> list[str]:
    """Extract user IDs from a list of user items."""
    found_users = []
    for item in items:
        attrs = item.get("attrs", {})
        uid_values = attrs.get("uid", [])
        if isinstance(uid_values, list) and uid_values:
            found_users.append(uid_values[0])
        elif uid_values:
            found_users.append(uid_values)
    return found_users

