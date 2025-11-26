"""Tests for LDAP search tools.

Following FastMCP testing patterns:
- Each test verifies exactly one behavior
- Tests are self-contained and can run in any order
- Use in-memory transport via Client(server) pattern
"""

from __future__ import annotations

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

pytestmark = pytest.mark.asyncio


# ------------------------------------------------------------------------- #
# Basic search functionality
# ------------------------------------------------------------------------- #


async def test_ldap_search_subtree_returns_results(dirsrv_server):
    """Test that ldap_search with SUBTREE scope returns results."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool(
            "ldap_search",
            {
                "base_dn": "dc=test,dc=com",
                "scope": "SUBTREE",
                "filter": "(objectClass=*)",
                "limit": 100,
            },
        )
        data = result.data

        assert data["type"] == "ldap_search", "Response type should be 'ldap_search'"
        assert data["total_returned"] > 0, "SUBTREE search should return results"
        assert len(data["items"]) > 0, "items should not be empty"


async def test_ldap_search_preserves_search_parameters(dirsrv_server):
    """Test that ldap_search preserves search parameters in response."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool(
            "ldap_search",
            {
                "base_dn": "dc=test,dc=com",
                "scope": "SUBTREE",
                "filter": "(objectClass=*)",
                "limit": 100,
            },
        )
        data = result.data

        assert data["base_dn"] == "dc=test,dc=com", "base_dn should be preserved"
        assert data["scope"] == "SUBTREE", "scope should be preserved"
        assert data["filter"] == "(objectClass=*)", "filter should be preserved"


async def test_ldap_search_onelevel_finds_users(dirsrv_server, expected_test_users):
    """Test that ldap_search with ONELEVEL scope finds users in ou=people."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool(
            "ldap_search",
            {
                "base_dn": "ou=people,dc=test,dc=com",
                "scope": "ONELEVEL",
                "filter": "(objectClass=inetOrgPerson)",
                "limit": 50,
            },
        )
        data = result.data

        found_users = _extract_user_ids(data["items"])

        for expected_user in expected_test_users:
            assert expected_user in found_users, (
                f"Expected user '{expected_user}' not found in ONELEVEL search"
            )


async def test_ldap_search_base_returns_single_entry(dirsrv_server):
    """Test that ldap_search with BASE scope returns exactly one entry."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool(
            "ldap_search",
            {
                "base_dn": "uid=testuser1,ou=people,dc=test,dc=com",
                "scope": "BASE",
                "filter": "(objectClass=*)",
                "limit": 10,
            },
        )
        data = result.data

        assert data["total_returned"] == 1, "BASE scope should return exactly one entry"
        assert len(data["items"]) == 1, "items should contain exactly one entry"


async def test_ldap_search_base_returns_correct_entry(dirsrv_server):
    """Test that ldap_search with BASE scope returns the specified entry."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool(
            "ldap_search",
            {
                "base_dn": "uid=testuser1,ou=people,dc=test,dc=com",
                "scope": "BASE",
                "filter": "(objectClass=*)",
                "limit": 10,
            },
        )
        data = result.data

        entry = data["items"][0]
        assert entry["dn"] == "uid=testuser1,ou=people,dc=test,dc=com", (
            "Returned entry DN should match base_dn"
        )
        assert "testuser1" in entry["attrs"]["uid"], "Entry should have correct uid"


# ------------------------------------------------------------------------- #
# Attribute filtering
# ------------------------------------------------------------------------- #


async def test_ldap_search_with_specific_attributes(dirsrv_server):
    """Test that ldap_search returns only requested attributes."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool(
            "ldap_search",
            {
                "base_dn": "ou=people,dc=test,dc=com",
                "scope": "ONELEVEL",
                "filter": "(uid=testuser1)",
                "attributes": "uid,cn,mail",
                "limit": 10,
            },
        )
        data = result.data

        assert data["attributes_requested"] == "uid,cn,mail", (
            "attributes_requested should be preserved"
        )
        assert data["total_returned"] >= 1, "Should find at least one entry"

        attrs = data["items"][0]["attrs"]
        assert "uid" in attrs, "uid should be present"
        assert "cn" in attrs, "cn should be present"
        assert "mail" in attrs, "mail should be present"


async def test_ldap_search_attrs_only_returns_empty_values(dirsrv_server):
    """Test that ldap_search with attrs_only returns attribute names only."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool(
            "ldap_search",
            {
                "base_dn": "uid=testuser1,ou=people,dc=test,dc=com",
                "scope": "BASE",
                "filter": "(objectClass=*)",
                "attrs_only": True,
                "limit": 10,
            },
        )
        data = result.data

        assert data["attrs_only"] is True, "attrs_only should be True"

        for attr_name, attr_values in data["items"][0]["attrs"].items():
            assert isinstance(attr_values, list), f"Attribute {attr_name} should be a list"
            assert len(attr_values) == 0, (
                f"Attribute {attr_name} should have empty values with attrs_only=True"
            )


# ------------------------------------------------------------------------- #
# Complex filters
# ------------------------------------------------------------------------- #


async def test_ldap_search_complex_filter(dirsrv_server):
    """Test that ldap_search handles complex AND filters."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool(
            "ldap_search",
            {
                "base_dn": "ou=people,dc=test,dc=com",
                "scope": "SUBTREE",
                "filter": "(&(objectClass=inetOrgPerson)(uid=testuser*))",
                "limit": 50,
            },
        )
        data = result.data

        assert data["filter"] == "(&(objectClass=inetOrgPerson)(uid=testuser*))", (
            "Complex filter should be preserved"
        )
        assert data["total_returned"] >= 2, "Should find at least testuser1 and testuser2"

        found_users = _extract_user_ids(data["items"])
        for user in found_users:
            assert user.startswith("testuser"), (
                f"User '{user}' doesn't match testuser* pattern"
            )


async def test_ldap_search_groups(dirsrv_server, expected_test_groups):
    """Test that ldap_search can find group entries."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool(
            "ldap_search",
            {
                "base_dn": "ou=groups,dc=test,dc=com",
                "scope": "ONELEVEL",
                "filter": "(objectClass=groupOfNames)",
                "attributes": "cn,gidNumber",
                "limit": 50,
            },
        )
        data = result.data

        found_groups = _extract_group_names(data["items"])

        for expected_group in expected_test_groups:
            assert expected_group in found_groups, (
                f"Expected group '{expected_group}' not found in search results"
            )


# ------------------------------------------------------------------------- #
# Limit enforcement
# ------------------------------------------------------------------------- #


async def test_ldap_search_respects_limit(dirsrv_server):
    """Test that ldap_search respects the limit parameter."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool(
            "ldap_search",
            {
                "base_dn": "dc=test,dc=com",
                "scope": "SUBTREE",
                "filter": "(objectClass=*)",
                "limit": 2,
            },
        )
        data = result.data

        assert data["limit_applied"] == 2, "Limit should be applied as specified"
        assert data["total_returned"] <= 2, (
            f"Should return at most 2 entries, got {data['total_returned']}"
        )


# ------------------------------------------------------------------------- #
# Error handling
# ------------------------------------------------------------------------- #


async def test_ldap_search_invalid_scope_raises_error(dirsrv_server):
    """Test that ldap_search with invalid scope raises ToolError."""
    async with Client(dirsrv_server) as client:
        with pytest.raises(ToolError) as exc_info:
            await client.call_tool(
                "ldap_search",
                {
                    "base_dn": "dc=test,dc=com",
                    "scope": "INVALID",
                    "filter": "(objectClass=*)",
                    "limit": 10,
                },
            )

        assert "Invalid scope" in str(exc_info.value), (
            f"Error should mention 'Invalid scope', got: {exc_info.value}"
        )


async def test_ldap_search_nonexistent_base_dn_raises_error(dirsrv_server):
    """Test that ldap_search with non-existent base DN raises ToolError."""
    async with Client(dirsrv_server) as client:
        with pytest.raises(ToolError) as exc_info:
            await client.call_tool(
                "ldap_search",
                {
                    "base_dn": "ou=nonexistent,dc=test,dc=com",
                    "scope": "SUBTREE",
                    "filter": "(objectClass=*)",
                    "limit": 10,
                },
            )

        error_msg = str(exc_info.value)
        assert "does not exist" in error_msg or "No such object" in error_msg, (
            f"Error should mention non-existent DN, got: {error_msg}"
        )


async def test_ldap_search_invalid_filter_raises_error(dirsrv_server):
    """Test that ldap_search with invalid filter syntax raises ToolError."""
    async with Client(dirsrv_server) as client:
        with pytest.raises(ToolError) as exc_info:
            await client.call_tool(
                "ldap_search",
                {
                    "base_dn": "dc=test,dc=com",
                    "scope": "SUBTREE",
                    "filter": "(invalid_filter_syntax",
                    "limit": 10,
                },
            )

        # Just verify an error was raised with some message
        assert str(exc_info.value), "Error should have a message"


# ------------------------------------------------------------------------- #
# Helper functions
# ------------------------------------------------------------------------- #


def _extract_user_ids(items: list) -> list[str]:
    """Extract user IDs from a list of LDAP items."""
    found_users = []
    for item in items:
        attrs = item.get("attrs", {})
        uid_values = attrs.get("uid", [])
        if isinstance(uid_values, list) and uid_values:
            found_users.append(uid_values[0])
        elif uid_values:
            found_users.append(uid_values)
    return found_users


def _extract_group_names(items: list) -> list[str]:
    """Extract group names from a list of LDAP items."""
    found_groups = []
    for item in items:
        attrs = item.get("attrs", {})
        cn_values = attrs.get("cn", [])
        if isinstance(cn_values, list) and cn_values:
            found_groups.append(cn_values[0])
        elif cn_values:
            found_groups.append(cn_values)
    return found_groups

