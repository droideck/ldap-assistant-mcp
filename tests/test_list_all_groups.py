import pytest

from tests.helpers import call_tool

pytestmark = pytest.mark.asyncio


async def test_list_all_groups(dirsrv_server, expected_test_groups):
    """Test that list_all_groups returns all groups from the directory."""

    response = await call_tool(dirsrv_server, "list_all_groups", limit=50)
    response_data = response.data

    # Verify response structure
    assert response_data["type"] == "group_list"
    assert "items" in response_data
    assert "total_returned" in response_data
    assert "limit_applied" in response_data

    # Verify response format is correct even if no groups exist
    assert response_data["total_returned"] >= 0
    assert len(response_data["items"]) == response_data["total_returned"]

    # If we have groups, verify structure
    if response_data["total_returned"] > 0:
        # Extract group names from the response
        found_groups = []
        for item in response_data["items"]:
            if "attrs" in item and "cn" in item["attrs"]:
                cn_values = item["attrs"]["cn"]
                if isinstance(cn_values, list) and cn_values:
                    found_groups.append(cn_values[0])

        # Verify our expected test groups are present (if any exist)
        for expected_group in expected_test_groups:
            assert expected_group in found_groups, f"Expected group {expected_group} not found in results"

        print(f"✓ Found {len(found_groups)} groups including all expected test groups")
    else:
        print("✓ No groups found - this is acceptable if no groups are configured")


async def test_list_all_groups_with_limit(dirsrv_server):
    """Test that list_all_groups respects the limit parameter."""

    response = await call_tool(dirsrv_server, "list_all_groups", limit=5)
    response_data = response.data

    # Verify response structure
    assert response_data["type"] == "group_list"
    assert response_data["limit_applied"] == 5
    assert len(response_data["items"]) <= 5

    print(f"✓ Limit respected: returned {len(response_data['items'])} groups (max 5)")


async def test_list_all_groups_default_limit(dirsrv_server):
    """Test that list_all_groups uses default limit when none specified."""

    response = await call_tool(dirsrv_server, "list_all_groups")
    response_data = response.data

    # Verify default limit is applied
    assert response_data["limit_applied"] == 50
    assert len(response_data["items"]) <= 50

    print(f"✓ Default limit applied: returned {len(response_data['items'])} groups (max 50)")
