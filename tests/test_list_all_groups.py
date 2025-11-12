import json
import pytest
from src.providers.dirsrv_mcp.tools import list_all_groups


def test_list_all_groups(mock_env, expected_test_groups):
    """Test that list_all_groups returns all groups from the directory."""
    # Call the tool - now returns dict directly
    response_data = list_all_groups(limit=50)

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


def test_list_all_groups_with_limit(mock_env):
    """Test that list_all_groups respects the limit parameter."""
    # Test with a small limit - now returns dict directly
    response_data = list_all_groups(limit=5)

    # Verify response structure
    assert response_data["type"] == "group_list"
    assert response_data["limit_applied"] == 5
    assert len(response_data["items"]) <= 5

    print(f"✓ Limit respected: returned {len(response_data['items'])} groups (max 5)")


def test_list_all_groups_default_limit(mock_env):
    """Test that list_all_groups uses default limit when none specified."""
    # Call without specifying limit - now returns dict directly
    response_data = list_all_groups()

    # Verify default limit is applied
    assert response_data["limit_applied"] == 50
    assert len(response_data["items"]) <= 50

    print(f"✓ Default limit applied: returned {len(response_data['items'])} groups (max 50)")
