import json
import pytest
from src.providers.dirsrv_mcp.tools import list_all_users


def test_list_all_users(mock_env, expected_test_users):
    """Test that list_all_users returns all users from the directory."""
    # Call the tool - now returns dict directly
    response_data = list_all_users(limit=50)

    # Verify response structure
    assert response_data["type"] == "user_list"
    assert "items" in response_data
    assert "total_returned" in response_data
    assert "limit_applied" in response_data

    # Verify we got some users
    assert response_data["total_returned"] > 0
    assert len(response_data["items"]) > 0

    # Extract user IDs from the response
    found_users = []
    for item in response_data["items"]:
        if "attrs" in item and "uid" in item["attrs"]:
            uid_values = item["attrs"]["uid"]
            if isinstance(uid_values, list) and uid_values:
                found_users.append(uid_values[0])

    # Verify our test users are present
    for expected_user in expected_test_users:
        assert expected_user in found_users, f"Expected user {expected_user} not found in results"

    print(f"✓ Found {len(found_users)} users including all expected test users")