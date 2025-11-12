import json
import pytest
from src.providers.dirsrv_mcp.tools import list_locked_users


def test_list_locked_users(mock_env):
    """Test that list_locked_users returns only locked users."""
    # Call the tool - now returns dict directly
    response_data = list_locked_users(limit=50)

    # Verify response structure
    assert response_data["type"] == "locked_users"
    assert "items" in response_data
    assert "locked_users_found" in response_data
    assert "total_processed" in response_data

    # Extract user IDs and verify they are all locked
    found_users = []
    for item in response_data["items"]:
        if "attrs" in item:
            attrs = item["attrs"]
            if "uid" in attrs:
                uid_values = attrs["uid"]
                if isinstance(uid_values, list) and uid_values:
                    found_users.append(uid_values[0])

            # Verify the user is marked as locked
            if "computed_status" in attrs:
                status = attrs["computed_status"]
                assert status.get("simple_status") == "locked", f"Non-locked user found in locked users list"

    # Verify expected locked user is present
    assert "lockeduser" in found_users, "Expected locked user 'lockeduser' not found"

    # Verify active users are NOT present
    active_users = ["testuser1", "testuser2", "contractor"]
    for active_user in active_users:
        assert active_user not in found_users, f"Active user {active_user} found in locked users list"

    print(f"✓ Found {len(found_users)} locked users, excluding active users")