import json
import pytest
from src.providers.dirsrv_mcp.tools import get_user_details


def test_get_user_details(mock_env):
    """Test that get_user_details returns detailed information for a specific user."""
    # Get details for testuser1 - now returns dict directly
    response_data = get_user_details(username="testuser1")

    # Verify response structure
    assert response_data["type"] == "user_details"
    assert "username" in response_data
    assert response_data["username"] == "testuser1"
    assert "user" in response_data

    # Verify user data structure
    user_data = response_data["user"]
    assert "attrs" in user_data
    assert "dn" in user_data

    # Verify we have the expected user attributes
    attrs = user_data["attrs"]
    assert "uid" in attrs
    assert "cn" in attrs
    assert "mail" in attrs

    # Verify the UID matches
    uid_values = attrs["uid"]
    if isinstance(uid_values, list) and uid_values:
        assert uid_values[0] == "testuser1"

    # Verify we have computed status
    assert "computed_status" in attrs
    assert "simple_status" in attrs["computed_status"]

    print(f"✓ Successfully retrieved details for testuser1")