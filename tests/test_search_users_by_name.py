import json
import pytest
from src.providers.dirsrv_mcp.tools import search_users_by_name


def test_search_users_by_name(mock_env):
    """Test that search_users_by_name can find users by name."""
    # Search for testuser1 - now returns dict directly
    response_data = search_users_by_name(name="testuser1", limit=50)

    # Verify response structure
    assert response_data["type"] == "user_search"
    assert "items" in response_data
    assert "search_term" in response_data
    assert response_data["search_term"] == "testuser1"

    # Verify we found the user
    assert response_data["total_returned"] >= 1
    assert len(response_data["items"]) >= 1

    # Extract user IDs from the response
    found_users = []
    for item in response_data["items"]:
        if "attrs" in item and "uid" in item["attrs"]:
            uid_values = item["attrs"]["uid"]
            if isinstance(uid_values, list) and uid_values:
                found_users.append(uid_values[0])

    # Verify testuser1 is in the results
    assert "testuser1" in found_users, "testuser1 not found in search results"

    print(f"✓ Successfully found testuser1 in search results")