import pytest

from tests.helpers import call_tool

pytestmark = pytest.mark.asyncio


async def test_search_users_by_name(dirsrv_server):
    """Test that search_users_by_name can find users by name."""

    response = await call_tool(dirsrv_server, "search_users_by_name", name="testuser1", limit=50)
    response_data = response.data

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