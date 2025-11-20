import pytest

from tests.helpers import call_tool

pytestmark = pytest.mark.asyncio


async def test_list_active_users(dirsrv_server):
    """Test that list_active_users returns only active users."""

    response = await call_tool(dirsrv_server, "list_active_users", limit=50)
    response_data = response.data

    # Verify response structure
    assert response_data["type"] == "active_users"
    assert "items" in response_data
    assert "active_users_found" in response_data
    assert response_data["active_users_found"] == len(response_data["items"])

    # Verify we got some active users
    assert response_data["active_users_found"] > 0
    assert len(response_data["items"]) > 0

    # Extract user IDs and verify they are all active
    found_users = []
    for item in response_data["items"]:
        if "attrs" in item:
            attrs = item["attrs"]
            if "uid" in attrs:
                uid_values = attrs["uid"]
                if isinstance(uid_values, list) and uid_values:
                    found_users.append(uid_values[0])

            # Verify the user is marked as active
            if "computed_status" in attrs:
                status = attrs["computed_status"]
                assert status.get("simple_status") == "active", f"Non-active user found in active users list"

    # Verify expected active users are present (testuser1, testuser2, contractor)
    expected_active_users = ["testuser1", "testuser2", "contractor"]
    for expected_user in expected_active_users:
        assert expected_user in found_users, f"Expected active user {expected_user} not found"

    # Verify locked user is NOT present
    assert "lockeduser" not in found_users, "Locked user found in active users list"

    print(f"✓ Found {len(found_users)} active users, excluding locked users")