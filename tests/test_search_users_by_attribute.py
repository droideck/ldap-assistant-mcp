import json
import pytest
from src.providers.dirsrv_mcp.tools import search_users_by_attribute


def test_search_users_by_attribute(mock_env):
    """Test that search_users_by_attribute can find users by specific attributes."""
    # Search for users with employeeType = Contractor - now returns dict directly
    response_data = search_users_by_attribute(attribute="employeeType", value="Contractor", limit=50)

    # Verify response structure
    assert response_data["type"] == "attribute_search"
    assert "items" in response_data
    assert "attribute" in response_data
    assert "value" in response_data
    assert response_data["attribute"] == "employeeType"
    assert response_data["value"] == "Contractor"

    # Verify we found the user
    assert response_data["total_returned"] >= 1
    assert len(response_data["items"]) >= 1

    # Extract user IDs and verify they have the expected attribute
    found_users = []
    for item in response_data["items"]:
        if "attrs" in item:
            attrs = item["attrs"]
            if "uid" in attrs:
                uid_values = attrs["uid"]
                if isinstance(uid_values, list) and uid_values:
                    found_users.append(uid_values[0])

            # Verify the employeeType attribute is present and correct
            if "employeeType" in attrs:
                employee_type_values = attrs["employeeType"]
                if isinstance(employee_type_values, list) and employee_type_values:
                    assert "Contractor" in employee_type_values, "Found user doesn't have expected employeeType"

    # Verify contractor user is in the results
    assert "contractor" in found_users, "Expected contractor user not found in attribute search results"

    print(f"✓ Successfully found {len(found_users)} users with employeeType=Contractor")