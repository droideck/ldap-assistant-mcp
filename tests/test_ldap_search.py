import pytest
from fastmcp.exceptions import ToolError

from tests.helpers import call_tool

pytestmark = pytest.mark.asyncio


async def test_ldap_search_basic_subtree(dirsrv_server):
    """Test basic LDAP search with SUBTREE scope."""

    response = await call_tool(
        dirsrv_server,
        "ldap_search",
        base_dn="dc=test,dc=com",
        scope="SUBTREE",
        filter="(objectClass=*)",
        limit=100,
    )
    response_data = response.data

    # Verify response structure
    assert response_data["type"] == "ldap_search"
    assert response_data["base_dn"] == "dc=test,dc=com"
    assert response_data["scope"] == "SUBTREE"
    assert response_data["filter"] == "(objectClass=*)"
    assert "items" in response_data
    assert "total_returned" in response_data
    assert "limit_applied" in response_data

    # Verify we got some results
    assert response_data["total_returned"] > 0
    assert len(response_data["items"]) > 0

    print(f"✓ Basic SUBTREE search returned {response_data['total_returned']} entries")


async def test_ldap_search_users_only(dirsrv_server, expected_test_users):
    """Test searching for users only with specific filter."""

    response = await call_tool(
        dirsrv_server,
        "ldap_search",
        base_dn="ou=people,dc=test,dc=com",
        scope="ONELEVEL",
        filter="(objectClass=inetOrgPerson)",
        limit=50,
    )
    response_data = response.data

    # Verify response structure
    assert response_data["type"] == "ldap_search"
    assert response_data["base_dn"] == "ou=people,dc=test,dc=com"
    assert response_data["scope"] == "ONELEVEL"
    assert response_data["filter"] == "(objectClass=inetOrgPerson)"

    # Verify we found users
    assert response_data["total_returned"] >= len(expected_test_users)

    # Extract user IDs from the response
    found_users = []
    for item in response_data["items"]:
        if "attrs" in item and "uid" in item["attrs"]:
            uid_values = item["attrs"]["uid"]
            if isinstance(uid_values, list) and uid_values:
                found_users.append(uid_values[0])

    # Verify our test users are present
    for expected_user in expected_test_users:
        assert expected_user in found_users, f"Expected user {expected_user} not found in search results"

    print(f"✓ User-only search found {len(found_users)} users including all expected test users")


async def test_ldap_search_with_specific_attributes(dirsrv_server):
    """Test LDAP search requesting specific attributes only."""

    response = await call_tool(
        dirsrv_server,
        "ldap_search",
        base_dn="ou=people,dc=test,dc=com",
        scope="ONELEVEL",
        filter="(uid=testuser1)",
        attributes="uid,cn,mail",
        limit=10,
    )
    response_data = response.data

    # Verify response structure
    assert response_data["type"] == "ldap_search"
    assert response_data["attributes_requested"] == "uid,cn,mail"

    # Verify we found at least one result
    assert response_data["total_returned"] >= 1
    assert len(response_data["items"]) >= 1

    # Check that we only got the requested attributes (plus any operational attributes DS might add)
    user_entry = response_data["items"][0]
    assert "attrs" in user_entry
    attrs = user_entry["attrs"]

    # Verify requested attributes are present
    assert "uid" in attrs
    assert "cn" in attrs
    assert "mail" in attrs

    # Verify uid is testuser1
    assert "testuser1" in attrs["uid"]

    print("✓ Specific attributes search returned entry with requested attributes")


async def test_ldap_search_base_scope(dirsrv_server):
    """Test LDAP search with BASE scope (single entry)."""

    response = await call_tool(
        dirsrv_server,
        "ldap_search",
        base_dn="uid=testuser1,ou=people,dc=test,dc=com",
        scope="BASE",
        filter="(objectClass=*)",
        limit=10,
    )
    response_data = response.data

    # Verify response structure
    assert response_data["type"] == "ldap_search"
    assert response_data["base_dn"] == "uid=testuser1,ou=people,dc=test,dc=com"
    assert response_data["scope"] == "BASE"

    # BASE scope should return exactly one entry (the base DN itself)
    assert response_data["total_returned"] == 1
    assert len(response_data["items"]) == 1

    # Verify we got the correct entry
    entry = response_data["items"][0]
    assert entry["dn"] == "uid=testuser1,ou=people,dc=test,dc=com"
    assert "attrs" in entry
    assert "uid" in entry["attrs"]
    assert "testuser1" in entry["attrs"]["uid"]

    print("✓ BASE scope search returned exactly one entry as expected")


async def test_ldap_search_complex_filter(dirsrv_server):
    """Test LDAP search with complex filter."""

    response = await call_tool(
        dirsrv_server,
        "ldap_search",
        base_dn="ou=people,dc=test,dc=com",
        scope="SUBTREE",
        filter="(&(objectClass=inetOrgPerson)(uid=testuser*))",
        limit=50,
    )
    response_data = response.data

    # Verify response structure
    assert response_data["type"] == "ldap_search"
    assert response_data["filter"] == "(&(objectClass=inetOrgPerson)(uid=testuser*))"

    # Verify we found test users
    assert response_data["total_returned"] >= 2  # testuser1 and testuser2

    # Extract user IDs and verify they match our pattern
    found_users = []
    for item in response_data["items"]:
        if "attrs" in item and "uid" in item["attrs"]:
            uid_values = item["attrs"]["uid"]
            if isinstance(uid_values, list) and uid_values:
                found_users.append(uid_values[0])

    # All found users should match the testuser* pattern
    for user in found_users:
        assert user.startswith("testuser"), f"User {user} doesn't match testuser* pattern"

    print(f"✓ Complex filter search found {len(found_users)} matching users")


async def test_ldap_search_attrs_only(dirsrv_server):
    """Test LDAP search with attrs_only=True (attribute names only, no values)."""

    response = await call_tool(
        dirsrv_server,
        "ldap_search",
        base_dn="uid=testuser1,ou=people,dc=test,dc=com",
        scope="BASE",
        filter="(objectClass=*)",
        attrs_only=True,
        limit=10,
    )
    response_data = response.data

    # Verify response structure
    assert response_data["type"] == "ldap_search"
    assert response_data["attrs_only"] == True

    # Verify we got one entry
    assert response_data["total_returned"] == 1
    entry = response_data["items"][0]

    # When attrs_only=True, attribute values should be empty lists
    assert "attrs" in entry
    for attr_name, attr_values in entry["attrs"].items():
        assert isinstance(attr_values, list)
        assert len(attr_values) == 0, f"Attribute {attr_name} should have empty values with attrs_only=True"

    print("✓ attrs_only search returned attribute names without values")


async def test_ldap_search_invalid_scope(dirsrv_server):
    """Test LDAP search with invalid scope raises error."""

    with pytest.raises(ToolError) as exc_info:
        await call_tool(
            dirsrv_server,
            "ldap_search",
            base_dn="dc=test,dc=com",
            scope="INVALID",
            filter="(objectClass=*)",
            limit=10,
        )

    error_message = str(exc_info.value)
    assert "Invalid scope" in error_message

    print("✓ Invalid scope correctly raised ToolError")


async def test_ldap_search_nonexistent_base_dn(dirsrv_server):
    """Test LDAP search with non-existent base DN raises error."""

    with pytest.raises(ToolError) as exc_info:
        await call_tool(
            dirsrv_server,
            "ldap_search",
            base_dn="ou=nonexistent,dc=test,dc=com",
            scope="SUBTREE",
            filter="(objectClass=*)",
            limit=10,
        )

    error_message = str(exc_info.value)
    assert "does not exist" in error_message or "No such object" in error_message

    print("✓ Non-existent base DN correctly raised ToolError")


async def test_ldap_search_invalid_filter(dirsrv_server):
    """Test LDAP search with invalid filter syntax raises error."""

    with pytest.raises(ToolError) as exc_info:
        await call_tool(
            dirsrv_server,
            "ldap_search",
            base_dn="dc=test,dc=com",
            scope="SUBTREE",
            filter="(invalid_filter_syntax",
            limit=10,
        )

    error_message = str(exc_info.value)
    assert error_message

    print("✓ Invalid filter syntax correctly raised ToolError")


async def test_ldap_search_limit_enforcement(dirsrv_server):
    """Test that LDAP search respects the limit parameter."""

    response = await call_tool(
        dirsrv_server,
        "ldap_search",
        base_dn="dc=test,dc=com",
        scope="SUBTREE",
        filter="(objectClass=*)",
        limit=2,
    )
    response_data = response.data

    # Verify limit was applied
    assert response_data["limit_applied"] == 2
    assert response_data["total_returned"] <= 2
    assert len(response_data["items"]) <= 2

    print(
        f"✓ Limit enforcement working - returned {response_data['total_returned']} entries with limit 2"
    )


async def test_ldap_search_groups(dirsrv_server, expected_test_groups):
    """Test LDAP search for group entries."""

    response = await call_tool(
        dirsrv_server,
        "ldap_search",
        base_dn="ou=groups,dc=test,dc=com",
        scope="ONELEVEL",
        filter="(objectClass=groupOfNames)",
        attributes="cn,gidNumber",
        limit=50,
    )
    response_data = response.data

    # Verify we found groups
    assert response_data["total_returned"] >= len(expected_test_groups)

    # Extract group names
    found_groups = []
    for item in response_data["items"]:
        if "attrs" in item and "cn" in item["attrs"]:
            cn_values = item["attrs"]["cn"]
            if isinstance(cn_values, list) and cn_values:
                found_groups.append(cn_values[0])

    # Verify our test groups are present
    for expected_group in expected_test_groups:
        assert expected_group in found_groups, f"Expected group {expected_group} not found in search results"

    print(f"✓ Group search found {len(found_groups)} groups including all expected test groups")
