"""Tests for Phase 0 privacy-mode leak fixes (IMPROVEMENT-PLAN 0.6).

Covers:
- Credential attributes (ALWAYS_REDACT_ATTRIBUTES) stripped unconditionally
  from user/group/search tool outputs — in BOTH privacy modes.
- compare_dse_configs redacts credential hash values regardless of mode.
- Mapping-tree DNs no longer leak suffixes through privacy mode.
- format_tool_error sanitizes tracebacks in debug+privacy mode.
- list_replication_conflicts per-entry error strings are sanitized.
- PrivacySanitizer mapping dicts are bounded by _MAX_MAPPING_SIZE.
- search_users_by_attribute is disabled in privacy mode (count-oracle).

No live LDAP server is required: the LDAP layer is mocked and LDIF
fixtures are written to tmp_path.
"""

from __future__ import annotations

import json
import os
from contextlib import contextmanager
from unittest.mock import MagicMock, patch

import pytest
from fastmcp import Client

from ldap_assistant_mcp.core import LDAPServerConfig, MCPSettings
from ldap_assistant_mcp.dirsrv_mcp.server import DirSrvMCP
from ldap_assistant_mcp.lib.privacy import (
    _MAX_MAPPING_SIZE,
    PrivacySanitizer,
    strip_credential_attributes,
)


# ── Helpers ──────────────────────────────────────────────────────────

def _make_mcp(privacy_enabled: bool = True, debug_enabled: bool = False) -> MagicMock:
    """Build a minimal MCP mock with a real PrivacySanitizer."""
    mcp = MagicMock()
    mcp.privacy_enabled = privacy_enabled
    mcp.debug_enabled = debug_enabled
    mcp.sanitizer = PrivacySanitizer()
    return mcp


def _make_server(expose: bool) -> DirSrvMCP:
    """Create a DirSrvMCP with one live-mode server config (never contacted)."""
    config = LDAPServerConfig(
        name="ds-mock",
        hostname="localhost",
        port=33891,
        base_dn="dc=example,dc=com",
        bind_dn="cn=Directory Manager",
        bind_password="TestPassword123",
    )
    env = {k: v for k, v in os.environ.items() if k != "LDAP_SERVERS_CONFIG"}
    with patch.dict(os.environ, env, clear=True):
        return DirSrvMCP(
            servers=[config],
            include_env_fallback=False,
            settings=MCPSettings(expose_sensitive_data=expose),
        )


def _install_fake_connection(server: DirSrvMCP, ds) -> None:
    """Replace server._connection so tools never open a real LDAP connection."""

    @contextmanager
    def _conn(server_name=None):
        yield (server_name or server.default_server, ds)

    server._connection = _conn


class FakeEntry:
    """Minimal stand-in for a lib389 DSLdapObject entry."""

    def __init__(self, dn: str, attrs: dict):
        self.dn = dn
        self._data = {"dn": dn, "attrs": attrs}

    def get_all_attrs_json(self) -> str:
        return json.dumps(self._data)


_FAKE_STATUS = {
    "simple_status": "active",
    "detailed_status": "ACTIVATED",
    "status_params": {},
    "calc_time": None,
}

_USER_ATTRS = {
    "uid": ["jdoe"],
    "cn": ["John Doe"],
    "userPassword": ["{PBKDF2-SHA512}10000$AAAAsecrethash"],
    "nsslapd-rootpw": ["{SSHA512}rootsecrethash"],
    "userCertificate": ["MIIBbase64cert"],
    "mail": ["jdoe@example.com"],
}


# ── strip_credential_attributes (unit) ───────────────────────────────

class TestStripCredentialAttributes:
    def test_strips_always_redact_case_insensitive(self):
        attrs = {
            "userPassword": ["hash"],
            "USERPASSWORD": ["hash2"],
            "nsDS5ReplicaCredentials": ["{AES}secret"],
            "jpegPhoto": ["binary"],
            "uid": ["jdoe"],
        }
        stripped = strip_credential_attributes(attrs)
        assert "uid" in stripped
        for key in stripped:
            assert key.lower() not in {
                "userpassword", "nsds5replicacredentials", "jpegphoto",
            }

    def test_preserves_other_attributes(self):
        attrs = {"uid": ["jdoe"], "mail": ["a@b.com"], "cn": ["John"]}
        assert strip_credential_attributes(attrs) == attrs


# ── User tools strip credentials in BOTH modes ───────────────────────

class TestUserToolsCredentialStripping:
    @pytest.mark.asyncio
    async def test_get_user_details_strips_credentials_exposed_mode(self):
        server = _make_server(expose=True)
        ds = MagicMock()
        _install_fake_connection(server, ds)

        users_obj = MagicMock()
        users_obj.get.return_value = FakeEntry(
            "uid=jdoe,dc=example,dc=com", dict(_USER_ATTRS)
        )
        with patch(
            "ldap_assistant_mcp.dirsrv_mcp.tools.users.nsUserAccounts",
            return_value=users_obj,
        ), patch(
            "ldap_assistant_mcp.dirsrv_mcp.tools.users._get_user_status",
            return_value=dict(_FAKE_STATUS),
        ):
            async with Client(server) as client:
                result = await client.call_tool(
                    "get_user_details", {"username": "jdoe"}
                )
                data = result.data

        attrs = data["user"]["attrs"]
        assert attrs["uid"] == ["jdoe"]
        for key in attrs:
            assert key.lower() not in {
                "userpassword", "nsslapd-rootpw", "usercertificate",
            }
        serialized = json.dumps(data)
        assert "secrethash" not in serialized
        assert "base64cert" not in serialized

    @pytest.mark.asyncio
    async def test_list_all_users_strips_credentials_exposed_mode(self):
        server = _make_server(expose=True)
        ds = MagicMock()
        _install_fake_connection(server, ds)

        users_obj = MagicMock()
        users_obj.list.return_value = [
            FakeEntry("uid=jdoe,dc=example,dc=com", dict(_USER_ATTRS)),
        ]
        with patch(
            "ldap_assistant_mcp.dirsrv_mcp.tools.users.nsUserAccounts",
            return_value=users_obj,
        ), patch(
            "ldap_assistant_mcp.dirsrv_mcp.tools.users._get_user_status",
            return_value=dict(_FAKE_STATUS),
        ):
            async with Client(server) as client:
                result = await client.call_tool("list_all_users", {})
                data = result.data

        assert data["total_returned"] == 1
        attrs = data["items"][0]["attrs"]
        assert attrs["uid"] == ["jdoe"]
        assert "secrethash" not in json.dumps(data)
        for key in attrs:
            assert key.lower() != "userpassword"

    @pytest.mark.asyncio
    async def test_list_all_users_privacy_mode_no_credentials(self):
        server = _make_server(expose=False)
        ds = MagicMock()
        _install_fake_connection(server, ds)

        users_obj = MagicMock()
        users_obj.list.return_value = [
            FakeEntry("uid=jdoe,dc=example,dc=com", dict(_USER_ATTRS)),
        ]
        with patch(
            "ldap_assistant_mcp.dirsrv_mcp.tools.users.nsUserAccounts",
            return_value=users_obj,
        ):
            async with Client(server) as client:
                result = await client.call_tool("list_all_users", {})
                data = result.data

        assert data["privacy_mode"] is True
        assert data["count"] == 1
        assert "items" not in data
        assert "secrethash" not in json.dumps(data)


# ── Group tools strip credentials ────────────────────────────────────

class TestGroupToolsCredentialStripping:
    @pytest.mark.asyncio
    async def test_list_all_groups_strips_credentials_exposed_mode(self):
        server = _make_server(expose=True)
        ds = MagicMock()
        _install_fake_connection(server, ds)

        group_attrs = {
            "cn": ["admins"],
            "member": ["uid=jdoe,dc=example,dc=com"],
            "userPassword": ["{SSHA}groupsecrethash"],
        }
        groups_obj = MagicMock()
        groups_obj.list.return_value = [
            FakeEntry("cn=admins,ou=groups,dc=example,dc=com", group_attrs),
        ]
        with patch(
            "ldap_assistant_mcp.dirsrv_mcp.tools.groups.Groups",
            return_value=groups_obj,
        ):
            async with Client(server) as client:
                result = await client.call_tool("list_all_groups", {})
                data = result.data

        assert data["total_returned"] == 1
        attrs = data["items"][0]["attrs"]
        assert attrs["cn"] == ["admins"]
        assert attrs["member"] == ["uid=jdoe,dc=example,dc=com"]
        for key in attrs:
            assert key.lower() != "userpassword"
        assert "groupsecrethash" not in json.dumps(data)


# ── ldap_search strips credentials ───────────────────────────────────

class TestLdapSearchCredentialStripping:
    @pytest.mark.asyncio
    async def test_ldap_search_strips_credentials_exposed_mode(self):
        import ldap as _ldap

        server = _make_server(expose=True)
        ds = MagicMock()
        # ldap_search issues an async search (search_ext + result loop) so
        # partial results survive SIZELIMIT_EXCEEDED.
        ds.search_ext.return_value = 1
        ds.result.side_effect = [
            (
                _ldap.RES_SEARCH_ENTRY,
                [
                    (
                        "uid=jdoe,dc=example,dc=com",
                        {
                            "uid": [b"jdoe"],
                            "userPassword": [b"{PBKDF2-SHA512}searchsecrethash"],
                            "nsds5ReplicaCredentials": [b"{AES}replsecret"],
                            "mail": [b"jdoe@example.com"],
                        },
                    ),
                ],
            ),
            (_ldap.RES_SEARCH_RESULT, []),
        ]
        _install_fake_connection(server, ds)

        async with Client(server) as client:
            result = await client.call_tool(
                "ldap_search",
                {"base_dn": "dc=example,dc=com", "filter": "(uid=jdoe)"},
            )
            data = result.data

        assert data["total_returned"] == 1
        attrs = data["items"][0]["attrs"]
        assert attrs["uid"] == ["jdoe"]
        assert attrs["mail"] == ["jdoe@example.com"]
        for key in attrs:
            assert key.lower() not in {"userpassword", "nsds5replicacredentials"}
        serialized = json.dumps(data)
        assert "searchsecrethash" not in serialized
        assert "replsecret" not in serialized


# ── search_users_by_attribute count-oracle guard ─────────────────────

class TestSearchUsersByAttributePrivacyGuard:
    @pytest.mark.asyncio
    async def test_disabled_in_privacy_mode(self):
        server = _make_server(expose=False)
        # No connection installed: the guard must trigger before any
        # LDAP work happens.
        async with Client(server) as client:
            result = await client.call_tool(
                "search_users_by_attribute",
                {"attribute": "mail", "value": "a"},
            )
            data = result.data

        assert data["type"] == "privacy_restricted"
        assert "disabled" in data["error"].lower()
        assert "count" not in data

    @pytest.mark.asyncio
    async def test_works_in_exposed_mode(self):
        server = _make_server(expose=True)
        ds = MagicMock()
        _install_fake_connection(server, ds)

        users_obj = MagicMock()
        users_obj.filter.return_value = [
            FakeEntry("uid=jdoe,dc=example,dc=com", dict(_USER_ATTRS)),
        ]
        with patch(
            "ldap_assistant_mcp.dirsrv_mcp.tools.users.nsUserAccounts",
            return_value=users_obj,
        ), patch(
            "ldap_assistant_mcp.dirsrv_mcp.tools.users._get_user_status",
            return_value=dict(_FAKE_STATUS),
        ):
            async with Client(server) as client:
                result = await client.call_tool(
                    "search_users_by_attribute",
                    {"attribute": "mail", "value": "jdoe"},
                )
                data = result.data

        assert data["type"] == "attribute_search"
        assert data["total_returned"] == 1
        # Credentials stripped here too
        assert "secrethash" not in json.dumps(data)


# ── compare_dse_configs credential redaction ─────────────────────────

_DSE_TEMPLATE = """dn: cn=config
cn: config
nsslapd-rootpw: {rootpw}
nsslapd-port: {port}

dn: cn="dc=acme,dc=com",cn=mapping tree,cn=config
cn: dc=acme,dc=com
nsslapd-state: backend

dn: cn=replica,cn="dc=acme,dc=com",cn=mapping tree,cn=config
cn: replica
nsds5ReplicaCredentials: {creds}
nsds5ReplicaId: {replica_id}
"""


def _compare_fixture(tmp_path):
    """Build a dse_comparison result from two real dse.ldif files."""
    from lib389._ldifconn import LDIFConn

    from ldap_assistant_mcp.dirsrv_mcp.tools.archive import _compare_ldif_entries

    path1 = tmp_path / "dse1.ldif"
    path2 = tmp_path / "dse2.ldif"
    path1.write_text(_DSE_TEMPLATE.format(
        rootpw="{PBKDF2-SHA512}10000$AAAAroothash1",
        port="389",
        creds="{AES}replcredhash1",
        replica_id="1",
    ))
    path2.write_text(_DSE_TEMPLATE.format(
        rootpw="{PBKDF2-SHA512}10000$AAAAroothash2",
        port="3389",
        creds="{AES}replcredhash2",
        replica_id="2",
    ))
    return _compare_ldif_entries(
        LDIFConn(str(path1)), LDIFConn(str(path2)), "server-a", "server-b"
    )


class TestCompareDseCredentialRedaction:
    def test_credentials_redacted_unconditionally(self, tmp_path):
        """Raw compare output never carries credential hashes."""
        result = _compare_fixture(tmp_path)
        serialized = json.dumps(result)
        assert "roothash" not in serialized
        assert "replcredhash" not in serialized

        # The differences are still noted, with placeholder values
        diff_attrs = {
            dv["attribute"].lower(): dv
            for d in result["differences"]
            for dv in d["different_values"]
        }
        assert diff_attrs["nsslapd-rootpw"]["server1"] == ["<redacted>"]
        assert diff_attrs["nsslapd-rootpw"]["server2"] == ["<redacted>"]
        assert diff_attrs["nsds5replicacredentials"]["server1"] == ["<redacted>"]

        # Non-credential attributes keep their raw values
        assert diff_attrs["nsslapd-port"]["server1"] == ["389"]
        assert diff_attrs["nsslapd-port"]["server2"] == ["3389"]

    def test_no_hash_after_sanitize_privacy_off(self, tmp_path):
        from ldap_assistant_mcp.dirsrv_mcp.tools.archive import _sanitize_archive_result

        mcp = _make_mcp(privacy_enabled=False)
        sanitized = _sanitize_archive_result(mcp, _compare_fixture(tmp_path))
        serialized = json.dumps(sanitized)
        assert "roothash" not in serialized
        assert "replcredhash" not in serialized

    def test_no_hash_after_sanitize_privacy_on(self, tmp_path):
        from ldap_assistant_mcp.dirsrv_mcp.tools.archive import _sanitize_archive_result

        mcp = _make_mcp(privacy_enabled=True)
        sanitized = _sanitize_archive_result(mcp, _compare_fixture(tmp_path))
        serialized = json.dumps(sanitized)
        assert "roothash" not in serialized
        assert "replcredhash" not in serialized


# ── Mapping-tree DN suffix sanitization ──────────────────────────────

class TestMappingTreeDnSanitization:
    def test_mapping_tree_dns_sanitized_privacy_on(self):
        from ldap_assistant_mcp.dirsrv_mcp.tools.archive import _sanitize_archive_result

        mcp = _make_mcp(privacy_enabled=True)
        result = {
            "type": "dse_comparison",
            "server1": "a",
            "server2": "b",
            "only_in_server1": [
                'cn="dc=acme,dc=com",cn=mapping tree,cn=config',
                "cn=MemberOf Plugin,cn=plugins,cn=config",
            ],
            "only_in_server2": [
                'cn=replica,cn="dc=acme,dc=com",cn=mapping tree,cn=config',
            ],
            "differences": [
                {
                    "dn": 'cn="dc=acme,dc=com",cn=mapping tree,cn=config',
                    "attrs_only_in_server1": [],
                    "attrs_only_in_server2": [],
                    "different_values": [],
                },
            ],
        }
        sanitized = _sanitize_archive_result(mcp, result)
        serialized = json.dumps(sanitized)

        # The user suffix must not leak anywhere
        assert "acme" not in serialized

        # The mapping-tree structure remains identifiable
        mt_dn = sanitized["only_in_server1"][0]
        assert mt_dn.endswith("cn=mapping tree,cn=config")
        assert "[suffix-" in mt_dn

        replica_dn = sanitized["only_in_server2"][0]
        assert replica_dn.startswith("cn=replica,")
        assert replica_dn.endswith("cn=mapping tree,cn=config")
        assert "[suffix-" in replica_dn

        diff_dn = sanitized["differences"][0]["dn"]
        assert "acme" not in diff_dn
        assert "[suffix-" in diff_dn

        # Plain config DNs are still kept clear (server metadata)
        assert sanitized["only_in_server1"][1] == \
            "cn=MemberOf Plugin,cn=plugins,cn=config"

    def test_suffix_token_consistent_with_sanitize_suffix(self):
        """Mapping-tree RDN uses the same token as sanitize_suffix."""
        from ldap_assistant_mcp.dirsrv_mcp.tools.archive import _sanitize_config_entry_dn

        sanitizer = PrivacySanitizer()
        expected = sanitizer.sanitize_suffix("dc=acme,dc=com")
        dn = _sanitize_config_entry_dn(
            sanitizer, 'cn="dc=acme,dc=com",cn=mapping tree,cn=config'
        )
        assert expected in dn

    def test_mapping_tree_dns_clear_privacy_off(self):
        from ldap_assistant_mcp.dirsrv_mcp.tools.archive import _sanitize_archive_result

        mcp = _make_mcp(privacy_enabled=False)
        result = {
            "type": "dse_comparison",
            "only_in_server1": [
                'cn="dc=acme,dc=com",cn=mapping tree,cn=config',
            ],
        }
        sanitized = _sanitize_archive_result(mcp, result)
        assert sanitized["only_in_server1"] == [
            'cn="dc=acme,dc=com",cn=mapping tree,cn=config',
        ]


# ── Traceback sanitization in debug+privacy mode ─────────────────────

def _raise_sensitive_error():
    raise ValueError(
        "Bind failed to ldap://prod1.example.com:636 as "
        "uid=admin,dc=example,dc=com (config: /etc/dirsrv/slapd-prod/dse.ldif)"
    )


class TestTracebackSanitization:
    def test_traceback_sanitized_in_debug_privacy_mode(self):
        from ldap_assistant_mcp.dirsrv_mcp.tools.error_utils import format_tool_error

        mcp = _make_mcp(privacy_enabled=True, debug_enabled=True)
        try:
            _raise_sensitive_error()
        except ValueError as exc:
            result = format_tool_error(exc, mcp, "test_tool")

        assert "traceback" in result
        tb_text = "".join(result["traceback"])
        assert "example.com" not in tb_text
        assert "dc=example" not in tb_text
        assert "/etc/dirsrv" not in tb_text
        # The test file's own path must be scrubbed as well
        assert __file__ not in tb_text
        # And the scrubbed error text stays scrubbed
        assert "example.com" not in result["error"]

    def test_traceback_verbatim_when_privacy_off(self):
        from ldap_assistant_mcp.dirsrv_mcp.tools.error_utils import format_tool_error

        mcp = _make_mcp(privacy_enabled=False, debug_enabled=True)
        try:
            _raise_sensitive_error()
        except ValueError as exc:
            result = format_tool_error(exc, mcp, "test_tool")

        tb_text = "".join(result["traceback"])
        assert "example.com" in tb_text

    def test_no_traceback_when_debug_off(self):
        from ldap_assistant_mcp.dirsrv_mcp.tools.error_utils import format_tool_error

        mcp = _make_mcp(privacy_enabled=True, debug_enabled=False)
        try:
            _raise_sensitive_error()
        except ValueError as exc:
            result = format_tool_error(exc, mcp, "test_tool")

        assert "traceback" not in result


# ── Replication conflict/glue error sanitization ─────────────────────

class TestReplicationConflictErrorSanitization:
    def test_conflict_and_glue_errors_sanitized(self):
        from ldap_assistant_mcp.dirsrv_mcp.tools.replication import (
            _sanitize_replication_result,
        )

        mcp = _make_mcp(privacy_enabled=True)
        result = {
            "type": "replication_conflicts",
            "server": "ds-test-1",
            "conflicts": [
                {
                    "dn": "nsuniqueid=abc+uid=user1,dc=example,dc=com",
                    "error": (
                        "NO_SUCH_OBJECT for uid=user1,dc=example,dc=com "
                        "on host1.example.com"
                    ),
                },
            ],
            "glue_entries": [
                {
                    "dn": "ou=people,dc=example,dc=com",
                    "error": "Read failed: /var/lib/dirsrv/slapd-x/db corrupted",
                },
            ],
        }
        sanitized = _sanitize_replication_result(mcp, result)

        conflict = sanitized["conflicts"][0]
        assert "example.com" not in conflict["error"]
        assert "dc=example" not in conflict["error"]

        glue = sanitized["glue_entries"][0]
        assert "/var/lib/dirsrv" not in glue["error"]

    def test_entries_without_error_unaffected(self):
        from ldap_assistant_mcp.dirsrv_mcp.tools.replication import (
            _sanitize_replication_result,
        )

        mcp = _make_mcp(privacy_enabled=True)
        result = {
            "type": "replication_conflicts",
            "server": "ds-test-1",
            "conflicts": [
                {
                    "dn": "uid=user1,dc=example,dc=com",
                    "suffix": "dc=example,dc=com",
                    "conflict_attribute": None,
                    "valid_entry_dn": None,
                },
            ],
            "glue_entries": [],
        }
        sanitized = _sanitize_replication_result(mcp, result)
        assert "error" not in sanitized["conflicts"][0]

    def test_pass_through_when_privacy_off(self):
        from ldap_assistant_mcp.dirsrv_mcp.tools.replication import (
            _sanitize_replication_result,
        )

        mcp = _make_mcp(privacy_enabled=False)
        result = {
            "type": "replication_conflicts",
            "server": "ds-test-1",
            "conflicts": [
                {"dn": "uid=u,dc=example,dc=com", "error": "raw error text"},
            ],
        }
        sanitized = _sanitize_replication_result(mcp, result)
        assert sanitized["conflicts"][0]["error"] == "raw error text"


# ── Sanitizer mapping size cap ───────────────────────────────────────

class TestSanitizerMappingCap:
    def test_cap_evicts_oldest_half(self):
        sanitizer = PrivacySanitizer()
        tokens = {}
        for i in range(_MAX_MAPPING_SIZE + 1):
            name = f"host{i}.example.com"
            tokens[name] = sanitizer.sanitize_hostname(name)

        # Bounded: one eviction of the oldest half has happened
        assert len(sanitizer._hostname_map) <= _MAX_MAPPING_SIZE
        assert len(sanitizer._hostname_map) == _MAX_MAPPING_SIZE // 2 + 1

        # Oldest entries evicted, recent entries survive
        assert "host0.example.com" not in sanitizer._hostname_map
        assert f"host{_MAX_MAPPING_SIZE}.example.com" in sanitizer._hostname_map
        assert f"host{_MAX_MAPPING_SIZE - 1}.example.com" in sanitizer._hostname_map

    def test_evicted_value_token_stable(self):
        """Re-sanitizing an evicted value yields the same token (keyed hash)."""
        sanitizer = PrivacySanitizer()
        first_token = sanitizer.sanitize_hostname("host0.example.com")
        for i in range(1, _MAX_MAPPING_SIZE + 1):
            sanitizer.sanitize_hostname(f"host{i}.example.com")
        assert "host0.example.com" not in sanitizer._hostname_map
        assert sanitizer.sanitize_hostname("host0.example.com") == first_token

    def test_dn_map_also_bounded(self):
        sanitizer = PrivacySanitizer()
        for i in range(_MAX_MAPPING_SIZE + 1):
            sanitizer.sanitize_dn(f"uid=user{i},dc=example,dc=com")
        assert len(sanitizer._dn_map) <= _MAX_MAPPING_SIZE

    def test_existing_key_does_not_trigger_eviction(self):
        """Re-looking-up a cached value never evicts."""
        sanitizer = PrivacySanitizer()
        for i in range(_MAX_MAPPING_SIZE):
            sanitizer.sanitize_suffix(f"dc=org{i},dc=com")
        assert len(sanitizer._suffix_map) == _MAX_MAPPING_SIZE
        sanitizer.sanitize_suffix("dc=org0,dc=com")
        assert len(sanitizer._suffix_map) == _MAX_MAPPING_SIZE
