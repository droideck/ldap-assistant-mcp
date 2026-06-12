"""Phase 0 regression tests: offline/archive replication detection.

Real dse.ldif files write replica attributes in camelCase
(nsDS5ReplicaRoot, nsDS5ReplicaType, nsDS5Flags, ...), but the patched
DSEldif._find_attr used to match attribute names case-sensitively, so
every lowercase lookup missed and replication was reported as
``enabled: false`` on every real instance.

These tests verify:
1. DSEldif attribute lookups (via the dse_utils patch) are
   case-insensitive while still requiring an exact attribute-name match.
2. The offline/archive backend tool detects replication from a
   realistic camelCase replica entry and derives the correct role from
   nsDS5ReplicaType + nsDS5Flags (3 -> supplier, 2+1 -> hub,
   2+0 -> consumer).
"""

from __future__ import annotations

import asyncio
import os
from unittest.mock import MagicMock, patch

import pytest
from fastmcp import Client

# Importing dse_utils applies the DSEldif._find_attr patch under test.
from ldap_assistant_mcp.dirsrv_mcp.tools import dse_utils  # noqa: F401
from ldap_assistant_mcp.dirsrv_mcp.tools.config import (
    _replica_role_from_type_flags,
)
from ldap_assistant_mcp.dirsrv_mcp.server import DirSrvMCP
from ldap_assistant_mcp.core import LDAPServerConfig

from lib389.dseldif import DSEldif


REPLICA_DN = 'cn=replica,cn="dc=example,dc=com",cn=mapping tree,cn=config'

# Realistic dse.ldif skeleton: cn=config, plugins, one ldbm backend, and
# the mapping tree for dc=example,dc=com.  Replica entry appended per test.
BASE_DSE_LDIF = """\
dn: cn=config
objectClass: top
objectClass: extensibleObject
objectClass: nsslapdConfig
cn: config
nsslapd-port: 389
nsslapd-secureport: 636
nsslapd-versionstring: 389-Directory/2.4.6
nsslapd-localhost: localhost.localdomain
nsslapd-listenhost:
nsslapd-security: on

dn: cn=plugins,cn=config
objectClass: top
objectClass: nsContainer
cn: plugins

dn: cn=ldbm database,cn=plugins,cn=config
objectClass: top
objectClass: nsSlapdPlugin
cn: ldbm database
nsslapd-pluginEnabled: on
nsslapd-pluginType: database

dn: cn=userRoot,cn=ldbm database,cn=plugins,cn=config
objectClass: top
objectClass: extensibleObject
objectClass: nsBackendInstance
cn: userRoot
nsslapd-suffix: dc=example,dc=com
nsslapd-cachememsize: 209715200

dn: cn=index,cn=userRoot,cn=ldbm database,cn=plugins,cn=config
objectClass: top
objectClass: extensibleObject
cn: index

dn: cn=uid,cn=index,cn=userRoot,cn=ldbm database,cn=plugins,cn=config
objectClass: top
objectClass: nsIndex
cn: uid
nsSystemIndex: false
nsIndexType: eq
nsIndexType: pres
nsIndexType: sub

dn: cn=mapping tree,cn=config
objectClass: top
objectClass: extensibleObject
cn: mapping tree

dn: cn="dc=example,dc=com",cn=mapping tree,cn=config
objectClass: top
objectClass: extensibleObject
objectClass: nsMappingTree
cn: "dc=example,dc=com"
nsslapd-state: backend
nsslapd-backend: userRoot
"""


def _replica_entry(rtype: str, flags: str | None) -> str:
    """Build a camelCase replica entry, as 389 DS writes it to dse.ldif."""
    lines = [
        "",
        f"dn: {REPLICA_DN}",
        "objectClass: top",
        "objectClass: nsDS5Replica",
        "objectClass: extensibleObject",
        "cn: replica",
        "nsDS5ReplicaRoot: dc=example,dc=com",
        "nsDS5ReplicaId: 1",
        f"nsDS5ReplicaType: {rtype}",
        "nsDS5ReplicaName: 66a2b699-1dd211b2-80de93a8-00000000",
        "nsDS5ReplicaBindDN: cn=replication manager,cn=config",
    ]
    if flags is not None:
        lines.append(f"nsDS5Flags: {flags}")
    # Real dse.ldif files end with a blank line; lib389's DSEldif reader
    # drops the very last line of the file, so the trailing newline matters.
    return "\n".join(lines) + "\n\n"


def _write_archive(tmp_path, dse_content: str):
    """Write an SOS-report-like archive layout under tmp_path."""
    inst = "slapd-replication-test"
    config_dir = tmp_path / "etc" / "dirsrv" / inst
    config_dir.mkdir(parents=True)
    (config_dir / "dse.ldif").write_text(dse_content)

    logs_dir = tmp_path / "var" / "log" / "dirsrv" / inst
    logs_dir.mkdir(parents=True)
    (logs_dir / "access").write_text("")
    (logs_dir / "errors").write_text("")
    return tmp_path


def _archive_mcp(archive_path: str) -> DirSrvMCP:
    config = LDAPServerConfig(
        name="archive-test",
        hostname="archive",
        port=0,
        is_archive=True,
        archive_path=archive_path,
    )
    return DirSrvMCP(
        servers=[config],
        include_env_fallback=False,
    )


@pytest.fixture
def archive_env():
    """Ensure no external config leaks into tests."""
    env = {
        "LDAP_MCP_EXPOSE_SENSITIVE_DATA": "true",
        "LDAP_SERVERS_CONFIG": "",
    }
    with patch.dict(os.environ, env):
        yield


# DSEldif._find_attr case-insensitivity (dse_utils patch)


class TestFindAttrCaseInsensitive:
    """Patched DSEldif._find_attr must match attribute names case-insensitively."""

    @pytest.fixture
    def dse(self, tmp_path):
        dse_path = tmp_path / "dse.ldif"
        dse_path.write_text(BASE_DSE_LDIF + _replica_entry("3", "1"))
        return DSEldif(MagicMock(), path=str(dse_path))

    def test_lowercase_query_matches_camelcase_attr(self, dse):
        """nsds5replicaroot must find nsDS5ReplicaRoot."""
        assert dse.get(REPLICA_DN, "nsds5replicaroot", single=True) == \
            "dc=example,dc=com"

    def test_camelcase_query_matches_camelcase_attr(self, dse):
        assert dse.get(REPLICA_DN, "nsDS5ReplicaType", single=True) == "3"

    def test_mixed_case_query_matches_lowercase_attr(self, dse):
        """Querying with different case must find lowercase file attrs too."""
        assert dse.get("cn=config", "NSSLAPD-PORT", single=True) == "389"

    def test_flags_lookup(self, dse):
        assert dse.get(REPLICA_DN, "nsds5flags", single=True) == "1"

    def test_no_prefix_false_match(self, dse):
        """An attr-name prefix must not match (nsDS5Replica vs nsDS5ReplicaRoot)."""
        assert dse.get(REPLICA_DN, "nsds5replica", single=True) is None

    def test_missing_attr_returns_none(self, dse):
        assert dse.get(REPLICA_DN, "nonexistentattr", single=True) is None

    def test_empty_value_does_not_crash(self, dse):
        """'attr:' with no value (nsslapd-listenhost:) must parse as empty."""
        assert dse.get("cn=config", "nsslapd-listenhost", single=True) == ""

    def test_multivalued_attr_returns_all_values(self, dse):
        index_dn = "cn=uid,cn=index,cn=userRoot,cn=ldbm database,cn=plugins,cn=config"
        values = dse.get(index_dn, "nsindextype")
        assert values == ["eq", "pres", "sub"]


# Role derivation helper


class TestReplicaRoleFromTypeFlags:
    """Role derivation must mirror lib389 (type 3=supplier, 2+1=hub, 2+0=consumer)."""

    def test_supplier(self):
        assert _replica_role_from_type_flags("3", "1") == "supplier"

    def test_supplier_without_flags(self):
        assert _replica_role_from_type_flags("3", None) == "supplier"

    def test_hub(self):
        assert _replica_role_from_type_flags("2", "1") == "hub"

    def test_consumer(self):
        assert _replica_role_from_type_flags("2", "0") == "consumer"

    def test_consumer_without_flags(self):
        """Missing nsDS5Flags defaults to 0 -> consumer."""
        assert _replica_role_from_type_flags("2", None) == "consumer"

    def test_unknown_type(self):
        assert _replica_role_from_type_flags("9", "1") == "unknown"

    def test_no_type(self):
        assert _replica_role_from_type_flags(None, None) == "unknown"


# End-to-end through the offline/archive config tool


class TestOfflineReplicationDetection:
    """get_backend_configuration must detect camelCase replica entries."""

    def _get_user_root(self, archive_path: str):
        mcp = _archive_mcp(archive_path)

        async def run():
            async with Client(mcp) as client:
                result = await client.call_tool(
                    "get_backend_configuration",
                    {"server_name": "archive-test"},
                )
                return result.data

        data = asyncio.run(run())
        assert data["type"] == "backend_configuration"
        assert "error" not in data
        backends = data.get("backends", [])
        assert len(backends) >= 1
        return next(b for b in backends if b["name"] == "userRoot")

    def test_supplier_detected(self, archive_env, tmp_path):
        """Type 3 + flags 1 (camelCase attrs) -> enabled, role supplier."""
        archive = _write_archive(
            tmp_path, BASE_DSE_LDIF + _replica_entry("3", "1")
        )
        user_root = self._get_user_root(str(archive))
        assert user_root["replication"]["enabled"] is True
        assert user_root["replication"]["role"] == "supplier"

    def test_hub_detected(self, archive_env, tmp_path):
        """Type 2 + flags 1 -> enabled, role hub."""
        archive = _write_archive(
            tmp_path, BASE_DSE_LDIF + _replica_entry("2", "1")
        )
        user_root = self._get_user_root(str(archive))
        assert user_root["replication"]["enabled"] is True
        assert user_root["replication"]["role"] == "hub"

    def test_consumer_detected(self, archive_env, tmp_path):
        """Type 2 + flags 0 -> enabled, role consumer."""
        archive = _write_archive(
            tmp_path, BASE_DSE_LDIF + _replica_entry("2", "0")
        )
        user_root = self._get_user_root(str(archive))
        assert user_root["replication"]["enabled"] is True
        assert user_root["replication"]["role"] == "consumer"

    def test_supplier_without_flags(self, archive_env, tmp_path):
        """Type 3 with no nsDS5Flags attr is still a supplier."""
        archive = _write_archive(
            tmp_path, BASE_DSE_LDIF + _replica_entry("3", None)
        )
        user_root = self._get_user_root(str(archive))
        assert user_root["replication"]["enabled"] is True
        assert user_root["replication"]["role"] == "supplier"

    def test_no_replica_entry_reports_disabled(self, archive_env, tmp_path):
        """Without a replica entry, replication must stay disabled."""
        archive = _write_archive(tmp_path, BASE_DSE_LDIF)
        user_root = self._get_user_root(str(archive))
        assert user_root["replication"] == {"enabled": False}
