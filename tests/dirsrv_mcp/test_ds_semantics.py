"""Regression tests: 389 DS semantic corrections.

Covers:

- Archive replica roles derive from nsDS5ReplicaType AND nsDS5Flags
  (type=2/flags=0 is a consumer, not a hub).
- An agreement still catching up ("Replication still in progress")
  is not synchronized and must not be counted in in_sync_count.
- lib389 contacts the consumer with the supplier's credentials; a
  credential rejection means consumer status is UNKNOWN, not an error.
- Topology SPOF/orphan analysis reasons over actual agreement
  edges, and reports UNKNOWN when agreement collection failed.
- Index recommendations carry basis/risk metadata and
  workload-dependent suggestions are LOW severity.
- Unindexed-search remediation maps the filter operator to the
  right index type (pres/sub/approx/eq, with a range caveat).
- Certificate expiry severity depends on whether the cert is the
  ACTIVE server certificate (nsSSLPersonalitySSL), not mere NSS DB presence.

All tests are non-live: lib389 objects are mocked at the tool-module
boundary, or real DSEldif/log parsing runs against tmp_path SOS trees.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import ldap
import pytest
from fastmcp import Client
from lib389._constants import ReplicaRole

import ldap_assistant_mcp.dirsrv_mcp.tools.health as health
import ldap_assistant_mcp.dirsrv_mcp.tools.indexes as indexes
import ldap_assistant_mcp.dirsrv_mcp.tools.replication as replication
from ldap_assistant_mcp.core import LDAPServerConfig
from ldap_assistant_mcp.dirsrv_mcp.server import DirSrvMCP
from ldap_assistant_mcp.lib.privacy import PrivacySanitizer


# ---------------------------------------------------------------------------
# Shared fixtures / helpers
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolate_servers_config(monkeypatch):
    """Keep synthetic tests independent of live CI server configuration."""
    monkeypatch.setenv("LDAP_SERVERS_CONFIG", "")


@pytest.fixture
def archive_env():
    """Ensure no external config leaks into archive tests; expose data."""
    env = {
        "LDAP_MCP_EXPOSE_SENSITIVE_DATA": "true",
        "LDAP_SERVERS_CONFIG": "",
    }
    with patch.dict(os.environ, env):
        yield


def _make_mcp():
    """Bare mcp stand-in for direct helper calls (phase0 idiom)."""
    return MagicMock()


# ---------------------------------------------------------------------------
# Archive replica role from type AND flags
# ---------------------------------------------------------------------------


ROLE_DSE_LDIF = """\
dn: cn=config
objectClass: top
objectClass: extensibleObject
objectClass: nsslapdConfig
cn: config
nsslapd-port: 389
nsslapd-secureport: 636
nsslapd-versionstring: 389-Directory/2.4.6
nsslapd-localhost: localhost.localdomain
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
nsslapd-suffix: dc=supplier,dc=com

dn: cn=mapping tree,cn=config
objectClass: top
objectClass: extensibleObject
cn: mapping tree
"""


def _replica_entry(suffix: str, rtype: str, flags: str) -> str:
    """Build a camelCase replica entry, as 389 DS writes it to dse.ldif."""
    dn = f'cn=replica,cn="{suffix}",cn=mapping tree,cn=config'
    return "\n".join(
        [
            "",
            f"dn: {dn}",
            "objectClass: top",
            "objectClass: nsDS5Replica",
            "cn: replica",
            f"nsDS5ReplicaRoot: {suffix}",
            "nsDS5ReplicaId: 1",
            f"nsDS5ReplicaType: {rtype}",
            f"nsDS5Flags: {flags}",
        ]
    )


def _write_role_archive(tmp_path) -> DirSrvMCP:
    """SOS-style tree with one supplier, one hub, and one consumer replica."""
    inst = "slapd-roles-test"
    config_dir = tmp_path / "etc" / "dirsrv" / inst
    config_dir.mkdir(parents=True)
    content = (
        ROLE_DSE_LDIF
        + _replica_entry("dc=supplier,dc=com", "3", "1")
        + _replica_entry("dc=hub,dc=com", "2", "1")
        + _replica_entry("dc=consumer,dc=com", "2", "0")
        # lib389's DSEldif reader drops the very last line of the file, so
        # the trailing blank line matters.
        + "\n\n"
    )
    (config_dir / "dse.ldif").write_text(content)

    logs_dir = tmp_path / "var" / "log" / "dirsrv" / inst
    logs_dir.mkdir(parents=True)
    (logs_dir / "access").write_text("")
    (logs_dir / "errors").write_text("")

    config = LDAPServerConfig(
        name="roles-archive",
        hostname="archive",
        port=0,
        is_archive=True,
        archive_path=str(tmp_path),
    )
    return DirSrvMCP(servers=[config], include_env_fallback=False)


class TestArchiveReplicaRoles:
    async def test_roles_from_type_and_flags(self, archive_env, tmp_path):
        """type=3 -> supplier, type=2/flags=1 -> hub, type=2/flags=0 -> consumer."""
        mcp = _write_role_archive(tmp_path)
        async with Client(mcp) as client:
            result = await client.call_tool(
                "analyze_archive", {"server_name": "roles-archive"}
            )
            data = result.data

        assert "error" not in data
        roles = {
            r["suffix"]: r["role"] for r in data["config_summary"]["replication"]
        }
        assert roles == {
            "dc=supplier,dc=com": "supplier",
            "dc=hub,dc=com": "hub",
            "dc=consumer,dc=com": "consumer",
        }


# ---------------------------------------------------------------------------
# check_replication_lag: catch-up and credential-failure semantics
# ---------------------------------------------------------------------------


IN_SYNC_STATUS = {
    "msg": "In Synchronization",
    "agmt_maxcsn": "5f000001000000010000",
    "con_maxcsn": "5f000001000000010000",
    "state": "green",
    "reason": "In sync",
}

CATCHING_UP_STATUS = {
    "msg": "Not in Synchronization",
    "agmt_maxcsn": "5f110002000000010000",
    "con_maxcsn": "5f000001000000010000",
    "state": "green",
    "reason": "Replication still in progress",
}


def _lag_agmt_mock(
    name="agmt-to-b",
    host="consumer1.example.com",
    port="389",
    status=None,
    status_exc=None,
):
    agmt = MagicMock()
    agmt.get_attr_val_utf8.side_effect = lambda attr: {
        "cn": name,
        "nsDS5ReplicaHost": host,
        "nsDS5ReplicaPort": port,
    }.get(attr)
    if status_exc is not None:
        agmt.get_agmt_status.side_effect = status_exc
    else:
        agmt.get_agmt_status.return_value = json.dumps(status or IN_SYNC_STATUS)
    return agmt


def _supplier_replica_mock(suffix="dc=example,dc=com", agmts=()):
    replica = MagicMock()
    replica.get_suffix.return_value = suffix
    replica.get_role.return_value = ReplicaRole.SUPPLIER
    coll = MagicMock()
    coll.list.return_value = list(agmts)
    replica.get_agreements.return_value = coll
    return replica


class TestLagCatchingUpNotInSync:
    async def _run(self, server, replicas_list, args=None):
        replicas = MagicMock()
        replicas.list.return_value = replicas_list
        with patch.object(replication, "Replicas", return_value=replicas), \
             patch.object(server.connection_manager, "connect", return_value=MagicMock()):
            async with Client(server) as client:
                result = await client.call_tool("check_replication_lag", args or {})
                return result.data

    async def test_catching_up_is_not_in_sync(self, dirsrv_server):
        """An agreement reporting 'Replication still in progress' is not in sync."""
        data = await self._run(
            dirsrv_server,
            [_supplier_replica_mock(agmts=[_lag_agmt_mock(status=CATCHING_UP_STATUS)])],
        )
        assert data["in_sync_count"] == 0
        assert data["catching_up_count"] == 1
        assert not data["summary"].startswith("HEALTHY")
        assert "catching up" in data["summary"]
        assert data["lag_data"][0]["lag_status"] == "syncing"

    async def test_mixed_states_summary_separates_counts(self, dirsrv_server):
        data = await self._run(
            dirsrv_server,
            [
                _supplier_replica_mock(
                    agmts=[
                        _lag_agmt_mock(name="a1", status=IN_SYNC_STATUS),
                        _lag_agmt_mock(name="a2", status=CATCHING_UP_STATUS),
                    ]
                )
            ],
        )
        assert data["in_sync_count"] == 1
        assert data["catching_up_count"] == 1
        assert "1 synchronized, 1 catching up" in data["summary"]

    async def test_all_synchronized_still_healthy(self, dirsrv_server):
        """Positive control: only truly synchronized agreements read HEALTHY."""
        data = await self._run(
            dirsrv_server,
            [_supplier_replica_mock(agmts=[_lag_agmt_mock(status=IN_SYNC_STATUS)])],
        )
        assert data["in_sync_count"] == 1
        assert data["catching_up_count"] == 0
        assert data["summary"].startswith("HEALTHY: All 1")

    async def test_consumer_credential_failure_is_unknown(self, dirsrv_server):
        """Consumer rejecting supplier credentials -> status unknown."""
        data = await self._run(
            dirsrv_server,
            [
                _supplier_replica_mock(
                    agmts=[_lag_agmt_mock(status_exc=ldap.INVALID_CREDENTIALS())]
                )
            ],
        )
        entry = data["lag_data"][0]
        assert entry["lag_status"] == "unknown"
        assert entry["status"] == "unknown"
        assert entry["reason"] == replication.CONSUMER_STATUS_UNKNOWN_REASON
        assert data["unknown_count"] == 1
        assert data["error_count"] == 0
        assert data["summary"].startswith("UNKNOWN")
        assert "supplier credentials" in data["summary"]

    async def test_generic_failure_still_counts_as_error(self, dirsrv_server):
        """Non-credential failures keep the existing error-labelled path."""
        data = await self._run(
            dirsrv_server,
            [
                _supplier_replica_mock(
                    agmts=[_lag_agmt_mock(status_exc=RuntimeError("boom"))]
                )
            ],
        )
        assert data["error_count"] == 1
        assert data["unknown_count"] == 0
        assert data["summary"].startswith("CRITICAL")

    async def test_shape_compatibility(self, dirsrv_server):
        data = await self._run(
            dirsrv_server,
            [_supplier_replica_mock(agmts=[_lag_agmt_mock(status=IN_SYNC_STATUS)])],
        )
        for key in (
            "type", "server", "suffix_filter", "summary", "in_sync_count",
            "lagging_count", "error_count", "catching_up_count",
            "unknown_count", "lag_data", "findings",
        ):
            assert key in data, f"missing key {key}"


class TestAgreementDetailsCredentialFailure:
    def test_credential_failure_labeled_unknown(self):
        """The same rule applies to _get_agreement_details (status/agreement tools)."""
        agmt = _lag_agmt_mock(status_exc=ldap.INVALID_CREDENTIALS())
        details = replication._get_agreement_details(agmt, _make_mcp())
        assert details["status"]["state"] == "unknown"
        assert details["status"]["reason"] == replication.CONSUMER_STATUS_UNKNOWN_REASON
        assert details["status"]["consumer_reachable"] is False


# ---------------------------------------------------------------------------
# Topology analysis from agreement edges
# ---------------------------------------------------------------------------


def _topo_agmt_mock(name, target_host, target_port, enabled="on"):
    agmt = MagicMock()
    agmt.get_attr_val_utf8.side_effect = lambda attr: {
        "cn": name,
        "nsDS5ReplicaHost": target_host,
        "nsDS5ReplicaPort": target_port,
        "nsds5ReplicaEnabled": enabled,
    }.get(attr)
    return agmt


def _topo_replica_mock(suffix, role=ReplicaRole.SUPPLIER, agmts=(), agmt_exc=None):
    replica = MagicMock()
    replica.get_suffix.return_value = suffix
    replica.get_role.return_value = role
    replica.get_rid.return_value = "1"
    if agmt_exc is not None:
        replica.get_agreements.side_effect = agmt_exc
    else:
        coll = MagicMock()
        coll.list.return_value = list(agmts)
        replica.get_agreements.return_value = coll
    return replica


@pytest.fixture
def two_supplier_mcp(mock_env) -> DirSrvMCP:
    cfgs = [
        LDAPServerConfig(
            name="s1", hostname="host1", port=3891,
            bind_dn="cn=Directory Manager", bind_password="pw",
            base_dn="dc=example,dc=com",
        ),
        LDAPServerConfig(
            name="s2", hostname="host2", port=3892,
            bind_dn="cn=Directory Manager", bind_password="pw",
            base_dn="dc=example,dc=com",
        ),
    ]
    return DirSrvMCP(servers=cfgs, include_env_fallback=False)


SUFFIX = "dc=example,dc=com"


class TestTopologyEdgeAnalysis:
    async def _run(self, server, replicas_by_server):
        ds_by_name = {name: MagicMock() for name in replicas_by_server}
        colls = {}
        for name, replicas_list in replicas_by_server.items():
            coll = MagicMock()
            coll.list.return_value = replicas_list
            colls[name] = coll

        def connect(name):
            return ds_by_name[name]

        def replicas_factory(ds):
            for name, mock_ds in ds_by_name.items():
                if mock_ds is ds:
                    return colls[name]
            raise AssertionError("unexpected ds")

        with patch.object(server.connection_manager, "connect", side_effect=connect), \
             patch.object(replication, "Replicas", side_effect=replicas_factory):
            async with Client(server) as client:
                result = await client.call_tool("get_replication_topology", {})
                return result.data

    async def test_two_suppliers_without_edges_are_flagged(self, two_supplier_mcp):
        """Two suppliers with NO agreements: redundancy is illusory."""
        data = await self._run(
            two_supplier_mcp,
            {
                "s1": [_topo_replica_mock(SUFFIX)],
                "s2": [_topo_replica_mock(SUFFIX)],
            },
        )
        suffix_data = data["suffixes"][SUFFIX]
        assert suffix_data["analysis_status"] == "complete"
        assert suffix_data["edges"] == []
        assert set(suffix_data["servers_without_incoming_agreements"]) == {"s1", "s2"}
        assert set(suffix_data["servers_without_outgoing_agreements"]) == {"s1", "s2"}
        titles = [f["title"] for f in data["findings"]]
        assert any("Isolated Replica" in t for t in titles)
        assert any("Supplier Without Inbound Supplier Agreement" in t for t in titles)
        assert data["summary"].startswith("ISSUES DETECTED")

    async def test_proper_mesh_reports_healthy(self, two_supplier_mcp):
        """Positive control: a full supplier mesh yields no edge findings."""
        data = await self._run(
            two_supplier_mcp,
            {
                "s1": [_topo_replica_mock(SUFFIX, agmts=[
                    _topo_agmt_mock("to-s2", "host2", "3892"),
                ])],
                "s2": [_topo_replica_mock(SUFFIX, agmts=[
                    _topo_agmt_mock("to-s1", "host1", "3891"),
                ])],
            },
        )
        suffix_data = data["suffixes"][SUFFIX]
        assert suffix_data["analysis_status"] == "complete"
        assert len(suffix_data["edges"]) == 2
        targets = {e["source"]: e["target_server"] for e in suffix_data["edges"]}
        assert targets == {"s1": "s2", "s2": "s1"}
        assert suffix_data["servers_without_incoming_agreements"] == []
        assert suffix_data["servers_without_outgoing_agreements"] == []
        assert data["findings"] == []
        assert data["summary"].startswith("HEALTHY")

    async def test_agreement_collection_failure_is_unknown(self, two_supplier_mcp):
        """A member whose agreements could not be read makes the suffix UNKNOWN."""
        data = await self._run(
            two_supplier_mcp,
            {
                "s1": [_topo_replica_mock(SUFFIX, agmt_exc=RuntimeError("search denied"))],
                "s2": [_topo_replica_mock(SUFFIX, agmts=[
                    _topo_agmt_mock("to-s1", "host1", "3891"),
                ])],
            },
        )
        assert data["agreement_errors"]
        assert data["agreement_errors"][0]["server"] == "s1"
        suffix_data = data["suffixes"][SUFFIX]
        assert suffix_data["analysis_status"] == "unknown"
        titles = [f["title"] for f in data["findings"]]
        assert any("Topology Analysis Incomplete" in t for t in titles)
        assert any("Incomplete Agreement Data" in t for t in titles)
        # No connectivity claim may be made from incomplete evidence
        assert not any("Isolated Replica" in t for t in titles)
        assert not data["summary"].startswith("HEALTHY")

    async def test_unresolved_target_is_partial(self, two_supplier_mcp):
        """Agreements to hosts outside the config: inbound analysis is partial."""
        data = await self._run(
            two_supplier_mcp,
            {
                "s1": [_topo_replica_mock(SUFFIX, agmts=[
                    _topo_agmt_mock("to-elsewhere", "unknown-host", "399"),
                ])],
                "s2": [],
            },
        )
        suffix_data = data["suffixes"][SUFFIX]
        assert suffix_data["analysis_status"] == "partial"
        assert suffix_data["edges"][0]["target_server"] is None
        titles = [f["title"] for f in data["findings"]]
        assert any("Unresolved Agreement Targets" in t for t in titles)
        # No isolation claim can be made when targets are unresolved
        assert not any("Isolated Replica" in t for t in titles)


# ---------------------------------------------------------------------------
# Risk-aware index recommendations
# ---------------------------------------------------------------------------


def _index_mock(attr, types):
    idx = MagicMock()
    idx.get_attr_val_utf8.side_effect = lambda name: {
        "cn": attr,
        "nsSystemIndex": "false",
    }.get(name)
    idx.get_attr_vals_utf8.side_effect = lambda name: {
        "nsIndexType": list(types),
    }.get(name, [])
    return idx


def _backend_mock(name="userroot", suffix="dc=example,dc=com", indexes_list=None):
    be = MagicMock()
    be.get_attr_val_utf8.side_effect = lambda attr: {
        "cn": name,
        "nsslapd-suffix": suffix,
    }.get(attr)
    idx_coll = MagicMock()
    idx_coll.list.return_value = indexes_list or []
    be.get_indexes.return_value = idx_coll
    return be


def _indexes_for(attr_filter):
    return [
        _index_mock(attr, types)
        for attr, types in indexes.RECOMMENDED_INDEXES.items()
        if attr_filter(attr)
    ]


class TestIndexAdvisorRisk:
    async def _run(self, server, backend_list, memberof_enabled=None, args=None):
        backends = MagicMock()
        backends.list.return_value = backend_list
        plugin = MagicMock()
        if memberof_enabled is None:
            plugin.status.side_effect = RuntimeError("plugin state unavailable")
        else:
            plugin.status.return_value = memberof_enabled
        with patch.object(indexes, "Backends", return_value=backends), \
             patch.object(indexes, "MemberOfPlugin", return_value=plugin), \
             patch.object(server.connection_manager, "connect", return_value=MagicMock()):
            async with Client(server) as client:
                result = await client.call_tool(
                    "analyze_index_configuration", args or {}
                )
                return result.data

    async def test_missing_core_index_carries_risk_metadata(self, dirsrv_server):
        data = await self._run(dirsrv_server, [_backend_mock()], memberof_enabled=True)
        missing = {
            m["attribute"]: m
            for m in data["backends"][0]["missing_recommended"]
        }
        uid = missing["uid"]
        assert uid["basis"] == "static_best_practice"
        assert uid["category"] == "core"
        assert uid["risk"] == {
            "risk": "change",
            "requires_reindex": True,
            "write_cost": "adds index maintenance on writes",
            "approval_required": True,
        }
        uid_findings = [
            f for f in data["findings"]
            if f["title"] == "Missing Recommended Index: uid"
        ]
        assert uid_findings[0]["severity"] == "medium"
        assert data["status"] == "warning"
        assert data["summary"].startswith("ATTENTION")

    async def test_workload_dependent_missing_is_low(self, dirsrv_server):
        """Only workload-dependent attrs missing -> LOW findings, fair status."""
        core_and_plugin = indexes.CORE_INDEX_ATTRIBUTES | set(
            indexes.PLUGIN_DEPENDENT_INDEX_ATTRIBUTES
        )
        idx_list = _indexes_for(lambda a: a.lower() in core_and_plugin)
        data = await self._run(
            dirsrv_server, [_backend_mock(indexes_list=idx_list)], memberof_enabled=True
        )
        missing = data["backends"][0]["missing_recommended"]
        assert missing, "expected workload-dependent attributes to be missing"
        assert all(m["category"] == "workload_dependent" for m in missing)
        display_findings = [
            f for f in data["findings"]
            if f["title"] == "Missing Recommended Index: displayName"
        ]
        assert display_findings[0]["severity"] == "low"
        assert "consider only if" in display_findings[0]["details"]
        assert data["status"] == "fair"
        assert "workload-dependent" in data["summary"]

    async def test_memberof_disabled_is_not_recommended(self, dirsrv_server):
        """Plugin off: indexing memberOf has no benefit -> no recommendation."""
        idx_list = _indexes_for(lambda a: a.lower() != "memberof")
        data = await self._run(
            dirsrv_server, [_backend_mock(indexes_list=idx_list)], memberof_enabled=False
        )
        missing_attrs = [
            m["attribute"] for m in data["backends"][0]["missing_recommended"]
        ]
        assert "memberOf" not in missing_attrs
        assert data["status"] == "healthy"

    async def test_memberof_unknown_state_is_workload_dependent(self, dirsrv_server):
        idx_list = _indexes_for(lambda a: a.lower() != "memberof")
        data = await self._run(
            dirsrv_server, [_backend_mock(indexes_list=idx_list)], memberof_enabled=None
        )
        missing = {
            m["attribute"]: m
            for m in data["backends"][0]["missing_recommended"]
        }
        assert missing["memberOf"]["category"] == "workload_dependent"
        memberof_findings = [
            f for f in data["findings"]
            if f["title"] == "Missing Recommended Index: memberOf"
        ]
        assert memberof_findings[0]["severity"] == "low"

    async def test_incomplete_index_carries_risk_metadata(self, dirsrv_server):
        idx_list = _indexes_for(lambda a: a.lower() != "uid")
        idx_list.append(_index_mock("uid", ["eq"]))  # missing pres, sub
        data = await self._run(
            dirsrv_server, [_backend_mock(indexes_list=idx_list)], memberof_enabled=True
        )
        incomplete = data["backends"][0]["incomplete_indexes"]
        assert incomplete[0]["attribute"] == "uid"
        assert incomplete[0]["basis"] == "static_best_practice"
        assert incomplete[0]["risk"]["approval_required"] is True
        assert data["status"] == "fair"


# ---------------------------------------------------------------------------
# Operator-aware unindexed-search remediation
# ---------------------------------------------------------------------------


class TestFilterOperatorClassification:
    def test_presence(self):
        evidence = indexes._classify_filter_operators("(manager=*)")
        assert evidence == {"manager": {"operator": "presence", "index_type": "pres"}}

    def test_substring_both_sides(self):
        evidence = indexes._classify_filter_operators("(cn=*smith*)")
        assert evidence["cn"] == {"operator": "substring", "index_type": "sub"}

    def test_substring_trailing_wildcard(self):
        evidence = indexes._classify_filter_operators("(telephoneNumber=555*)")
        assert evidence["telephoneNumber"]["index_type"] == "sub"

    def test_range_operators(self):
        assert indexes._classify_filter_operators("(uidNumber>=1000)")["uidNumber"][
            "operator"
        ] == "range"
        assert indexes._classify_filter_operators("(uidNumber<=5)")["uidNumber"][
            "operator"
        ] == "range"

    def test_approximate(self):
        evidence = indexes._classify_filter_operators("(givenName~=jon)")
        assert evidence["givenName"] == {
            "operator": "approximate", "index_type": "approx",
        }

    def test_equality(self):
        evidence = indexes._classify_filter_operators("(uid=john)")
        assert evidence["uid"] == {"operator": "equality", "index_type": "eq"}

    def test_compound_filter(self):
        evidence = indexes._classify_filter_operators(
            "(&(objectClass=person)(cn=*smith*))"
        )
        assert evidence["objectClass"]["index_type"] == "eq"
        assert evidence["cn"]["index_type"] == "sub"


class TestFilterNormalizationPreservesOperators:
    def test_substring_keeps_wildcard_structure(self):
        assert indexes._normalize_filter_pattern("(cn=*smith*)") == "(cn=*VAL*)"
        assert (
            indexes._normalize_filter_pattern("(telephoneNumber=555*)")
            == "(telephoneNumber=VAL*)"
        )

    def test_equality_uses_legacy_placeholder(self):
        assert indexes._normalize_filter_pattern("(uid=john)") == "(uid=*)"

    def test_presence_unchanged(self):
        assert indexes._normalize_filter_pattern("(manager=*)") == "(manager=*)"

    def test_range_and_approx_operators_preserved(self):
        assert (
            indexes._normalize_filter_pattern("(uidNumber>=1000)")
            == "(uidNumber>=VAL)"
        )
        assert (
            indexes._normalize_filter_pattern("(givenName~=jon)")
            == "(givenName~=VAL)"
        )

    def test_no_values_survive_normalization(self):
        """Even unrecognized components must not leak values into patterns."""
        normalized = indexes._normalize_filter_pattern("(cn:caseExactMatch:=Secret)")
        assert "Secret" not in normalized


def _ts(dt: datetime) -> str:
    return dt.strftime("[%d/%b/%Y:%H:%M:%S.392560011 %z]")


INDEX_DSE_LDIF = """\
dn: cn=config
objectClass: top
objectClass: nsslapdConfig
cn: config
nsslapd-port: 389
nsslapd-localhost: localhost.localdomain

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
objectClass: nsBackendInstance
cn: userRoot
nsslapd-suffix: dc=example,dc=com
"""


def _operator_access_log() -> str:
    recent = _ts(datetime.now(timezone.utc) - timedelta(minutes=5))
    return "\n".join(
        [
            "389-Directory/2.4.6 B2024.123.456",
            f'{recent} conn=1 op=1 SRCH base="dc=example,dc=com" scope=2 filter="(cn=*smith*)" attrs=ALL',
            f"{recent} conn=1 op=1 RESULT err=0 tag=101 nentries=5000 wtime=0.1 optime=0.5 etime=0.6 notes=U",
            f'{recent} conn=2 op=1 SRCH base="dc=example,dc=com" scope=2 filter="(uidNumber>=1000)" attrs=ALL',
            f"{recent} conn=2 op=1 RESULT err=0 tag=101 nentries=100 wtime=0.1 optime=0.5 etime=0.6 notes=U",
            f'{recent} conn=3 op=1 SRCH base="dc=example,dc=com" scope=2 filter="(manager=*)" attrs=ALL',
            f"{recent} conn=3 op=1 RESULT err=0 tag=101 nentries=100 wtime=0.1 optime=0.5 etime=0.6 notes=A",
            "",
        ]
    )


def _index_archive_mcp(tmp_path) -> DirSrvMCP:
    inst = "slapd-testinst"
    config_dir = tmp_path / "etc" / "dirsrv" / inst
    config_dir.mkdir(parents=True)
    (config_dir / "dse.ldif").write_text(INDEX_DSE_LDIF)
    logs_dir = tmp_path / "var" / "log" / "dirsrv" / inst
    logs_dir.mkdir(parents=True)
    (logs_dir / "access").write_text(_operator_access_log())
    config = LDAPServerConfig(
        name="test-archive",
        hostname="archive",
        port=0,
        is_archive=True,
        archive_path=str(tmp_path),
    )
    return DirSrvMCP(servers=[config], include_env_fallback=False)


class TestUnindexedOperatorRecommendations:
    async def _patterns(self, tmp_path):
        mcp = _index_archive_mcp(tmp_path)
        async with Client(mcp) as client:
            result = await client.call_tool(
                "find_unindexed_searches",
                {"server_name": "test-archive", "time_range": "1h"},
            )
            data = result.data
        assert "error" not in data
        return {p["example_filter"]: p for p in data["patterns"]}

    async def test_substring_filter_recommends_sub_index(self, archive_env, tmp_path):
        patterns = await self._patterns(tmp_path)
        rec = patterns["(cn=*smith*)"]["recommended_indexes"][0]
        assert rec["attribute"] == "cn"
        assert rec["operator"] == "substring"
        assert rec["index_type_suggested"] == "sub"
        assert rec["recommended_type"] == "sub"
        assert "--index-type sub" in rec["dsconf_command"]

    async def test_range_filter_carries_caveat_note(self, archive_env, tmp_path):
        patterns = await self._patterns(tmp_path)
        rec = patterns["(uidNumber>=1000)"]["recommended_indexes"][0]
        assert rec["attribute"] == "uidNumber"
        assert rec["operator"] == "range"
        assert "does not serve range scans" in rec["note"]

    async def test_presence_filter_recommends_pres_index(self, archive_env, tmp_path):
        patterns = await self._patterns(tmp_path)
        rec = patterns["(manager=*)"]["recommended_indexes"][0]
        assert rec["attribute"] == "manager"
        assert rec["operator"] == "presence"
        assert rec["recommended_type"] == "pres"
        assert "--index-type pres" in rec["dsconf_command"]


# ---------------------------------------------------------------------------
# Certificate severity: active cert vs inventory
# ---------------------------------------------------------------------------


def _cert_detail(nickname, days_from_now, trust="u,u,u"):
    expires = (datetime.now(timezone.utc) + timedelta(days=days_from_now)).strftime(
        "%Y-%m-%d %H:%M:%S"
    )
    return [nickname, f"CN={nickname}", "CN=Test CA", expires, trust]


class TestCertificateActiveVsInventory:
    def _run(self, server_certs, ca_certs=None, active=None, rsa_exc=None):
        nss = MagicMock()
        nss.list_certs.side_effect = (
            lambda ca=False: (ca_certs or []) if ca else server_certs
        )
        rsa = MagicMock()
        if rsa_exc is not None:
            rsa.get_attr_val_utf8.side_effect = rsa_exc
        else:
            rsa.get_attr_val_utf8.return_value = active
        findings, metrics = [], {}
        with patch.object(health, "NssSsl", return_value=nss), \
             patch.object(health, "RSA", return_value=rsa):
            health._check_certificate_health(
                _make_mcp(), MagicMock(), "srv1", findings, metrics, is_local=True
            )
        return findings, metrics

    def test_expired_active_cert_is_critical(self):
        findings, metrics = self._run(
            [_cert_detail("Server-Cert", -10)], active="Server-Cert"
        )
        expired = [f for f in findings if "Expired" in f["title"]]
        assert expired[0]["severity"] == "critical"
        assert "ACTIVE" in expired[0]["impact"]
        assert metrics["certificates"]["active_nickname"] == "Server-Cert"
        assert metrics["certificates"]["certs"][0]["is_active"] is True

    def test_expired_inactive_cert_is_medium(self):
        findings, metrics = self._run(
            [_cert_detail("Server-Cert", 300), _cert_detail("Old-Cert", -10)],
            active="Server-Cert",
        )
        expired = [f for f in findings if "Expired" in f["title"]]
        assert len(expired) == 1
        assert expired[0]["severity"] == "medium"
        assert "unused/unknown-role certificate expired" in expired[0]["impact"]
        by_nick = {c["nickname"]: c for c in metrics["certificates"]["certs"]}
        assert by_nick["Old-Cert"]["is_active"] is False

    def test_expired_ca_cert_stays_high(self):
        findings, _ = self._run(
            [_cert_detail("Server-Cert", 300)],
            ca_certs=[_cert_detail("Old-CA", -10, trust="CTu,u,u")],
            active="Server-Cert",
        )
        expired = [f for f in findings if "Expired" in f["title"]]
        assert expired[0]["severity"] == "high"

    def test_unknown_active_keeps_critical_with_inventory_label(self):
        """Nickname unavailable: keep worst-case severity, label honestly."""
        findings, metrics = self._run(
            [_cert_detail("Server-Cert", -10)],
            rsa_exc=RuntimeError("no encryption config"),
        )
        expired = [f for f in findings if "Expired" in f["title"]]
        assert expired[0]["severity"] == "critical"
        assert "inventory" in expired[0]["impact"].lower()
        assert "active_nickname" not in metrics["certificates"]
        assert "is_active" not in metrics["certificates"]["certs"][0]

    def test_expiring_inactive_cert_is_low(self):
        findings, _ = self._run(
            [_cert_detail("Server-Cert", 300), _cert_detail("Old-Cert", 5)],
            active="Server-Cert",
        )
        expiring = [f for f in findings if "Expiring Soon" in f["title"]]
        assert expiring[0]["severity"] == "low"

    def test_expiring_active_cert_keeps_high(self):
        findings, _ = self._run(
            [_cert_detail("Server-Cert", 5)], active="Server-Cert"
        )
        expiring = [f for f in findings if "Expiring Soon" in f["title"]]
        assert expiring[0]["severity"] == "high"


# ---------------------------------------------------------------------------
# Privacy: new keys must be sanitized
# ---------------------------------------------------------------------------


class TestResultKeySanitization:
    def _mcp(self):
        mcp = MagicMock()
        mcp.privacy_enabled = True
        mcp.sanitizer = PrivacySanitizer()
        return mcp

    def test_topology_edges_are_sanitized(self):
        result = {
            "type": "replication_topology",
            "suffixes": {
                "dc=corp,dc=example,dc=com": {
                    "suppliers": ["s1"],
                    "hubs": [],
                    "consumers": [],
                    "edges": [
                        {
                            "source": "s1",
                            "target_host": "secret-host.example.com",
                            "target_port": "389",
                            "target_server": None,
                            "agreement": "agmt-to-secret",
                            "enabled": "on",
                        }
                    ],
                    "analysis_status": "partial",
                }
            },
        }
        sanitized = replication._sanitize_replication_result(self._mcp(), result)
        suffix_key = next(iter(sanitized["suffixes"]))
        assert "dc=corp" not in suffix_key
        edge = sanitized["suffixes"][suffix_key]["edges"][0]
        assert "secret-host" not in str(edge["target_host"])
        assert edge["target_port"] == "[port]"
        assert edge["agreement"] == "[agreement]"
        assert edge["source"] == "s1"  # server config labels stay

    def test_agreement_errors_are_sanitized(self):
        result = {
            "type": "replication_topology",
            "agreement_errors": [
                {
                    "server": "s1",
                    "suffix": "dc=corp,dc=example,dc=com",
                    "error": "denied at secret-host.example.com",
                },
                {"server": "s2", "suffix": None, "error": "boom"},
            ],
        }
        sanitized = replication._sanitize_replication_result(self._mcp(), result)
        entry = sanitized["agreement_errors"][0]
        assert "dc=corp" not in entry["suffix"]
        assert "secret-host" not in entry["error"]
        assert sanitized["agreement_errors"][1]["suffix"] is None

    def test_lag_credential_entry_is_sanitized(self):
        result = {
            "type": "replication_lag",
            "lag_data": [
                {
                    "suffix": "dc=corp,dc=example,dc=com",
                    "agreement": "agmt-to-b",
                    "consumer": "secret-host.example.com:389",
                    "status": "unknown",
                    "lag_status": "unknown",
                    "reason": replication.CONSUMER_STATUS_UNKNOWN_REASON,
                    "error": "INVALID_CREDENTIALS at secret-host.example.com",
                }
            ],
        }
        sanitized = replication._sanitize_replication_result(self._mcp(), result)
        entry = sanitized["lag_data"][0]
        assert entry["lag_status"] == "unknown"
        assert "secret-host" not in entry["error"]
        assert "secret-host" not in entry["consumer"]

    def test_cert_metrics_active_nickname_sanitized(self):
        result = {
            "type": "first_look",
            "detailed_metrics": {
                "srv1": {
                    "certificates": {
                        "available": True,
                        "active_nickname": "secret-host.example.com-cert",
                        "certs": [
                            {
                                "nickname": "secret-host.example.com-cert",
                                "subject": "CN=secret-host.example.com",
                                "type": "server",
                                "days_until_expiry": 5,
                                "is_active": True,
                            }
                        ],
                    }
                }
            },
        }
        sanitized = health._sanitize_health_result(self._mcp(), result)
        certs = sanitized["detailed_metrics"]["srv1"]["certificates"]
        assert certs["active_nickname"] == "[certificate]"
        assert certs["certs"][0]["subject"] == "[certificate]"
        assert certs["certs"][0]["is_active"] is True
        assert "nickname" not in certs["certs"][0]
