"""Regression tests for Phase 1 improvements.

Covers:
- Package version reported to MCP clients; stderr logging handler
  configured on the ``ldap_assistant_mcp`` logger tree.
- Archive loader decompression-bomb guards, extraction cache keyed by
  (path, mtime, size), plain ``.tar`` support, archive_path+logs_path
  precedence, ArchivePaths None-safety, compare_dse_configs DN/attr
  normalization, healthcheck file selection, JSON log malformed-line
  counting, and the bounded slow-operations heap.
- Shared replica-role vocabulary, user-index counting parity,
  empty search-term rejection, run_monitor error formatting, and base64
  LDIF value decoding.

No live LDAP server is required.
"""

from __future__ import annotations

import json
import logging
import os
import tarfile
from contextlib import contextmanager
from unittest.mock import MagicMock, patch

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from ldap_assistant_mcp.core import (
    LDAPServerConfig,
    MCPSettings,
    __version__,
    configure_package_logging,
)
from ldap_assistant_mcp.dirsrv_mcp.archive import loader
from ldap_assistant_mcp.dirsrv_mcp.archive.loader import (
    detect_archive_layout,
    extract_archive,
)
from ldap_assistant_mcp.dirsrv_mcp.archive.stub import ArchiveDirSrv, ArchivePaths
from ldap_assistant_mcp.dirsrv_mcp.server import DirSrvMCP


# ── Helpers ──────────────────────────────────────────────────────────

def _make_server(expose: bool = True, **settings_kwargs) -> DirSrvMCP:
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
            settings=MCPSettings(expose_sensitive_data=expose, **settings_kwargs),
        )


def _install_fake_connection(server: DirSrvMCP, ds) -> None:
    """Replace server._connection so tools never open a real LDAP connection."""

    @contextmanager
    def _conn(server_name=None):
        yield (server_name or server.default_server, ds)

    server._connection = _conn


def _write_tar(tar_path, files, mode="w:gz"):
    """Create a tar archive at *tar_path* from a {name: content} mapping."""
    with tarfile.open(tar_path, mode) as tar:
        for name, content in files.items():
            member_path = tar_path.parent / f".tar-src-{name.replace('/', '_')}"
            member_path.write_text(content)
            tar.add(member_path, arcname=name)
            member_path.unlink()


# ── 1.1 Version + logging ────────────────────────────────────────────

@pytest.mark.asyncio
async def test_server_reports_package_version_to_clients():
    server = _make_server()
    async with Client(server) as client:
        info = client.initialize_result.serverInfo
    assert info.version == __version__
    assert info.version not in ("", None)


def test_package_logging_handler_configured():
    server = _make_server()  # noqa: F841 — constructing configures logging
    pkg_logger = logging.getLogger("ldap_assistant_mcp")
    ours = [
        h for h in pkg_logger.handlers
        if getattr(h, "_ldap_assistant_mcp_handler", False)
    ]
    assert len(ours) == 1, "expected exactly one stderr handler on the package tree"
    assert pkg_logger.level in (logging.INFO, logging.DEBUG)


def test_package_logging_is_idempotent():
    configure_package_logging()
    configure_package_logging()
    pkg_logger = logging.getLogger("ldap_assistant_mcp")
    ours = [
        h for h in pkg_logger.handlers
        if getattr(h, "_ldap_assistant_mcp_handler", False)
    ]
    assert len(ours) == 1


def test_debug_settings_raise_package_log_level():
    _make_server(debug=True)
    assert logging.getLogger("ldap_assistant_mcp").level == logging.DEBUG
    # Restore INFO for other tests
    configure_package_logging(debug=False)


# ── 1.3 Archive loader guards ────────────────────────────────────────

def test_extract_archive_rejects_too_many_members(tmp_path, monkeypatch):
    monkeypatch.setattr(loader, "MAX_ARCHIVE_MEMBERS", 1)
    tar_path = tmp_path / "many.tar.gz"
    _write_tar(tar_path, {"a.txt": "a", "b.txt": "b"})
    with pytest.raises(ValueError, match="members"):
        extract_archive(str(tar_path))


def test_extract_archive_rejects_declared_size_bomb(tmp_path, monkeypatch):
    monkeypatch.setattr(loader, "MAX_ARCHIVE_TOTAL_BYTES", 10)
    tar_path = tmp_path / "big.tar.gz"
    _write_tar(tar_path, {"big.txt": "x" * 100})
    with pytest.raises(ValueError, match="refusing to extract"):
        extract_archive(str(tar_path))


def test_extract_archive_recaches_when_archive_changes(tmp_path):
    tar_path = tmp_path / "cache.tar.gz"
    _write_tar(tar_path, {"dse.ldif": "dn: cn=config\n"})
    try:
        first = extract_archive(str(tar_path))
        # Same file → cached
        assert extract_archive(str(tar_path)) == first

        # Rewrite with different content (different size ⇒ different cache key)
        _write_tar(tar_path, {"dse.ldif": "dn: cn=config\nnsslapd-port: 389\n"})
        second = extract_archive(str(tar_path))
        assert second != first, "modified archive must be re-extracted"
    finally:
        loader.cleanup_temp_dirs()


def test_plain_tar_archive_supported(tmp_path):
    tar_path = tmp_path / "plain.tar"
    _write_tar(tar_path, {"dse.ldif": "dn: cn=config\n"}, mode="w")
    try:
        layout = detect_archive_layout(archive_path=str(tar_path))
        assert layout.dse_ldif_path and os.path.isfile(layout.dse_ldif_path)
    finally:
        loader.cleanup_temp_dirs()


def test_tar_without_extension_detected_by_content(tmp_path):
    tar_path = tmp_path / "archive.bin"
    _write_tar(tar_path, {"dse.ldif": "dn: cn=config\n"}, mode="w:gz")
    try:
        layout = detect_archive_layout(archive_path=str(tar_path))
        assert layout.config_dir is not None
    finally:
        loader.cleanup_temp_dirs()


# ── 1.3 archive_path + logs_path precedence ──────────────────────────

def test_archive_path_with_logs_path_override(tmp_path):
    archive_root = tmp_path / "archive"
    archive_root.mkdir()
    (archive_root / "dse.ldif").write_text("dn: cn=config\n")

    external_logs = tmp_path / "external-logs"
    external_logs.mkdir()
    (external_logs / "access").write_text("[01/Jan/2024:10:00:00.000000000 +0000] conn=1\n")

    layout = detect_archive_layout(
        archive_path=str(archive_root), logs_path=str(external_logs)
    )
    assert layout.config_dir == str(archive_root)
    assert layout.logs_dir == str(external_logs.resolve())

    # The full stub path must work end-to-end (this combination used to
    # crash in ArchivePaths with a None config_dir join).
    ds = ArchiveDirSrv(layout)
    assert ds.ds_paths.access_log == os.path.join(str(external_logs.resolve()), "access")
    assert ds.dse_ldif_path == str(archive_root / "dse.ldif")


def test_archive_paths_none_safe_for_logs_only():
    paths = ArchivePaths(config_dir=None, log_dir="/some/logs")
    assert paths.config_dir is None
    assert paths.schema_dir is None
    assert paths.cert_dir is None
    assert paths.access_log == "/some/logs/access"


def test_logs_only_layout_produces_working_stub(tmp_path):
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "errors").write_text("[01/Jan/2024:10:00:00.000000000 +0000] - INFO - main - up\n")

    layout = detect_archive_layout(logs_path=str(logs))
    ds = ArchiveDirSrv(layout)
    assert ds.ds_paths.error_log == os.path.join(str(logs.resolve()), "errors")
    assert ds.dse_ldif_path is None


# ── 1.3 compare_dse_configs normalization ────────────────────────────

_LDIF_BASE = """\
dn: cn=config
cn: config
nsslapd-port: 389

dn: cn="dc=example,dc=com",cn=mapping tree,cn=config
objectClass: top
cn: dc=example,dc=com
nsslapd-state: backend
"""

# Same logical content: different DN case, unquoted mapping-tree RDN,
# different attribute-name case.
_LDIF_VARIANT = """\
dn: CN=Config
CN: config
NSSLAPD-PORT: 389

dn: cn=dc\\3Dexample\\2Cdc\\3Dcom,cn=mapping tree,cn=config
objectclass: top
cn: dc=example,dc=com
NSSLAPD-STATE: backend
"""


def test_compare_dse_configs_ignores_dn_and_attr_case(tmp_path):
    from lib389._ldifconn import LDIFConn

    from ldap_assistant_mcp.dirsrv_mcp.tools.archive import _compare_ldif_entries

    f1 = tmp_path / "dse1.ldif"
    f2 = tmp_path / "dse2.ldif"
    f1.write_text(_LDIF_BASE)
    f2.write_text(_LDIF_VARIANT)

    result = _compare_ldif_entries(LDIFConn(str(f1)), LDIFConn(str(f2)), "s1", "s2")

    assert result["only_in_server1"] == [], (
        "quoting/case variants must not appear as only-in-server1"
    )
    assert result["only_in_server2"] == []
    assert result["differences"] == []
    assert result["matching_count"] == 2


def test_compare_dse_configs_still_reports_real_differences(tmp_path):
    from lib389._ldifconn import LDIFConn

    from ldap_assistant_mcp.dirsrv_mcp.tools.archive import _compare_ldif_entries

    f1 = tmp_path / "dse1.ldif"
    f2 = tmp_path / "dse2.ldif"
    f1.write_text("dn: cn=config\ncn: config\nnsslapd-port: 389\n")
    f2.write_text("dn: cn=config\ncn: config\nnsslapd-port: 636\n")

    result = _compare_ldif_entries(LDIFConn(str(f1)), LDIFConn(str(f2)), "s1", "s2")
    assert len(result["differences"]) == 1
    diff = result["differences"][0]["different_values"][0]
    assert diff["attribute"].lower() == "nsslapd-port"
    assert diff["server1"] == ["389"]
    assert diff["server2"] == ["636"]


# ── 1.3 healthcheck file selection ───────────────────────────────────

def test_healthcheck_file_selection_prefers_matching_instance():
    from ldap_assistant_mcp.dirsrv_mcp.tools.archive import _select_healthcheck_file

    files = [
        "/sos/sos_commands/dirsrv/dsctl_consumer1_healthcheck",
        "/sos/sos_commands/dirsrv/dsctl_supplier1_healthcheck",
    ]
    assert _select_healthcheck_file(files, "slapd-supplier1") == files[1]
    assert _select_healthcheck_file(files, "supplier1") == files[1]
    assert _select_healthcheck_file(files, "slapd-consumer1") == files[0]
    # Unknown instance / no serverid falls back to the first file
    assert _select_healthcheck_file(files, "slapd-elsewhere") == files[0]
    assert _select_healthcheck_file(files, None) == files[0]


# ── 1.3 JSON log robustness ──────────────────────────────────────────

def _fake_log_ds(tmp_path, access_lines):
    (tmp_path / "access").write_text("\n".join(access_lines) + "\n")
    ds = MagicMock()
    ds.ds_paths.access_log = str(tmp_path / "access")
    return ds


def test_json_access_log_counts_malformed_lines(tmp_path):
    from ldap_assistant_mcp.dirsrv_mcp.tools.logs import _parse_access_log_entries

    lines = [
        json.dumps({"operation": "SEARCH", "err": 0, "etime": "0.01"}),
        "{this is not json",
        json.dumps({"operation": "RESULT", "err": 0, "etime": "0.02"}),
        "[42, 43]",  # valid JSON but not an object
    ]
    ds = _fake_log_ds(tmp_path, lines)
    result = _parse_access_log_entries(
        ds, None, None, None, None, False, 100, stats_only=True
    )
    assert result["total_parsed"] == 2
    assert result["malformed_lines"] == 2


def test_slow_operations_bounded_to_top_20(tmp_path):
    from ldap_assistant_mcp.dirsrv_mcp.tools.logs import _parse_access_log_entries

    lines = [
        json.dumps({"operation": "SEARCH", "err": 0, "etime": f"{1.5 + i}"})
        for i in range(30)
    ]
    ds = _fake_log_ds(tmp_path, lines)
    result = _parse_access_log_entries(
        ds, None, None, None, None, False, 5, stats_only=False
    )
    slow = result["slow_operations"]
    assert len(slow) == 20, "slow_operations must be capped at 20"
    etimes = [op["etime"] for op in slow]
    assert etimes == sorted(etimes, reverse=True), "sorted by etime descending"
    assert etimes[0] == pytest.approx(30.5)  # the 10 slowest survive the heap


# ── 1.4 role vocabulary shared between live and offline paths ────────

def test_config_uses_shared_role_to_string():
    from ldap_assistant_mcp.dirsrv_mcp.tools import config as config_tools
    from ldap_assistant_mcp.dirsrv_mcp.tools import replication as repl_tools
    from lib389._constants import ReplicaRole

    assert config_tools._role_to_string is repl_tools._role_to_string
    assert config_tools._role_to_string(ReplicaRole.SUPPLIER) == "supplier"


# ── 1.4 user-index counting parity ───────────────────────────────────

_DSE_WITH_INDEX = """\
dn: cn=config
cn: config
nsslapd-port: 389

dn: cn=plugins,cn=config
cn: plugins

dn: cn=ldbm database,cn=plugins,cn=config
cn: ldbm database

dn: cn=userroot,cn=ldbm database,cn=plugins,cn=config
cn: userroot
nsslapd-suffix: dc=example,dc=com

dn: cn=index,cn=userroot,cn=ldbm database,cn=plugins,cn=config
cn: index

dn: cn=customattr,cn=index,cn=userroot,cn=ldbm database,cn=plugins,cn=config
cn: customattr
nsIndexType: eq

dn: cn=objectclass,cn=index,cn=userroot,cn=ldbm database,cn=plugins,cn=config
cn: objectclass
nsIndexType: eq
nsSystemIndex: true
"""


@pytest.mark.asyncio
async def test_analyze_index_configuration_counts_index_without_nssystemindex(tmp_path):
    """An index entry with no nsSystemIndex attribute counts as a user index."""
    config_dir = tmp_path / "etc" / "dirsrv" / "slapd-idx"
    config_dir.mkdir(parents=True)
    (config_dir / "dse.ldif").write_text(_DSE_WITH_INDEX)

    config = LDAPServerConfig(
        name="idx-archive",
        hostname="unused",
        is_archive=True,
        archive_path=str(tmp_path),
    )
    env = {
        "LDAP_MCP_EXPOSE_SENSITIVE_DATA": "true",
        "LDAP_SERVERS_CONFIG": "",
    }
    with patch.dict(os.environ, env):
        server = DirSrvMCP(servers=[config], include_env_fallback=False)
        async with Client(server) as client:
            result = await client.call_tool(
                "analyze_index_configuration", {"server_name": "idx-archive"}
            )
            data = result.data

    backends = data["backends"]
    assert len(backends) == 1
    # customattr has no nsSystemIndex ⇒ user index; objectclass is system
    assert backends[0]["user_index_count"] == 1


# ── 1.4 empty search terms rejected ──────────────────────────────────

@pytest.mark.asyncio
@pytest.mark.parametrize("term", ["   ", "*", "**", " * "])
async def test_search_users_by_name_rejects_empty_terms(term):
    server = _make_server(expose=True)
    async with Client(server) as client:
        with pytest.raises(ToolError, match="non-wildcard"):
            await client.call_tool("search_users_by_name", {"name": term})


@pytest.mark.asyncio
async def test_search_users_by_attribute_rejects_empty_value():
    server = _make_server(expose=True)
    async with Client(server) as client:
        with pytest.raises(ToolError, match="non-wildcard"):
            await client.call_tool(
                "search_users_by_attribute", {"attribute": "mail", "value": "**"}
            )


def test_normalize_search_term_collapses_wildcards():
    from ldap_assistant_mcp.dirsrv_mcp.tools.users import _normalize_search_term

    assert _normalize_search_term("a**b", "name") == "a*b"
    assert _normalize_search_term("  jdoe  ", "name") == "jdoe"


# ── 1.4 run_monitor error formatting ─────────────────────────────────

@pytest.mark.asyncio
async def test_run_monitor_error_returns_formatted_dict_not_raw_exception():
    server = _make_server(expose=True)
    ds = MagicMock()
    _install_fake_connection(server, ds)

    with patch(
        "ldap_assistant_mcp.dirsrv_mcp.tools.monitoring.Monitor",
        side_effect=RuntimeError("boom on /etc/dirsrv/slapd-prod1"),
    ):
        async with Client(server) as client:
            result = await client.call_tool("run_monitor", {})
            data = result.data

    assert data["type"] == "monitor"
    assert data["server"] == "ds-mock"
    assert "RuntimeError" in data["error"]


@pytest.mark.asyncio
async def test_run_monitor_error_sanitized_in_privacy_mode():
    server = _make_server(expose=False)
    ds = MagicMock()
    _install_fake_connection(server, ds)

    with patch(
        "ldap_assistant_mcp.dirsrv_mcp.tools.monitoring.Monitor",
        side_effect=RuntimeError("boom on /etc/dirsrv/slapd-prod1"),
    ):
        async with Client(server) as client:
            result = await client.call_tool("run_monitor", {})
            data = result.data

    assert data["type"] == "monitor"
    assert "/etc/dirsrv" not in data["error"], "paths must be scrubbed in privacy mode"


# ── 1.4 base64 LDIF values decoded ───────────────────────────────────

def test_parse_ldif_value_decodes_base64():
    from ldap_assistant_mcp.dirsrv_mcp.tools.dse_utils import _parse_ldif_value

    assert _parse_ldif_value("description:: aGVsbG8gd29ybGQ=\n") == "hello world"
    assert _parse_ldif_value("description: plain value\n") == "plain value"
    assert _parse_ldif_value("description:\n") == ""


def test_parse_ldif_value_keeps_invalid_base64_as_is():
    from ldap_assistant_mcp.dirsrv_mcp.tools.dse_utils import _parse_ldif_value

    # Not valid base64 → returned unchanged rather than crashing
    assert _parse_ldif_value("attr:: !!!not-base64!!!\n") == "!!!not-base64!!!"


def test_get_all_entry_attrs_decodes_base64_values():
    from ldap_assistant_mcp.dirsrv_mcp.tools.dse_utils import get_all_entry_attrs

    dse = MagicMock()
    dse._contents = [
        "dn: cn=config\n",
        "cn: config\n",
        "description:: aGVsbG8=\n",
        "\n",
    ]
    attrs = get_all_entry_attrs(dse, "cn=config")
    assert attrs["description"] == ["hello"]


def test_dseldif_keeps_last_line_without_trailing_blank(tmp_path):
    """lib389 DSEldif.__init__ drops the file's final line; our patch keeps it.

    Without the patch, a dse.ldif that does not end with a blank line loses
    the last attribute of its last entry (here nsSystemIndex), silently
    flipping a system index to a user index.
    """
    from lib389.dseldif import DSEldif

    dse_path = tmp_path / "dse.ldif"
    dse_path.write_text(
        "dn: cn=objectclass,cn=index,cn=userroot,cn=ldbm database,cn=plugins,cn=config\n"
        "cn: objectclass\n"
        "nsIndexType: eq\n"
        "nsSystemIndex: true\n"  # last line, no trailing blank line
    )
    ds = MagicMock()
    ds.serverid = "x"
    dse = DSEldif(ds, path=str(dse_path))
    dn = "cn=objectclass,cn=index,cn=userroot,cn=ldbm database,cn=plugins,cn=config"
    assert dse.get(dn, "nsSystemIndex", single=True) == "true"


# ── 1.4 ldap_search truncation flag ──────────────────────────────────

@pytest.mark.asyncio
async def test_ldap_search_sets_truncated_on_sizelimit():
    import ldap as _ldap

    server = _make_server(expose=True)
    ds = MagicMock()
    ds.search_ext.return_value = 7
    ds.result.side_effect = [
        (_ldap.RES_SEARCH_ENTRY, [("uid=a,dc=example,dc=com", {"uid": [b"a"]})]),
        _ldap.SIZELIMIT_EXCEEDED(),
    ]
    _install_fake_connection(server, ds)

    async with Client(server) as client:
        result = await client.call_tool(
            "ldap_search",
            {"base_dn": "dc=example,dc=com", "filter": "(uid=*)", "limit": 1},
        )
        data = result.data

    assert data["truncated"] is True
    assert data["total_returned"] == 1
    # The server was asked to enforce the cap
    assert ds.search_ext.call_args.kwargs["sizelimit"] == 1


@pytest.mark.asyncio
async def test_ldap_search_not_truncated_on_complete_result():
    import ldap as _ldap

    server = _make_server(expose=True)
    ds = MagicMock()
    ds.search_ext.return_value = 7
    ds.result.side_effect = [
        (_ldap.RES_SEARCH_ENTRY, [("uid=a,dc=example,dc=com", {"uid": [b"a"]})]),
        (_ldap.RES_SEARCH_RESULT, []),
    ]
    _install_fake_connection(server, ds)

    async with Client(server) as client:
        result = await client.call_tool(
            "ldap_search", {"base_dn": "dc=example,dc=com", "filter": "(uid=a)"}
        )
        data = result.data

    assert data["truncated"] is False
    assert data["total_returned"] == 1


@pytest.mark.asyncio
async def test_ldap_search_empty_base_dn_returns_root_dse():
    """base_dn="" is the root DSE — a valid search, and the entry's empty DN
    must not be dropped as malformed (regression: min_length=1 rejected it,
    then the ``not dn`` guard skipped the returned entry)."""
    import ldap as _ldap

    server = _make_server(expose=True)
    ds = MagicMock()
    ds.search_ext.return_value = 7
    ds.result.side_effect = [
        # python-ldap returns the root DSE with an empty DN
        (_ldap.RES_SEARCH_ENTRY, [("", {"vendorName": [b"389 Project"]})]),
        (_ldap.RES_SEARCH_RESULT, []),
    ]
    _install_fake_connection(server, ds)

    async with Client(server) as client:
        result = await client.call_tool(
            "ldap_search",
            {"base_dn": "", "scope": "BASE", "filter": "(objectClass=*)"},
        )
        data = result.data

    assert data["total_returned"] == 1
    assert data["items"][0]["dn"] == ""
    assert data["items"][0]["attrs"]["vendorName"] == ["389 Project"]


# ── lib389 >= 3.3 _find_attr signature compatibility ─────────────────

def test_patched_find_attr_accepts_lower_kwarg(tmp_path):
    """lib389 >= 3.3 DSEldif.get() calls _find_attr(..., lower=...) — the
    patched replacement must accept the kwarg on any lib389 version
    (regression: TypeError broke every offline/archive DSE read on 3.3.0)."""
    from lib389.dseldif import DSEldif

    dse_path = tmp_path / "dse.ldif"
    dse_path.write_text(
        "dn: cn=config\n"
        "cn: config\n"
        "nsDS5ReplicaRoot: dc=example,dc=com\n"
        "\n"
    )
    ds = MagicMock()
    ds.serverid = "x"
    dse = DSEldif(ds, path=str(dse_path))

    # Direct calls with the new-signature kwarg (both values)
    _, attr_data = dse._find_attr("cn=config", "nsds5replicaroot", lower=True)
    assert list(attr_data.values()) == ["dc=example,dc=com"]
    _, attr_data = dse._find_attr("cn=config", "nsds5replicaroot", lower=False)
    assert list(attr_data.values()) == ["dc=example,dc=com"]

    # And through get(), which passes lower= on lib389 >= 3.3
    assert dse.get("cn=config", "nsDS5ReplicaRoot", single=True) == "dc=example,dc=com"
