"""Regression tests for the operability surface.

Covers:
- service_liveness never touches the connection manager
- service_readiness ready / degraded / not_ready (zero servers)
- get_capabilities tool availability matrix (mode, file access, privacy)
- server-addressable resource template ldap://{server_name}/config
- doctor / support-bundle / --check-config / --list-tools CLI exit codes
"""

from __future__ import annotations

import json
import os
import stat
from unittest.mock import patch

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from ldap_assistant_mcp.core import LDAPServerConfig, MCPSettings, __version__
from ldap_assistant_mcp.dirsrv_mcp.server import DirSrvMCP
from ldap_assistant_mcp.lib.envelope import CODE_INVALID_CONFIG
from ldap_assistant_mcp.main import main

DSE_LDIF = """\
dn: cn=config
cn: config
nsslapd-port: 389
nsslapd-versionstring: 389-Directory/2.4.6
nsslapd-security: on

dn: cn=ldbm database,cn=plugins,cn=config
cn: ldbm database

"""

ACCESS_LOG = """\
[01/Jan/2024:10:00:02.000000000 +0000] conn=1 op=1 SRCH base="dc=example,dc=com" scope=2 filter="(uid=a)" attrs=ALL
[01/Jan/2024:10:00:02.100000000 +0000] conn=1 op=1 RESULT err=0 tag=101 nentries=1 wtime=0.000001 optime=0.0002 etime=0.000201
"""

ERROR_LOG = """\
[01/Jan/2024:10:00:01.000000000 +0000] - INFO - main - starting up
"""


def _make_sos_tree(tmp_path):
    """Create a minimal extracted-archive tree (the shared archive-test idiom)."""
    inst = "slapd-t013"
    config_dir = tmp_path / "etc" / "dirsrv" / inst
    config_dir.mkdir(parents=True)
    (config_dir / "dse.ldif").write_text(DSE_LDIF)
    logs_dir = tmp_path / "var" / "log" / "dirsrv" / inst
    logs_dir.mkdir(parents=True)
    (logs_dir / "access").write_text(ACCESS_LOG)
    (logs_dir / "errors").write_text(ERROR_LOG)
    return tmp_path


def _archive_config(tmp_path, name="t013-archive"):
    return LDAPServerConfig(
        name=name,
        hostname="archive",
        port=0,
        is_archive=True,
        archive_path=str(tmp_path),
    )


@pytest.fixture
def sos_tree(tmp_path):
    return _make_sos_tree(tmp_path)


@pytest.fixture
def archive_mcp(sos_tree):
    env = {"LDAP_MCP_EXPOSE_SENSITIVE_DATA": "true", "LDAP_SERVERS_CONFIG": ""}
    with patch.dict(os.environ, env):
        yield DirSrvMCP(
            servers=[_archive_config(sos_tree)], include_env_fallback=False
        )


@pytest.fixture
def privacy_archive_mcp(sos_tree):
    env = {"LDAP_MCP_EXPOSE_SENSITIVE_DATA": "", "LDAP_SERVERS_CONFIG": ""}
    with patch.dict(os.environ, env):
        yield DirSrvMCP(
            servers=[_archive_config(sos_tree)],
            settings=MCPSettings(expose_sensitive_data=False),
            include_env_fallback=False,
        )


async def _call(server, tool, args=None):
    async with Client(server) as client:
        result = await client.call_tool(tool, args or {})
        return result.data


class _PoisonedManager:
    """Any attribute access proves the connection manager was touched."""

    def __getattr__(self, name):
        raise AssertionError(
            f"service_liveness touched connection_manager.{name}"
        )


class TestServiceLiveness:
    async def test_liveness_never_touches_connection_manager(self, archive_mcp):
        archive_mcp.connection_manager = _PoisonedManager()
        data = await _call(archive_mcp, "service_liveness")
        assert data["type"] == "service_liveness"
        assert data["status"] == "alive"
        assert data["version"] == __version__
        assert data["server_count"] == 1
        assert data["uptime_seconds"] >= 0


class TestServiceReadiness:
    async def test_zero_servers_is_not_ready(self, archive_mcp):
        archive_mcp.server_configs.clear()
        data = await _call(archive_mcp, "service_readiness")
        assert data["status"] == "not_ready"
        assert data["checks"]["config_loaded"]["status"] == "failed"
        assert data["checks"]["config_loaded"]["server_count"] == 0
        codes = {reason["code"] for reason in data["reasons"]}
        assert CODE_INVALID_CONFIG in codes

    async def test_archive_server_is_ready(self, archive_mcp):
        data = await _call(archive_mcp, "service_readiness")
        assert data["status"] == "ready"
        assert data["reasons"] == []
        assert data["reachability_checked"] is False
        assert data["checks"]["tools_registered"]["status"] == "ok"
        assert data["checks"]["tools_registered"]["tool_count"] >= 45
        server = data["checks"]["servers"][0]
        assert server["name"] == "t013-archive"
        assert server["mode"] == "archive"
        assert server["state"] == "valid"

    async def test_invalid_server_config_is_degraded(self, sos_tree):
        # Remote simple-auth server with no bind password source: connect()
        # would refuse it, so readiness must flag it without connecting.
        bad = LDAPServerConfig(name="badpw", hostname="ldap.example.com")
        env = {"LDAP_MCP_EXPOSE_SENSITIVE_DATA": "true", "LDAP_SERVERS_CONFIG": ""}
        with patch.dict(os.environ, env):
            mcp = DirSrvMCP(
                servers=[_archive_config(sos_tree), bad],
                include_env_fallback=False,
            )
        data = await _call(mcp, "service_readiness")
        assert data["status"] == "degraded"
        states = {s["name"]: s for s in data["checks"]["servers"]}
        assert states["t013-archive"]["state"] == "valid"
        assert states["badpw"]["state"] == "invalid"
        assert states["badpw"]["code"] == CODE_INVALID_CONFIG
        assert "password" in states["badpw"]["detail"]


class TestGetCapabilities:
    async def test_archive_marks_live_only_tools_unavailable(self, archive_mcp):
        data = await _call(archive_mcp, "get_capabilities")
        assert data["type"] == "capabilities"
        assert data["service"]["tool_count"] >= 45
        server = data["servers"][0]
        assert server["mode"] == "archive"
        assert server["file_access"] == "archive"
        assert server["reachable"] is None  # not probed by default
        matrix = server["tools"]
        # Live-only tools are unavailable with a reason
        for live_only in ("get_replication_status", "ldap_search", "run_monitor"):
            assert matrix[live_only]["available"] is False
            assert "live" in matrix[live_only]["reason"]
        # Archive tools and mode-agnostic tools stay available
        for available in ("analyze_archive", "validate_configuration", "first_look"):
            assert matrix[available]["available"] is True
        assert server["evidence_limitations"]

    async def test_live_server_capabilities(self, archive_mcp):
        # Add a remote live server and check the inverse gating.
        live = LDAPServerConfig(
            name="live-1", hostname="ldap.example.com", bind_password="x"
        )
        archive_mcp.add_server(live)
        data = await _call(archive_mcp, "get_capabilities", {"server_name": "live-1"})
        assert len(data["servers"]) == 1
        server = data["servers"][0]
        assert server["mode"] == "remote_live"
        assert server["file_access"] == "none"
        matrix = server["tools"]
        assert matrix["analyze_archive"]["available"] is False
        assert "offline or archive" in matrix["analyze_archive"]["reason"]
        # Log tools need local file access on a remote server
        assert matrix["analyze_access_log"]["available"] is False
        assert "file access" in matrix["analyze_access_log"]["reason"]
        assert matrix["get_replication_status"]["available"] is True

    async def test_privacy_mode_disables_raw_tools_with_reason(
        self, privacy_archive_mcp
    ):
        data = await _call(privacy_archive_mcp, "get_capabilities")
        assert data["service"]["privacy_mode"] is True
        matrix = data["servers"][0]["tools"]
        # parse_* is mode-compatible with archive but privacy-disabled
        assert matrix["parse_access_log"]["available"] is False
        assert "privacy" in matrix["parse_access_log"]["reason"]
        # analyze_* statistics tools stay available in privacy mode
        assert matrix["analyze_access_log"]["available"] is True

    async def test_check_reachability_probes_archive(self, archive_mcp):
        data = await _call(
            archive_mcp, "get_capabilities", {"check_reachability": True}
        )
        assert data["servers"][0]["reachable"] is True

    async def test_unknown_server_is_explicit_error(self, archive_mcp):
        with pytest.raises(ToolError) as excinfo:
            await _call(archive_mcp, "get_capabilities", {"server_name": "nope"})
        assert "not configured" in str(excinfo.value)


class TestServerAddressableResources:
    async def test_template_registered_alongside_old_uris(self, archive_mcp):
        async with Client(archive_mcp) as client:
            templates = await client.list_resource_templates()
            resources = await client.list_resources()
        template_uris = {t.uriTemplate for t in templates}
        assert "ldap://{server_name}/config" in template_uris
        assert "config://config-attribute/{attribute}" in template_uris
        by_uri = {str(r.uri): r for r in resources}
        assert "config://config-all" in by_uri
        assert by_uri["config://config-all"].mimeType == "application/json"

    async def test_server_addressable_config_rejects_archive(self, archive_mcp):
        async with Client(archive_mcp) as client:
            with pytest.raises(Exception) as excinfo:
                await client.read_resource("ldap://t013-archive/config")
        msg = str(excinfo.value)
        assert "requires a running server" in msg
        assert "t013-archive" in msg

    async def test_server_addressable_config_unknown_server(self, archive_mcp):
        async with Client(archive_mcp) as client:
            with pytest.raises(Exception) as excinfo:
                await client.read_resource("ldap://nope/config")
        assert "not configured" in str(excinfo.value)


def _write_config(tmp_path, payload, mode=None):
    cfg = tmp_path / "servers.json"
    cfg.write_text(json.dumps(payload))
    if mode is not None:
        cfg.chmod(mode)
    return cfg


class TestDoctorCLI:
    def test_doctor_valid_config_exits_0(self, sos_tree, tmp_path, capsys):
        cfg = _write_config(
            tmp_path,
            {
                "servers": [
                    {
                        "name": "t013-archive",
                        "is_archive": True,
                        "archive_path": str(sos_tree),
                    }
                ]
            },
        )
        with patch.dict(os.environ, {"LDAP_SERVERS_CONFIG": ""}):
            with pytest.raises(SystemExit) as excinfo:
                main(["doctor", "--config", str(cfg), "--json"])
        assert excinfo.value.code == 0
        report = json.loads(capsys.readouterr().out)
        assert report["status"] == "healthy"
        assert report["server_count"] == 1
        assert report["servers"][0]["mode"] == "archive"
        assert report["servers"][0]["transport"] == "file"
        assert report["versions"]["ldap_assistant_mcp"] == __version__
        # No hostnames anywhere in the per-server posture
        assert "hostname" not in report["servers"][0]

    def test_doctor_config_typo_exits_1(self, tmp_path, capsys):
        cfg = _write_config(
            tmp_path,
            {"servers": [{"name": "x", "hostname": "h", "tls_verify": "flase"}]},
        )
        with patch.dict(os.environ, {"LDAP_SERVERS_CONFIG": ""}):
            with pytest.raises(SystemExit) as excinfo:
                main(["doctor", "--config", str(cfg), "--json"])
        assert excinfo.value.code == 1
        report = json.loads(capsys.readouterr().out)
        assert report["status"] == "config_error"
        assert "tls_verify" in report["error"]

    def test_doctor_degraded_invalid_server_exits_2(self, tmp_path, capsys):
        # Loads fine but is statically unusable (simple auth, no password).
        cfg = _write_config(
            tmp_path,
            {"servers": [{"name": "badpw", "hostname": "ldap.example.com"}]},
        )
        with patch.dict(os.environ, {"LDAP_SERVERS_CONFIG": ""}):
            with pytest.raises(SystemExit) as excinfo:
                main(["doctor", "--config", str(cfg), "--json"])
        assert excinfo.value.code == 2
        report = json.loads(capsys.readouterr().out)
        assert report["status"] == "degraded"

    def test_doctor_connect_probes_archive(self, sos_tree, tmp_path, capsys):
        cfg = _write_config(
            tmp_path,
            {
                "servers": [
                    {
                        "name": "t013-archive",
                        "is_archive": True,
                        "archive_path": str(sos_tree),
                    }
                ]
            },
        )
        with patch.dict(os.environ, {"LDAP_SERVERS_CONFIG": ""}):
            with pytest.raises(SystemExit) as excinfo:
                main(["doctor", "--config", str(cfg), "--json", "--connect"])
        assert excinfo.value.code == 0
        report = json.loads(capsys.readouterr().out)
        assert report["servers"][0]["reachable"] is True

    def test_doctor_connect_error_sanitized_in_privacy_mode(self, tmp_path, capsys):
        """Review fix: doctor --json is pasted into tickets; a failed
        probe's error detail must be scrubbed in privacy mode instead of
        carrying raw hostnames/URLs/DNs."""
        from ldap_assistant_mcp.dirsrv_mcp.connection import (
            ConnectionFailed,
            ConnectionManager,
        )

        cfg = _write_config(
            tmp_path,
            {
                "servers": [
                    {
                        "name": "prod",
                        "hostname": "secret-doctor-host.internal.example",
                        "bind_dn": "cn=admin,dc=corp,dc=internal",
                        "bind_password_env": "TEST_DOCTOR_BIND_PW",
                    }
                ]
            },
        )
        boom = ConnectionFailed(
            "Cannot connect to ldap://secret-doctor-host.internal.example:389 "
            "bound as cn=admin,dc=corp,dc=internal"
        )
        env = {"LDAP_SERVERS_CONFIG": "", "TEST_DOCTOR_BIND_PW": "pw"}
        with patch.dict(os.environ, env):
            with patch.object(ConnectionManager, "connect", side_effect=boom):
                with pytest.raises(SystemExit) as excinfo:
                    main(["doctor", "--config", str(cfg), "--json", "--connect"])
        assert excinfo.value.code == 2
        report = json.loads(capsys.readouterr().out)
        server = report["servers"][0]
        assert server["reachable"] is False
        err = server.get("reachability_error", "")
        assert "secret-doctor-host" not in err
        assert "dc=corp" not in err


CANARY_PASSWORD = "CANARY-Secret.12345"
CANARY_HOSTNAME = "secret-host.internal.example"
CANARY_BIND_DN = "cn=admin,dc=corp,dc=internal"


class TestSupportBundleCLI:
    def test_bundle_is_0600_and_leak_free(self, tmp_path, capsys):
        cfg = _write_config(
            tmp_path,
            {
                "servers": [
                    {
                        "name": "prod-1",
                        "hostname": CANARY_HOSTNAME,
                        "bind_dn": CANARY_BIND_DN,
                        "bind_password": CANARY_PASSWORD,
                        "base_dn": "dc=corp,dc=internal",
                    }
                ]
            },
            mode=0o600,  # inline bind_password requires owner-only config
        )
        out = tmp_path / "bundle.json"
        with patch.dict(os.environ, {"LDAP_SERVERS_CONFIG": ""}):
            with pytest.raises(SystemExit) as excinfo:
                main(["support-bundle", "--config", str(cfg), "--output", str(out)])
        assert excinfo.value.code == 0
        st = os.stat(out)
        assert stat.S_IMODE(st.st_mode) == 0o600
        text = out.read_text()
        assert len(text.encode()) < 1024 * 1024
        assert CANARY_PASSWORD not in text
        assert CANARY_HOSTNAME not in text
        assert CANARY_BIND_DN not in text
        assert "dc=corp" not in text
        bundle = json.loads(text)
        assert bundle["type"] == "support_bundle"
        assert bundle["config_fingerprint"]["servers"][0]["name"] == "prod-1"
        assert bundle["config_fingerprint"]["servers"][0]["transport"] == "ldap"
        assert bundle["versions"]["ldap_assistant_mcp"] == __version__
        assert bundle["doctor"]["servers"][0]["credential_source"] == "inline"

    def test_bundle_config_error_exits_1(self, tmp_path):
        cfg = _write_config(tmp_path, {"servers": []})
        out = tmp_path / "bundle.json"
        with patch.dict(os.environ, {"LDAP_SERVERS_CONFIG": ""}):
            with pytest.raises(SystemExit) as excinfo:
                main(["support-bundle", "--config", str(cfg), "--output", str(out)])
        assert excinfo.value.code == 1
        assert not out.exists()

    def test_bundle_refuses_leaky_server_name(self, tmp_path):
        # A server *named* after its hostname would leak via the fingerprint;
        # the forbidden-content scan must refuse to write the bundle.
        cfg = _write_config(
            tmp_path,
            {"servers": [{"hostname": CANARY_HOSTNAME, "bind_password_env": "X"}]},
        )
        out = tmp_path / "bundle.json"
        env = {"LDAP_SERVERS_CONFIG": "", "X": "pw"}
        with patch.dict(os.environ, env):
            with pytest.raises(SystemExit) as excinfo:
                main(["support-bundle", "--config", str(cfg), "--output", str(out)])
        assert excinfo.value.code == 2
        assert not out.exists()

    def test_bundle_catches_case_differing_hostname_leak(self, tmp_path):
        """Review fix: the leak scan casefolds, so a case-differing
        spelling of a forbidden hostname still refuses the bundle."""
        cfg = _write_config(
            tmp_path,
            {
                "servers": [
                    {
                        "name": CANARY_HOSTNAME.upper(),
                        "hostname": CANARY_HOSTNAME,
                        "bind_password_env": "X",
                    }
                ]
            },
        )
        out = tmp_path / "bundle.json"
        env = {"LDAP_SERVERS_CONFIG": "", "X": "pw"}
        with patch.dict(os.environ, env):
            with pytest.raises(SystemExit) as excinfo:
                main(["support-bundle", "--config", str(cfg), "--output", str(out)])
        assert excinfo.value.code == 2
        assert not out.exists()

    def test_bundle_catches_json_escaped_leak(self, tmp_path):
        """Review fix: a forbidden value with non-ASCII appears
        \\uXXXX-escaped in the JSON payload; the scan must catch the
        JSON-encoded spelling, not just the raw substring."""
        leaky_dn = "cn=ädmin,dc=corp,dc=internal"
        cfg = _write_config(
            tmp_path,
            {
                "servers": [
                    {
                        "name": leaky_dn,
                        "hostname": "h1.example",
                        "bind_dn": leaky_dn,
                        "bind_password_env": "X",
                    }
                ]
            },
        )
        out = tmp_path / "bundle.json"
        env = {"LDAP_SERVERS_CONFIG": "", "X": "pw"}
        with patch.dict(os.environ, env):
            with pytest.raises(SystemExit) as excinfo:
                main(["support-bundle", "--config", str(cfg), "--output", str(out)])
        assert excinfo.value.code == 2
        assert not out.exists()


class TestPrivacyDisabledMirror:
    def test_mirror_matches_create_privacy_error_call_sites(self):
        """_PRIVACY_DISABLED_TOOLS is a hand-maintained mirror of the
        create_privacy_error() call sites; this pins the two together so a
        new call site cannot silently make get_capabilities misreport."""
        import re
        from pathlib import Path

        import ldap_assistant_mcp.dirsrv_mcp.tools as tools_pkg
        from ldap_assistant_mcp.dirsrv_mcp.tools.capabilities import (
            _PRIVACY_DISABLED_TOOLS,
        )

        found = set()
        for py in Path(tools_pkg.__file__).parent.glob("*.py"):
            for match in re.finditer(
                r'create_privacy_error\(\s*"([^"]+)"', py.read_text()
            ):
                found.add(match.group(1))
        assert found == set(_PRIVACY_DISABLED_TOOLS)


class TestConfigAndToolFlags:
    def test_check_config_valid_exits_0(self, sos_tree, tmp_path, capsys):
        cfg = _write_config(
            tmp_path,
            {
                "servers": [
                    {
                        "name": "t013-archive",
                        "is_archive": True,
                        "archive_path": str(sos_tree),
                    }
                ]
            },
        )
        with patch.dict(os.environ, {"LDAP_SERVERS_CONFIG": ""}):
            with pytest.raises(SystemExit) as excinfo:
                main(["--check-config", "--config", str(cfg)])
        assert excinfo.value.code == 0
        assert "Configuration OK" in capsys.readouterr().out

    def test_check_config_invalid_exits_1(self, tmp_path, capsys):
        cfg = _write_config(
            tmp_path,
            {"servers": [{"name": "x", "hostname": "h", "tls_verify": "flase"}]},
        )
        with patch.dict(os.environ, {"LDAP_SERVERS_CONFIG": ""}):
            with pytest.raises(SystemExit) as excinfo:
                main(["--check-config", "--config", str(cfg)])
        assert excinfo.value.code == 1
        assert "INVALID" in capsys.readouterr().err

    def test_list_tools_includes_new_tools(self, sos_tree, tmp_path, capsys):
        cfg = _write_config(
            tmp_path,
            {
                "servers": [
                    {
                        "name": "t013-archive",
                        "is_archive": True,
                        "archive_path": str(sos_tree),
                    }
                ]
            },
        )
        with patch.dict(os.environ, {"LDAP_SERVERS_CONFIG": ""}):
            with pytest.raises(SystemExit) as excinfo:
                main(["--list-tools", "--config", str(cfg)])
        assert excinfo.value.code == 0
        out = capsys.readouterr().out
        for tool in ("get_capabilities", "service_liveness", "service_readiness"):
            assert tool in out
