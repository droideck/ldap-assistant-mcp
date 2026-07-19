"""Regression tests: privacy oracles and final-output/stderr leaks.

Covers:

- ``search_users_by_name`` privacy counts are bucketed (anti count-oracle).
- ``analyze_audit_log`` DN filters are disabled in privacy mode (existence
  oracle for arbitrary DNs, subtree matching included).
- ``sanitize_text`` catches two-label/arbitrary-TLD hostnames, DNs with
  spaces in values, and bare single-segment system paths.
- Endpoint details (URLs, serverids, archive paths) are logged at DEBUG,
  not INFO, and the stderr handler sanitizes records in privacy mode.
"""

from __future__ import annotations

import logging
import os
from contextlib import contextmanager
from unittest.mock import MagicMock, patch

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from ldap_assistant_mcp.core import MCPSettings, _RedactingStderrFilter, LDAPServerConfig
from ldap_assistant_mcp.dirsrv_mcp.server import DirSrvMCP
from ldap_assistant_mcp.lib.privacy import PrivacySanitizer, bucket_count


def _make_server(expose: bool) -> DirSrvMCP:
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
    @contextmanager
    def _conn(server_name=None):
        yield (server_name or server.default_server, ds)

    server._connection = _conn


# ---------------------------------------------------------------------------
# sanitize_text pattern gaps
# ---------------------------------------------------------------------------


class TestSanitizeTextGaps:
    def setup_method(self):
        self.sanitizer = PrivacySanitizer()

    def test_two_label_arbitrary_tld_hostname(self):
        out = self.sanitizer.sanitize_text("connect to ldapserver.prodnet failed")
        assert "prodnet" not in out
        assert "[hostname]" in out

    def test_multi_label_arbitrary_tld_hostname(self):
        out = self.sanitizer.sanitize_text("host db1.internal.megacorp responded")
        assert "megacorp" not in out

    def test_dn_with_spaces_in_value(self):
        out = self.sanitizer.sanitize_text(
            "entry cn=John Smith,ou=People,dc=example,dc=com rejected"
        )
        assert "John Smith" not in out
        assert "[dn]" in out

    def test_bare_system_path(self):
        out = self.sanitizer.sanitize_text("check /etc for permissions")
        assert "/etc" not in out
        assert "[path]" in out

    def test_file_names_are_preserved(self):
        out = self.sanitizer.sanitize_text("read logs.py and dse.ldif then access.log")
        assert "logs.py" in out
        assert "dse.ldif" in out
        assert "access.log" in out

    def test_version_numbers_are_preserved(self):
        out = self.sanitizer.sanitize_text("389-Directory/2.4.6 with FastMCP 3.4.2")
        assert "2.4.6" in out
        assert "3.4.2" in out


# ---------------------------------------------------------------------------
# Count oracles
# ---------------------------------------------------------------------------


class TestBucketCount:
    @pytest.mark.parametrize("count,expected", [
        (0, "0"), (1, "1-5"), (5, "1-5"), (6, "6-20"), (20, "6-20"),
        (21, "21-100"), (100, "21-100"), (101, "100+"), (10_000, "100+"),
    ])
    def test_buckets(self, count, expected):
        assert bucket_count(count) == expected


class TestNameSearchOracle:
    async def _search(self, expose: bool, n_matches: int):
        server = _make_server(expose=expose)
        ds = MagicMock()
        _install_fake_connection(server, ds)

        users_obj = MagicMock()
        users_obj.filter.return_value = [MagicMock() for _ in range(n_matches)]
        with patch(
            "ldap_assistant_mcp.dirsrv_mcp.tools.users.nsUserAccounts",
            return_value=users_obj,
        ), patch(
            "ldap_assistant_mcp.dirsrv_mcp.tools.users._collect_entries",
            return_value=([], False),
        ):
            async with Client(server) as client:
                result = await client.call_tool(
                    "search_users_by_name", {"name": "jd"}
                )
                return result.data

    async def test_privacy_mode_count_is_bucketed(self):
        data = await self._search(expose=False, n_matches=7)
        assert data["privacy_mode"] is True
        assert data["count"] == "6-20"
        assert "7" not in str(data["count"])

    async def test_privacy_mode_zero_matches(self):
        data = await self._search(expose=False, n_matches=0)
        assert data["count"] == "0"


class TestAuditDnOracle:
    @pytest.fixture
    def privacy_archive(self, tmp_path):
        inst = "slapd-t004"
        config_dir = tmp_path / "etc" / "dirsrv" / inst
        config_dir.mkdir(parents=True)
        (config_dir / "dse.ldif").write_text("dn: cn=config\ncn: config\n\n")
        logs_dir = tmp_path / "var" / "log" / "dirsrv" / inst
        logs_dir.mkdir(parents=True)
        (logs_dir / "audit").write_text(
            "time: 20240101100001\ndn: cn=config\nchangetype: modify\n"
            "modifiersname: cn=Directory Manager\n"
        )
        env = {"LDAP_MCP_EXPOSE_SENSITIVE_DATA": "false", "LDAP_SERVERS_CONFIG": ""}
        with patch.dict(os.environ, env):
            config = LDAPServerConfig(
                name="t004-archive",
                hostname="archive",
                port=0,
                is_archive=True,
                archive_path=str(tmp_path),
            )
            yield DirSrvMCP(servers=[config], include_env_fallback=False)

    async def test_target_dn_rejected_in_privacy_mode(self, privacy_archive):
        async with Client(privacy_archive) as client:
            with pytest.raises(ToolError) as exc:
                await client.call_tool(
                    "analyze_audit_log",
                    {"target_dn": "uid=victim,ou=People,dc=example,dc=com"},
                )
        assert "privacy mode" in str(exc.value)

    async def test_bind_dn_rejected_in_privacy_mode(self, privacy_archive):
        async with Client(privacy_archive) as client:
            with pytest.raises(ToolError):
                await client.call_tool(
                    "analyze_audit_log", {"bind_dn": "cn=probe"},
                )

    async def test_unfiltered_analysis_still_works(self, privacy_archive):
        async with Client(privacy_archive) as client:
            result = await client.call_tool("analyze_audit_log", {})
            data = result.data
        assert data["total_parsed"] == 1


# ---------------------------------------------------------------------------
# INFO logs and the stderr boundary
# ---------------------------------------------------------------------------


class TestLogEgress:
    def test_info_logs_do_not_carry_endpoints(self, caplog):
        with caplog.at_level(logging.INFO, logger="ldap_assistant_mcp"):
            _make_server(expose=False)
        info_messages = [
            r.getMessage() for r in caplog.records if r.levelno == logging.INFO
        ]
        joined = "\n".join(info_messages)
        assert "ldap://" not in joined
        assert "33891" not in joined

    def test_redacting_filter_sanitizes_in_privacy_mode(self):
        record = logging.LogRecord(
            name="ldap_assistant_mcp.test", level=logging.INFO, pathname="", lineno=0,
            msg="failed to reach ldap://secret-host.example.com:636",
            args=(), exc_info=None,
        )
        env = {k: v for k, v in os.environ.items() if k != "LDAP_MCP_EXPOSE_SENSITIVE_DATA"}
        with patch.dict(os.environ, env, clear=True):
            assert _RedactingStderrFilter().filter(record) is True
        assert "secret-host.example.com" not in record.getMessage()

    def test_redacting_filter_passthrough_when_exposed(self):
        record = logging.LogRecord(
            name="ldap_assistant_mcp.test", level=logging.INFO, pathname="", lineno=0,
            msg="failed to reach ldap://host.example.com:636",
            args=(), exc_info=None,
        )
        with patch.dict(os.environ, {"LDAP_MCP_EXPOSE_SENSITIVE_DATA": "true"}):
            assert _RedactingStderrFilter().filter(record) is True
        assert record.getMessage() == "failed to reach ldap://host.example.com:636"
