"""Regression tests: bounded results, cursors, and safe regex.

Covers:

- ``list_all_users`` / ``list_all_groups`` paginate with opaque cursors and
  report ``has_more`` — results are never silently cut.
- The regex validator rejects catastrophic patterns by structural analysis
  and accepts safe prefix-code alternations.
- ``find_unindexed_searches`` streams the access-log family (rotated + gz,
  per-file format) and anchors relative ranges to the dataset end for
  archives.
"""

from __future__ import annotations

import gzip
import json
import os
from contextlib import contextmanager
from unittest.mock import MagicMock, patch

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from ldap_assistant_mcp.core import LDAPServerConfig, MCPSettings
from ldap_assistant_mcp.dirsrv_mcp.server import DirSrvMCP
from ldap_assistant_mcp.dirsrv_mcp.tools.logs import _validate_regex
from ldap_assistant_mcp.lib.pagination import decode_cursor, encode_cursor, paginate


class TestPaginationHelpers:
    def test_roundtrip(self):
        assert decode_cursor(encode_cursor(42)) == 42
        assert decode_cursor(None) == 0
        assert decode_cursor("") == 0

    def test_garbage_cursor_raises(self):
        for bad in ("nonsense", "bzo6LTU=", "aGVsbG8="):  # incl. o:-5, hello
            with pytest.raises(ToolError):
                decode_cursor(bad)

    def test_paginate_pages(self):
        items = list(range(10))
        page, has_more, cursor = paginate(items, 0, 4)
        assert page == [0, 1, 2, 3] and has_more and decode_cursor(cursor) == 4
        page, has_more, cursor = paginate(items, 4, 4)
        assert page == [4, 5, 6, 7] and has_more and decode_cursor(cursor) == 8
        page, has_more, cursor = paginate(items, 8, 4)
        assert page == [8, 9] and not has_more and cursor is None

    def test_paginate_is_lazy(self):
        consumed = []

        def gen():
            for i in range(1000):
                consumed.append(i)
                yield i

        page, has_more, _ = paginate(gen(), 0, 5)
        assert page == [0, 1, 2, 3, 4]
        assert has_more
        # offset + limit + 1 items at most
        assert len(consumed) <= 6

    def test_offset_past_end(self):
        page, has_more, cursor = paginate([1, 2], 10, 5)
        assert page == [] and not has_more and cursor is None


def _make_server() -> DirSrvMCP:
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
            settings=MCPSettings(expose_sensitive_data=True),
        )


def _install_fake_connection(server: DirSrvMCP, ds) -> None:
    @contextmanager
    def _conn(server_name=None):
        yield (server_name or server.default_server, ds)

    server._connection = _conn


def _fake_user(uid: str):
    entry = MagicMock()
    entry.get_all_attrs_json.return_value = json.dumps(
        {"dn": f"uid={uid},ou=People,dc=example,dc=com", "attrs": {"uid": [uid]}}
    )
    return entry


class TestUserPagination:
    async def _page(self, n_users: int, limit: int, cursor=None):
        server = _make_server()
        _install_fake_connection(server, MagicMock())
        users_obj = MagicMock()
        users_obj.list.return_value = [_fake_user(f"user{i:03d}") for i in range(n_users)]
        with patch(
            "ldap_assistant_mcp.dirsrv_mcp.tools.users.nsUserAccounts",
            return_value=users_obj,
        ), patch(
            "ldap_assistant_mcp.dirsrv_mcp.tools.users._get_user_status",
            return_value={"simple_status": "active"},
        ):
            async with Client(server) as client:
                args = {"limit": limit}
                if cursor:
                    args["cursor"] = cursor
                result = await client.call_tool("list_all_users", args)
                return result.data

    async def test_first_page_reports_more(self):
        data = await self._page(7, 3)
        assert data["total_returned"] == 3
        assert data["has_more"] is True
        assert data["next_cursor"]
        assert data["items"][0]["attrs"]["uid"] == ["user000"]

    async def test_cursor_walks_all_pages(self):
        seen = []
        cursor = None
        for _ in range(5):
            data = await self._page(7, 3, cursor)
            seen.extend(u["attrs"]["uid"][0] for u in data["items"])
            cursor = data["next_cursor"]
            if not data["has_more"]:
                break
        assert seen == [f"user{i:03d}" for i in range(7)]

    async def test_last_page_has_no_cursor(self):
        data = await self._page(3, 5)
        assert data["has_more"] is False
        assert data["next_cursor"] is None

    async def test_invalid_cursor_is_explicit_error(self):
        with pytest.raises(ToolError) as exc:
            await self._page(3, 5, cursor="garbage")
        assert "cursor" in str(exc.value).lower()


class TestGroupPagination:
    async def test_groups_paginate(self):
        server = _make_server()
        _install_fake_connection(server, MagicMock())
        groups_obj = MagicMock()

        def _fake_group(cn):
            g = MagicMock()
            g.get_all_attrs_json.return_value = json.dumps(
                {"dn": f"cn={cn},ou=Groups,dc=example,dc=com", "attrs": {"cn": [cn]}}
            )
            return g

        groups_obj.list.return_value = [_fake_group(f"g{i}") for i in range(5)]
        with patch(
            "ldap_assistant_mcp.dirsrv_mcp.tools.groups.Groups",
            return_value=groups_obj,
        ):
            async with Client(server) as client:
                result = await client.call_tool("list_all_groups", {"limit": 2})
                data = result.data
        assert data["total_returned"] == 2
        assert data["has_more"] is True
        assert data["next_cursor"]


class TestRegexStructuralValidation:
    @pytest.mark.parametrize("bad", [
        "(a|aa)+$", "(a|aa)*", r"(\d|\d\d)+", "(a+)+", "(x*)*",
        "((a+))+", "(a|a)+", r"([a-z]+)*", "(a?)+", "(a|ab)*",
        # NOT_LITERAL bypass: a negated class is not a literal — [^a]
        # overlaps 'b' on every non-'a' char, so this is ambiguous.
        "([^a]|b)+c", "([^x]|y)*z",
        # Case-insensitive compile makes case-variant words ambiguous.
        "(A|aa)+c", "(aB|Ab)+x",
    ])
    def test_catastrophic_rejected(self, bad):
        compiled, err = _validate_regex(bad)
        assert compiled is None, f"accepted catastrophic pattern {bad!r}"

    @pytest.mark.parametrize("good", [
        "err=32", "conn=1 op=[0-9]+", "SRCH.*uid=admin",
        "(ADD|MOD|DEL)+", "(err=0|err=49)*", "uid=[a-z]+",
        "a{1,10}", "(?:GET|POST) /api", "a++",
    ])
    def test_safe_accepted(self, good):
        compiled, err = _validate_regex(good)
        assert compiled is not None, f"rejected safe pattern {good!r}: {err}"


UNINDEXED_LOG = """\
[01/Jan/2024:10:00:02.000000000 +0000] conn=1 op=1 SRCH base="dc=example,dc=com" scope=2 filter="(department=eng)" attrs=ALL
[01/Jan/2024:10:00:02.100000000 +0000] conn=1 op=1 RESULT err=0 tag=101 nentries=500 notes=U wtime=0.1 optime=0.9 etime=1.0
"""


class TestUnindexedStreaming:
    @pytest.fixture
    def archive_mcp(self, tmp_path):
        inst = "slapd-t012"
        config_dir = tmp_path / "etc" / "dirsrv" / inst
        config_dir.mkdir(parents=True)
        (config_dir / "dse.ldif").write_text("dn: cn=config\ncn: config\n\n")
        logs_dir = tmp_path / "var" / "log" / "dirsrv" / inst
        logs_dir.mkdir(parents=True)
        (logs_dir / "access").write_text(UNINDEXED_LOG)
        with gzip.open(logs_dir / "access.20231231-000000.gz", "wt") as fh:
            fh.write(UNINDEXED_LOG.replace("department=eng", "title=mgr"))
        (logs_dir / "errors").write_text("")
        env = {"LDAP_MCP_EXPOSE_SENSITIVE_DATA": "true", "LDAP_SERVERS_CONFIG": ""}
        with patch.dict(os.environ, env):
            config = LDAPServerConfig(
                name="t012-archive",
                hostname="archive",
                port=0,
                is_archive=True,
                archive_path=str(tmp_path),
            )
            yield DirSrvMCP(servers=[config], include_env_fallback=False)

    async def test_archive_anchors_and_reads_gz_rotation(self, archive_mcp):
        async with Client(archive_mcp) as client:
            result = await client.call_tool(
                "find_unindexed_searches", {"time_range": "24h"}
            )
            data = result.data
        # Wall-clock "24h" would find nothing in a 2024 archive
        assert data["time_anchor"] == "dataset_end"
        assert data["total_unindexed_count"] >= 1
        filters = {p["filter_pattern"] for p in data["patterns"]}
        assert any("department" in f for f in filters)

    async def test_wider_window_includes_gz_rotation(self, archive_mcp):
        async with Client(archive_mcp) as client:
            result = await client.call_tool(
                "find_unindexed_searches", {"time_range": "60d"}
            )
            data = result.data
        filters = {p["filter_pattern"] for p in data["patterns"]}
        assert any("title" in f for f in filters), filters

    async def test_unreadable_rotation_counted_once(self, tmp_path):
        """A corrupt rotation is one incident, not one per scan pass.

        The traditional-format branch streams each file twice (SRCH
        correlation + notes scan); the reader incidents surfaced in the
        result must still count files, not passes.
        """
        inst = "slapd-t012b"
        config_dir = tmp_path / "etc" / "dirsrv" / inst
        config_dir.mkdir(parents=True)
        (config_dir / "dse.ldif").write_text("dn: cn=config\ncn: config\n\n")
        logs_dir = tmp_path / "var" / "log" / "dirsrv" / inst
        logs_dir.mkdir(parents=True)
        (logs_dir / "access").write_text(UNINDEXED_LOG)
        (logs_dir / "access.20231231-000000.gz").write_bytes(
            b"\x1f\x8b\x08\x00 this is not really gzip data"
        )
        (logs_dir / "errors").write_text("")
        env = {"LDAP_MCP_EXPOSE_SENSITIVE_DATA": "true", "LDAP_SERVERS_CONFIG": ""}
        with patch.dict(os.environ, env):
            config = LDAPServerConfig(
                name="t012b-archive",
                hostname="archive",
                port=0,
                is_archive=True,
                archive_path=str(tmp_path),
            )
            server = DirSrvMCP(servers=[config], include_env_fallback=False)
            async with Client(server) as client:
                result = await client.call_tool(
                    "find_unindexed_searches", {"time_range": "60d"}
                )
                data = result.data
        assert data["unreadable_files"] == 1
        # The readable current file was still analyzed
        assert data["total_unindexed_count"] >= 1

    @staticmethod
    def _make_archive(tmp_path, inst, access_writer, expose="true"):
        config_dir = tmp_path / "etc" / "dirsrv" / inst
        config_dir.mkdir(parents=True)
        (config_dir / "dse.ldif").write_text("dn: cn=config\ncn: config\n\n")
        logs_dir = tmp_path / "var" / "log" / "dirsrv" / inst
        logs_dir.mkdir(parents=True)
        access_writer(logs_dir)
        (logs_dir / "errors").write_text("")
        env = {"LDAP_MCP_EXPOSE_SENSITIVE_DATA": expose, "LDAP_SERVERS_CONFIG": ""}
        with patch.dict(os.environ, env):
            config = LDAPServerConfig(
                name=f"{inst}-archive",
                hostname="archive",
                port=0,
                is_archive=True,
                archive_path=str(tmp_path),
            )
            return DirSrvMCP(servers=[config], include_env_fallback=False)

    async def test_json_notes_object_carries_base_and_filter(self, tmp_path):
        """389 DS JSON RESULT records put base/filter inside notes[]."""
        record = (
            '{"local_time": "2024-01-01T10:00:02Z", "operation": "RESULT", '
            '"err": 0, "nentries": 500, "notes": [{"note": "U", '
            '"description": "Partially Unindexed Filter", '
            '"base": "dc=example,dc=com", "filter": "(department=eng)"}]}\n'
        )
        server = self._make_archive(
            tmp_path, "slapd-t012c",
            lambda d: (d / "access").write_text(record),
        )
        async with Client(server) as client:
            result = await client.call_tool(
                "find_unindexed_searches", {"time_range": "60d"}
            )
            data = result.data
        assert data["total_unindexed_count"] == 1
        pattern = data["patterns"][0]
        assert "department" in pattern["filter_pattern"]
        assert pattern["base_dn"] == "dc=example,dc=com"

    async def test_empty_current_file_still_anchors_to_rotation(self, tmp_path):
        """An empty current access log must not revert the archive anchor
        to the wall clock while a rotation still holds the evidence."""
        def _write(d):
            (d / "access").write_text("")
            with gzip.open(d / "access.20240101-000000.gz", "wt") as fh:
                fh.write(UNINDEXED_LOG)

        server = self._make_archive(tmp_path, "slapd-t012d", _write)
        async with Client(server) as client:
            result = await client.call_tool(
                "find_unindexed_searches", {"time_range": "24h"}
            )
            data = result.data
        assert data["time_anchor"] == "dataset_end"
        assert data["total_unindexed_count"] == 1

    async def test_all_files_unreadable_is_incomplete_not_healthy(self, tmp_path):
        """Zero readable evidence must not produce a HEALTHY no-findings.

        Rotated-only family whose single .gz member is corrupt: the reader
        counts it unreadable and nothing else was scanned.
        """
        def _write(d):
            (d / "access.20240101-000000.gz").write_bytes(
                b"\x1f\x8b\x08\x00 this is not really gzip data"
            )

        server = self._make_archive(tmp_path, "slapd-t012e", _write)
        async with Client(server) as client:
            result = await client.call_tool(
                "find_unindexed_searches", {"time_range": "24h"}
            )
            data = result.data
        assert data["status"] == "unknown"
        assert data["summary"].startswith("INCOMPLETE")
        assert data["unreadable_files"] == 1

    async def test_privacy_mode_findings_use_placeholders(self, tmp_path):
        """Finding details/title/metadata must not leak filter values or
        base DNs in privacy mode (the patterns list already redacts them)."""
        lines = []
        for i in range(12):
            lines.append(
                f'[01/Jan/2024:10:00:{i:02d}.000000000 +0000] conn={i} op=1 '
                f'SRCH base="dc=example,dc=com" scope=2 '
                f'filter="(telephoneNumber=555-000{i})" attrs=ALL\n'
            )
            lines.append(
                f'[01/Jan/2024:10:00:{i:02d}.100000000 +0000] conn={i} op=1 '
                f'RESULT err=0 tag=101 nentries=500 notes=U wtime=0.1 '
                f'optime=0.9 etime=1.0\n'
            )
        server = self._make_archive(
            tmp_path, "slapd-t012f",
            lambda d: (d / "access").write_text("".join(lines)),
            expose="false",
        )
        async with Client(server) as client:
            result = await client.call_tool(
                "find_unindexed_searches", {"time_range": "60d"}
            )
            data = result.data
        assert data["findings"], "expected a high-frequency finding"
        serialized = str(data["findings"])
        # Filter VALUES and base DNs are directory data and must not leak;
        # attribute names are schema-level and stay visible by design.
        assert "555-000" not in serialized
        assert "dc=example" not in serialized
        assert "[filter]" in data["findings"][0]["details"]
