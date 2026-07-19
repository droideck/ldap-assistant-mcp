"""Regression tests: unified streaming log/archive evidence readers.

Covers:

- Format is detected PER FILE, so mixed-format rotations each get the right
  parser; pretty-printed (multi-line) JSON records parse instead of counting
  as malformed; header records stay out of operation/severity statistics.
- Traditional LDIF audit logs stream record-by-record, unfold folded lines,
  and decode base64 DNs so DN filters can match them.
- Corrupt gzip rotations are skipped (and counted) without aborting the
  family; gzipped files stop at a decompression budget.
- Rotated-only families (no current base file) are still readable; entry
  limits keep the NEWEST matches instead of the oldest.
"""

from __future__ import annotations

import base64
import gzip
import os
from unittest.mock import MagicMock, patch

import pytest
from fastmcp import Client

from ldap_assistant_mcp.core import LDAPServerConfig
from ldap_assistant_mcp.dirsrv_mcp.server import DirSrvMCP
from ldap_assistant_mcp.dirsrv_mcp.tools.logs import (
    _iter_audit_records,
    _log_family_paths,
    _parse_access_log_entries,
    _read_lines_single,
    _unfold_ldif_lines,
)

DSE_LDIF = """\
dn: cn=config
cn: config
nsslapd-port: 389

"""

TRADITIONAL_LINES = """\
[01/Jan/2024:10:00:02.000000000 +0000] conn=1 op=1 SRCH base="dc=example,dc=com" scope=2 filter="(uid=a)" attrs=ALL
[01/Jan/2024:10:00:02.100000000 +0000] conn=1 op=1 RESULT err=0 tag=101 nentries=1 wtime=0.000001 optime=0.000200 etime=0.000201
"""

JSON_LINES = """\
{"local_time": "2024-01-02T10:00:01Z", "operation": "SEARCH", "err": 0}
{"local_time": "2024-01-02T10:00:02Z", "operation": "RESULT", "err": 0, "etime": "0.01"}
"""

PRETTY_JSON = """\
{
  "local_time": "2024-01-03T10:00:01Z",
  "operation": "SEARCH",
  "err": 0
}
{
  "local_time": "2024-01-03T10:00:02Z",
  "operation": "RESULT",
  "err": 0
}
"""

HEADER_THEN_RECORDS = """\
{"version": "389-Directory/3.0.0", "features": ["json-logging"]}
{"local_time": "2024-01-02T10:00:01Z", "operation": "SEARCH", "err": 0}
"""


def _fake_ds(access_path):
    ds = MagicMock()
    ds.ds_paths.access_log = str(access_path)
    return ds


class TestPerFileFormatDetection:
    def test_mixed_rotation_each_file_parsed_correctly(self, tmp_path):
        """A traditional rotation in a JSON family must be parsed
        as traditional, not counted line-by-line as malformed JSON."""
        current = tmp_path / "access"
        current.write_text(JSON_LINES)
        (tmp_path / "access.20240101-000000").write_text(TRADITIONAL_LINES)

        result = _parse_access_log_entries(
            _fake_ds(current), None, None, None, None, True, 100
        )
        # 2 JSON records + 2 traditional records, none malformed
        assert result["total_parsed"] == 4
        assert result["malformed_lines"] == 0
        assert result["operation_stats"].get("SRCH") == 1
        assert result["operation_stats"].get("SEARCH") == 1

    def test_pretty_json_records_parse(self, tmp_path):
        """Pretty-printed multi-line JSON is parsed, not malformed."""
        current = tmp_path / "access"
        current.write_text(PRETTY_JSON)
        result = _parse_access_log_entries(
            _fake_ds(current), None, None, None, None, False, 100
        )
        assert result["total_parsed"] == 2
        assert result["malformed_lines"] == 0
        assert result["operation_stats"] == {"SEARCH": 1, "RESULT": 1}

    def test_header_records_excluded_from_stats(self, tmp_path):
        """Header/metadata records must not pollute operation stats."""
        current = tmp_path / "access"
        current.write_text(HEADER_THEN_RECORDS)
        result = _parse_access_log_entries(
            _fake_ds(current), None, None, None, None, False, 100
        )
        assert result["total_parsed"] == 1
        assert "" not in result["operation_stats"]
        assert result["header_records"] == 1

    def test_malformed_ndjson_still_counted(self, tmp_path):
        current = tmp_path / "access"
        current.write_text('{"broken json\n{"local_time": "2024-01-02T10:00:01Z", "operation": "SEARCH", "err": 0}\n')
        result = _parse_access_log_entries(
            _fake_ds(current), None, None, None, None, False, 100
        )
        assert result["malformed_lines"] == 1
        assert result["total_parsed"] == 1


class TestAuditStreaming:
    def test_unfold_ldif_lines(self):
        lines = ["dn: uid=verylonguser,\n", " ou=People,dc=example,dc=com\n", "changetype: modify\n"]
        assert list(_unfold_ldif_lines(lines)) == [
            "dn: uid=verylonguser,ou=People,dc=example,dc=com",
            "changetype: modify",
        ]

    def test_folded_dn_is_matched(self):
        """A folded dn: line must still populate the record's dn."""
        log = (
            "time: 20240101100001\n"
            "dn: uid=folded-user,ou=People,\n"
            " dc=example,dc=com\n"
            "changetype: modify\n"
            "modifiersname: cn=Directory Manager\n"
        )
        records = list(_iter_audit_records(log.splitlines(keepends=True)))
        assert len(records) == 1
        assert records[0]["dn"] == "uid=folded-user,ou=People,dc=example,dc=com"

    def test_base64_dn_is_decoded(self):
        """Records written as dn:: <base64> must be decodable for DN filters."""
        dn = "uid=ünïcode,ou=People,dc=example,dc=com"
        b64 = base64.b64encode(dn.encode()).decode()
        log = (
            "time: 20240101100001\n"
            f"dn:: {b64}\n"
            "changetype: add\n"
            "creatorsname: cn=Directory Manager\n"
        )
        records = list(_iter_audit_records(log.splitlines(keepends=True)))
        assert records[0]["dn"] == dn

    def test_stats_only_collects_no_raw(self):
        """Stats mode must not accumulate raw record text."""
        log = (
            "time: 20240101100001\n"
            "dn: cn=config\n"
            "changetype: modify\n"
        )
        records = list(_iter_audit_records(log.splitlines(keepends=True), collect_raw=False))
        assert "raw" not in records[0]

    def test_streaming_is_lazy(self):
        """The audit parser must be a generator (no full-log accumulation)."""
        import types
        gen = _iter_audit_records(iter([]))
        assert isinstance(gen, types.GeneratorType)


class TestFamilyRobustness:
    def test_corrupt_gz_rotation_does_not_abort_family(self, tmp_path):
        """A corrupt .gz rotation is skipped and counted."""
        current = tmp_path / "access"
        current.write_text(TRADITIONAL_LINES)
        bad_gz = tmp_path / "access.20240101-000000.gz"
        bad_gz.write_bytes(b"\x1f\x8b\x08\x00 this is not really gzip data")

        result = _parse_access_log_entries(
            _fake_ds(current), None, None, None, None, True, 100
        )
        assert result["total_parsed"] == 2  # current file still parsed
        assert result["unreadable_files"] == 1

    def test_gz_json_rotation_detected_and_parsed_as_json(self, tmp_path):
        """A gzip-compressed JSON rotation must be detected as JSON.

        _detect_json_log used to read raw gz bytes and misdetect the file
        as traditional, silently losing every record in the rotation.
        """
        from ldap_assistant_mcp.dirsrv_mcp.tools.logs import _detect_json_log

        current = tmp_path / "access"
        current.write_text(JSON_LINES)
        gz = tmp_path / "access.20240101-000000.gz"
        with gzip.open(gz, "wt") as fh:
            fh.write('{"local_time": "2024-01-01T09:00:01Z", "operation": "MODIFY", "err": 0}\n')

        assert _detect_json_log(str(gz)) is True

        result = _parse_access_log_entries(
            _fake_ds(current), None, None, None, None, True, 100
        )
        # Both the current file's records AND the rotated gz JSON record
        # are parsed as JSON: nothing malformed, MODIFY counted.
        assert result["total_parsed"] == 3
        assert result["malformed_lines"] == 0
        assert result["operation_stats"].get("MODIFY") == 1

    def test_rotated_only_gz_json_family_is_readable(self, tmp_path):
        """SOS case: only a gz JSON rotation exists (no current file)."""
        gz = tmp_path / "access.20240101-000000.gz"
        with gzip.open(gz, "wt") as fh:
            fh.write(JSON_LINES)
        ds = MagicMock()
        ds.ds_paths.access_log = str(tmp_path / "access")
        result = _parse_access_log_entries(ds, None, None, None, None, True, 100)
        assert result["total_parsed"] == 2
        assert result["operation_stats"].get("SEARCH") == 1

    def test_valid_gz_rotation_is_read(self, tmp_path):
        current = tmp_path / "access"
        current.write_text(TRADITIONAL_LINES)
        gz = tmp_path / "access.20240101-000000.gz"
        with gzip.open(gz, "wt") as fh:
            fh.write(TRADITIONAL_LINES)
        result = _parse_access_log_entries(
            _fake_ds(current), None, None, None, None, True, 100
        )
        assert result["total_parsed"] == 4

    def test_rotated_only_family_is_readable(self, tmp_path):
        """A family with only rotated files (no current base file)
        must not error out when include_archived is set."""
        (tmp_path / "access.20240101-000000").write_text(TRADITIONAL_LINES)
        missing_current = tmp_path / "access"

        result = _parse_access_log_entries(
            _fake_ds(missing_current), None, None, None, None, True, 100
        )
        assert "error" not in result
        assert result["total_parsed"] == 2

    def test_missing_family_still_errors(self, tmp_path):
        result = _parse_access_log_entries(
            _fake_ds(tmp_path / "access"), None, None, None, None, True, 100
        )
        assert "error" in result

    def test_family_paths_order_current_last(self, tmp_path):
        (tmp_path / "access.20240102-000000").write_text("b")
        (tmp_path / "access.20240101-000000").write_text("a")
        (tmp_path / "access").write_text("c")
        paths = _log_family_paths(str(tmp_path / "access"), include_archived=True)
        assert [os.path.basename(p) for p in paths] == [
            "access.20240101-000000", "access.20240102-000000", "access",
        ]

    def test_limit_keeps_newest_matches(self, tmp_path):
        """When matches exceed the limit, the NEWEST entries are
        returned, not the oldest."""
        lines = []
        for hour in range(10, 14):
            lines.append(
                f"[01/Jan/2024:{hour}:00:00.000000000 +0000] conn=1 op=1 "
                'SRCH base="dc=example,dc=com" scope=2 filter="(uid=a)" attrs=ALL\n'
            )
        current = tmp_path / "access"
        current.write_text("".join(lines))
        result = _parse_access_log_entries(
            _fake_ds(current), "SRCH", None, None, None, False, 2
        )
        assert result["matched_count"] == 4
        assert len(result["entries"]) == 2
        stamps = [e["timestamp"] for e in result["entries"]]
        assert all("12:00:00" in s or "13:00:00" in s for s in stamps), stamps


class TestDecompressionBudget:
    def test_gz_budget_truncates(self, tmp_path, monkeypatch):
        import ldap_assistant_mcp.dirsrv_mcp.tools.logs as logs_mod
        monkeypatch.setattr(logs_mod, "_MAX_DECOMPRESSED_BYTES_PER_FILE", 100)
        gz = tmp_path / "big.gz"
        with gzip.open(gz, "wt") as fh:
            fh.write("x" * 10_000)
        counters: dict = {}
        lines = list(_read_lines_single(str(gz), counters))
        assert counters.get("decompression_truncated") == 1
        assert sum(len(ln) for ln in lines) <= 200

    def test_plain_files_have_no_budget(self, tmp_path):
        big = tmp_path / "big"
        big.write_text("line\n" * 1000)
        counters: dict = {}
        lines = list(_read_lines_single(str(big), counters))
        assert len(lines) == 1000
        assert not counters


class TestEndToEndArchive:
    """Tool-level check that the new reader keys surface through the tools."""

    @pytest.fixture
    def archive_mcp(self, tmp_path):
        inst = "slapd-t011"
        config_dir = tmp_path / "etc" / "dirsrv" / inst
        config_dir.mkdir(parents=True)
        (config_dir / "dse.ldif").write_text(DSE_LDIF)
        logs_dir = tmp_path / "var" / "log" / "dirsrv" / inst
        logs_dir.mkdir(parents=True)
        (logs_dir / "access").write_text(JSON_LINES)
        (logs_dir / "access.20240101-000000").write_text(TRADITIONAL_LINES)
        (logs_dir / "errors").write_text(
            "[01/Jan/2024:10:00:01.000000000 +0000] - INFO - main - starting up\n"
        )
        (logs_dir / "audit").write_text(
            "time: 20240101100001\ndn: cn=config\nchangetype: modify\n"
            "modifiersname: cn=Directory Manager\n"
        )
        env = {"LDAP_MCP_EXPOSE_SENSITIVE_DATA": "true", "LDAP_SERVERS_CONFIG": ""}
        with patch.dict(os.environ, env):
            config = LDAPServerConfig(
                name="t011-archive",
                hostname="archive",
                port=0,
                is_archive=True,
                archive_path=str(tmp_path),
            )
            yield DirSrvMCP(servers=[config], include_env_fallback=False)

    async def test_mixed_family_through_tool(self, archive_mcp):
        async with Client(archive_mcp) as client:
            result = await client.call_tool(
                "parse_access_log", {"include_archived_logs": True}
            )
            data = result.data
        assert data["total_parsed"] == 4
        assert data["malformed_lines"] == 0

    async def test_audit_include_archived_param(self, archive_mcp):
        async with Client(archive_mcp) as client:
            result = await client.call_tool(
                "parse_audit_log", {"include_archived_logs": True}
            )
            data = result.data
        assert data["total_parsed"] == 1
        assert data["changes"][0]["dn"] == "cn=config"
