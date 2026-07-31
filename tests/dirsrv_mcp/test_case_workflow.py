"""Regression tests: bounded case-oriented support workflow MVP.

Covers the deterministic case substrate:
- inspect_log_coverage inventories families/spans without raw content
- collect_case_snapshot records per-probe status with stable evidence IDs
- correlate_incident_window buckets signals and flags change points only
- render_case_packet renders audiences and validates evidence refs
"""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from ldap_assistant_mcp.core import LDAPServerConfig
from ldap_assistant_mcp.dirsrv_mcp.server import DirSrvMCP

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
[01/Jan/2024:11:30:00.000000000 +0000] conn=2 op=1 SRCH base="dc=example,dc=com" scope=2 filter="(uid=b)" attrs=ALL
[01/Jan/2024:11:30:00.100000000 +0000] conn=2 op=1 RESULT err=32 tag=101 nentries=0 wtime=0.000001 optime=0.0002 etime=0.000201
[01/Jan/2024:11:30:01.000000000 +0000] conn=3 op=1 RESULT err=32 tag=101 nentries=0 wtime=0.000001 optime=0.0002 etime=0.000201
[01/Jan/2024:11:30:02.000000000 +0000] conn=4 op=1 RESULT err=32 tag=101 nentries=0 wtime=0.000001 optime=0.0002 etime=0.000201
[01/Jan/2024:11:30:03.000000000 +0000] conn=5 op=1 RESULT err=32 tag=101 nentries=0 wtime=0.000001 optime=0.0002 etime=0.000201
[01/Jan/2024:11:30:04.000000000 +0000] conn=6 op=1 RESULT err=32 tag=101 nentries=0 wtime=0.000001 optime=0.0002 etime=0.000201
[01/Jan/2024:11:30:05.000000000 +0000] conn=7 op=1 RESULT err=32 tag=101 nentries=0 wtime=0.000001 optime=0.0002 etime=0.000201
[01/Jan/2024:11:30:06.000000000 +0000] conn=8 op=1 RESULT err=32 tag=101 nentries=0 wtime=0.000001 optime=0.0002 etime=0.000201
"""

ERROR_LOG = """\
[01/Jan/2024:10:00:01.000000000 +0000] - INFO - main - starting up
[01/Jan/2024:11:30:00.000000000 +0000] - ERR - backend - something failed
[01/Jan/2024:11:30:01.000000000 +0000] - ERR - backend - something failed again
"""

AUDIT_LOG = """\
time: 20240101100001
dn: cn=config
changetype: modify
modifiersname: cn=Directory Manager
"""


@pytest.fixture
def archive_mcp(tmp_path):
    inst = "slapd-t015"
    config_dir = tmp_path / "etc" / "dirsrv" / inst
    config_dir.mkdir(parents=True)
    (config_dir / "dse.ldif").write_text(DSE_LDIF)
    logs_dir = tmp_path / "var" / "log" / "dirsrv" / inst
    logs_dir.mkdir(parents=True)
    (logs_dir / "access").write_text(ACCESS_LOG)
    (logs_dir / "errors").write_text(ERROR_LOG)
    (logs_dir / "audit").write_text(AUDIT_LOG)
    env = {"LDAP_MCP_EXPOSE_SENSITIVE_DATA": "true", "LDAP_SERVERS_CONFIG": ""}
    with patch.dict(os.environ, env):
        config = LDAPServerConfig(
            name="t015-archive",
            hostname="archive",
            port=0,
            is_archive=True,
            archive_path=str(tmp_path),
        )
        yield DirSrvMCP(servers=[config], include_env_fallback=False)


async def _call(server, tool, args=None):
    async with Client(server) as client:
        result = await client.call_tool(tool, args or {})
        return result.data


class TestLogCoverage:
    async def test_coverage_inventories_families(self, archive_mcp):
        data = await _call(archive_mcp, "inspect_log_coverage", {})
        assert data["type"] == "log_coverage"
        assert data["mode"] == "archive"
        assert data["logs"]["access"]["present"] is True
        assert data["logs"]["access"]["format"] == "traditional"
        assert data["logs"]["access"]["first_timestamp"].startswith("2024-01-01T10:00:02")
        assert data["logs"]["audit"]["last_timestamp"].startswith("2024-01-01T10:00:01")
        assert data["dataset_end"].startswith("2024-01-01T11:30")

    async def test_no_raw_content_in_coverage(self, archive_mcp):
        data = await _call(archive_mcp, "inspect_log_coverage", {})
        serialized = str(data)
        assert "uid=a" not in serialized
        assert "cn=Directory Manager" not in serialized


class TestCaseSnapshot:
    async def test_snapshot_collects_with_evidence_ids(self, archive_mcp):
        data = await _call(archive_mcp, "collect_case_snapshot", {})
        assert data["type"] == "case_snapshot"
        assert data["evidence_status"] == "complete"
        assert data["coverage"]["failed"] == 0
        assert data["coverage"]["succeeded"] >= 2  # log_coverage + config_summary
        # every successful probe's evidence ref resolves
        for probe in data["probes"]:
            if probe["status"] == "succeeded":
                assert probe["evidence_ref"] in data["evidence"]
        source = data["sources"][0]
        assert source["mode"] == "archive"
        assert source["evidence_status"] == "complete"

    async def test_snapshot_evidence_ids_are_stable(self, archive_mcp):
        d1 = await _call(archive_mcp, "collect_case_snapshot", {})
        d2 = await _call(archive_mcp, "collect_case_snapshot", {})
        assert set(d1["evidence"].keys()) == set(d2["evidence"].keys())

    async def test_unknown_server_is_explicit_error(self, archive_mcp):
        with pytest.raises(ToolError):
            await _call(archive_mcp, "collect_case_snapshot", {"server_names": ["nope"]})

    async def test_bad_focus_is_explicit_error(self, archive_mcp):
        with pytest.raises(ToolError):
            await _call(archive_mcp, "collect_case_snapshot", {"focus": "everything"})


class TestIncidentCorrelation:
    async def test_correlation_buckets_and_change_points(self, archive_mcp):
        data = await _call(
            archive_mcp, "correlate_incident_window",
            {"time_range": "last 24h", "bucket_minutes": 15},
        )
        assert data["type"] == "incident_correlation"
        assert data["bucket_count"] >= 2
        # The 11:30 burst (4 failed ops + 2 errors) must be a change point
        assert data["change_points"], "expected the 11:30 burst to be flagged"
        cp = data["change_points"][0]
        assert cp["bucket_start_utc"].startswith("2024-01-01T11:30")
        assert cp["signals"].get("access_failed_ops", 0) >= 3
        # Causality is never claimed
        assert "not causes" in data["note"]

    async def test_correlation_is_count_only(self, archive_mcp):
        data = await _call(
            archive_mcp, "correlate_incident_window", {"time_range": "last 24h"},
        )
        serialized = str(data)
        assert "uid=" not in serialized
        assert "cn=Directory Manager" not in serialized

    async def test_clean_run_reports_complete_evidence(self, archive_mcp):
        data = await _call(
            archive_mcp, "correlate_incident_window", {"time_range": "last 24h"},
        )
        assert data["evidence_status"] == "complete"
        assert "unreadable_files" not in data
        assert "unknown_timestamp_count" not in data

    @staticmethod
    def _make_archive(tmp_path, inst, extra_writer):
        config_dir = tmp_path / "etc" / "dirsrv" / inst
        config_dir.mkdir(parents=True)
        (config_dir / "dse.ldif").write_text(DSE_LDIF)
        logs_dir = tmp_path / "var" / "log" / "dirsrv" / inst
        logs_dir.mkdir(parents=True)
        (logs_dir / "access").write_text(ACCESS_LOG)
        (logs_dir / "errors").write_text(ERROR_LOG)
        (logs_dir / "audit").write_text(AUDIT_LOG)
        extra_writer(logs_dir)
        env = {"LDAP_MCP_EXPOSE_SENSITIVE_DATA": "true", "LDAP_SERVERS_CONFIG": ""}
        with patch.dict(os.environ, env):
            config = LDAPServerConfig(
                name=f"{inst}-archive",
                hostname="archive",
                port=0,
                is_archive=True,
                archive_path=str(tmp_path),
            )
            return DirSrvMCP(servers=[config], include_env_fallback=False)

    async def test_reader_incidents_surface_as_partial_evidence(self, tmp_path):
        """An unreadable rotation means the timeline was computed from
        partial evidence: the incident count and evidence_status must say
        so instead of a quiet bucket reading as 'no spike happened'."""
        server = self._make_archive(
            tmp_path, "slapd-t015b",
            lambda d: (d / "errors.20231231-000000.gz").write_bytes(
                b"\x1f\x8b\x08\x00 this is not really gzip data"
            ),
        )
        data = await _call(
            server, "correlate_incident_window", {"time_range": "last 24h"},
        )
        assert data["unreadable_files"] >= 1
        assert data["evidence_status"] == "partial"
        # The readable logs were still correlated
        assert data["bucket_count"] >= 1

    async def test_unknown_timestamps_are_counted(self, tmp_path):
        """Records whose timestamp cannot be parsed are excluded from the
        timeline — that exclusion must be counted, not silent."""
        server = self._make_archive(
            tmp_path, "slapd-t015c",
            lambda d: (d / "access").write_text(
                ACCESS_LOG
                + "[not-a-timestamp] conn=9 op=1 RESULT err=0 tag=101 "
                "nentries=0 wtime=0.1 optime=0.9 etime=1.0\n"
            ),
        )
        data = await _call(
            server, "correlate_incident_window", {"time_range": "last 24h"},
        )
        assert data["unknown_timestamp_count"] == 1
        assert data["evidence_status"] == "partial"

    async def test_archive_window_anchors_to_dataset(self, archive_mcp):
        data = await _call(
            archive_mcp, "correlate_incident_window",
            {"time_range": "last 2h", "bucket_minutes": 15},
        )
        window = data["windows"]["access"]["effective_window"]
        assert window["anchor"] == "dataset_end"

    async def test_all_signal_kinds_share_one_window(self, archive_mcp):
        """The timeline must use ONE window for every log kind.

        Anchoring each kind to its own dataset end would correlate signals
        from different time windows: the audit log ends at 10:00 while the
        access log ends at 11:30, so a per-kind 'last 1h' would include a
        10:00 audit change in a timeline whose access data covers
        10:30-11:30.
        """
        data = await _call(
            archive_mcp, "correlate_incident_window",
            {"time_range": "last 1h", "bucket_minutes": 15},
        )
        windows = [
            v["effective_window"] for v in data["windows"].values()
            if v.get("present")
        ]
        assert len(windows) == 3
        assert len({w["start"] for w in windows}) == 1, windows
        # The 10:00:01 audit change is OUTSIDE the shared last-1h window
        # (anchored to the access log's 11:30 dataset end).
        for bucket in data["timeline"]:
            assert "audit_change" not in bucket["signals"], bucket

    async def test_audit_signal_included_when_window_covers_it(self, archive_mcp):
        data = await _call(
            archive_mcp, "correlate_incident_window",
            {"time_range": "last 24h", "bucket_minutes": 15},
        )
        assert any(
            "audit_change" in bucket["signals"] for bucket in data["timeline"]
        )


class TestCasePacket:
    async def test_render_support_packet(self, archive_mcp):
        snapshot = await _call(archive_mcp, "collect_case_snapshot", {})
        data = await _call(
            archive_mcp, "render_case_packet",
            {"snapshot": snapshot, "audience": "support"},
        )
        assert data["type"] == "case_packet"
        md = data["markdown"]
        assert "# Directory Server Case Packet" in md
        assert "Evidence status: **complete**" in md
        assert "ev-" in md  # evidence refs listed
        assert data["evidence_ref_count"] >= 1

    async def test_customer_packet_hides_internals(self, archive_mcp):
        snapshot = await _call(archive_mcp, "collect_case_snapshot", {})
        data = await _call(
            archive_mcp, "render_case_packet",
            {"snapshot": snapshot, "audience": "customer"},
        )
        md = data["markdown"]
        assert "Probe results" not in md
        assert "Evidence index" not in md

    async def test_engineering_packet_includes_data(self, archive_mcp):
        snapshot = await _call(archive_mcp, "collect_case_snapshot", {})
        data = await _call(
            archive_mcp, "render_case_packet",
            {"snapshot": snapshot, "audience": "engineering"},
        )
        assert "data:" in data["markdown"]

    async def test_unresolvable_refs_fail_validation(self, archive_mcp):
        snapshot = await _call(archive_mcp, "collect_case_snapshot", {})
        snapshot["evidence"] = {}  # break the refs
        with pytest.raises(ToolError) as exc:
            await _call(
                archive_mcp, "render_case_packet",
                {"snapshot": snapshot, "audience": "support"},
            )
        assert "inconsistent" in str(exc.value)

    async def test_malformed_probes_rejected_cleanly(self, archive_mcp):
        """Malformed snapshots must fail validation, not KeyError mid-render."""
        snapshot = {
            "type": "case_snapshot",
            "evidence": {},
            "probes": [{"status": "failed"}],  # missing id/server/name
            "sources": [],
        }
        with pytest.raises(ToolError) as exc_info:
            await _call(archive_mcp, "render_case_packet", {"snapshot": snapshot})
        assert "required probe fields" in str(exc_info.value)

    async def test_malformed_skipped_servers_rejected(self, archive_mcp):
        snapshot = {
            "type": "case_snapshot",
            "evidence": {},
            "probes": [],
            "sources": [],
            "skipped_servers": 3,
        }
        with pytest.raises(ToolError):
            await _call(archive_mcp, "render_case_packet", {"snapshot": snapshot})

    async def test_wrong_snapshot_shape_rejected(self, archive_mcp):
        with pytest.raises(ToolError):
            await _call(
                archive_mcp, "render_case_packet",
                {"snapshot": {"type": "not_a_snapshot"}, "audience": "support"},
            )
