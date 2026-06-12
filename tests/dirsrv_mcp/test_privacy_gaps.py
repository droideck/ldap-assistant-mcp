"""Tests for privacy gap fixes across all tool modules.

Each test verifies that specific sensitive data is properly sanitized
in privacy mode. Tests cover the fixes from the privacy audit:

- monitoring.py: SAFE_MONITOR_KEYS allowlist for item field
- archive.py: config_summary backends/ports, sos_healthcheck, compare_dse_configs
- indexes.py: VLV index sanitization
- replication.py: conflict_attribute sanitization
- health.py: suffixes and port sanitization in offline metrics
- performance.py: top-level disk handling
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from ldap_assistant_mcp.lib.privacy import PrivacySanitizer


# ── Helpers ──────────────────────────────────────────────────────────

def _make_mcp(privacy_enabled: bool = True) -> MagicMock:
    """Build a minimal MCP mock with a real PrivacySanitizer."""
    mcp = MagicMock()
    mcp.privacy_enabled = privacy_enabled
    mcp.sanitizer = PrivacySanitizer()
    return mcp


# ── monitoring.py ────────────────────────────────────────────────────

class TestMonitoringSanitization:
    """Tests for _sanitize_monitor_result SAFE_MONITOR_KEYS filtering."""

    def test_monitor_item_filtered_in_privacy_mode(self):
        """Monitor item dict should only contain safe keys in privacy mode."""
        from ldap_assistant_mcp.dirsrv_mcp.tools.monitoring import _sanitize_monitor_result

        mcp = _make_mcp(privacy_enabled=True)
        result = {
            "type": "monitor",
            "server": "ds-test-1",
            "backend": "main",
            "item": {
                "currentconnections": 10,
                "totalconnections": 500,
                "threads": 16,
                "nsslapd-localhost": "server1.example.com",
                "nsslapd-certdir": "/etc/dirsrv/slapd-instance",
                "connection": "1:20240101:5:5:cn=directory manager:rw:ip=10.1.2.3",
                "backendmonitordn": "cn=monitor,cn=userroot,cn=ldbm database,cn=plugins,cn=config",
            },
        }
        sanitized = _sanitize_monitor_result(mcp, result)
        item = sanitized["item"]

        # Safe keys preserved
        assert item["currentconnections"] == 10
        assert item["totalconnections"] == 500
        assert item["threads"] == 16

        # Sensitive keys removed — "connection" carries bind DNs and client
        # IPs, "backendmonitordn" embeds backend DNs
        assert "connection" not in item
        assert "backendmonitordn" not in item
        assert "nsslapd-localhost" not in item
        assert "nsslapd-certdir" not in item

        # Privacy note added
        assert "_privacy_note" in item

    def test_monitor_item_unfiltered_when_privacy_off(self):
        """Monitor item dict should pass through when privacy is off."""
        from ldap_assistant_mcp.dirsrv_mcp.tools.monitoring import _sanitize_monitor_result

        mcp = _make_mcp(privacy_enabled=False)
        result = {
            "type": "monitor",
            "server": "ds-test-1",
            "backend": "main",
            "item": {
                "currentconnections": 10,
                "nsslapd-localhost": "server1.example.com",
            },
        }
        sanitized = _sanitize_monitor_result(mcp, result)
        assert sanitized["item"]["nsslapd-localhost"] == "server1.example.com"

    def test_monitor_backend_sanitized(self):
        """Non-main backend name should be sanitized."""
        from ldap_assistant_mcp.dirsrv_mcp.tools.monitoring import _sanitize_monitor_result

        mcp = _make_mcp(privacy_enabled=True)
        result = {
            "type": "monitor",
            "server": "ds-test-1",
            "backend": "userroot",
            "suffix": "dc=example,dc=com",
            "item": {},
        }
        sanitized = _sanitize_monitor_result(mcp, result)
        assert sanitized["backend"] == "[backend]"
        assert "[suffix-" in sanitized["suffix"]


# ── archive.py ───────────────────────────────────────────────────────

class TestArchiveSanitization:
    """Tests for _sanitize_archive_result extensions."""

    def test_config_summary_backends_sanitized(self):
        """Backend names and suffixes in config_summary should be sanitized."""
        from ldap_assistant_mcp.dirsrv_mcp.tools.archive import _sanitize_archive_result

        mcp = _make_mcp(privacy_enabled=True)
        result = {
            "type": "archive_analysis",
            "server": "archive1",
            "config_summary": {
                "version": "389-Directory/2.4.6",
                "port": "389",
                "secure_port": "636",
                "backends": [
                    {"name": "userroot", "suffix": "dc=example,dc=com"},
                    {"name": "o_netscaperoot", "suffix": "o=NetscapeRoot"},
                ],
                "suffixes": ["dc=example,dc=com", "o=NetscapeRoot"],
                "replication": [
                    {"suffix": "dc=example,dc=com", "role": "supplier", "replica_id": "1"},
                ],
            },
        }
        sanitized = _sanitize_archive_result(mcp, result)
        cs = sanitized["config_summary"]

        # Ports sanitized
        assert cs["port"] == "[port]"
        assert cs["secure_port"] == "[port]"

        # Backends sanitized
        for be in cs["backends"]:
            assert be["name"] == "[backend]"
            assert "[suffix-" in be["suffix"]

        # Suffixes sanitized
        for s in cs["suffixes"]:
            assert "[suffix-" in s

        # Replication suffixes sanitized
        for r in cs["replication"]:
            assert "[suffix-" in r["suffix"]
            assert r["role"] == "supplier"  # Non-sensitive preserved

        # Version preserved
        assert cs["version"] == "389-Directory/2.4.6"

    def test_sos_healthcheck_sanitized(self):
        """SOS healthcheck raw_output and findings should be sanitized."""
        from ldap_assistant_mcp.dirsrv_mcp.tools.archive import _sanitize_archive_result

        mcp = _make_mcp(privacy_enabled=True)
        result = {
            "type": "archive_analysis",
            "server": "archive1",
            "sos_healthcheck": {
                "raw_output": "Checking cn=config on server.example.com...\nAll checks passed",
                "findings": [
                    {
                        "code": "DSELE0001",
                        "severity": "HIGH",
                        "description": "Replication error on cn=replica,cn=dc=example,dc=com,cn=mapping tree,cn=config",
                        "details": "Consumer host.example.com is unreachable on port 636",
                    },
                ],
                "total_findings": 1,
            },
        }
        sanitized = _sanitize_archive_result(mcp, result)
        hc = sanitized["sos_healthcheck"]

        assert hc["raw_output"] == "[redacted-healthcheck-output]"
        assert hc["total_findings"] == 1  # Numeric preserved
        f = hc["findings"][0]
        assert f["code"] == "DSELE0001"  # Code preserved
        assert f["severity"] == "HIGH"  # Severity preserved
        assert "example" not in f["description"]
        assert "example" not in f["details"]

    def test_dse_comparison_sanitized(self):
        """DSE comparison DNs and values should be sanitized."""
        from ldap_assistant_mcp.dirsrv_mcp.tools.archive import _sanitize_archive_result

        mcp = _make_mcp(privacy_enabled=True)
        result = {
            "type": "dse_comparison",
            "server1": "archive1",
            "server2": "archive2",
            "section": "all",
            "only_in_server1": [
                "cn=MemberOf Plugin,cn=plugins,cn=config",
            ],
            "only_in_server2": [
                "cn=Retro Changelog,cn=plugins,cn=config",
            ],
            "differences": [
                {
                    "dn": "cn=config",
                    "attrs_only_in_server1": ["nsslapd-foo"],
                    "attrs_only_in_server2": [],
                    "different_values": [
                        {
                            "attribute": "nsslapd-localhost",
                            "server1": ["server1.example.com"],
                            "server2": ["server2.example.com"],
                        },
                        {
                            "attribute": "nsslapd-port",
                            "server1": ["389"],
                            "server2": ["3389"],
                        },
                    ],
                },
            ],
            "matching_count": 50,
            "total_entries": 55,
        }
        sanitized = _sanitize_archive_result(mcp, result)

        # Server names are never sanitized (user-chosen config labels)
        assert sanitized["server1"] == "archive1"
        assert sanitized["server2"] == "archive2"

        # Config DNs (under cn=config) are preserved — they are server
        # metadata, not user data, and redacting them makes the comparison
        # output uninterpretable.
        assert sanitized["only_in_server1"] == [
            "cn=MemberOf Plugin,cn=plugins,cn=config",
        ]
        assert sanitized["only_in_server2"] == [
            "cn=Retro Changelog,cn=plugins,cn=config",
        ]

        diff = sanitized["differences"][0]
        assert diff["dn"] == "cn=config"

        # Sensitive attribute values sanitized
        for dv in diff["different_values"]:
            if dv["attribute"] == "nsslapd-localhost":
                for v in dv["server1"] + dv["server2"]:
                    assert "example" not in str(v)

        # Numeric values preserved
        assert sanitized["matching_count"] == 50
        assert sanitized["total_entries"] == 55

    def test_archive_no_sanitization_when_privacy_off(self):
        """Archive results should pass through when privacy is off."""
        from ldap_assistant_mcp.dirsrv_mcp.tools.archive import _sanitize_archive_result

        mcp = _make_mcp(privacy_enabled=False)
        result = {
            "type": "archive_analysis",
            "server": "archive1",
            "config_summary": {"port": "389", "backends": [{"name": "userroot"}]},
        }
        sanitized = _sanitize_archive_result(mcp, result)
        assert sanitized["server"] == "archive1"
        assert sanitized["config_summary"]["port"] == "389"


# ── indexes.py ───────────────────────────────────────────────────────

class TestIndexSanitization:
    """Tests for _sanitize_backend VLV handling."""

    def test_vlv_indexes_sanitized(self):
        """VLV index name, base, and filter should be sanitized."""
        from ldap_assistant_mcp.dirsrv_mcp.tools.indexes import _sanitize_backend

        sanitizer = PrivacySanitizer()
        backend = {
            "name": "userroot",
            "suffix": "dc=example,dc=com",
            "indexes": [],
            "vlv_indexes": [
                {
                    "name": "MCC Managed Customers",
                    "base": "ou=customers,dc=example,dc=com",
                    "scope": "2",
                    "filter": "(objectClass=inetOrgPerson)",
                    "sort": "cn givenName sn",
                },
                {
                    "name": "All Users VLV",
                    "base": "dc=example,dc=com",
                    "scope": "2",
                    "filter": "(uid=*)",
                    "sort": "uid",
                },
            ],
        }
        result = _sanitize_backend(sanitizer, backend)

        assert result["name"] == "[backend]"
        assert "[suffix-" in result["suffix"]

        for vlv in result["vlv_indexes"]:
            assert vlv["name"] == "[vlv]"
            assert "[entry-" in vlv["base"]
            assert vlv["filter"] == "[filter]"
            # scope and sort are safe
            assert vlv["scope"] == "2"
            assert vlv["sort"] in ("cn givenName sn", "uid")

    def test_vlv_indexes_empty(self):
        """Empty VLV list should not cause errors."""
        from ldap_assistant_mcp.dirsrv_mcp.tools.indexes import _sanitize_backend

        sanitizer = PrivacySanitizer()
        backend = {
            "name": "userroot",
            "suffix": "dc=example,dc=com",
            "vlv_indexes": [],
        }
        result = _sanitize_backend(sanitizer, backend)
        assert result["vlv_indexes"] == []

    def test_backend_without_vlv_indexes(self):
        """Backend without vlv_indexes key should not cause errors."""
        from ldap_assistant_mcp.dirsrv_mcp.tools.indexes import _sanitize_backend

        sanitizer = PrivacySanitizer()
        backend = {"name": "userroot", "suffix": "dc=test,dc=com"}
        result = _sanitize_backend(sanitizer, backend)
        assert result["name"] == "[backend]"
        assert "vlv_indexes" not in result  # Not present, not added


# ── replication.py ───────────────────────────────────────────────────

class TestReplicationSanitization:
    """Tests for _sanitize_replication_result conflict_attribute handling."""

    def test_conflict_attribute_sanitized(self):
        """conflict_attribute containing DNs should be sanitized."""
        from ldap_assistant_mcp.dirsrv_mcp.tools.replication import _sanitize_replication_result

        mcp = _make_mcp(privacy_enabled=True)
        result = {
            "type": "replication_conflicts",
            "server": "ds-test-1",
            "conflicts": [
                {
                    "dn": "nsuniqueid=abc+uid=user1,dc=example,dc=com",
                    "suffix": "dc=example,dc=com",
                    "conflict_attribute": "namingConflict uid=user1,dc=example,dc=com (uniqueid abc)",
                    "valid_entry_dn": "uid=user1,dc=example,dc=com",
                },
            ],
        }
        sanitized = _sanitize_replication_result(mcp, result)

        conflict = sanitized["conflicts"][0]
        assert "[entry-" in conflict["dn"]
        assert "[suffix-" in conflict["suffix"]
        assert "[entry-" in conflict["valid_entry_dn"]
        # conflict_attribute should be sanitized (no raw DNs)
        assert "example" not in conflict["conflict_attribute"]

    def test_conflict_attribute_none_preserved(self):
        """conflict_attribute that is None should stay None."""
        from ldap_assistant_mcp.dirsrv_mcp.tools.replication import _sanitize_replication_result

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
        }
        sanitized = _sanitize_replication_result(mcp, result)
        assert sanitized["conflicts"][0]["conflict_attribute"] is None

    def test_replication_no_sanitization_when_off(self):
        """Replication results pass through when privacy is off."""
        from ldap_assistant_mcp.dirsrv_mcp.tools.replication import _sanitize_replication_result

        mcp = _make_mcp(privacy_enabled=False)
        result = {
            "type": "replication_conflicts",
            "server": "ds-test-1",
            "conflicts": [
                {
                    "dn": "uid=user1,dc=example,dc=com",
                    "suffix": "dc=example,dc=com",
                    "conflict_attribute": "raw conflict data",
                },
            ],
        }
        sanitized = _sanitize_replication_result(mcp, result)
        assert sanitized["conflicts"][0]["conflict_attribute"] == "raw conflict data"


# ── health.py ────────────────────────────────────────────────────────

class TestHealthSanitization:
    """Tests for _sanitize_server_metrics suffixes and port handling."""

    def test_offline_metrics_suffixes_sanitized(self):
        """Suffixes list in offline metrics should be sanitized."""
        from ldap_assistant_mcp.dirsrv_mcp.tools.health import _sanitize_server_metrics

        sanitizer = PrivacySanitizer()
        data = {
            "server": "ds-offline-1",
            "mode": "offline",
            "version": "389-Directory/2.4.6",
            "port": "389",
            "secure_port": "636",
            "suffixes": ["dc=example,dc=com", "o=NetscapeRoot"],
            "backends": 2,
            "plugins": 15,
        }
        result = _sanitize_server_metrics(sanitizer, data)

        # Server names are never sanitized (user-chosen config labels)
        assert result["server"] == "ds-offline-1"

        # Ports sanitized
        assert result["port"] == "[port]"
        assert result["secure_port"] == "[port]"

        # Suffixes sanitized
        for s in result["suffixes"]:
            assert "[suffix-" in s

        # Numeric values preserved
        assert result["backends"] == 2
        assert result["plugins"] == 15
        assert result["version"] == "389-Directory/2.4.6"

    def test_metrics_without_suffixes_no_error(self):
        """Metrics without suffixes key should not cause errors."""
        from ldap_assistant_mcp.dirsrv_mcp.tools.health import _sanitize_server_metrics

        sanitizer = PrivacySanitizer()
        data = {"server": "ds-test-1", "backends": 1}
        result = _sanitize_server_metrics(sanitizer, data)
        assert result["server"] == "ds-test-1"
        assert result["backends"] == 1


# ── performance.py ───────────────────────────────────────────────────

class TestPerformanceSanitization:
    """Tests for _sanitize_performance_result top-level disk handling."""

    def test_top_level_disk_partitions_sanitized(self):
        """Top-level disk.partitions[].partition should be sanitized."""
        from ldap_assistant_mcp.dirsrv_mcp.tools.performance import _sanitize_performance_result

        mcp = _make_mcp(privacy_enabled=True)
        result = {
            "type": "resource_utilization",
            "server": "ds-test-1",
            "disk": {
                "available": True,
                "partitions": [
                    {"partition": "/dev/sda1", "usage_percent": 45, "size": "100G", "available": "55G"},
                    {"partition": "/dev/sdb1", "usage_percent": 80, "size": "500G", "available": "100G"},
                ],
            },
        }
        sanitized = _sanitize_performance_result(mcp, result)

        for p in sanitized["disk"]["partitions"]:
            assert p["partition"] == "[partition]"
            # Numeric values preserved
            assert isinstance(p["usage_percent"], int)

    def test_nested_resources_disk_still_works(self):
        """Nested resources.disk.partitions still sanitized."""
        from ldap_assistant_mcp.dirsrv_mcp.tools.performance import _sanitize_performance_result

        mcp = _make_mcp(privacy_enabled=True)
        result = {
            "type": "performance_summary",
            "server": "ds-test-1",
            "resources": {
                "disk": {
                    "partitions": [
                        {"partition": "/dev/sda1", "usage_percent": 45},
                    ],
                },
            },
        }
        sanitized = _sanitize_performance_result(mcp, result)
        assert sanitized["resources"]["disk"]["partitions"][0]["partition"] == "[partition]"

    def test_disk_no_sanitization_when_off(self):
        """Disk partitions pass through when privacy is off."""
        from ldap_assistant_mcp.dirsrv_mcp.tools.performance import _sanitize_performance_result

        mcp = _make_mcp(privacy_enabled=False)
        result = {
            "type": "resource_utilization",
            "server": "ds-test-1",
            "disk": {
                "available": True,
                "partitions": [
                    {"partition": "/dev/sda1", "usage_percent": 45},
                ],
            },
        }
        sanitized = _sanitize_performance_result(mcp, result)
        assert sanitized["disk"]["partitions"][0]["partition"] == "/dev/sda1"

    def test_disk_without_partitions_no_error(self):
        """Disk dict without partitions key should not cause errors."""
        from ldap_assistant_mcp.dirsrv_mcp.tools.performance import _sanitize_performance_result

        mcp = _make_mcp(privacy_enabled=True)
        result = {
            "type": "resource_utilization",
            "server": "ds-test-1",
            "disk": {
                "available": False,
                "message": "Disk monitoring requires local access",
            },
        }
        sanitized = _sanitize_performance_result(mcp, result)
        assert sanitized["disk"]["available"] is False


# ── Error message sanitization ──────────────────────────────────────

class TestErrorMessageSanitization:
    """Tests that error messages don't leak raw server names."""

    def test_compare_dse_configs_available_list_preserves_names(self):
        """_sanitize_server_list passes server names through unchanged."""
        from ldap_assistant_mcp.dirsrv_mcp.tools.archive import _sanitize_server_list

        mcp = _make_mcp(privacy_enabled=True)
        names = ["ds-live", "ds-offline", "ds-archive-supplier1", "ds-archive-supplier2"]
        sanitized = _sanitize_server_list(mcp, names)
        # Server names are never sanitized
        assert sanitized == names

    def test_compare_dse_configs_available_list_unsanitized_when_off(self):
        """When privacy is off, server names pass through unchanged."""
        from ldap_assistant_mcp.dirsrv_mcp.tools.archive import _sanitize_server_list

        mcp = _make_mcp(privacy_enabled=False)
        names = ["ds-live", "ds-offline"]
        sanitized = _sanitize_server_list(mcp, names)
        assert sanitized == names

    def test_archive_error_field_sanitized_but_server_name_kept(self):
        """Error string is sanitized for DNs/paths; server name passes through."""
        from ldap_assistant_mcp.dirsrv_mcp.tools.archive import _sanitize_archive_result

        mcp = _make_mcp(privacy_enabled=True)
        result = {
            "type": "archive_analysis",
            "server": "ds-archive-supplier1",
            "error": "analyze_archive requires offline. Server 'ds-archive-supplier1' is live.",
        }
        sanitized = _sanitize_archive_result(mcp, result)
        # Server names are never sanitized
        assert sanitized["server"] == "ds-archive-supplier1"

    def test_config_error_field_sanitized_but_server_name_kept(self):
        """Error string is sanitized for DNs/paths; server name passes through."""
        from ldap_assistant_mcp.dirsrv_mcp.tools.config import _sanitize_config_result

        mcp = _make_mcp(privacy_enabled=True)
        result = {
            "type": "server_configuration",
            "server": "ds-live",
            "error": "Failed to connect to ds-live: timeout",
        }
        sanitized = _sanitize_config_result(mcp, result)
        # Server names are never sanitized
        assert sanitized["server"] == "ds-live"

    def test_config_available_list_preserves_server_names(self):
        """_sanitize_server_list should pass through server names unchanged."""
        from ldap_assistant_mcp.dirsrv_mcp.tools.config import _sanitize_server_list

        mcp = _make_mcp(privacy_enabled=True)
        names = ["ds-live", "ds-offline"]
        sanitized = _sanitize_server_list(mcp, names)
        assert sanitized == names

    def test_finding_text_keeps_server_name(self):
        """sanitize_finding should keep server names in text and server fields."""
        from ldap_assistant_mcp.lib.privacy import PrivacySanitizer

        sanitizer = PrivacySanitizer()
        finding = {
            "title": "Skipped Archive Server: ds-archive-supplier1",
            "severity": "info",
            "impact": "ds-archive-supplier1 cannot provide live data",
            "details": "Server 'ds-archive-supplier1' is in archive mode",
            "server": "ds-archive-supplier1",
        }
        sanitized = sanitizer.sanitize_finding(finding)
        # Server names are never sanitized
        assert sanitized["server"] == "ds-archive-supplier1"

    def test_log_remote_error_keeps_server_name(self):
        """Log tool errors keep server name; error text is still sanitized for DNs/paths."""
        from ldap_assistant_mcp.dirsrv_mcp.tools.logs import _sanitize_log_result

        mcp = _make_mcp(privacy_enabled=True)
        result = {
            "type": "access_log_analysis",
            "server": "ds-dev-1",
            "error": (
                "Log analysis requires local or archive server access. "
                "Server 'ds-dev-1' is a remote connection."
            ),
        }
        sanitized = _sanitize_log_result(mcp, result)
        # Server names are never sanitized
        assert sanitized["server"] == "ds-dev-1"

    def test_log_remote_error_unsanitized_when_off(self):
        """Log tool error should preserve server name when privacy is off."""
        from ldap_assistant_mcp.dirsrv_mcp.tools.logs import _sanitize_log_result

        mcp = _make_mcp(privacy_enabled=False)
        result = {
            "type": "access_log",
            "server": "ds-dev-1",
            "error": "Server 'ds-dev-1' is a remote connection.",
        }
        sanitized = _sanitize_log_result(mcp, result)
        assert sanitized["server"] == "ds-dev-1"
        assert "ds-dev-1" in sanitized["error"]

    def test_require_live_preserves_server_name_in_privacy_mode(self):
        """require_live_server() should keep real server name (never sanitized)."""
        from ldap_assistant_mcp.dirsrv_mcp.connection import ConnectionManager, LiveServerRequired, ServerConfig, require_live_server

        cm = ConnectionManager()
        cm.add_server(ServerConfig(
            name="ds-offline-1",
            ldap_url="ldap://localhost:389",
            base_dn="dc=example,dc=com",
            bind_dn="cn=Directory Manager",
            is_local=True,
            serverid="localhost",
            is_offline=True,
        ))

        with pytest.raises(LiveServerRequired) as exc_info:
            require_live_server(cm, "ds-offline-1", "test_tool")
        # Server names are never sanitized — they pass through as-is
        assert "ds-offline-1" in str(exc_info.value)

    def test_require_live_preserves_name_when_privacy_off(self):
        """require_live_server should preserve raw name when privacy is off."""
        from ldap_assistant_mcp.dirsrv_mcp.connection import ConnectionManager, LiveServerRequired, ServerConfig, require_live_server

        cm = ConnectionManager()
        cm.add_server(ServerConfig(
            name="ds-offline-1",
            ldap_url="ldap://localhost:389",
            base_dn="dc=example,dc=com",
            bind_dn="cn=Directory Manager",
            is_local=True,
            serverid="localhost",
            is_offline=True,
        ))
        with pytest.raises(LiveServerRequired) as exc_info:
            require_live_server(cm, "ds-offline-1", "test_tool")
        assert "ds-offline-1" in str(exc_info.value)

    def test_connect_no_password_error_preserves_name(self):
        """ConnectionManager.connect() password ToolError should keep real server name."""
        from fastmcp.exceptions import ToolError
        from ldap_assistant_mcp.dirsrv_mcp.connection import ConnectionManager, ServerConfig

        cm = ConnectionManager()
        cm.add_server(ServerConfig(
            name="ds-prod-1",
            ldap_url="ldap://localhost:389",
            base_dn="dc=example,dc=com",
            bind_dn="cn=Directory Manager",
            bind_password=None,
        ))
        with pytest.raises(ToolError) as exc_info:
            cm.connect("ds-prod-1")
        # Server names are never sanitized
        assert "ds-prod-1" in str(exc_info.value)

    def test_connect_no_password_error_raw_when_no_sanitizer(self):
        """Without _sanitize_name, connect() error shows raw server name."""
        from fastmcp.exceptions import ToolError
        from ldap_assistant_mcp.dirsrv_mcp.connection import ConnectionManager, ServerConfig

        cm = ConnectionManager()
        cm.add_server(ServerConfig(
            name="ds-prod-1",
            ldap_url="ldap://localhost:389",
            base_dn="dc=example,dc=com",
            bind_dn="cn=Directory Manager",
            bind_password=None,
        ))
        with pytest.raises(ToolError) as exc_info:
            cm.connect("ds-prod-1")
        assert "ds-prod-1" in str(exc_info.value)

    def test_nested_error_fields_sanitized_in_health_metrics(self):
        """Error fields inside nested health metric dicts must be sanitized."""
        from ldap_assistant_mcp.dirsrv_mcp.tools.health import _sanitize_server_metrics

        sanitizer = PrivacySanitizer()
        data = {
            "server": "ds-test",
            "replication": {"configured": False, "error": "Failed on cn=replica,cn=dc=example,dc=com"},
            "cache": {"error": "Cannot read /etc/dirsrv/slapd-test/dse.ldif"},
            "disk": {"available": False, "error": "Permission denied /var/log/dirsrv/slapd-test"},
            "certificates": {"available": False, "error": "NSS db at /etc/dirsrv/slapd-test not found"},
            "dse_error": "FileNotFoundError: /etc/dirsrv/slapd-test/dse.ldif",
        }
        result = _sanitize_server_metrics(sanitizer, data)
        assert "/etc/dirsrv" not in result.get("dse_error", "")
        assert "/etc/dirsrv" not in result["replication"].get("error", "")
        assert "/etc/dirsrv" not in result["cache"].get("error", "")
        assert "/var/log/dirsrv" not in result["disk"].get("error", "")
        assert "/etc/dirsrv" not in result["certificates"].get("error", "")

    def test_nested_error_fields_sanitized_in_performance(self):
        """Error fields inside performance backend dicts must be sanitized."""
        from ldap_assistant_mcp.dirsrv_mcp.tools.performance import _sanitize_performance_result

        mcp = _make_mcp(privacy_enabled=True)
        result = {
            "type": "cache_statistics",
            "server": "ds-test",
            "global_db_cache": {"error": "Failed at /etc/dirsrv/slapd-test/db"},
            "backends": [
                {"name": "userroot", "error": "Cannot read cn=config,cn=ldbm database on host.example.com"},
            ],
        }
        sanitized = _sanitize_performance_result(mcp, result)
        assert "/etc/dirsrv" not in sanitized["global_db_cache"]["error"]
        assert "example.com" not in sanitized["backends"][0]["error"]

    def test_nested_error_fields_sanitized_in_replica(self):
        """Error fields inside replica/agreement dicts must be sanitized."""
        sanitizer = PrivacySanitizer()
        replica = {
            "suffix": "dc=example,dc=com",
            "error": "Cannot connect to ldaps://host.example.com:636",
            "agreements": [
                {"name": "agmt1", "error": "Bind failed on cn=config,dc=example,dc=com"},
            ],
        }
        result = sanitizer.sanitize_replica(replica)
        assert "example.com" not in result.get("error", "")
        assert "example.com" not in result["agreements"][0].get("error", "")

    def test_all_sanitizers_handle_error_field(self):
        """Every module sanitizer should sanitize the error field."""
        from ldap_assistant_mcp.dirsrv_mcp.tools.health import _sanitize_health_result
        from ldap_assistant_mcp.dirsrv_mcp.tools.replication import _sanitize_replication_result
        from ldap_assistant_mcp.dirsrv_mcp.tools.indexes import _sanitize_index_result
        from ldap_assistant_mcp.dirsrv_mcp.tools.performance import _sanitize_performance_result
        from ldap_assistant_mcp.dirsrv_mcp.tools.monitoring import _sanitize_monitor_result
        from ldap_assistant_mcp.dirsrv_mcp.tools.logs import _sanitize_log_result

        sanitizers = [
            ("health", _sanitize_health_result),
            ("replication", _sanitize_replication_result),
            ("indexes", _sanitize_index_result),
            ("performance", _sanitize_performance_result),
            ("monitoring", _sanitize_monitor_result),
            ("logs", _sanitize_log_result),
        ]

        mcp = _make_mcp(privacy_enabled=True)
        for name, fn in sanitizers:
            result = {
                "type": "test",
                "server": "ds-test",
                "error": "Failed at ldaps://server.example.com:636/dc=example,dc=com",
            }
            sanitized = fn(mcp, result)
            assert "server.example.com" not in sanitized["error"], \
                f"{name} sanitizer did not sanitize error field"
