"""Tests for archive mode (Phase 1: core infrastructure).

Tests verify that:
1. ArchiveLayout detection works for SOS reports and manual extracts
2. ArchiveDirSrv stub provides the interface lib389 classes expect
3. Config loader parses archive fields with proper validation
4. ConnectionManager routes archive servers through _connect_archive()
5. describe_servers() includes archive mode markers
6. require_live_server() guards reject archive servers
"""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from ldap_assistant_mcp.config.loader import ServerListConfig, _server_config_from_dict
from ldap_assistant_mcp.dirsrv_mcp.archive.loader import (
    ArchiveLayout,
    detect_archive_layout,
    extract_archive,
)
from ldap_assistant_mcp.dirsrv_mcp.archive.stub import ArchiveDirSrv, ArchivePaths
from ldap_assistant_mcp.dirsrv_mcp.connection import (
    ConnectionManager,
    LiveServerRequired,
    ServerConfig,
    is_archive_server,
    is_offline_or_archive,
    is_offline_server,
    require_live_server,
)
from ldap_assistant_mcp.dirsrv_mcp.server import DirSrvMCP
from ldap_assistant_mcp.core import LDAPServerConfig


# Test fixtures

# Minimal dse.ldif content for testing
MINIMAL_DSE_LDIF = """\
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
"""

MINIMAL_ACCESS_LOG = """\
[01/Jan/2024:00:00:01.000000000 +0000] conn=1 fd=64 slot=64 connection from 127.0.0.1 to 127.0.0.1
[01/Jan/2024:00:00:01.000000000 +0000] conn=1 op=0 BIND dn="cn=Directory Manager" method=128 version=3
[01/Jan/2024:00:00:01.000000000 +0000] conn=1 op=0 RESULT err=0 tag=97 nentries=0 wtime=0.000001 optime=0.000100 etime=0.000101
"""

MINIMAL_ERROR_LOG = """\
[01/Jan/2024:00:00:01.000000000 +0000] - INFO - main - 389-Directory/2.4.6 starting up
"""


@pytest.fixture
def sos_report_dir(tmp_path):
    """Create a realistic SOS report directory structure."""
    inst = "slapd-localhost"

    # Config
    config_dir = tmp_path / "etc" / "dirsrv" / inst
    config_dir.mkdir(parents=True)
    (config_dir / "dse.ldif").write_text(MINIMAL_DSE_LDIF)
    schema_dir = config_dir / "schema"
    schema_dir.mkdir()
    (schema_dir / "99user.ldif").write_text("# custom schema\n")

    # Logs
    logs_dir = tmp_path / "var" / "log" / "dirsrv" / inst
    logs_dir.mkdir(parents=True)
    (logs_dir / "access").write_text(MINIMAL_ACCESS_LOG)
    (logs_dir / "errors").write_text(MINIMAL_ERROR_LOG)

    # SOS commands
    sos_dir = tmp_path / "sos_commands" / "dirsrv"
    sos_dir.mkdir(parents=True)
    (sos_dir / "dsctl_localhost_healthcheck").write_text("No issues found.\n")

    return tmp_path


@pytest.fixture
def config_only_dir(tmp_path):
    """Create a directory with just dse.ldif."""
    (tmp_path / "dse.ldif").write_text(MINIMAL_DSE_LDIF)
    return tmp_path


@pytest.fixture
def manual_extract_dir(tmp_path):
    """Create manual extract with separate config and logs dirs."""
    config_dir = tmp_path / "config" / "slapd-prod"
    config_dir.mkdir(parents=True)
    (config_dir / "dse.ldif").write_text(MINIMAL_DSE_LDIF)

    logs_dir = tmp_path / "logs" / "slapd-prod"
    logs_dir.mkdir(parents=True)
    (logs_dir / "access").write_text(MINIMAL_ACCESS_LOG)
    (logs_dir / "errors").write_text(MINIMAL_ERROR_LOG)

    return config_dir, logs_dir


@pytest.fixture
def archive_server_config(sos_report_dir):
    """Create an archive server configuration."""
    return LDAPServerConfig(
        name="archive-test",
        hostname="archive",
        port=0,
        is_archive=True,
        archive_path=str(sos_report_dir),
    )


@pytest.fixture
def archive_env():
    """Ensure no external config leaks into archive tests."""
    env = {
        "LDAP_MCP_EXPOSE_SENSITIVE_DATA": "true",
        "LDAP_SERVERS_CONFIG": "",
    }
    with patch.dict(os.environ, env):
        yield


@pytest.fixture
def archive_dirsrv_server(archive_env, archive_server_config):
    """Create a DirSrvMCP instance with archive server configured."""
    return DirSrvMCP(
        servers=[archive_server_config],
        include_env_fallback=False,
    )


# Archive Loader tests


class TestDetectArchiveLayout:
    """Test detect_archive_layout() with various directory structures."""

    def test_sos_report_detection(self, sos_report_dir):
        """Should detect standard SOS report layout."""
        layout = detect_archive_layout(archive_path=str(sos_report_dir))
        assert layout.archive_type == "sos_report"
        assert layout.instance_name == "slapd-localhost"
        assert layout.config_dir is not None
        assert layout.dse_ldif_path is not None
        assert os.path.isfile(layout.dse_ldif_path)
        assert layout.logs_dir is not None
        assert layout.sos_commands_dir is not None
        assert layout.schema_dir is not None

    def test_config_only_detection(self, config_only_dir):
        """Should detect directory with just dse.ldif."""
        layout = detect_archive_layout(archive_path=str(config_only_dir))
        assert layout.archive_type == "config_only"
        assert layout.config_dir == str(config_only_dir)
        assert layout.dse_ldif_path is not None
        assert layout.logs_dir is None

    def test_explicit_config_path(self, manual_extract_dir):
        """Should use explicit config_path."""
        config_dir, _ = manual_extract_dir
        layout = detect_archive_layout(config_path=str(config_dir))
        assert layout.archive_type == "config_only"
        assert layout.config_dir == str(config_dir)
        assert layout.instance_name == "slapd-prod"

    def test_explicit_config_and_logs_paths(self, manual_extract_dir):
        """Should use explicit config_path and logs_path."""
        config_dir, logs_dir = manual_extract_dir
        layout = detect_archive_layout(
            config_path=str(config_dir),
            logs_path=str(logs_dir),
        )
        assert layout.archive_type == "manual_extract"
        assert layout.config_dir == str(config_dir)
        assert layout.logs_dir == str(logs_dir)
        assert layout.instance_name == "slapd-prod"

    def test_nested_sosreport_directory(self, tmp_path):
        """Should handle nested sosreport-*/ directory."""
        nested = tmp_path / "sosreport-host-2024"
        config_dir = nested / "etc" / "dirsrv" / "slapd-inst1"
        config_dir.mkdir(parents=True)
        (config_dir / "dse.ldif").write_text(MINIMAL_DSE_LDIF)

        layout = detect_archive_layout(archive_path=str(tmp_path))
        assert layout.archive_type == "sos_report"
        assert layout.instance_name == "slapd-inst1"

    def test_no_dse_ldif_raises(self, tmp_path):
        """Should raise when no dse.ldif found."""
        (tmp_path / "some_file.txt").write_text("not relevant")
        with pytest.raises(FileNotFoundError, match="No dse.ldif found"):
            detect_archive_layout(archive_path=str(tmp_path))

    def test_nonexistent_path_raises(self):
        """Should raise for nonexistent archive_path."""
        with pytest.raises(FileNotFoundError):
            detect_archive_layout(archive_path="/nonexistent/path")

    def test_no_paths_raises(self):
        """Should raise when no paths provided."""
        with pytest.raises(ValueError, match="Either archive_path or config_path"):
            detect_archive_layout()

    def test_invalid_config_path_raises(self, tmp_path):
        """Should raise when config_path doesn't exist."""
        with pytest.raises(FileNotFoundError, match="Config path"):
            detect_archive_layout(config_path=str(tmp_path / "nonexistent"))

    def test_invalid_logs_path_raises(self, tmp_path):
        """Should raise when logs_path doesn't exist."""
        (tmp_path / "dse.ldif").write_text(MINIMAL_DSE_LDIF)
        with pytest.raises(FileNotFoundError, match="Logs path"):
            detect_archive_layout(
                config_path=str(tmp_path),
                logs_path=str(tmp_path / "nonexistent"),
            )

    def test_direct_slapd_directory(self, tmp_path):
        """Should detect slapd-* directory directly under root."""
        inst_dir = tmp_path / "slapd-myinst"
        inst_dir.mkdir()
        (inst_dir / "dse.ldif").write_text(MINIMAL_DSE_LDIF)

        layout = detect_archive_layout(archive_path=str(tmp_path))
        assert layout.instance_name == "slapd-myinst"
        assert layout.config_dir == str(inst_dir)

    def test_tarball_extraction(self, sos_report_dir):
        """Should extract .tar.xz and detect layout inside."""
        import tarfile

        # Create a .tar.xz from the SOS report directory
        tarball_path = str(sos_report_dir.parent / "sosreport-test-host-123.tar.xz")
        with tarfile.open(tarball_path, "w:xz") as tar:
            tar.add(str(sos_report_dir), arcname="sosreport-test-host-123")

        layout = detect_archive_layout(archive_path=tarball_path)
        assert layout.archive_type == "sos_report"
        assert layout.instance_name == "slapd-localhost"
        assert layout.dse_ldif_path is not None
        assert os.path.isfile(layout.dse_ldif_path)

    def test_tarball_with_config_only(self, config_only_dir):
        """Should extract .tar.gz and detect config-only layout."""
        import tarfile

        tarball_path = str(config_only_dir.parent / "config-extract.tar.gz")
        with tarfile.open(tarball_path, "w:gz") as tar:
            # Add files at root level (no subdirectory) so dse.ldif is at top
            for item in os.listdir(str(config_only_dir)):
                tar.add(os.path.join(str(config_only_dir), item), arcname=item)

        layout = detect_archive_layout(archive_path=tarball_path)
        assert layout.archive_type == "config_only"
        assert layout.dse_ldif_path is not None


# Multi-instance selection tests


@pytest.fixture
def multi_instance_sos(tmp_path):
    """Create a SOS report with multiple DS instances."""
    instances = ["slapd-supplier1", "slapd-supplier2", "slapd-consumer1"]
    for inst in instances:
        config_dir = tmp_path / "etc" / "dirsrv" / inst
        config_dir.mkdir(parents=True)
        (config_dir / "dse.ldif").write_text(MINIMAL_DSE_LDIF)
        logs_dir = tmp_path / "var" / "log" / "dirsrv" / inst
        logs_dir.mkdir(parents=True)
        (logs_dir / "access").write_text(MINIMAL_ACCESS_LOG)
        (logs_dir / "errors").write_text(MINIMAL_ERROR_LOG)
    return tmp_path


class TestMultiInstanceSelection:
    """Test instance_name selection when archive has multiple DS instances."""

    def test_multiple_instances_no_selector_raises(self, multi_instance_sos):
        """Should raise ValueError listing available instances."""
        with pytest.raises(ValueError, match="3 DS instances") as exc_info:
            detect_archive_layout(archive_path=str(multi_instance_sos))
        # All instance names should be listed in the error
        assert "slapd-supplier1" in str(exc_info.value)
        assert "slapd-supplier2" in str(exc_info.value)
        assert "slapd-consumer1" in str(exc_info.value)

    def test_select_specific_instance(self, multi_instance_sos):
        """Should select the requested instance from multi-instance archive."""
        layout = detect_archive_layout(
            archive_path=str(multi_instance_sos),
            instance_name="slapd-supplier1",
        )
        assert layout.instance_name == "slapd-supplier1"
        assert layout.archive_type == "sos_report"
        assert layout.dse_ldif_path is not None
        assert "slapd-supplier1" in layout.dse_ldif_path

    def test_select_each_instance(self, multi_instance_sos):
        """Should be able to select any of the available instances."""
        for inst in ["slapd-supplier1", "slapd-supplier2", "slapd-consumer1"]:
            layout = detect_archive_layout(
                archive_path=str(multi_instance_sos),
                instance_name=inst,
            )
            assert layout.instance_name == inst
            assert layout.logs_dir is not None

    def test_nonexistent_instance_raises(self, multi_instance_sos):
        """Should raise ValueError when instance_name doesn't exist."""
        with pytest.raises(ValueError, match="not found in archive"):
            detect_archive_layout(
                archive_path=str(multi_instance_sos),
                instance_name="slapd-nonexistent",
            )

    def test_single_instance_with_selector(self, sos_report_dir):
        """Specifying instance_name with a single-instance archive should work."""
        layout = detect_archive_layout(
            archive_path=str(sos_report_dir),
            instance_name="slapd-localhost",
        )
        assert layout.instance_name == "slapd-localhost"

    def test_single_instance_wrong_selector_raises(self, sos_report_dir):
        """Wrong instance_name with single-instance archive should raise."""
        with pytest.raises(ValueError, match="does not match"):
            detect_archive_layout(
                archive_path=str(sos_report_dir),
                instance_name="slapd-wrong",
            )

    def test_single_instance_no_selector(self, sos_report_dir):
        """Single instance should auto-select without instance_name."""
        layout = detect_archive_layout(archive_path=str(sos_report_dir))
        assert layout.instance_name == "slapd-localhost"

    def test_config_loader_instance_name(self):
        """Config loader should parse instance_name field."""
        data = {
            "name": "sos-supplier1",
            "is_archive": True,
            "archive_path": "/cases/sos-report",
            "instance_name": "slapd-supplier1",
        }
        config = _server_config_from_dict(data)
        assert config.instance_name == "slapd-supplier1"

    def test_config_loader_instance_name_none(self):
        """Config loader should leave instance_name as None when not set."""
        data = {
            "name": "sos-single",
            "is_archive": True,
            "archive_path": "/cases/sos-report",
        }
        config = _server_config_from_dict(data)
        assert config.instance_name is None

    def test_connection_manager_passes_instance_name(self, multi_instance_sos):
        """ConnectionManager should pass instance_name through to archive layout."""
        cm = ConnectionManager()
        config = LDAPServerConfig(
            name="sos-supplier1",
            hostname="archive",
            port=0,
            is_archive=True,
            archive_path=str(multi_instance_sos),
            instance_name="slapd-supplier1",
        )
        cm.add_server(config)
        ds = cm.connect("sos-supplier1")
        assert isinstance(ds, ArchiveDirSrv)
        assert ds.serverid == "slapd-supplier1"


# ArchivePaths tests


class TestArchivePaths:
    """Test ArchivePaths property interface."""

    def test_basic_paths(self):
        paths = ArchivePaths(
            config_dir="/archive/etc/dirsrv/slapd-inst",
            log_dir="/archive/var/log/dirsrv/slapd-inst",
        )
        assert paths.config_dir == "/archive/etc/dirsrv/slapd-inst"
        assert paths.log_dir == "/archive/var/log/dirsrv/slapd-inst"
        assert paths.access_log == "/archive/var/log/dirsrv/slapd-inst/access"
        assert paths.error_log == "/archive/var/log/dirsrv/slapd-inst/errors"
        assert paths.audit_log == "/archive/var/log/dirsrv/slapd-inst/audit"
        assert paths.security_log == "/archive/var/log/dirsrv/slapd-inst/security"

    def test_no_log_dir(self):
        paths = ArchivePaths(config_dir="/archive/config")
        assert paths.log_dir is None
        assert paths.access_log is None
        assert paths.error_log is None

    def test_schema_default(self):
        paths = ArchivePaths(config_dir="/archive/config")
        assert paths.schema_dir == "/archive/config/schema"

    def test_cert_dir_default(self):
        paths = ArchivePaths(config_dir="/archive/config")
        assert paths.cert_dir == "/archive/config"


# ArchiveDirSrv stub tests


class TestArchiveDirSrv:
    """Test ArchiveDirSrv stub interface."""

    def test_basic_attributes(self, sos_report_dir):
        layout = detect_archive_layout(archive_path=str(sos_report_dir))
        stub = ArchiveDirSrv(layout)

        assert stub.serverid == "slapd-localhost"
        assert stub.ds_paths is not None
        assert stub.ds_paths.config_dir is not None
        assert stub.log is not None
        assert stub.verbose is False

    def test_get_cert_dir(self, sos_report_dir):
        layout = detect_archive_layout(archive_path=str(sos_report_dir))
        stub = ArchiveDirSrv(layout)
        assert stub.get_cert_dir() == stub.ds_paths.cert_dir

    def test_open_raises(self, sos_report_dir):
        layout = detect_archive_layout(archive_path=str(sos_report_dir))
        stub = ArchiveDirSrv(layout)
        with pytest.raises(RuntimeError, match="Cannot open LDAP connection"):
            stub.open()

    def test_close_is_noop(self, sos_report_dir):
        layout = detect_archive_layout(archive_path=str(sos_report_dir))
        stub = ArchiveDirSrv(layout)
        stub.close()  # Should not raise

    def test_search_raises(self, sos_report_dir):
        layout = detect_archive_layout(archive_path=str(sos_report_dir))
        stub = ArchiveDirSrv(layout)
        with pytest.raises(RuntimeError, match="Cannot perform LDAP search"):
            stub.search_s("cn=config")

    def test_dse_ldif_path_property(self, sos_report_dir):
        """ArchiveDirSrv.dse_ldif_path should return the path to dse.ldif."""
        layout = detect_archive_layout(archive_path=str(sos_report_dir))
        stub = ArchiveDirSrv(layout)
        assert stub.dse_ldif_path is not None
        assert os.path.isfile(stub.dse_ldif_path)

    def test_stub_with_dseldif(self, sos_report_dir):
        """ArchiveDirSrv should work with lib389 DSEldif using explicit path.

        DSEldif's default path resolution uses lib389.paths.Paths which needs
        defaults.inf (only available on DS hosts). For archive mode, we always
        pass the explicit path since we already know it from the layout.
        """
        from lib389.dseldif import DSEldif

        layout = detect_archive_layout(archive_path=str(sos_report_dir))
        stub = ArchiveDirSrv(layout)

        dse = DSEldif(stub, path=stub.dse_ldif_path)
        port = dse.get("cn=config", "nsslapd-port")
        assert port is not None

    def test_stub_with_ldifconn(self, sos_report_dir):
        """LDIFConn should work with dse.ldif from archive layout."""
        from lib389._ldifconn import LDIFConn

        layout = detect_archive_layout(archive_path=str(sos_report_dir))
        ldif_data = LDIFConn(layout.dse_ldif_path)
        entry = ldif_data.get("cn=config")
        assert entry is not None
        assert entry.hasAttr("nsslapd-port")


# LDAPServerConfig archive fields


class TestLDAPServerConfigArchive:
    """Test LDAPServerConfig with archive mode fields."""

    def test_archive_defaults(self):
        config = LDAPServerConfig(name="test", hostname="localhost")
        assert config.is_archive is False
        assert config.archive_path is None
        assert config.config_path is None
        assert config.logs_path is None

    def test_archive_can_be_set(self):
        config = LDAPServerConfig(
            name="test",
            hostname="archive",
            is_archive=True,
            archive_path="/path/to/sos",
        )
        assert config.is_archive is True
        assert config.archive_path == "/path/to/sos"

    def test_as_dict_includes_archive(self):
        config = LDAPServerConfig(
            name="test",
            hostname="archive",
            is_archive=True,
            archive_path="/path/to/sos",
            config_path="/path/to/config",
            logs_path="/path/to/logs",
        )
        d = config.as_dict()
        assert d["is_archive"] is True
        assert d["archive_path"] == "/path/to/sos"
        assert d["config_path"] == "/path/to/config"
        assert d["logs_path"] == "/path/to/logs"

    def test_as_dict_excludes_archive_when_false(self):
        config = LDAPServerConfig(name="test", hostname="localhost")
        d = config.as_dict()
        assert "is_archive" not in d
        assert "archive_path" not in d


# ServerConfig archive fields


class TestServerConfigArchive:
    """Test ServerConfig with archive mode fields."""

    def test_archive_defaults(self):
        config = ServerConfig(
            name="test",
            ldap_url="ldap://localhost:389",
            base_dn="dc=test,dc=com",
            bind_dn="",
            bind_password="",
        )
        assert config.is_archive is False

    def test_archive_can_be_set(self):
        config = ServerConfig(
            name="test",
            ldap_url="ldap://archive:0",
            base_dn="",
            bind_dn="",
            bind_password="",
            is_archive=True,
            archive_path="/path/to/sos",
        )
        assert config.is_archive is True
        assert config.archive_path == "/path/to/sos"


# Config loader archive parsing


class TestConfigLoaderArchive:
    """Test config loader with archive mode fields."""

    def test_parse_archive_with_archive_path(self):
        data = {
            "name": "sos-report",
            "is_archive": True,
            "archive_path": "/cases/sosreport-host-2024",
        }
        config = _server_config_from_dict(data)
        assert config.is_archive is True
        assert config.archive_path == "/cases/sosreport-host-2024"
        assert config.hostname == "archive"
        assert config.port == 0

    def test_parse_archive_with_config_path(self):
        data = {
            "name": "manual-extract",
            "is_archive": True,
            "config_path": "/tmp/config/slapd-prod",
            "logs_path": "/tmp/logs/slapd-prod",
        }
        config = _server_config_from_dict(data)
        assert config.is_archive is True
        assert config.config_path == "/tmp/config/slapd-prod"
        assert config.logs_path == "/tmp/logs/slapd-prod"

    def test_archive_requires_path(self):
        data = {
            "name": "bad-archive",
            "is_archive": True,
        }
        with pytest.raises(ValueError, match="requires archive_path or config_path"):
            _server_config_from_dict(data)

    def test_offline_and_archive_mutually_exclusive(self):
        data = {
            "name": "bad",
            "is_offline": True,
            "is_archive": True,
            "serverid": "inst",
            "archive_path": "/sos",
        }
        with pytest.raises(ValueError, match="mutually exclusive"):
            _server_config_from_dict(data)

    def test_archive_string_bool(self):
        data = {
            "name": "sos",
            "is_archive": "true",
            "archive_path": "/sos",
        }
        config = _server_config_from_dict(data)
        assert config.is_archive is True

    def test_tilde_expansion_in_archive_path(self):
        """Tilde (~) in archive_path should be expanded to home directory."""
        data = {
            "name": "sos-tilde",
            "is_archive": True,
            "archive_path": "~/sosreport-host.tar.xz",
        }
        config = _server_config_from_dict(data)
        assert "~" not in config.archive_path
        assert config.archive_path == os.path.expanduser("~/sosreport-host.tar.xz")

    def test_tilde_expansion_in_config_path(self):
        """Tilde (~) in config_path and logs_path should be expanded."""
        data = {
            "name": "manual-tilde",
            "is_archive": True,
            "config_path": "~/config/slapd-prod",
            "logs_path": "~/logs/slapd-prod",
        }
        config = _server_config_from_dict(data)
        assert "~" not in config.config_path
        assert "~" not in config.logs_path

    def test_relative_archive_path_resolved(self):
        """Relative archive_path should be resolved to absolute."""
        data = {
            "name": "sos-rel",
            "is_archive": True,
            "archive_path": "sosreport-host-123-2026-02-11-abc.tar.xz",
        }
        config = _server_config_from_dict(data)
        assert os.path.isabs(config.archive_path)
        assert config.archive_path.endswith("sosreport-host-123-2026-02-11-abc.tar.xz")

    def test_relative_path_resolved_against_base_dir(self):
        """Relative archive_path should resolve against base_dir, not CWD."""
        data = {
            "name": "sos-rel",
            "is_archive": True,
            "archive_path": "sosreport-host.tar.xz",
        }
        config = _server_config_from_dict(data, base_dir="/opt/configs")
        assert config.archive_path == "/opt/configs/sosreport-host.tar.xz"

    def test_absolute_path_ignores_base_dir(self):
        """Absolute archive_path should not be affected by base_dir."""
        data = {
            "name": "sos-abs",
            "is_archive": True,
            "archive_path": "/cases/sosreport.tar.xz",
        }
        config = _server_config_from_dict(data, base_dir="/opt/configs")
        assert config.archive_path == "/cases/sosreport.tar.xz"

    def test_from_dict_passes_base_dir(self, tmp_path):
        """ServerListConfig.from_dict should pass base_dir through."""
        data = {
            "servers": [
                {
                    "name": "sos",
                    "is_archive": True,
                    "archive_path": "report.tar.xz",
                }
            ]
        }
        config = ServerListConfig.from_dict(data, base_dir=str(tmp_path))
        assert config.servers[0].archive_path == str(tmp_path / "report.tar.xz")

    def test_tarball_archive_path_preserved(self):
        """A .tar.xz archive_path should be accepted and stored as-is (after expansion)."""
        data = {
            "name": "sos-tarball",
            "is_archive": True,
            "archive_path": "/cases/sosreport-vm-10-0-184-211-123-2026-02-11-ktm.tar.xz",
        }
        config = _server_config_from_dict(data)
        assert config.archive_path.endswith(".tar.xz")
        assert config.is_archive is True

    def test_backward_compatibility(self):
        """Existing live server configs should still work unchanged."""
        data = {
            "name": "live",
            "hostname": "ldap.example.com",
            "port": 636,
            "use_ssl": True,
            "bind_dn": "cn=Directory Manager",
            "bind_password": "secret",
            "base_dn": "dc=example,dc=com",
        }
        config = _server_config_from_dict(data)
        assert config.is_archive is False
        assert config.is_offline is False
        assert config.hostname == "ldap.example.com"


# ServerListConfig roundtrip with archive


class TestServerListConfigArchive:
    """Test ServerListConfig serialization with archive mode."""

    def test_to_dict_includes_archive(self):
        servers = [
            LDAPServerConfig(
                name="sos",
                hostname="archive",
                port=0,
                is_archive=True,
                archive_path="/cases/sos-report",
            ),
        ]
        config = ServerListConfig(servers=servers)
        d = config.to_dict()
        archive_dict = d["servers"][0]
        assert archive_dict["is_archive"] is True
        assert archive_dict["archive_path"] == "/cases/sos-report"

    def test_from_dict_parses_archive(self):
        data = {
            "servers": [
                {
                    "name": "sos-report",
                    "is_archive": True,
                    "archive_path": "/cases/sos",
                }
            ]
        }
        config = ServerListConfig.from_dict(data)
        assert len(config.servers) == 1
        assert config.servers[0].is_archive is True
        assert config.servers[0].archive_path == "/cases/sos"

    def test_roundtrip_archive_config(self):
        original = ServerListConfig(
            servers=[
                LDAPServerConfig(
                    name="sos",
                    hostname="archive",
                    port=0,
                    is_archive=True,
                    archive_path="/cases/sos",
                ),
            ]
        )
        d = original.to_dict()
        restored = ServerListConfig.from_dict(d)
        assert len(restored.servers) == 1
        assert restored.servers[0].is_archive is True
        assert restored.servers[0].archive_path == "/cases/sos"
        assert restored.servers[0].name == "sos"

    def test_mixed_live_offline_archive(self):
        data = {
            "servers": [
                {
                    "name": "live",
                    "hostname": "ldap.example.com",
                    "port": 389,
                    "bind_dn": "cn=DM",
                    "bind_password": "s",
                },
                {
                    "name": "offline",
                    "is_local": True,
                    "serverid": "inst",
                    "is_offline": True,
                },
                {
                    "name": "archive",
                    "is_archive": True,
                    "archive_path": "/sos",
                },
            ]
        }
        config = ServerListConfig.from_dict(data)
        assert len(config.servers) == 3
        live = next(s for s in config.servers if s.name == "live")
        offline = next(s for s in config.servers if s.name == "offline")
        archive = next(s for s in config.servers if s.name == "archive")
        assert not live.is_offline and not live.is_archive
        assert offline.is_offline and not offline.is_archive
        assert archive.is_archive and not archive.is_offline


# ConnectionManager archive handling


class TestConnectionManagerArchive:
    """Test ConnectionManager with archive mode."""

    def test_add_archive_server(self):
        cm = ConnectionManager()
        config = LDAPServerConfig(
            name="sos-test",
            hostname="archive",
            port=0,
            is_archive=True,
            archive_path="/cases/sos",
        )
        cm.add_server(config)
        stored = cm.get_config("sos-test")
        assert stored.is_archive is True
        assert stored.archive_path == "/cases/sos"

    def test_connect_archive_returns_stub(self, sos_report_dir):
        cm = ConnectionManager()
        config = LDAPServerConfig(
            name="sos-test",
            hostname="archive",
            port=0,
            is_archive=True,
            archive_path=str(sos_report_dir),
        )
        cm.add_server(config)
        ds = cm.connect("sos-test")
        assert isinstance(ds, ArchiveDirSrv)
        assert ds.serverid == "slapd-localhost"
        ds.close()  # Should be no-op

    def test_connect_archive_with_explicit_paths(self, manual_extract_dir):
        config_dir, logs_dir = manual_extract_dir
        cm = ConnectionManager()
        config = LDAPServerConfig(
            name="extract-test",
            hostname="archive",
            port=0,
            is_archive=True,
            config_path=str(config_dir),
            logs_path=str(logs_dir),
        )
        cm.add_server(config)
        ds = cm.connect("extract-test")
        assert isinstance(ds, ArchiveDirSrv)
        assert ds.ds_paths.config_dir == str(config_dir)
        assert ds.ds_paths.log_dir == str(logs_dir)


# Archive server helper functions


class TestArchiveServerHelpers:
    """Test is_archive_server(), is_offline_or_archive(), require_live_server()."""

    def _make_cm(self, **configs):
        cm = ConnectionManager()
        for name, cfg in configs.items():
            cm.add_server(cfg)
        return cm

    def test_is_archive_server_true(self):
        cm = self._make_cm(
            sos=LDAPServerConfig(
                name="sos", hostname="archive", is_archive=True, archive_path="/sos",
            )
        )
        assert is_archive_server(cm, "sos") is True

    def test_is_archive_server_false_for_live(self):
        cm = self._make_cm(
            live=LDAPServerConfig(name="live", hostname="localhost", port=389)
        )
        assert is_archive_server(cm, "live") is False

    def test_is_archive_server_false_for_unknown(self):
        cm = ConnectionManager()
        assert is_archive_server(cm, "nonexistent") is False

    def test_is_offline_or_archive_for_archive(self):
        cm = self._make_cm(
            sos=LDAPServerConfig(
                name="sos", hostname="archive", is_archive=True, archive_path="/sos",
            )
        )
        assert is_offline_or_archive(cm, "sos") is True

    def test_is_offline_or_archive_for_offline(self):
        cm = self._make_cm(
            off=LDAPServerConfig(
                name="off", hostname="localhost", is_local=True, serverid="inst", is_offline=True,
            )
        )
        assert is_offline_or_archive(cm, "off") is True

    def test_is_offline_or_archive_false_for_live(self):
        cm = self._make_cm(
            live=LDAPServerConfig(name="live", hostname="localhost", port=389)
        )
        assert is_offline_or_archive(cm, "live") is False

    def test_require_live_server_raises_for_archive(self):
        cm = self._make_cm(
            sos=LDAPServerConfig(
                name="sos", hostname="archive", is_archive=True, archive_path="/sos",
            )
        )
        with pytest.raises(LiveServerRequired) as exc_info:
            require_live_server(cm, "sos", "list_all_users")
        assert "archive" in str(exc_info.value).lower()
        assert "list_all_users" in str(exc_info.value)

    def test_require_live_server_passes_for_live(self):
        cm = self._make_cm(
            live=LDAPServerConfig(name="live", hostname="localhost", port=389)
        )
        require_live_server(cm, "live", "list_all_users")  # Should not raise


# describe_servers with archive mode


class TestDescribeServersArchive:
    """Test describe_servers() with archive mode markers."""

    def test_archive_server_has_mode_archive(self, archive_dirsrv_server):
        descriptions = archive_dirsrv_server.describe_servers()
        assert len(descriptions) == 1
        desc = descriptions[0]
        assert desc["mode"] == "archive"
        assert desc["is_archive"] is True

    def test_mixed_modes(self):
        with patch.dict(os.environ, {
            "LDAP_MCP_EXPOSE_SENSITIVE_DATA": "true",
            "LDAP_SERVERS_CONFIG": "",
        }):
            server = DirSrvMCP(
                servers=[
                    LDAPServerConfig(
                        name="live", hostname="localhost", port=389,
                        is_local=True, serverid="inst",
                    ),
                    LDAPServerConfig(
                        name="offline", hostname="localhost", port=389,
                        is_local=True, serverid="inst", is_offline=True,
                    ),
                    LDAPServerConfig(
                        name="archive", hostname="archive", port=0,
                        is_archive=True, archive_path="/sos",
                    ),
                ],
                include_env_fallback=False,
            )
        descriptions = server.describe_servers()
        modes = {d["name"]: d["mode"] for d in descriptions}
        assert modes == {"live": "live", "offline": "offline", "archive": "archive"}

    def test_archive_privacy_mode(self):
        with patch.dict(os.environ, {
            "LDAP_MCP_EXPOSE_SENSITIVE_DATA": "false",
            "LDAP_SERVERS_CONFIG": "",
        }):
            server = DirSrvMCP(
                servers=[
                    LDAPServerConfig(
                        name="archive", hostname="archive", port=0,
                        is_archive=True, archive_path="/cases/sos-report",
                    ),
                ],
                include_env_fallback=False,
            )
        descriptions = server.describe_servers()
        desc = descriptions[0]
        assert desc["mode"] == "archive"
        assert desc["is_archive"] is True
        # archive_path should be sanitized
        assert desc.get("archive_path") == "[archive_path]"


# Tool guards for archive servers


# Same guarded tools as offline mode — they should also reject archive servers
GUARDED_TOOLS = [
    ("list_all_users", {}),
    ("search_users_by_name", {"name": "test"}),
    ("get_user_details", {"username": "testuser"}),
    ("list_active_users", {}),
    ("list_locked_users", {}),
    ("search_users_by_attribute", {"attribute": "uid", "value": "test"}),
    ("list_all_groups", {}),
    ("ldap_search", {"base_dn": "dc=test,dc=com"}),
    ("run_monitor", {}),
    ("get_cache_statistics", {}),
    ("get_connection_statistics", {}),
    ("get_operation_statistics", {}),
    ("get_thread_statistics", {}),
    ("get_resource_utilization", {}),
    ("get_performance_summary", {}),
    ("get_replication_status", {}),
    ("check_replication_lag", {}),
    ("list_replication_conflicts", {}),
    ("get_agreement_status", {}),
]


class TestToolGuardsArchiveMode:
    """Test that guarded tools reject archive servers."""

    @pytest.mark.parametrize("tool_name,params", GUARDED_TOOLS)
    def test_guarded_tool_rejects_archive(self, archive_dirsrv_server, tool_name, params):
        from fastmcp import Client

        async def run_test():
            async with Client(archive_dirsrv_server) as client:
                call_params = dict(params)
                call_params["server_name"] = "archive-test"

                with pytest.raises(Exception) as exc_info:
                    await client.call_tool(tool_name, call_params)

                error_msg = str(exc_info.value).lower()
                assert (
                    "live" in error_msg
                    or "archive" in error_msg
                    or "running server" in error_msg
                ), f"Tool '{tool_name}' error should mention archive/live mode, got: {exc_info.value}"

        asyncio.run(run_test())
