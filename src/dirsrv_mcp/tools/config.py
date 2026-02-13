"""Configuration analysis tools for 389 Directory Server.

This module provides server configuration retrieval including:
- Retrieving server configuration from cn=config
- Comparing configurations between servers
- Listing plugins and their status
- Backend-specific configuration details

All tools fetch data dynamically without hardcoded attribute lists,
ensuring compatibility across different 389 DS versions.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set

from lib389.backend import Backends
from lib389.config import Config
from lib389.plugins import Plugins
from lib389.replica import Replicas

from src.dirsrv_mcp.connection import is_offline_or_archive
from src.dirsrv_mcp.tools.dse_utils import find_child_dns, get_all_entry_attrs, get_dse_ldif_path
from src.dirsrv_mcp.tools.error_utils import format_tool_error
from src.lib.privacy import create_privacy_error

if TYPE_CHECKING:
    from src.dirsrv_mcp.server import DirSrvMCP


def _sanitize_config_result(mcp: "DirSrvMCP", result: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitize configuration result for privacy mode."""
    if not mcp.privacy_enabled:
        return result

    sanitizer = mcp.sanitizer
    sanitized = dict(result)

    if "server" in sanitized:
        sanitized["server"] = sanitizer.sanitize_server_name(sanitized["server"])

    if "server1" in sanitized:
        sanitized["server1"] = sanitizer.sanitize_server_name(sanitized["server1"])
    if "server2" in sanitized:
        sanitized["server2"] = sanitizer.sanitize_server_name(sanitized["server2"])

    if "config" in sanitized and isinstance(sanitized["config"], dict):
        sanitized["config"] = {
            attr: "[REDACTED]" for attr in sanitized["config"].keys()
        }

    if "differences" in sanitized and isinstance(sanitized["differences"], list):
        sanitized["differences"] = [
            {
                "attribute": d.get("attribute"),
                sanitized.get("server1", "server1"): "[REDACTED]",
                sanitized.get("server2", "server2"): "[REDACTED]",
            }
            for d in sanitized["differences"]
        ]

    if "plugins" in sanitized and isinstance(sanitized["plugins"], list):
        for plugin in sanitized["plugins"]:
            if "path" in plugin:
                plugin["path"] = "[path]"

    if "backends" in sanitized and isinstance(sanitized["backends"], list):
        sanitized["backends"] = [
            _sanitize_backend(sanitizer, b) for b in sanitized["backends"]
        ]

    return sanitized


def _sanitize_backend(sanitizer, backend: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitize a backend configuration."""
    result = {}
    for key, value in backend.items():
        if key == "name":
            result[key] = "[backend]"
        elif key == "suffix":
            result[key] = sanitizer.sanitize_suffix(value)
        elif key == "config" and isinstance(value, dict):
            # Redact all config values
            result[key] = {attr: "[REDACTED]" for attr in value.keys()}
        elif key == "statistics" and isinstance(value, dict):
            # Keep statistics as they're numeric/diagnostic
            result[key] = value
        elif key == "replication" and isinstance(value, dict):
            # Keep replication status but sanitize role details
            result[key] = {
                "enabled": value.get("enabled"),
                "role": value.get("role"),
            }
        else:
            result[key] = value
    return result


def _parse_plugin_entry(plugin) -> Dict[str, Any]:
    """Parse a plugin entry into a dictionary."""
    return {
        "name": plugin.get_attr_val_utf8("cn"),
        "enabled": plugin.get_attr_val_utf8("nsslapd-pluginEnabled"),
        "type": plugin.get_attr_val_utf8("nsslapd-pluginType"),
        "path": plugin.get_attr_val_utf8("nsslapd-pluginPath"),
        "vendor": plugin.get_attr_val_utf8("nsslapd-pluginVendor"),
        "version": plugin.get_attr_val_utf8("nsslapd-pluginVersion"),
        "description": plugin.get_attr_val_utf8("nsslapd-pluginDescription"),
    }


_get_dse_ldif_path = get_dse_ldif_path
_find_child_dns = find_child_dns
_get_all_entry_attrs = get_all_entry_attrs


def _get_all_config_attrs(ds, is_offline_archive: bool) -> Dict[str, Any]:
    """Get all cn=config attributes from live server or dse.ldif.

    Returns dict of {attr_name: values} compatible with Config.get_all_attrs().
    """
    if is_offline_archive:
        from lib389.dseldif import DSEldif
        dse_path = _get_dse_ldif_path(ds)
        dse = DSEldif(ds, path=dse_path)
        return _get_all_entry_attrs(dse, "cn=config")
    else:
        config_obj = Config(ds)
        return config_obj.get_all_attrs()


def _list_plugins_offline(ds, enabled_only: bool = True) -> List[Dict[str, Any]]:
    """List plugins from dse.ldif using DSEldif."""
    from lib389.dseldif import DSEldif
    dse_path = _get_dse_ldif_path(ds)
    dse = DSEldif(ds, path=dse_path)

    plugins_dn = "cn=plugins,cn=config"
    plugin_dns = _find_child_dns(dse, plugins_dn)

    plugin_list: List[Dict[str, Any]] = []
    for plugin_dn in plugin_dns:
        plugin_data = {
            "name": dse.get(plugin_dn, "cn", single=True),
            "enabled": dse.get(plugin_dn, "nsslapd-pluginEnabled", single=True),
            "type": dse.get(plugin_dn, "nsslapd-pluginType", single=True),
            "path": dse.get(plugin_dn, "nsslapd-pluginPath", single=True),
            "vendor": dse.get(plugin_dn, "nsslapd-pluginVendor", single=True),
            "version": dse.get(plugin_dn, "nsslapd-pluginVersion", single=True),
            "description": dse.get(plugin_dn, "nsslapd-pluginDescription", single=True),
        }

        is_enabled = (plugin_data.get("enabled") or "").lower() == "on"
        if enabled_only and not is_enabled:
            continue

        plugin_list.append(plugin_data)

    plugin_list.sort(key=lambda p: (p.get("name") or "").lower())
    return plugin_list


def _get_backends_offline(
    ds, mcp: "DirSrvMCP", target: str, backend: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Get backend configuration from dse.ldif using DSEldif."""
    from lib389.dseldif import DSEldif

    dse_path = _get_dse_ldif_path(ds)
    dse = DSEldif(ds, path=dse_path)

    # Build replica suffix map by scanning for replica DNs
    replica_map: Dict[str, str] = {}
    for line in dse._contents:
        if not line.startswith("dn: ") or "cn=replica" not in line:
            continue
        replica_dn = line[4:].rstrip("\n")
        suffix = dse.get(replica_dn, "nsds5replicaroot", single=True)
        if suffix:
            rtype = dse.get(replica_dn, "nsds5replicatype", single=True)
            role_map = {"3": "supplier", "2": "hub", "1": "consumer"}
            role = role_map.get(rtype, "unknown") if rtype else "unknown"
            replica_map[suffix.lower()] = role

    ldbm_dn = "cn=ldbm database,cn=plugins,cn=config"
    backend_dns = _find_child_dns(dse, ldbm_dn)

    backend_list: List[Dict[str, Any]] = []
    for be_dn in backend_dns:
        be_suffix = dse.get(be_dn, "nsslapd-suffix", single=True)
        if be_suffix is None:
            continue  # Not a real backend entry

        be_name = dse.get(be_dn, "cn", single=True)
        if backend and be_name and be_name.lower() != backend.lower():
            continue

        backend_data: Dict[str, Any] = {
            "name": be_name,
            "suffix": be_suffix,
        }

        # All backend config attributes from DSEldif
        be_attrs = _get_all_entry_attrs(dse, be_dn)
        be_config: Dict[str, Any] = {}
        for attr, values in be_attrs.items():
            if attr.lower() in ['dn', 'objectclass']:
                continue
            if len(values) == 1:
                be_config[attr] = values[0]
            else:
                be_config[attr] = values
        backend_data["config"] = be_config

        # Index count from DSEldif
        try:
            indexes = dse.get_indexes(be_name)
            backend_data["index_count"] = len(indexes)
        except Exception:
            pass

        # Replication info from config
        if be_suffix and be_suffix.lower() in replica_map:
            backend_data["replication"] = {
                "enabled": True,
                "role": replica_map[be_suffix.lower()],
            }
        else:
            backend_data["replication"] = {"enabled": False}

        backend_list.append(backend_data)

    return backend_list


def register_config_tools(mcp: DirSrvMCP) -> None:
    """Register configuration analysis tools with the MCP server."""

    @mcp.tool()
    def get_server_configuration(
        pattern: Optional[str] = None,
        server_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Get server configuration from cn=config.

        Dynamically fetches all configuration attributes from the server.
        No hardcoded attribute lists - works across all 389 DS versions.

        Args:
            pattern: Optional filter pattern for attribute names.
                    Examples: "nsslapd-security", "cache", "log"
                    If not specified, returns all attributes.
            server_name: Target server name. Uses default if not specified.

        Returns:
            All configuration attributes matching the pattern.
        """
        target = server_name or mcp.default_server
        if not target:
            return {
                "type": "server_configuration",
                "error": "No server configured",
            }

        ds = None
        try:
            offline_archive = is_offline_or_archive(mcp.connection_manager, target)
            ds = mcp.connection_manager.connect(target)

            # Get all attributes from cn=config (live or offline/archive)
            all_attrs = _get_all_config_attrs(ds, offline_archive)

            # Filter by pattern if specified
            config_data: Dict[str, Any] = {}
            pattern_lower = pattern.lower() if pattern else None

            for attr, values in all_attrs.items():
                if pattern_lower and pattern_lower not in attr.lower():
                    continue

                # Convert bytes to strings, handle single vs multi-valued
                if isinstance(values, list):
                    if len(values) == 1:
                        config_data[attr] = values[0].decode('utf-8') if isinstance(values[0], bytes) else str(values[0])
                    else:
                        config_data[attr] = [v.decode('utf-8') if isinstance(v, bytes) else str(v) for v in values]
                elif isinstance(values, bytes):
                    config_data[attr] = values.decode('utf-8')
                else:
                    config_data[attr] = str(values)

            result = {
                "type": "server_configuration",
                "server": target,
                "pattern": pattern,
                "attribute_count": len(config_data),
                "config": config_data,
            }
            if offline_archive:
                result["mode"] = "offline" if mcp.connection_manager.get_config(target).is_offline else "archive"

            return _sanitize_config_result(mcp, result)

        except Exception as e:
            mcp.logger.error("Error getting server configuration: %s", e)
            return _sanitize_config_result(
                mcp, format_tool_error(e, mcp, "server_configuration", server=target),
            )
        finally:
            if ds:
                try:
                    ds.close()
                except Exception:
                    pass

    @mcp.tool()
    def compare_server_configurations(
        server1: str,
        server2: str,
        pattern: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Compare configuration between two servers.

        Dynamically compares all configuration attributes found on both servers.

        Args:
            server1: First server name to compare
            server2: Second server name to compare
            pattern: Optional filter pattern for attribute names.

        Returns:
            Comparison showing differing and matching attributes.
        """
        server_names = mcp.connection_manager.get_server_names()
        if server1 not in server_names:
            return {
                "type": "config_comparison",
                "error": f"Server '{server1}' not found. Available: {', '.join(server_names)}",
            }
        if server2 not in server_names:
            return {
                "type": "config_comparison",
                "error": f"Server '{server2}' not found. Available: {', '.join(server_names)}",
            }

        ds1 = None
        ds2 = None
        try:
            offline_archive1 = is_offline_or_archive(mcp.connection_manager, server1)
            offline_archive2 = is_offline_or_archive(mcp.connection_manager, server2)
            ds1 = mcp.connection_manager.connect(server1)
            ds2 = mcp.connection_manager.connect(server2)

            # Get all attributes from both servers (live or offline/archive)
            attrs1 = _get_all_config_attrs(ds1, offline_archive1)
            attrs2 = _get_all_config_attrs(ds2, offline_archive2)

            pattern_lower = pattern.lower() if pattern else None

            def normalize_value(val):
                """Normalize attribute value for comparison."""
                if isinstance(val, list):
                    return [v.decode('utf-8') if isinstance(v, bytes) else str(v) for v in val]
                elif isinstance(val, bytes):
                    return val.decode('utf-8')
                return str(val)

            # Build value dicts
            values1: Dict[str, Any] = {}
            values2: Dict[str, Any] = {}

            for attr, val in attrs1.items():
                if pattern_lower and pattern_lower not in attr.lower():
                    continue
                values1[attr] = normalize_value(val)

            for attr, val in attrs2.items():
                if pattern_lower and pattern_lower not in attr.lower():
                    continue
                values2[attr] = normalize_value(val)

            # Find differences
            differences: List[Dict[str, Any]] = []
            only_on_server1: List[str] = []
            only_on_server2: List[str] = []
            matching_count = 0

            all_keys: Set[str] = set(values1.keys()) | set(values2.keys())

            for attr in sorted(all_keys):
                in_1 = attr in values1
                in_2 = attr in values2

                if in_1 and in_2:
                    if values1[attr] != values2[attr]:
                        differences.append({
                            "attribute": attr,
                            server1: values1[attr],
                            server2: values2[attr],
                        })
                    else:
                        matching_count += 1
                elif in_1:
                    only_on_server1.append(attr)
                else:
                    only_on_server2.append(attr)

            return _sanitize_config_result(mcp, {
                "type": "config_comparison",
                "server1": server1,
                "server2": server2,
                "pattern": pattern,
                "differences": differences,
                "only_on_server1": only_on_server1,
                "only_on_server2": only_on_server2,
                "matching_count": matching_count,
            })

        except Exception as e:
            mcp.logger.error("Error comparing configurations: %s", e)
            return _sanitize_config_result(
                mcp, format_tool_error(e, mcp, "config_comparison", server1=server1, server2=server2),
            )
        finally:
            if ds1:
                try:
                    ds1.close()
                except Exception:
                    pass
            if ds2:
                try:
                    ds2.close()
                except Exception:
                    pass

    @mcp.tool()
    def list_plugins(
        enabled_only: bool = True,
        server_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """List configured plugins.

        Args:
            enabled_only: If True, only return enabled plugins. Default True.
            server_name: Target server name. Uses default if not specified.

        Returns:
            List of plugins with name, type, enabled status, and details.
        """
        target = server_name or mcp.default_server
        if not target:
            return {
                "type": "plugin_list",
                "error": "No server configured",
            }

        ds = None
        try:
            offline_archive = is_offline_or_archive(mcp.connection_manager, target)
            ds = mcp.connection_manager.connect(target)

            if offline_archive:
                plugin_list = _list_plugins_offline(ds, enabled_only)
            else:
                plugin_list = []
                plugins = Plugins(ds)
                for plugin in plugins.list():
                    try:
                        plugin_data = _parse_plugin_entry(plugin)
                        is_enabled = plugin_data.get("enabled", "").lower() == "on"
                        if enabled_only and not is_enabled:
                            continue
                        plugin_list.append(plugin_data)
                    except Exception as e:
                        mcp.logger.debug("Error parsing plugin: %s", e)
                plugin_list.sort(key=lambda p: p.get("name", "").lower())

            result = {
                "type": "plugin_list",
                "server": target,
                "enabled_only": enabled_only,
                "count": len(plugin_list),
                "plugins": plugin_list,
            }
            if offline_archive:
                result["mode"] = "offline" if mcp.connection_manager.get_config(target).is_offline else "archive"

            return _sanitize_config_result(mcp, result)

        except Exception as e:
            mcp.logger.error("Error listing plugins: %s", e)
            return _sanitize_config_result(
                mcp, format_tool_error(e, mcp, "plugin_list", server=target),
            )
        finally:
            if ds:
                try:
                    ds.close()
                except Exception:
                    pass

    @mcp.tool()
    def get_backend_configuration(
        backend: Optional[str] = None,
        server_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Get backend-specific configuration.

        Args:
            backend: Specific backend name (e.g., 'userroot').
                    If not specified, returns all backends.
            server_name: Target server name. Uses default if not specified.

        Returns:
            Backend configuration including suffix, cache settings,
            statistics, and replication status.
        """
        target = server_name or mcp.default_server
        if not target:
            return {
                "type": "backend_configuration",
                "error": "No server configured",
            }

        ds = None
        try:
            offline_archive = is_offline_or_archive(mcp.connection_manager, target)
            ds = mcp.connection_manager.connect(target)

            if offline_archive:
                backend_list = _get_backends_offline(ds, mcp, target, backend)
            else:
                backends_obj = Backends(ds)

                # Get replica info
                replica_suffixes: Dict[str, str] = {}
                try:
                    replicas = Replicas(ds)
                    for replica in replicas.list():
                        suffix = replica.get_suffix()
                        role = replica.get_role()
                        replica_suffixes[suffix.lower()] = str(role)
                except Exception as e:
                    mcp.logger.debug("Could not get replication info: %s", e)

                backend_list = []

                for be in backends_obj.list():
                    be_name = be.get_attr_val_utf8("cn")

                    if backend and be_name.lower() != backend.lower():
                        continue

                    be_suffix = be.get_attr_val_utf8("nsslapd-suffix")

                    # Get all backend attributes dynamically
                    backend_data: Dict[str, Any] = {
                        "name": be_name,
                        "suffix": be_suffix,
                    }

                    # Get all backend config attributes
                    try:
                        all_attrs = be.get_all_attrs()
                        be_config: Dict[str, Any] = {}
                        for attr, values in all_attrs.items():
                            if attr.lower() in ['dn', 'objectclass']:
                                continue
                            if isinstance(values, list) and len(values) == 1:
                                val = values[0]
                                be_config[attr] = val.decode('utf-8') if isinstance(val, bytes) else str(val)
                            elif isinstance(values, list):
                                be_config[attr] = [v.decode('utf-8') if isinstance(v, bytes) else str(v) for v in values]
                            elif isinstance(values, bytes):
                                be_config[attr] = values.decode('utf-8')
                            else:
                                be_config[attr] = str(values)
                        backend_data["config"] = be_config
                    except Exception as e:
                        mcp.logger.debug("Error getting backend config: %s", e)

                    # Get monitor stats
                    try:
                        monitor = be.get_monitor()
                        status = monitor.get_status()
                        backend_data["statistics"] = {k: v for k, v in status.items()}
                    except Exception as e:
                        mcp.logger.debug("Error getting monitor stats: %s", e)

                    # Index count
                    try:
                        indexes = be.get_indexes()
                        backend_data["index_count"] = len(list(indexes.list()))
                    except Exception as e:
                        mcp.logger.debug("Error getting index count: %s", e)

                    # Replication status
                    if be_suffix and be_suffix.lower() in replica_suffixes:
                        backend_data["replication"] = {
                            "enabled": True,
                            "role": replica_suffixes[be_suffix.lower()],
                        }
                    else:
                        backend_data["replication"] = {"enabled": False}

                    backend_list.append(backend_data)

            if backend and not backend_list:
                return _sanitize_config_result(mcp, {
                    "type": "backend_configuration",
                    "server": target,
                    "error": f"Backend '{backend}' not found",
                })

            result = {
                "type": "backend_configuration",
                "server": target,
                "backends": backend_list,
            }
            if offline_archive:
                result["mode"] = "offline" if mcp.connection_manager.get_config(target).is_offline else "archive"

            return _sanitize_config_result(mcp, result)

        except Exception as e:
            mcp.logger.error("Error getting backend configuration: %s", e)
            return _sanitize_config_result(
                mcp, format_tool_error(e, mcp, "backend_configuration", server=target),
            )
        finally:
            if ds:
                try:
                    ds.close()
                except Exception:
                    pass
