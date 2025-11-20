from __future__ import annotations

import base64
import json
import logging
import os
from contextlib import contextmanager
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

import ldap
from fastmcp.exceptions import ResourceError, ToolError
from fastmcp.prompts import PromptMessage
from lib389.backend import Backends
from lib389.config import Config
from lib389.idm.account import Accounts
from lib389.idm.group import Groups
from lib389.idm.user import nsUserAccounts
from lib389.monitor import Monitor

from src.config.loader import load_config
from src.dirsrv_mcp.connection import ConnectionManager, ServerConfig
from src.ldap_assistant_mcp.server import LDAPAssistantMCP, LDAPServerConfig
from src.lib.datetime_utils import convert_datetimes_to_strings
from src.lib.result_formatter import Severity, format_finding

__all__ = ["DirSrvMCP"]


class DirSrvMCP(LDAPAssistantMCP):
    """FastMCP server exposing 389 Directory Server operations."""

    def __init__(
        self,
        *,
        config_path: Optional[str] = None,
        servers: Optional[Iterable[LDAPServerConfig]] = None,
        connection_manager: Optional[ConnectionManager] = None,
        name: str = "389 Directory Server MCP",
        instructions: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        self.logger = logging.getLogger(self.__class__.__name__)
        merged_servers = self._collect_servers(config_path=config_path, extra_servers=servers)

        super().__init__(
            name=name,
            instructions=instructions,
            servers=merged_servers or None,
            **kwargs,
        )

        self.connection_manager = connection_manager or ConnectionManager()
        for cfg in self.server_configs.values():
            self.connection_manager.add_server(cfg)

        self.logger.info(
            "DirSrv MCP initialized with %d server(s): %s",
            len(self.server_configs),
            ", ".join(self.server_configs.keys()),
        )

        self._register_prompts()
        self._register_tools()
        self._register_resources()

    # --------------------------------------------------------------------- #
    # Initialization helpers
    # --------------------------------------------------------------------- #

    def _collect_servers(
        self,
        *,
        config_path: Optional[str],
        extra_servers: Optional[Iterable[LDAPServerConfig]],
    ) -> List[LDAPServerConfig]:
        merged: Dict[str, LDAPServerConfig] = {}

        should_load_config = config_path or os.environ.get("LDAP_SERVERS_CONFIG")
        if should_load_config:
            try:
                config = load_config(config_file=config_path)  # type: ignore[arg-type]
            except Exception as exc:
                self.logger.warning("Failed to load multi-server config: %s", exc)
            else:
                for server in config.servers:
                    merged[server.name] = server

        if extra_servers:
            for server in extra_servers:
                merged[server.name] = server

        return list(merged.values())

    # --------------------------------------------------------------------- #
    # Registration
    # --------------------------------------------------------------------- #

    def _register_prompts(self) -> None:
        @self.prompt()
        def tool_navigator(goal: str) -> List[PromptMessage]:
            """Guide users through available tools and their usage."""

            return [
                PromptMessage(role="user", content=f"Directory task: {goal}"),
                PromptMessage(
                    role="assistant",
                    content=(
                        "Use the available MCP tools to accomplish the task. "
                        "Prefer specialized tools first, falling back to ldap_search for advanced queries.\n\n"
                        "**Health & Diagnostics:**\n"
                        "- first_look: Quick health overview across all servers.\n\n"
                        "**User Management:**\n"
                        "- list_active_users / list_locked_users / list_all_users\n"
                        "- search_users_by_name / search_users_by_attribute\n"
                        "- get_user_details\n\n"
                        "**Group Management:**\n"
                        "- list_all_groups\n\n"
                        "**Monitoring:**\n"
                        "- run_monitor\n\n"
                        "**Advanced:**\n"
                        "- ldap_search(base_dn, scope, filter, attributes, attrs_only, limit)\n\n"
                        "State which tool you'll call next and why; keep outputs concise."
                    ),
                ),
            ]

    def _register_resources(self) -> None:
        @self.resource("config://config-all")
        def get_cn_config_all_attributes() -> str:
            """Return all attributes for cn=config as JSON."""
            with self._connection() as (_, ds):
                try:
                    config_entry = Config(ds)
                    return config_entry.get_all_attrs_json()
                except Exception as exc:
                    self.logger.error("Error getting cn=config attributes: %s", exc)
                    raise ResourceError(f"Failed to retrieve cn=config attributes: {exc}") from exc

        @self.resource("config://config-attribute/{attribute}")
        def get_cn_config_attribute(attribute: str) -> Dict[str, Any]:
            """Return a specific attribute from cn=config."""
            attr_name = attribute.strip()
            with self._connection() as (_, ds):
                try:
                    config_entry = Config(ds)
                    values_list = []
                    single_value = None

                    try:
                        values_list = config_entry.get_attr_vals_utf8(attr_name)
                    except Exception:
                        values_list = []

                    try:
                        single_value = config_entry.get_attr_val_utf8(attr_name)
                    except Exception:
                        single_value = None

                    return {
                        "type": "cn_config_attribute",
                        "attribute": attr_name,
                        "values": values_list if isinstance(values_list, list) else [],
                        "value": single_value,
                    }
                except Exception as exc:
                    self.logger.error("Error getting cn=config attribute '%s': %s", attribute, exc)
                    raise ResourceError(
                        f"Failed to retrieve cn=config attribute '{attribute}': {exc}"
                    ) from exc

    def _register_tools(self) -> None:
        self._register_health_tools()
        self._register_user_tools()
        self._register_group_tools()
        self._register_monitoring_tools()
        self._register_search_tools()

    # --------------------------------------------------------------------- #
    # Tool registration helpers
    # --------------------------------------------------------------------- #

    def _register_health_tools(self) -> None:
        @self.tool()
        def first_look() -> Dict[str, Any]:
            """Quick health overview across all configured LDAP servers."""
            server_names = self.connection_manager.get_server_names()

            if not server_names:
                return {
                    "type": "first_look",
                    "summary": "No servers configured",
                    "critical_count": 1,
                    "high_count": 0,
                    "medium_count": 0,
                    "low_count": 0,
                    "info_count": 0,
                    "findings": [
                        format_finding(
                            title="No LDAP Servers Configured",
                            severity=Severity.CRITICAL,
                            impact="Cannot perform any directory operations",
                            details=(
                                "The LDAP Assistant has no servers configured. "
                                "Configure at least one server via environment variables "
                                "or the JSON configuration file."
                            ),
                            remediation=(
                                "1. Set LDAP_URL, LDAP_BASE_DN, LDAP_BIND_DN, "
                                "LDAP_BIND_PASSWORD for single-server mode\n"
                                "2. Or provide a servers.json file via LDAP_SERVERS_CONFIG"
                            ),
                        )
                    ],
                    "servers_checked": [],
                    "servers_failed": [],
                }

            findings: List[Dict[str, Any]] = []
            servers_checked: List[str] = []
            servers_failed: List[str] = []

            for server_name in server_names:
                ds = None
                try:
                    config = self.connection_manager.get_config(server_name)
                    ds = self.connection_manager.connect(server_name)
                    servers_checked.append(server_name)
                    self._check_server_health(ds, server_name, config, findings)
                except Exception as exc:
                    servers_failed.append(server_name)
                    severity = Severity.CRITICAL if "connect" in str(exc).lower() else Severity.HIGH
                    findings.append(
                        format_finding(
                            title=f"Server Check Failed: {server_name}",
                            severity=severity,
                            impact=f"Unable to complete health check for {server_name}",
                            details=str(exc),
                            remediation="Verify server connectivity and credentials",
                            server=server_name,
                        )
                    )
                finally:
                    if ds is not None:
                        try:
                            ds.close()
                        except Exception:
                            pass

            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            for finding in findings:
                severity = finding.get("severity", "info")
                if severity in severity_counts:
                    severity_counts[severity] += 1

            total_issues = sum(severity_counts.values())
            if severity_counts["critical"] > 0:
                summary = (
                    f"CRITICAL: {severity_counts['critical']} critical issue(s) found "
                    f"across {len(server_names)} servers"
                )
            elif severity_counts["high"] > 0:
                summary = f"WARNING: {severity_counts['high']} high-priority issue(s) found"
            elif total_issues > 0:
                summary = f"OK: {total_issues} minor issue(s) found"
            else:
                summary = f"HEALTHY: All {len(servers_checked)} servers are operating normally"

            result = {
                "type": "first_look",
                "summary": summary,
                "critical_count": severity_counts["critical"],
                "high_count": severity_counts["high"],
                "medium_count": severity_counts["medium"],
                "low_count": severity_counts["low"],
                "info_count": severity_counts["info"],
                "findings": findings,
                "servers_checked": servers_checked,
                "servers_failed": servers_failed,
                "total_servers": len(server_names),
            }

            self.logger.info("first_look completed: %s", summary)
            return result

    def _register_user_tools(self) -> None:
        @self.tool()
        def list_all_users(limit: int = 50, server_name: Optional[str] = None) -> Dict[str, Any]:
            """List users in the directory with computed status."""
            target = server_name or self.default_server
            with self._connection(target) as (name, ds):
                base_dn = self._get_base_dn(name)
                users = nsUserAccounts(ds, base_dn)
                results = self._collect_entries(users.list(), ds, base_dn, limit)
                return {
                    "type": "user_list",
                    "server": name,
                    "total_returned": len(results),
                    "limit_applied": limit,
                    "items": results,
                }

        @self.tool()
        def search_users_by_name(
            name: str, limit: int = 50, server_name: Optional[str] = None
        ) -> Dict[str, Any]:
            """Search for users by name (uid, cn, givenName, sn, displayName, mail)."""
            target = server_name or self.default_server
            with self._connection(target) as (srv, ds):
                base_dn = self._get_base_dn(srv)
                if "*" in name:
                    search_filter = (
                        f"(|(uid={name})(cn={name})(givenName={name})(sn={name})"
                        f"(displayName={name})(mail={name}))"
                    )
                else:
                    search_filter = (
                        f"(|(uid=*{name}*)(cn=*{name}*)(givenName=*{name}*)(sn=*{name}*)"
                        f"(displayName=*{name}*)(mail=*{name}*))"
                    )
                users = nsUserAccounts(ds, base_dn)
                results = self._collect_entries(users.filter(search_filter), ds, base_dn, limit)
                return {
                    "type": "user_search",
                    "server": srv,
                    "search_term": name,
                    "filter_used": search_filter,
                    "total_returned": len(results),
                    "limit_applied": limit,
                    "items": results,
                }

        @self.tool()
        def get_user_details(username: str, server_name: Optional[str] = None) -> Dict[str, Any]:
            """Get detailed information about a specific user."""
            target = server_name or self.default_server
            with self._connection(target) as (srv, ds):
                base_dn = self._get_base_dn(srv)
                users = nsUserAccounts(ds, base_dn)
                user = users.get(username)
                record = self._build_user_record(user, ds, base_dn)
                return {"type": "user_details", "server": srv, "username": username, "user": record}

        @self.tool()
        def list_active_users(limit: int = 50, server_name: Optional[str] = None) -> Dict[str, Any]:
            """List active (unlocked) users."""
            target = server_name or self.default_server
            with self._connection(target) as (srv, ds):
                base_dn = self._get_base_dn(srv)
                users = nsUserAccounts(ds, base_dn)
                records = self._collect_filtered_users(
                    users.list(), ds, base_dn, limit, desired_status="active"
                )
                return {
                    "type": "active_users",
                    "server": srv,
                    "active_users_found": len(records),
                    "limit_applied": limit,
                    "items": records,
                }

        @self.tool()
        def list_locked_users(limit: int = 50, server_name: Optional[str] = None) -> Dict[str, Any]:
            """List locked users."""
            target = server_name or self.default_server
            with self._connection(target) as (srv, ds):
                base_dn = self._get_base_dn(srv)
                users = nsUserAccounts(ds, base_dn)
                records = self._collect_filtered_users(
                    users.list(), ds, base_dn, limit, desired_status="locked"
                )
                return {
                    "type": "locked_users",
                    "server": srv,
                    "locked_users_found": len(records),
                    "limit_applied": limit,
                    "items": records,
                }

        @self.tool()
        def search_users_by_attribute(
            attribute: str, value: str, limit: int = 50, server_name: Optional[str] = None
        ) -> Dict[str, Any]:
            """Search for users by arbitrary attribute."""
            target = server_name or self.default_server
            with self._connection(target) as (srv, ds):
                base_dn = self._get_base_dn(srv)
                search_filter = f"({attribute}={value})" if "*" in value else f"({attribute}=*{value}*)"
                users = nsUserAccounts(ds, base_dn)
                results = self._collect_entries(users.filter(search_filter), ds, base_dn, limit)
                return {
                    "type": "attribute_search",
                    "server": srv,
                    "attribute": attribute,
                    "value": value,
                    "filter_used": search_filter,
                    "total_returned": len(results),
                    "limit_applied": limit,
                    "items": results,
                }

    def _register_group_tools(self) -> None:
        @self.tool()
        def list_all_groups(limit: int = 50, server_name: Optional[str] = None) -> Dict[str, Any]:
            """List directory groups."""
            target = server_name or self.default_server
            with self._connection(target) as (srv, ds):
                base_dn = self._get_base_dn(srv)
                groups = Groups(ds, base_dn)
                results = []
                count = 0
                for group in groups.list():
                    if count >= limit:
                        break
                    try:
                        group_data = json.loads(group.get_all_attrs_json())
                        if "attrs" in group_data:
                            group_data["attrs"] = convert_datetimes_to_strings(group_data["attrs"])
                        results.append(group_data)
                        count += 1
                    except Exception as exc:
                        self.logger.error("Error processing group: %s", exc)
                        continue

                return {
                    "type": "group_list",
                    "server": srv,
                    "total_returned": len(results),
                    "limit_applied": limit,
                    "items": results,
                }

    def _register_monitoring_tools(self) -> None:
        @self.tool()
        def run_monitor(
            backend: str = "", suffix: str = "", server_name: Optional[str] = None
        ) -> Dict[str, Any]:
            """Return server or backend monitor information."""
            target = server_name or self.default_server
            with self._connection(target) as (srv, ds):
                try:
                    if backend or suffix:
                        bes = Backends(ds)
                        be = bes.get(backend or suffix)
                        monitor = be.get_monitor()
                    else:
                        monitor = Monitor(ds)
                    data_json = monitor.get_all_attrs_json()
                    result = json.loads(data_json)
                    return {
                        "type": "monitor",
                        "server": srv,
                        "backend": backend or suffix or "main",
                        "item": result,
                    }
                except Exception as exc:
                    self.logger.error("Error accessing monitor on %s: %s", srv, exc)
                    raise ToolError(f"Error accessing monitor on {srv}: {exc}") from exc

    def _register_search_tools(self) -> None:
        @self.tool()
        def ldap_search(
            base_dn: str,
            scope: str = "SUBTREE",
            filter: str = "(objectClass=*)",
            attributes: Optional[str] = None,
            attrs_only: bool = False,
            limit: int = 100,
            server_name: Optional[str] = None,
        ) -> Dict[str, Any]:
            """Perform a generic LDAP search."""
            target = str(server_name) if server_name is not None else self.default_server
            with self._connection(target) as (srv, ds):
                try:
                    base_dn_value = str(base_dn)
                    filter_value = str(filter)
                    original_scope = str(scope).upper()
                    attributes_value = None if attributes is None else str(attributes)
                    attrs_only_flag = bool(attrs_only)
                    limit_value = int(limit)

                    scope_map = {
                        "BASE": ldap.SCOPE_BASE,
                        "ONELEVEL": ldap.SCOPE_ONELEVEL,
                        "SUBTREE": ldap.SCOPE_SUBTREE,
                    }
                    if original_scope not in scope_map:
                        raise ToolError(
                            "Invalid scope. Must be one of: BASE, ONELEVEL, SUBTREE"
                        )

                    capped_limit = max(1, min(limit_value, 1000))
                    attrlist = None
                    if attributes_value:
                        cleaned = attributes_value.strip()
                        if cleaned in {"*", "+", "*,+", "+,*"}:
                            attrlist = cleaned.split(",")
                        else:
                            attrlist = [
                                attr.strip() for attr in cleaned.split(",") if attr.strip()
                            ]

                    try:
                        search_results = ds.search_s(
                            base_dn_value,
                            scope_map[original_scope],
                            filter_value,
                            attrlist=attrlist,
                            attrsonly=1 if attrs_only_flag else 0,
                        )
                    except ldap.NO_SUCH_OBJECT:
                        raise ToolError(f"Base DN '{base_dn_value}' does not exist") from None
                    except ldap.INVALID_SYNTAX as exc:
                        raise ToolError(f"Invalid LDAP filter syntax: {exc}") from exc
                    except ldap.LDAPError as exc:
                        raise ToolError(f"LDAP search failed: {exc}") from exc

                    results = []
                    for item in search_results:
                        if len(results) >= capped_limit:
                            break
                        if isinstance(item, tuple) and len(item) == 2:
                            dn, attrs = item
                        else:
                            dn = getattr(item, "dn", None)
                            attrs = getattr(item, "data", None)
                        if not dn or attrs is None:
                            continue
                        attrs_out: Dict[str, List[str]] = {}
                        attr_items = attrs.items() if hasattr(attrs, "items") else []
                        for attr_name, attr_values in attr_items:
                            values_iter = (
                                attr_values
                                if isinstance(attr_values, (list, tuple))
                                else [attr_values]
                            )
                            converted_values = []
                            for val in values_iter:
                                if isinstance(val, bytes):
                                    try:
                                        converted_values.append(val.decode("utf-8"))
                                    except UnicodeDecodeError:
                                        converted_values.append(
                                            base64.b64encode(val).decode("ascii")
                                        )
                                else:
                                    converted_values.append(str(val))
                            attrs_out[attr_name] = converted_values
                        results.append({"dn": dn, "attrs": attrs_out})

                    return {
                        "type": "ldap_search",
                        "server": srv,
                        "base_dn": base_dn_value,
                        "scope": original_scope,
                        "filter": filter_value,
                        "attributes_requested": attributes_value or "all",
                        "attrs_only": attrs_only_flag,
                        "total_returned": len(results),
                        "limit_applied": capped_limit,
                        "items": results,
                    }
                except AttributeError as exc:
                    self.logger.exception(
                        "ldap_search AttributeError (base_dn=%r, scope=%r, filter=%r, "
                        "attributes=%r, attrs_only=%r, limit=%r)",
                        base_dn,
                        scope,
                        filter,
                        attributes,
                        attrs_only,
                        limit,
                    )
                    raise ToolError(
                        f"Unexpected internal attribute error in ldap_search: {exc}"
                    ) from exc

    # --------------------------------------------------------------------- #
    # Helper methods
    # --------------------------------------------------------------------- #

    @contextmanager
    def _connection(self, server_name: Optional[str] = None) -> Iterator[Tuple[str, Any]]:
        target = server_name or getattr(self, "default_server", None)
        if not target:
            raise ToolError("No LDAP server configured")
        ds = self.connection_manager.connect(target)
        try:
            yield target, ds
        finally:
            try:
                ds.close()
            except Exception:
                pass

    def _get_base_dn(self, server_name: str) -> str:
        config = self.get_server_config(server_name)
        if not config.base_dn:
            raise ToolError(f"Server '{server_name}' does not have a base DN configured")
        return config.base_dn

    def _collect_entries(
        self,
        entries: Iterable[Any],
        ds,
        base_dn: str,
        limit: int,
        include_all: bool = False,
    ) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        count = 0
        for entry in entries:
            if not include_all and count >= limit:
                break
            try:
                record = self._build_user_record(entry, ds, base_dn)
                results.append(record)
                count += 1
            except Exception as exc:
                self.logger.error("Error processing entry: %s", exc)
                continue
        return results

    def _build_user_record(self, entry, ds, base_dn: str) -> Dict[str, Any]:
        data = json.loads(entry.get_all_attrs_json())
        if "attrs" in data and isinstance(data["attrs"], dict):
            data["attrs"] = convert_datetimes_to_strings(data["attrs"])
        else:
            data["attrs"] = {}

        user_dn = data.get("dn", "")
        data["attrs"]["computed_status"] = self._get_user_status(ds, user_dn, base_dn)
        return data

    def _collect_filtered_users(
        self,
        entries: Iterable[Any],
        ds,
        base_dn: str,
        limit: int,
        *,
        desired_status: str,
    ) -> List[Dict[str, Any]]:
        records: List[Dict[str, Any]] = []
        for entry in entries:
            if len(records) >= limit:
                break
            try:
                record = self._build_user_record(entry, ds, base_dn)
            except Exception as exc:
                self.logger.error("Error processing entry: %s", exc)
                continue
            status = record["attrs"].get("computed_status", {}).get("simple_status")
            if status == desired_status:
                records.append(record)
        return records

    def _get_user_status(self, ds, user_dn: str, basedn: str) -> Dict[str, Any]:
        try:
            accounts = Accounts(ds, basedn)
            acct = accounts.get(dn=user_dn)
            status_data = acct.status()
            account_state = status_data.get("state", "unknown")
            params = convert_datetimes_to_strings(status_data.get("params", {}))
            calc_time = status_data.get("calc_time")
            calc_time_str = calc_time.isoformat() if hasattr(calc_time, "isoformat") else calc_time

            state_name = (
                account_state.name
                if hasattr(account_state, "name")
                else account_state.value
                if hasattr(account_state, "value")
                else str(account_state)
            )

            if state_name in {"DIRECTLY_LOCKED", "INDIRECTLY_LOCKED"}:
                simple_status = "locked"
            elif state_name == "INACTIVITY_LIMIT_EXCEEDED":
                simple_status = "inactive"
            elif state_name == "ACTIVATED":
                simple_status = "active"
            else:
                simple_status = "unknown"

            return {
                "simple_status": simple_status,
                "detailed_status": state_name,
                "status_params": params,
                "calc_time": calc_time_str,
            }
        except Exception as exc:
            self.logger.warning("Error getting status for %s: %s", user_dn, exc)
            return {
                "simple_status": "unknown",
                "detailed_status": f"error: {exc}",
                "status_params": {},
                "calc_time": None,
            }

    def _check_server_health(
        self,
        ds,
        server_name: str,
        config: ServerConfig,
        findings: List[Dict[str, Any]],
    ) -> None:
        try:
            monitor = Monitor(ds)
            monitor_data = monitor.get_all_attrs()
            self._check_connection_limits(monitor_data, server_name, findings)
            self._check_threads(monitor_data, server_name, findings)
            findings.append(
                format_finding(
                    title=f"Server {server_name} is operational",
                    severity=Severity.INFO,
                    impact="Server is responding to queries",
                    details=f"Successfully connected and retrieved monitor data from {config.ldap_url}",
                    remediation="No action needed",
                    server=server_name,
                )
            )
        except Exception as exc:
            self.logger.warning("Error checking server health for %s: %s", server_name, exc)
            findings.append(
                format_finding(
                    title=f"Partial Health Check Failure: {server_name}",
                    severity=Severity.MEDIUM,
                    impact="Unable to retrieve complete health information",
                    details=f"Connected successfully but failed to retrieve monitor data: {exc}",
                    remediation="Check server logs and verify monitoring endpoints are accessible",
                    server=server_name,
                )
            )

    def _check_connection_limits(
        self, monitor_data: Dict[str, Any], server_name: str, findings: List[Dict[str, Any]]
    ) -> None:
        try:
            current_conns = int(monitor_data.get("currentconnections", [0])[0])
            max_conns = int(monitor_data.get("maxconnections", [0])[0])
            if max_conns <= 0:
                return
            utilization = (current_conns / max_conns) * 100
            if utilization >= 90:
                severity = Severity.CRITICAL
                title = f"Connection Limit Critical: {server_name}"
            elif utilization >= 75:
                severity = Severity.HIGH
                title = f"Connection Limit Warning: {server_name}"
            else:
                return
            findings.append(
                format_finding(
                    title=title,
                    severity=severity,
                    impact="Server approaching maximum connections",
                    details=f"Current connections: {current_conns} / {max_conns} ({utilization:.1f}% utilization)",
                    remediation="Review connection usage and increase limits if necessary",
                    server=server_name,
                    metadata={
                        "current": current_conns,
                        "max": max_conns,
                        "utilization": utilization,
                    },
                )
            )
        except (KeyError, ValueError, IndexError):
            self.logger.debug("Could not check connection limits for %s", server_name)

    def _check_threads(
        self, monitor_data: Dict[str, Any], server_name: str, findings: List[Dict[str, Any]]
    ) -> None:
        try:
            threads = int(monitor_data.get("threads", [0])[0])
            if 0 < threads < 5:
                findings.append(
                    format_finding(
                        title=f"Low Thread Count: {server_name}",
                        severity=Severity.MEDIUM,
                        impact="Server may have reduced capacity to handle concurrent requests",
                        details=f"Only {threads} worker threads active",
                        remediation="Check server configuration and resource availability (CPU, memory)",
                        server=server_name,
                        metadata={"threads": threads},
                    )
                )
        except (KeyError, ValueError, IndexError):
            self.logger.debug("Could not check threads for %s", server_name)

