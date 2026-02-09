"""389 Directory Server MCP server implementation."""

from __future__ import annotations

import logging
import os
from contextlib import contextmanager
from pathlib import Path
import sys
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

from fastmcp.exceptions import ResourceError, ToolError
from fastmcp.prompts import PromptMessage
from mcp.types import TextContent
from lib389.config import Config

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    # Ensure imports like `src.*` work when this file is executed directly.
    sys.path.insert(0, str(PROJECT_ROOT))

from src.config.loader import load_config
from src.dirsrv_mcp.connection import ConnectionManager, ServerConfig
from src.dirsrv_mcp.tools import (
    register_config_tools,
    register_group_tools,
    register_health_tools,
    register_index_tools,
    register_monitoring_tools,
    register_performance_tools,
    register_replication_tools,
    register_search_tools,
    register_user_tools,
)
from src.ldap_assistant_mcp.server import LDAPAssistantMCP, LDAPServerConfig, MCPSettings
from src.lib.privacy import PrivacySanitizer, get_sanitizer

__all__ = ["DirSrvMCP"]


class DirSrvMCP(LDAPAssistantMCP):
    """FastMCP server exposing 389 Directory Server operations."""

    def __init__(
        self,
        *,
        config_path: Optional[str] = None,
        servers: Optional[Iterable[LDAPServerConfig]] = None,
        connection_manager: Optional[ConnectionManager] = None,
        settings: Optional[MCPSettings] = None,
        name: str = "389ds-mcp",
        instructions: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        self.logger = logging.getLogger(self.__class__.__name__)
        merged_servers, loaded_settings = self._collect_servers_and_settings(
            config_path=config_path, extra_servers=servers
        )

        super().__init__(
            name=name,
            instructions=instructions,
            servers=merged_servers or None,
            **kwargs,
        )

        # Use provided settings, loaded settings, or defaults
        # Note: We use _mcp_settings to avoid conflict with FastMCP's settings property
        self._mcp_settings = settings or loaded_settings or MCPSettings.from_env()
        self._sanitizer = get_sanitizer()

        self.connection_manager = connection_manager or ConnectionManager()
        for cfg in self.server_configs.values():
            self.connection_manager.add_server(cfg)

        self.logger.info(
            "DirSrv MCP initialized with %d server(s): %s (privacy_mode=%s)",
            len(self.server_configs),
            ", ".join(self.server_configs.keys()),
            not self._mcp_settings.expose_sensitive_data,
        )

        self._register_prompts()
        self._register_tools()
        self._register_resources()

    @property
    def privacy_enabled(self) -> bool:
        """Return True if privacy mode is enabled (sensitive data is redacted)."""
        return not self._mcp_settings.expose_sensitive_data

    @property
    def sanitizer(self) -> PrivacySanitizer:
        """Return the privacy sanitizer instance."""
        return self._sanitizer

    # --------------------------------------------------------------------- #
    # Initialization helpers
    # --------------------------------------------------------------------- #

    def _collect_servers_and_settings(
        self,
        *,
        config_path: Optional[str],
        extra_servers: Optional[Iterable[LDAPServerConfig]],
    ) -> Tuple[List[LDAPServerConfig], Optional[MCPSettings]]:
        """Collect server configurations and settings from config file.

        Returns:
            Tuple of (server list, settings or None if not loaded from config)
        """
        merged: Dict[str, LDAPServerConfig] = {}
        loaded_settings: Optional[MCPSettings] = None

        should_load_config = config_path or os.environ.get("LDAP_SERVERS_CONFIG")
        if should_load_config:
            try:
                config = load_config(config_file=config_path)  # type: ignore[arg-type]
            except Exception as exc:
                self.logger.warning("Failed to load multi-server config: %s", exc)
            else:
                for server in config.servers:
                    merged[server.name] = server
                loaded_settings = config.settings

        if extra_servers:
            for server in extra_servers:
                merged[server.name] = server

        return list(merged.values()), loaded_settings

    # --------------------------------------------------------------------- #
    # Registration
    # --------------------------------------------------------------------- #

    def _register_prompts(self) -> None:
        @self.prompt()
        def tool_navigator(goal: str) -> List[PromptMessage]:
            """Guide users through available tools and their usage."""

            return [
                PromptMessage(role="user", content=TextContent(type="text", text=f"Directory task: {goal}")),
                PromptMessage(
                    role="assistant",
                    content=TextContent(
                        type="text",
                        text=(
                            "Use the available MCP tools to accomplish the task. "
                            "Prefer specialized tools first, falling back to ldap_search for advanced queries.\n\n"
                            "**Health & Diagnostics:**\n"
                            "- first_look: Comprehensive health overview across all servers.\n"
                            "- run_healthcheck: Deep health checks with lint rules.\n\n"
                            "**Performance:**\n"
                            "- get_performance_summary: Combined performance overview.\n"
                            "- get_cache_statistics: Entry/DN/DB cache analysis.\n"
                            "- get_connection_statistics: Connection patterns and FD usage.\n"
                            "- get_operation_statistics: Operation counts by type.\n"
                            "- get_thread_statistics: Thread pool utilization.\n"
                            "- get_resource_utilization: Memory, CPU, disk usage.\n\n"
                            "**Replication:**\n"
                            "- get_replication_status: Comprehensive replica and agreement status.\n"
                            "- get_replication_topology: Map topology across all servers.\n"
                            "- check_replication_lag: Analyze sync status and CSN lag.\n"
                            "- list_replication_conflicts: Find conflict and glue entries.\n"
                            "- get_agreement_status: Detailed agreement information.\n\n"
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
                ),
            ]

        @self.prompt()
        def diagnose_replication() -> List[PromptMessage]:
            """Start a guided replication troubleshooting session."""

            return [
                PromptMessage(
                    role="user",
                    content=TextContent(type="text", text="I need help diagnosing replication issues in my directory."),
                ),
                PromptMessage(
                    role="assistant",
                    content=TextContent(
                        type="text",
                        text=(
                            "I'll help you diagnose replication issues. Let me perform a systematic analysis:\n\n"
                            "**Step 1: Check replication topology and agreement status**\n"
                            "I'll use `get_replication_status` to get an overview of all replicas and agreements.\n\n"
                            "**Step 2: Look for replication conflicts**\n"
                            "I'll use `list_replication_conflicts` to find any conflict or glue entries that need resolution.\n\n"
                            "**Step 3: Analyze replication lag**\n"
                            "I'll use `check_replication_lag` to identify any sync delays between servers.\n\n"
                            "**Step 4: Examine specific agreements if needed**\n"
                            "I'll use `get_agreement_status` to dive deeper into any problematic agreements.\n\n"
                            "Let me start by getting the replication status across your servers..."
                        ),
                    ),
                ),
            ]

        @self.prompt()
        def performance_investigation() -> List[PromptMessage]:
            """Start a guided performance troubleshooting session."""

            return [
                PromptMessage(
                    role="user",
                    content=TextContent(type="text", text="I need help investigating performance issues with my directory server."),
                ),
                PromptMessage(
                    role="assistant",
                    content=TextContent(
                        type="text",
                        text=(
                            "I'll help investigate performance issues. Here's my systematic approach:\n\n"
                            "**Step 1: Get performance overview**\n"
                            "I'll use `get_performance_summary` for a quick view of key metrics and any obvious issues.\n\n"
                            "**Step 2: Check connection and operation load**\n"
                            "I'll use `get_connection_statistics` and `get_operation_statistics` to understand the workload.\n\n"
                            "**Step 3: Analyze cache efficiency**\n"
                            "I'll use `get_cache_statistics` to check if cache sizes are adequate - low hit ratios cause disk I/O.\n\n"
                            "**Step 4: Check thread utilization**\n"
                            "I'll use `get_thread_statistics` to identify thread pool contention.\n\n"
                            "**Step 5: Review resource usage**\n"
                            "I'll use `get_resource_utilization` to check memory, CPU, and disk space.\n\n"
                            "Let me start by getting a performance summary..."
                        ),
                    ),
                ),
            ]

        @self.prompt()
        def daily_health_check() -> List[PromptMessage]:
            """Perform a comprehensive daily health check suitable for operations review."""

            return [
                PromptMessage(
                    role="user",
                    content=TextContent(type="text", text="Please perform a daily health check of my directory infrastructure."),
                ),
                PromptMessage(
                    role="assistant",
                    content=TextContent(
                        type="text",
                        text=(
                            "I'll perform a comprehensive daily health check covering all critical areas:\n\n"
                            "**1. Overall Health Assessment**\n"
                            "I'll use `first_look` to get a complete health overview including:\n"
                            "- Server connectivity\n"
                            "- Connection/thread utilization\n"
                            "- Replication status\n"
                            "- Cache efficiency\n"
                            "- Disk space\n"
                            "- Certificate expiration\n\n"
                            "**2. Detailed Health Checks**\n"
                            "I'll use `run_healthcheck` to run the full lint suite for configuration issues.\n\n"
                            "**3. Replication Verification** (if applicable)\n"
                            "I'll check for any replication lag or conflicts.\n\n"
                            "**4. Performance Baseline**\n"
                            "I'll capture current performance metrics for trending.\n\n"
                            "Let me start with the comprehensive health overview..."
                        ),
                    ),
                ),
            ]

        @self.prompt()
        def troubleshoot_connectivity() -> List[PromptMessage]:
            """Start a guided session to troubleshoot connection issues."""

            return [
                PromptMessage(
                    role="user",
                    content=TextContent(type="text", text="I'm having trouble connecting to my directory server or clients are reporting connection issues."),
                ),
                PromptMessage(
                    role="assistant",
                    content=TextContent(
                        type="text",
                        text=(
                            "I'll help troubleshoot connectivity issues. Let me check several areas:\n\n"
                            "**Step 1: Basic connectivity check**\n"
                            "I'll use `first_look` to verify server accessibility and basic health.\n\n"
                            "**Step 2: Connection capacity analysis**\n"
                            "I'll use `get_connection_statistics` to check:\n"
                            "- Current connection count vs. limits\n"
                            "- File descriptor utilization\n"
                            "- Connection states (CLOSE_WAIT can indicate client issues)\n\n"
                            "**Step 3: Thread availability**\n"
                            "I'll use `get_thread_statistics` to see if thread exhaustion is causing connection issues.\n\n"
                            "**Step 4: Resource constraints**\n"
                            "I'll use `get_resource_utilization` to check for resource exhaustion.\n\n"
                            "Let me start by checking basic connectivity..."
                        ),
                    ),
                ),
            ]

    def _register_resources(self) -> None:
        @self.resource("config://config-all")
        def get_cn_config_all_attributes() -> str:
            """Return all attributes for cn=config as JSON.

            Note: In privacy mode (default), sensitive values like hostnames,
            paths, and suffixes are redacted.
            """
            import json as _json

            with self._connection() as (_, ds):
                try:
                    config_entry = Config(ds)
                    raw_json = config_entry.get_all_attrs_json()

                    if not self.privacy_enabled:
                        return raw_json

                    # Sanitize in privacy mode
                    data = _json.loads(raw_json)
                    sanitized = self._sanitizer.sanitize_dict(data)
                    return _json.dumps(sanitized, indent=2)
                except Exception as exc:
                    self.logger.error("Error getting cn=config attributes: %s", exc)
                    raise ResourceError(f"Failed to retrieve cn=config attributes: {exc}") from exc

        @self.resource("config://config-attribute/{attribute}")
        def get_cn_config_attribute(attribute: str) -> Dict[str, Any]:
            """Return a specific attribute from cn=config.

            Note: In privacy mode (default), sensitive values like hostnames,
            paths, and suffixes are redacted.
            """
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

                    result = {
                        "type": "cn_config_attribute",
                        "attribute": attr_name,
                        "values": values_list if isinstance(values_list, list) else [],
                        "value": single_value,
                    }

                    if self.privacy_enabled:
                        # Sanitize the attribute values based on attribute name
                        result["values"] = [
                            self._sanitizer.sanitize_attribute_value(attr_name, v)
                            for v in result["values"]
                        ]
                        if result["value"] is not None:
                            result["value"] = self._sanitizer.sanitize_attribute_value(
                                attr_name, result["value"]
                            )

                    return result
                except Exception as exc:
                    self.logger.error("Error getting cn=config attribute '%s': %s", attribute, exc)
                    raise ResourceError(
                        f"Failed to retrieve cn=config attribute '{attribute}': {exc}"
                    ) from exc

    def _register_tools(self) -> None:
        """Register all tools from modular tool files."""
        register_health_tools(self)
        register_user_tools(self)
        register_group_tools(self)
        register_monitoring_tools(self)
        register_search_tools(self)
        register_replication_tools(self)
        register_performance_tools(self)
        register_index_tools(self)
        register_config_tools(self)

    # --------------------------------------------------------------------- #
    # Helper methods (used by tool modules)
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
            display_name = (
                self._sanitizer.sanitize_server_name(server_name)
                if self.privacy_enabled else server_name
            )
            raise ToolError(f"Server '{display_name}' does not have a base DN configured")
        return config.base_dn

    def describe_servers(self) -> List[Dict[str, Any]]:
        """Return a list of server descriptions (sanitized in privacy mode)."""
        descriptions = super().describe_servers()

        if not self.privacy_enabled:
            return descriptions

        # Sanitize sensitive information when privacy is enabled
        sanitized = []
        for desc in descriptions:
            sanitized_desc = {
                "name": self._sanitizer.sanitize_server_name(desc.get("name")),
                "hostname": self._sanitizer.sanitize_hostname(desc.get("hostname")),
                "port": "[port]",
                "use_ssl": desc.get("use_ssl"),
                "base_dn": self._sanitizer.sanitize_suffix(desc.get("base_dn")),
                "auth_method": desc.get("auth_method"),
                "provider_type": desc.get("provider_type"),
                "is_default": desc.get("is_default"),
                "is_local": desc.get("is_local"),
                "mode": desc.get("mode"),
            }
            if desc.get("is_local") and desc.get("serverid"):
                sanitized_desc["serverid"] = "[serverid]"
                sanitized_desc["use_ldapi"] = desc.get("use_ldapi")
            if desc.get("is_offline"):
                sanitized_desc["is_offline"] = True
            if desc.get("is_archive"):
                sanitized_desc["is_archive"] = True
                if desc.get("archive_path"):
                    sanitized_desc["archive_path"] = "[archive_path]"
            sanitized.append(sanitized_desc)
        return sanitized
