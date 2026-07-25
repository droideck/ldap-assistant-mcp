"""389 Directory Server MCP server implementation."""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager, contextmanager
from typing import Any, AsyncIterator, Dict, Iterable, Iterator, List, Optional, Tuple

from fastmcp.exceptions import ResourceError, ToolError
from fastmcp.prompts import Message
from lib389.config import Config

from ldap_assistant_mcp.config.loader import load_config
from ldap_assistant_mcp.dirsrv_mcp.connection import (
    ConnectionManager,
    LiveServerRequired,
    require_live_server,
)
from ldap_assistant_mcp.dirsrv_mcp.middleware import LoggingMiddleware, ResponseSizeMiddleware, TimeoutMiddleware
from ldap_assistant_mcp.dirsrv_mcp.tools import (
    register_archive_tools,
    register_capability_tools,
    register_case_tools,
    register_config_tools,
    register_group_tools,
    register_health_tools,
    register_index_tools,
    register_log_tools,
    register_monitoring_tools,
    register_performance_tools,
    register_replication_tools,
    register_search_tools,
    register_server_tools,
    register_user_tools,
)
from ldap_assistant_mcp.dirsrv_mcp.tools.error_utils import format_error_message
from ldap_assistant_mcp.core import (
    LDAPAssistantMCP,
    LDAPServerConfig,
    MCPSettings,
    configure_package_logging,
)
from ldap_assistant_mcp.lib.privacy import PrivacySanitizer

__all__ = ["DirSrvMCP"]

_server_logger = logging.getLogger(__name__)

_DEFAULT_INSTRUCTIONS = """\
389 Directory Server health & diagnostics assistant (read-only).

Servers run in one of three modes — call `list_servers` first to see them:
- LIVE: running server reached over LDAP (all tools available)
- OFFLINE: stopped local instance (dse.ldif + logs; no LDAP connection)
- ARCHIVE: SOS report / support tarball (config + log analysis only)
Tools that need a live connection fail with a LiveServerRequired error on
offline/archive servers; pick the analyze_*/validate_*/compare_dse_* tools there.

Start investigations with `first_look` (multi-server health overview), then
drill down with the specialized tools. `server_health` probes only this MCP
service, not the directory.

Privacy mode is ON by default: hostnames, DNs, and entry data are redacted or
count-only, and parse_* log tools, `ldap_search`, and `get_user_details` are
disabled. Statistics-focused analyze_* tools remain fully usable. Server names
(the `name` field from the configuration) are stable labels that are never
redacted — pass them unchanged between tool calls via `server_name`.

The `tool_navigator` prompt gives a complete tool map for a stated goal."""


@asynccontextmanager
async def _server_lifespan(server) -> AsyncIterator[dict]:
    """FastMCP lifespan: log startup, clean up temp dirs on shutdown."""
    _server_logger.info("server_starting")
    try:
        yield {}
    finally:
        from ldap_assistant_mcp.dirsrv_mcp.archive.loader import cleanup_temp_dirs

        cleanup_temp_dirs()
        _server_logger.info("server_stopped")


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
        # Configure stderr logging before anything can log (config-load
        # errors below must be visible); level refined once settings resolve.
        configure_package_logging()
        self.logger = logging.getLogger(
            f"ldap_assistant_mcp.{self.__class__.__name__}"
        )
        merged_servers, loaded_settings = self._collect_servers_and_settings(
            config_path=config_path, extra_servers=servers
        )

        # Use provided settings, loaded settings, or defaults
        # Note: We use _mcp_settings to avoid conflict with FastMCP's settings property
        self._mcp_settings = settings or loaded_settings or MCPSettings.from_env()

        # Tools that scan all servers or parse large archives get extra time
        _max_t = self._mcp_settings.max_tool_timeout
        tool_timeouts = {
            "first_look": _max_t,
            "run_healthcheck": _max_t,
            "compare_dse_configs": _max_t,
            "analyze_archive": _max_t,
            "get_replication_topology": _max_t,
        }

        middleware = [
            LoggingMiddleware(),
            TimeoutMiddleware(
                default_timeout=self._mcp_settings.tool_timeout,
                max_timeout=self._mcp_settings.max_tool_timeout,
                tool_timeouts=tool_timeouts,
            ),
            ResponseSizeMiddleware(),
        ]

        super().__init__(
            name=name,
            instructions=instructions or _DEFAULT_INSTRUCTIONS,
            servers=merged_servers or None,
            middleware=middleware,
            lifespan=_server_lifespan,
            **kwargs,
        )
        # Per-instance sanitizer: each DirSrvMCP instance gets its own
        # pseudonym scope (own random key), so tokens from one
        # investigation/server instance can never be correlated with
        # another's.  The process-global get_sanitizer() remains
        # for process-level consumers such as the stderr logging filter.
        self._sanitizer = PrivacySanitizer()

        self.connection_manager = connection_manager or ConnectionManager()
        for cfg in self.server_configs.values():
            self.connection_manager.add_server(cfg)

        # Wire debug mode (settings may come from the config file, not env,
        # so re-apply the package log level now that they are resolved)
        configure_package_logging(debug=self._mcp_settings.debug)
        if self._mcp_settings.debug:
            self.connection_manager.debug = True
            self.logger.setLevel(logging.DEBUG)

        self.logger.info(
            "DirSrv MCP initialized with %d server(s): %s (privacy_mode=%s, debug=%s)",
            len(self.server_configs),
            ", ".join(self.server_configs.keys()),
            not self._mcp_settings.expose_sensitive_data,
            self._mcp_settings.debug,
        )
        if self._mcp_settings.expose_sensitive_data:
            self.logger.warning(
                "Privacy mode is DISABLED (expose_sensitive_data=true): tool "
                "outputs will contain real DNs, hostnames, IP addresses, and "
                "configuration values. Use only with trusted/local LLMs — "
                "never with public LLMs against production directories."
            )

        self._register_prompts()
        self._register_tools()
        self._register_resources()

    @property
    def privacy_enabled(self) -> bool:
        """Return True if privacy mode is enabled (sensitive data is redacted)."""
        return not self._mcp_settings.expose_sensitive_data

    @property
    def debug_enabled(self) -> bool:
        """Return True if debug mode is enabled."""
        return self._mcp_settings.debug

    @property
    def sanitizer(self) -> PrivacySanitizer:
        """Return the privacy sanitizer instance."""
        return self._sanitizer

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

        explicit_config = config_path or os.environ.get("LDAP_SERVERS_CONFIG")
        if explicit_config:
            try:
                config = load_config(config_file=config_path)  # type: ignore[arg-type]
            except Exception as exc:
                # A config file was explicitly requested (config_path argument
                # or LDAP_SERVERS_CONFIG env var).  Swallowing the failure here
                # would silently discard every configured server and boot with
                # only the env-fallback default (invisible on stdio transport),
                # so fail loudly with the path and the underlying error.
                self.logger.error(
                    "Failed to load server configuration from '%s': %s",
                    explicit_config,
                    exc,
                )
                raise RuntimeError(
                    f"Failed to load LDAP server configuration from "
                    f"'{explicit_config}': {type(exc).__name__}: {exc}"
                ) from exc
            for server in config.servers:
                merged[server.name] = server
            loaded_settings = config.settings

        if extra_servers:
            for server in extra_servers:
                merged[server.name] = server

        return list(merged.values()), loaded_settings

    def _register_prompts(self) -> None:
        """Register guided troubleshooting prompts."""

        @self.prompt()
        def tool_navigator(goal: str) -> list[Message]:
            """Guide users through available tools and their usage."""

            return [
                Message(role="user", content=f"Directory task: {goal}"),
                Message(
                    role="assistant",
                    content=(
                        "Use the available MCP tools to accomplish the task. "
                        "Prefer specialized tools first, falling back to ldap_search for advanced queries.\n\n"
                        "**Server Modes:**\n"
                        "- LIVE = running server with LDAP connection\n"
                        "- OFFLINE = stopped local instance (dse.ldif + logs)\n"
                        "- ARCHIVE = SOS report or extracted tarball\n"
                        "Call `list_servers` to see which mode each server is in.\n\n"
                        "**Start Here — Health & Diagnostics:** [LIVE, OFFLINE, ARCHIVE]\n"
                        "- first_look: Comprehensive health overview across ALL servers (start here).\n"
                        "- run_healthcheck: Deep lint checks (dseldif, config, backends, tls, etc.).\n"
                        "- list_healthchecks / list_healthcheck_errors: Discover available checks and error codes.\n"
                        "- server_health: Probe this MCP service only (config/mode flags) — NOT directory health.\n\n"
                        "**Performance (LIVE only):**\n"
                        "- get_performance_summary: Combined overview — use first for performance questions.\n"
                        "- get_cache_statistics: Entry/DN/DB cache hit ratios (drill into cache problems).\n"
                        "- get_connection_statistics: Connection counts, FD usage, CLOSE_WAIT.\n"
                        "- get_operation_statistics: Op counts by type, bind errors, data transfer.\n"
                        "- get_thread_statistics: Thread contention and max-threads hits.\n"
                        "- get_resource_utilization: Memory (RSS/swap), CPU, disk space.\n"
                        "- run_monitor: Raw cn=monitor attributes (use only when above tools lack a specific counter).\n\n"
                        "**Replication (LIVE only):**\n"
                        "- get_replication_status: Per-server replica config, RUV, and agreements.\n"
                        "- get_replication_topology: Cross-server topology map with role distribution.\n"
                        "- check_replication_lag: CSN lag analysis per agreement.\n"
                        "- list_replication_conflicts: Find conflict and glue entries needing resolution.\n"
                        "- get_agreement_status: Detailed single-agreement status with schedule and flow control.\n\n"
                        "**Configuration:** [LIVE, OFFLINE, ARCHIVE]\n"
                        "- get_server_configuration: View cn=config attributes (supports offline/archive).\n"
                        "- compare_server_configurations: Diff cn=config between two servers (any mode combination).\n"
                        "- get_backend_configuration: Backend settings and cache config.\n"
                        "- list_plugins: Plugin inventory with enabled/disabled status.\n"
                        "- list_indexes / analyze_index_configuration: Index review and best-practice audit.\n"
                        "- find_unindexed_searches: Parse access logs for notes=U/A patterns (local/archive).\n\n"
                        "**Log Analysis:** [LOCAL, ARCHIVE]\n"
                        "- analyze_access_log: Statistics only — operations, errors, slow queries (privacy-safe).\n"
                        "- analyze_error_log: Statistics only — severity distribution, components (privacy-safe).\n"
                        "- analyze_audit_log: Statistics only — change types and actors (privacy-safe).\n"
                        "- parse_access_log: Full entries (requires expose_sensitive_data=true).\n"
                        "- parse_error_log: Full entries (requires expose_sensitive_data=true).\n"
                        "- parse_audit_log: Full entries (requires expose_sensitive_data=true).\n\n"
                        "**Archive & Offline Analysis:** [OFFLINE, ARCHIVE only]\n"
                        "- analyze_archive: Inventory available data (config, logs, schema, SOS healthcheck).\n"
                        "- validate_configuration: Static config lint on dse.ldif.\n"
                        "- compare_dse_configs: Full entry-by-entry dse.ldif diff between two archives.\n\n"
                        "**User & Group Management (LIVE only):**\n"
                        "- list_all_users / list_active_users / list_locked_users\n"
                        "- search_users_by_name / search_users_by_attribute / get_user_details\n"
                        "- list_all_groups\n\n"
                        "**Advanced (LIVE only):**\n"
                        "- ldap_search(base_dn, scope, filter, attributes, attrs_only, limit)\n\n"
                        "State which tool you'll call next and why; keep outputs concise."
                    ),
                ),
            ]

        @self.prompt()
        def diagnose_replication() -> list[Message]:
            """Start a guided replication troubleshooting session."""

            return [
                Message(
                    role="user",
                    content="I need help diagnosing replication issues in my directory.",
                ),
                Message(
                    role="assistant",
                    content=(
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
            ]

        @self.prompt()
        def performance_investigation() -> list[Message]:
            """Start a guided performance troubleshooting session."""

            return [
                Message(
                    role="user",
                    content="I need help investigating performance issues with my directory server.",
                ),
                Message(
                    role="assistant",
                    content=(
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
            ]

        @self.prompt()
        def daily_health_check() -> list[Message]:
            """Perform a comprehensive daily health check suitable for operations review."""

            return [
                Message(
                    role="user",
                    content="Please perform a daily health check of my directory infrastructure.",
                ),
                Message(
                    role="assistant",
                    content=(
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
            ]

        @self.prompt()
        def troubleshoot_connectivity() -> list[Message]:
            """Start a guided session to troubleshoot connection issues."""

            return [
                Message(
                    role="user",
                    content="I'm having trouble connecting to my directory server or clients are reporting connection issues.",
                ),
                Message(
                    role="assistant",
                    content=(
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
            ]

        @self.prompt()
        def archive_investigation() -> list[Message]:
            """Start a guided SOS report or archive analysis session."""

            return [
                Message(
                    role="user",
                    content="I have an SOS report or archive from a 389 Directory Server and need help investigating it.",
                ),
                Message(
                    role="assistant",
                    content=(
                        "I'll help you investigate this archive systematically. Here's my approach:\n\n"
                        "**Step 1: Inventory available data**\n"
                        "I'll use `analyze_archive` to discover what data is available — config, logs, "
                        "schema, certificates, and any SOS healthcheck output.\n\n"
                        "**Step 2: Validate configuration**\n"
                        "I'll use `validate_configuration` to run static lint checks on dse.ldif — "
                        "security settings, password schemes, TLS versions, and more.\n\n"
                        "**Step 3: Check error logs**\n"
                        "I'll use `analyze_error_log` to look for error severity distribution, "
                        "component breakdown, and common patterns.\n\n"
                        "**Step 4: Analyze access patterns**\n"
                        "I'll use `analyze_access_log` to check for failed operations, slow queries, "
                        "and unindexed searches.\n\n"
                        "**Step 5: Review recent changes**\n"
                        "If an audit log is available, I'll use `analyze_audit_log` to review change "
                        "type distribution and actor activity.\n\n"
                        "**Step 6: Compare against baseline**\n"
                        "If a known-good archive is available, I'll use `compare_dse_configs` to do a "
                        "full entry-by-entry comparison to identify what changed.\n\n"
                        "Let me start by inventorying the available data..."
                    ),
                ),
            ]

        @self.prompt()
        def intake_389ds_support_case(symptom: str) -> list[Message]:
            """Collect the minimum consequential facts for a new 389 DS support case, pick a route, then stop."""

            return [
                Message(role="user", content=f"New 389 DS support case: {symptom}"),
                Message(
                    role="assistant",
                    content=(
                        "I'll run a bounded case intake — collect the minimum facts that "
                        "change what we do next, select a route, and stop (no deep diagnosis yet).\n\n"
                        "**Step 1: What evidence do we have?**\n"
                        "I'll call `list_servers` and `collect_case_snapshot` to establish the "
                        "available modes (live/offline/archive) and evidence coverage — the "
                        "snapshot records every probe that failed, so we know what we CANNOT see.\n\n"
                        "**Step 2: Consequential intake facts**\n"
                        "Before collecting more, I need from you (only what's missing):\n"
                        "- Customer impact and scope (who/what is affected, how badly?)\n"
                        "- Onset time and timezone (when did it start?)\n"
                        "- Last known good state / recent changes (upgrade, config, network?)\n"
                        "- Any workaround currently in place?\n\n"
                        "**Step 3: Route selection**\n"
                        "Based on symptom + modes: replication issues -> `get_replication_status` "
                        "path; performance -> `get_performance_summary` path; log-driven incident "
                        "-> `build_389ds_incident_timeline` prompt; SOS archive -> `analyze_archive` "
                        "path.\n\n"
                        "**Output:** an intake record — impact, scope, onset, unknowns, available "
                        "modes, selected route, and next owner. I will state what the evidence "
                        "cannot establish rather than guessing.\n\n"
                        "Starting with the evidence inventory..."
                    ),
                ),
            ]

        @self.prompt()
        def build_389ds_incident_timeline(incident_window: str) -> list[Message]:
            """Build a cross-signal, time-bounded incident chronology; co-occurrence only, never causality."""

            return [
                Message(role="user", content=f"Build an incident timeline for: {incident_window}"),
                Message(
                    role="assistant",
                    content=(
                        "I'll build an evidence-linked incident chronology for that window.\n\n"
                        "**Step 1: Coverage first**\n"
                        "`inspect_log_coverage` — what logs exist and what time span they "
                        "actually cover. If the window falls outside the dataset, I'll say so "
                        "instead of returning an empty timeline.\n\n"
                        "**Step 2: Bucketed correlation**\n"
                        "`correlate_incident_window` with the incident window — error-log "
                        "severities, failed operations, and audit changes per time bucket, "
                        "with statistically anomalous buckets flagged as change points.\n\n"
                        "**Step 3: Drill into change points**\n"
                        "For each change point: `analyze_error_log` / `analyze_access_log` / "
                        "`analyze_audit_log` scoped to that bucket's time range to characterize "
                        "what changed (counts and patterns only in privacy mode).\n\n"
                        "**Step 4: Chronology**\n"
                        "A timeline of observations, each tied to its evidence: first anomaly, "
                        "correlated signals, config changes in the window, and coverage gaps. "
                        "Temporal co-occurrence is a lead, never proof of cause — I'll keep "
                        "observations separate from hypotheses.\n\n"
                        "Checking log coverage now..."
                    ),
                ),
            ]

        @self.prompt()
        def prepare_389ds_escalation(ask: str) -> list[Message]:
            """Assemble an engineering escalation packet from already-collected case evidence."""

            return [
                Message(role="user", content=f"Prepare an engineering escalation: {ask}"),
                Message(
                    role="assistant",
                    content=(
                        "I'll assemble an engineering-ready escalation packet from evidence "
                        "we already hold — rendering and validation only, no silent recollection.\n\n"
                        "**Required inputs** (tell me if any is missing):\n"
                        "- The case snapshot or evidence collected so far (or I'll run "
                        "`collect_case_snapshot` once, with your OK)\n"
                        "- What was already tried and ruled out\n"
                        "- The specific engineering ask and deadline\n\n"
                        "**Step 1: Validate evidence**\n"
                        "`render_case_packet(audience='engineering')` — every claim must resolve "
                        "to an evidence ID; unresolvable references fail instead of shipping.\n\n"
                        "**Step 2: Packet assembly**\n"
                        "Issue statement, impact, versions/topology (from the snapshot), timeline "
                        "(from `correlate_incident_window` if available), evidence index, "
                        "ruled-out paths, limitations (probes that failed and what that hides), "
                        "and the explicit ask.\n\n"
                        "**Step 3: Disclosure check**\n"
                        "In privacy mode the packet contains pseudonymized identifiers only; "
                        "I'll flag anything that still looks sensitive before you send it.\n\n"
                        "What evidence do we have so far, and what exactly is the engineering ask?"
                    ),
                ),
            ]

    def _register_resources(self) -> None:
        """Register MCP resources for cn=config access."""

        def _resource_error_detail(exc: BaseException) -> str:
            """Format an exception for ResourceError, scrubbing in privacy mode.

            Raw lib389 exception text can embed LDAP URIs, bind DNs, and
            hostnames, so it must pass through the sanitizer before being
            sent to the client (same policy as format_tool_error).
            """
            detail = format_error_message(exc)
            if self.privacy_enabled:
                detail = self._sanitizer.sanitize_text(detail)
            return detail

        def _require_live_default_server(uri: str) -> str:
            """Return the default server name, rejecting offline/archive modes.

            Resources read cn=config over a live LDAP connection, so they need
            the same live-mode guard the equivalent tools use.  The guard error
            is re-raised as ResourceError so mask_error_details does not hide
            the explanation from the client.
            """
            target = getattr(self, "default_server", None)
            if not target:
                raise ResourceError("No LDAP server configured")
            try:
                self.require_live(target, f"{uri} resource")
            except LiveServerRequired as exc:
                raise ResourceError(str(exc)) from exc
            return target

        def _cn_config_json(target: str) -> str:
            """Return all cn=config attributes of *target* as a JSON string.

            Shared by the default-server ``config://config-all`` resource
            and the server-addressable ``ldap://{server_name}/config``
            template.  Sanitized in privacy mode.
            """
            import json as _json

            with self._connection(target) as (_, ds):
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
                    raise ResourceError(
                        f"Failed to retrieve cn=config attributes: {_resource_error_detail(exc)}"
                    ) from exc

        @self.resource("config://config-all", mime_type="application/json")
        def get_cn_config_all_attributes() -> str:
            """Return all attributes for cn=config as JSON (default server).

            Note: In privacy mode (default), sensitive values like hostnames,
            paths, and suffixes are redacted.
            """
            target = _require_live_default_server("config://config-all")
            return _cn_config_json(target)

        @self.resource("ldap://{server_name}/config", mime_type="application/json")
        def get_server_cn_config(server_name: str) -> str:
            """Return all cn=config attributes for the named server as JSON.

            Server-addressable variant of ``config://config-all`` for
            multi-server configurations: pass any configured server name
            (see the ``list_servers`` tool).  Requires a live server; in
            privacy mode sensitive values are redacted.
            """
            if server_name not in self.server_configs:
                available = ", ".join(sorted(self.server_configs)) or "none"
                raise ResourceError(
                    f"Server '{server_name}' is not configured. "
                    f"Configured servers: {available}."
                )
            try:
                self.require_live(server_name, "ldap://{server_name}/config resource")
            except LiveServerRequired as exc:
                raise ResourceError(str(exc)) from exc
            return _cn_config_json(server_name)

        @self.resource(
            "config://config-attribute/{attribute}", mime_type="application/json"
        )
        def get_cn_config_attribute(attribute: str) -> Dict[str, Any]:
            """Return a specific attribute from cn=config.

            Note: In privacy mode (default), sensitive values like hostnames,
            paths, and suffixes are redacted.
            """
            attr_name = attribute.strip()
            target = _require_live_default_server("config://config-attribute")
            with self._connection(target) as (_, ds):
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
                        f"Failed to retrieve cn=config attribute '{attribute}': "
                        f"{_resource_error_detail(exc)}"
                    ) from exc

    def _register_tools(self) -> None:
        """Register all tools from modular tool files."""
        register_server_tools(self)
        register_health_tools(self)
        register_user_tools(self)
        register_group_tools(self)
        register_monitoring_tools(self)
        register_search_tools(self)
        register_replication_tools(self)
        register_performance_tools(self)
        register_index_tools(self)
        register_config_tools(self)
        register_log_tools(self)
        register_archive_tools(self)
        register_case_tools(self)
        register_capability_tools(self)

    @contextmanager
    def _connection(self, server_name: Optional[str] = None) -> Iterator[Tuple[str, Any]]:
        """Yield ``(server_name, ds)`` and close the connection on exit."""
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
        """Return the configured base DN for *server_name*, or raise."""
        config = self.get_server_config(server_name)
        if not config.base_dn:
            raise ToolError(f"Server '{server_name}' does not have a base DN configured")
        return config.base_dn

    def require_live(self, server_name: str, feature: str) -> None:
        """Guard that raises LiveServerRequired for offline/archive servers."""
        require_live_server(self.connection_manager, server_name, feature)

    def describe_servers(self) -> List[Dict[str, Any]]:
        """Return a list of server descriptions (sanitized in privacy mode).

        Server names are never sanitized — they are user-chosen config
        labels and must remain stable so that LLM clients can pass them
        back to subsequent tool calls.  Do not put private information
        in server names.
        """
        descriptions = super().describe_servers()

        if not self.privacy_enabled:
            return descriptions

        # Sanitize sensitive information when privacy is enabled.
        # Server names are intentionally kept as-is (see docstring).
        sanitized = []
        for desc in descriptions:
            sanitized_desc = {
                "name": desc.get("name"),
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
