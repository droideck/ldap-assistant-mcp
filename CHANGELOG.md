# Changelog

All notable changes to LDAP Assistant MCP will be documented in this file.

## [0.4.0] - 2026-04-01

### Added

#### Middleware
- **LoggingMiddleware** - Logs tool invocations (name + status only, no args/results)
- **TimeoutMiddleware** - Per-call time limits with per-tool overrides (configurable via `LDAP_MCP_TOOL_TIMEOUT` / `LDAP_MCP_MAX_TOOL_TIMEOUT`)
- **ResponseSizeMiddleware** - Truncates oversized responses with a notice (100k chars default)

#### Tool Annotations & Tags
- All 42 tools annotated with `ToolAnnotations` (`readOnlyHint`, `idempotentHint`, `openWorldHint`)
- Domain and mode tags on every tool (e.g. `{"health", "live", "offline", "archive"}`)

#### Health
- **server_health()** - Lightweight MCP server readiness probe (server count, privacy/debug modes)

#### Eval Framework
- `tests/eval/eval_dataset.json` with 31 tool-discovery test cases
- `tests/eval/run_eval.py` keyword-overlap scorer for tool routing evaluation

### Changed

#### Security Hardening
- `mask_error_details=True` on `LDAPAssistantMCP` — unhandled exceptions hidden from clients
- `LiveServerRequired` / `LocalServerRequired` now subclass `ToolError` so mode errors remain visible despite masking
- No default password: `LDAPServerConfig.from_env()` returns `None` if `LDAP_BIND_PASSWORD` is unset
- Connection hardening: bind password validated before LDAP open, error paths sanitized

#### Privacy Hardening
- Input bounds on all `limit` parameters (`ge=1, le=10000`)
- ReDoS-safe regex validation: rejects nested quantifiers, max 500 chars
- Privacy-aware error formatting via `format_tool_error()` — sanitizes server names and error text
- Config entry DNs preserved in `compare_dse_configs` output (attribute values still sanitized)

#### Server Lifecycle
- Server lifespan: `_server_lifespan()` calls `cleanup_temp_dirs()` on shutdown
- Temp dir tracking with `atexit.register()` fallback
- Archive tarball extraction caching to avoid re-extraction

#### Compatibility
- FastMCP 3.x prompt compatibility — all prompts return `list[Message]`

## [0.3.0] - 2026-02-16

### Added

#### Offline Mode
- Analyze stopped DS instances via dse.ldif and logs without LDAP connection
- `is_offline: true` server config option
- Health, config, index, and log tools work in offline mode

#### Archive Mode
- Analyze SOS reports or extracted configs from any machine
- `ArchiveDirSrv` stub for archive instances — no local DS installation required
- Auto-detection of SOS report layout, direct instance dirs, and config-only archives
- Tarball auto-extraction (`.tar.xz`, `.tar.gz`)
- `instance_name` config for multi-instance SOS reports

#### Archive & Offline Tools
- **analyze_archive()** - Inventory and summarize archive/offline data sources
- **validate_configuration()** - Static dse.ldif lint checks
- **compare_dse_configs()** - Entry-by-entry dse.ldif comparison between servers

#### Log Analysis Tools
- **parse_access_log()** - Parse and filter access log entries (local/archive)
- **parse_error_log()** - Parse and filter error log entries (local/archive)
- **parse_audit_log()** - Parse and filter audit log change records (local/archive)
- **analyze_access_log()** - Statistics-only access log analysis (privacy-safe)
- **analyze_error_log()** - Statistics-only error log analysis (privacy-safe)
- **analyze_audit_log()** - Statistics-only audit log analysis (privacy-safe)
- Support for both traditional and JSON log formats

#### Server Management
- **list_servers()** - List all configured servers with mode and status

#### Prompts
- **archive_investigation** - Guided SOS report / archive analysis workflow

### Changed

#### Privacy Improvements
- Privacy mode enabled by default
- Comprehensive sanitization across all tool modules (error messages, server lists, monitor data, VLV indexes, replication conflicts, disk paths, health metrics)
- analyze_* log tools as privacy-safe alternatives to parse_* tools
- Monitor data filtered to safe diagnostic keys only in privacy mode

#### Tool Improvements
- All tool docstrings updated with mode compatibility tags and cross-references
- `time_range` parameter replaces `start_time`/`end_time` in log tools (supports relative times like "last 24h")
- `include_archived_logs` parameter for access log tools to include rotated logs
- Offline/archive mode support added to config, index, health, and replication tools

## [0.2.0] - 2025-12-31

### Added

#### Health & Diagnostics
- **first_look()** - Multi-server quick health overview that provides comprehensive assessment across all configured servers including connectivity, replication, cache efficiency, disk space, and SSL certificate expiration
- **run_healthcheck()** - Full health check equivalent to `dsctl <instance> healthcheck`, examining configuration, backends, security, replication, plugins, certificates, disk space, and more
- **list_healthchecks()** - List all available health checks that can be run
- **list_healthcheck_errors()** - List all known DSLE error codes with severity and descriptions

#### Replication Diagnostics
- **get_replication_status()** - Comprehensive replication status including replica role, RUV analysis, and all agreement statuses with issue detection
- **get_replication_topology()** - Map complete replication topology across all configured servers, identifying single points of failure and orphaned replicas
- **check_replication_lag()** - Analyze replication lag by comparing CSN values between supplier and consumers
- **list_replication_conflicts()** - Find all conflict entries and glue entries that need resolution
- **get_agreement_status()** - Detailed status for specific or all replication agreements

#### Performance Diagnostics
- **get_performance_summary()** - Combined performance overview with prioritized findings from all categories
- **get_cache_statistics()** - Analyze database and entry cache efficiency with health assessments
- **get_connection_statistics()** - Analyze connection patterns, file descriptor utilization, and connection states
- **get_operation_statistics()** - Operation counts by type including binds, searches, modifications, and errors
- **get_thread_statistics()** - Worker thread utilization and contention detection
- **get_resource_utilization()** - System resource usage including memory, CPU, and disk

#### Index Analysis
- **list_indexes()** - List all configured indexes including regular and VLV indexes per backend
- **analyze_index_configuration()** - Compare current indexes against recommended best practices with remediation commands
- **find_unindexed_searches()** - Parse access logs to identify search patterns causing unindexed searches (local servers only)

#### Configuration Analysis
- **get_server_configuration()** - Dynamically fetch all cn=config attributes with optional pattern filtering
- **compare_server_configurations()** - Compare configuration between two servers to identify differences
- **list_plugins()** - List all configured plugins with enabled/disabled filtering
- **get_backend_configuration()** - Backend-specific configuration including cache settings, statistics, and replication status

#### Privacy Mode
- Added `LDAP_MCP_EXPOSE_SENSITIVE_DATA` environment variable for controlling data exposure
- Privacy sanitization for all tool outputs when privacy mode is enabled
- DNs, hostnames, and suffixes are anonymized in privacy mode (server names are never redacted — they are user-chosen config labels)

### Changed
- Enhanced multi-server support with consistent server_name parameter across all tools
- Improved error handling with structured findings including severity, impact, and remediation steps
- All diagnostic tools now return findings in a consistent format with severity levels (CRITICAL, HIGH, MEDIUM, LOW, INFO)

### Notes
- Some health and performance checks require local server access (is_local=True with serverid) for full functionality:
  - Disk space monitoring
  - Certificate expiration checking
  - Access log analysis for unindexed searches
  - Process memory and CPU monitoring

## [0.1.0] - 2024-10-24

### Added

#### User Management
- **list_all_users()** - Enumerate all users in the directory with configurable limit
- **search_users_by_name()** - Search for users by name or email
- **get_user_details()** - Get complete details for a specific user including group memberships
- **list_active_users()** - List only active (unlocked) users
- **list_locked_users()** - List only locked users with lock reason
- **search_users_by_attribute()** - Search for users by any LDAP attribute

#### Group Management
- **list_all_groups()** - Enumerate all groups with member counts

#### Monitoring
- **run_monitor()** - Get server and backend monitor data

#### Search
- **ldap_search()** - Full LDAP search with complete control over base DN, scope, filter, attributes, and limits

#### Configuration
- Multi-server support via JSON configuration file (LDAP_SERVERS_CONFIG)
- Single server configuration via environment variables (LDAP_URL, LDAP_BASE_DN, etc.)
- Provider-based architecture for 389 DS and OpenLDAP (OpenLDAP minimal)

#### Resources
- **config://config-all** - Returns all cn=config attributes
- **config://config-attribute/{attribute}** - Returns a single cn=config attribute

[0.4.0]: https://github.com/droideck/ldap-assistant-mcp/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/droideck/ldap-assistant-mcp/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/droideck/ldap-assistant-mcp/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/droideck/ldap-assistant-mcp/releases/tag/v0.1.0
