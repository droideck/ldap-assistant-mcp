# Changelog

All notable changes to LDAP Assistant MCP will be documented in this file.

## [Unreleased]

Broad hardening pass across diagnostic truthfulness, security and privacy,
log handling, release safety, and the support-case and operability surfaces.
Highlights:

### Fixed - trust
- Diagnostic summaries (`first_look`, `run_healthcheck`, `get_performance_summary`,
  `list_replication_conflicts`, `analyze_index_configuration`, `validate_configuration`)
  can no longer report healthy/OK/no-conflicts when a required probe failed;
  results carry `evidence_status` and explicit failure records
- Filtered log severity/change-type counts now contain only matched records
  (all-source totals separately named); archive `last N` time ranges anchor
  to the dataset end; unknown timestamps are counted, not silently blended
- Replication catch-up is no longer counted as synchronized; archive replica
  roles derived from type+flags; topology SPOF/orphan analysis uses real
  per-suffix agreement graphs; remote servers no longer receive MCP-host
  psutil/socket data; cumulative counters thresholded as rates per uptime

### Security & privacy
- Credential attribute denial normalizes `;options` and fail-closed matches
  unknown credential-like names in every privacy mode
- Privacy count oracles closed (bucketed name-search counts, audit DN
  filters rejected in privacy mode); free-text sanitizer catches
  arbitrary-TLD hostnames, spaced DNs, bare system paths; stderr log
  records sanitized in privacy mode; endpoint details demoted to DEBUG logs
- Remote SIMPLE bind over plaintext `ldap://` refused by default
  (`allow_insecure_plaintext` lab escape hatch); strict config parsing
  (booleans, URL schemes, conflicts, duplicates, unknown keys, empty
  explicit configs all fail startup); OpenLDAP honors `tls_verify`
- `bind_password_env` / `bind_password_file` secret indirection; configs
  never serialize secrets; world-readable configs with inline passwords
  refused; per-instance sanitizer scope with thread-safe caches

### Reliability & delivery
- Release workflow gated on the full test suite at the exact tag SHA plus
  version-consistency validation; weekly pip-audit workflow; local test
  scripts fail loudly, sync from the lock, and only remove containers they
  own; `uv.lock` refreshed
- Unified streaming log readers: per-file format detection across rotated
  families, pretty-JSON, corrupt-gz tolerance, decompression budgets,
  streaming audit parser with LDIF unfolding and base64 DNs; rotated-only
  families readable; `include_archived_logs` on error/audit tools
- Oversized structured responses are real tool errors; timeout errors state
  cancellation truth; error dicts carry stable `error_code`/`category`/
  `retryable`; ReDoS-safe structural regex validation
- Cursor pagination (`has_more`/`next_cursor`) on user/group listings

### Added - case workflow MVP & operability
- `inspect_log_coverage`, `collect_case_snapshot`, `correlate_incident_window`,
  `render_case_packet` tools with stable evidence IDs and audience rendering
- `intake_389ds_support_case`, `build_389ds_incident_timeline`,
  `prepare_389ds_escalation` prompts
- `get_capabilities`, `service_liveness`, `service_readiness` tools;
  `doctor` and `support-bundle` CLI commands

### Migration notes (target 0.6.0)
- Config typos, unknown keys, URL/use_ssl conflicts, and empty explicit
  configs that previously loaded silently now fail startup
- Remote plaintext SIMPLE binds require `ldaps://`, `ldapi://`, or the
  explicit `allow_insecure_plaintext: true` lab flag
- A group/other-readable servers.json containing an inline `bind_password`
  now fails startup (chmod 600)

## [0.5.0] - 2026-07-01

First beta release, targeting 389 DS support engineers triaging live instances
and SOS reports. Read-only diagnostics suitable for evaluation and internal
troubleshooting; tool schemas, output formats, and configuration fields may
still change before 1.0.0.

### Added

#### Support-engineer workflow
- Mode errors now teach the workflow: refusing a live-only tool on an offline/archive server (and archive-only tools on live servers, log tools on remote servers) names the tools that DO work there — `try_instead` in error dicts, alternatives listed in `LiveServerRequired` messages
- Admin playbooks: `docs/playbooks/archive-sos.md` (summarize an SOS report before opening the case) and `docs/playbooks/install-troubleshooting.md` (python-ldap builds, WSL2, uvx, config path resolution)
- `docs/RELEASE.md` release checklist (manual pre-tag steps; publishing itself is automated on tag)
- 8 release-critical routing cases in the eval dataset (SOS investigation, broken replication, slow directory, privacy/offline/archive mode queries) — gate in CI
- README restructured around the support-engineer path: uvx install from PyPI, four server modes table, "first questions to ask", tool groups, playbook links

#### Packaging & Distribution
- Proper installable package: `src/ldap_assistant_mcp/` distribution package, hatchling build, `ldap-assistant-mcp` console script, tests excluded from the wheel
- Tag-triggered release workflow (`release.yml`): build → PyPI trusted publishing → MCP Registry publish
- CI: fast no-container job (ruff + non-live tests + build + clean-venv wheel smoke test) on a Python 3.11/3.12/3.13 matrix; Dependabot; `live` pytest marker
- Package version reported to MCP clients; server-level `instructions` shipped by default; stderr logging handler (`LDAP_MCP_DEBUG` for debug level)

#### Privacy
- IPv4/IPv6 address redaction in text sanitization (bare, bracketed, zone-indexed, and port-suffixed forms) with deterministic per-session `[ip-…]` tokens
- Startup WARNING when privacy mode is disabled (`expose_sensitive_data=true`)
- Fail-closed sanitization: unrecognized backend-result and finding-metadata keys are now redacted by default instead of passed through raw
- Fail-closed hardening extended to RUV data (including error text), attribute values outside the sensitive sets (identifier-shaped values tokenized, nested entry structures sanitized per-attribute), and finding top-level keys; text sanitization now also covers email addresses and modern TLDs (.xyz, .dev, .ai, country codes, …)

#### Configuration
- `LDAP_IS_OFFLINE` environment variable implemented (was documented but ignored): implies `LDAP_IS_LOCAL=true`, requires `LDAP_SERVERID`
- `tls_verify` config field + `LDAP_TLS_VERIFY` / `LDAP_CONNECT_TIMEOUT` environment variables (from 0.4.x hardening)

### Changed

#### Contract honesty
- Unimplemented `auth_method` values (`sasl_gssapi`, `sasl_digest_md5`, `sasl_external`) are now rejected with a clear error instead of silently degrading to a simple bind with an empty password; LDAPI/SASL EXTERNAL is selected via `use_ldapi`
- Invalid `LDAP_PORT` / `LDAP_AUTH_METHOD` values fail startup with clear configuration errors instead of bare tracebacks
- A server with `is_offline=true` but missing `is_local`/`serverid` now gets a clear error instead of falling through to a live connection attempt
- The OpenLDAP provider (experimental, bypasses the privacy sanitizer) now requires an explicit `LDAP_MCP_EXPERIMENTAL_OPENLDAP=true` opt-in; `LDAP_PROVIDER=openldap` without it errors with guidance

#### Diagnostics correctness (0.4.x hardening series)
- Fixed silently-wrong results in `find_unindexed_searches`, disk/certificate health checks, backend lint discovery, SOS healthcheck parsing, log `time_range` filtering, and offline replication detection
- Archive robustness: decompression-bomb guard, extraction caching, DN-normalized `compare_dse_configs`, streamed JSON log parsing, bounded log memory

### Fixed
- Config-load failures for an explicitly configured `LDAP_SERVERS_CONFIG` now fail loudly instead of silently booting an env-fallback phantom server
- Multiple privacy-mode leak paths closed (monitor connection data, credential hashes, mapping-tree suffixes, resource errors, traceback text)
- lib389 workarounds: `DSEldif` case-sensitive attribute lookup, `DSEldif` last-line drop, `DirsrvAuditLog.parse_line` crash, `parse_timestamp` precision loss

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

[0.5.0]: https://github.com/droideck/ldap-assistant-mcp/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/droideck/ldap-assistant-mcp/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/droideck/ldap-assistant-mcp/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/droideck/ldap-assistant-mcp/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/droideck/ldap-assistant-mcp/releases/tag/v0.1.0
