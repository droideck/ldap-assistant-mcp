# Changelog

All notable changes to LDAP Assistant MCP will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2025-01-01

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
- Server names, DNs, hostnames, and suffixes are anonymized in privacy mode

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

## [0.1.0] - 2024-12-01

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

[0.2.0]: https://github.com/droideck/ldap-assistant-mcp/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/droideck/ldap-assistant-mcp/releases/tag/v0.1.0
