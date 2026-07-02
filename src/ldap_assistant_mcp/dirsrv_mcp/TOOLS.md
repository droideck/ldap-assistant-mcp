# 389 Directory Server Tools Reference

Complete reference for all 389 DS MCP tools (42 tools, 6 prompts, 2 resources).

This documentation covers the `dirsrv_mcp` provider which uses [lib389](https://lib389.readthedocs.io/) for 389 Directory Server operations.

> **Note:** Tools return accurate data from the server, but the LLM interprets that data. Hallucinations are possible - always verify recommendations before acting on them.

---

## Health & Diagnostics

### server_health()

Lightweight readiness probe for the **MCP service itself** — it never contacts a directory server (use `first_look` for directory health). Returns server count and privacy/debug mode status.

```
server_health()
```

**Returns:** `status`, `server_count`, `privacy_mode`, `debug_mode`.

**Modes:** Live, Offline, Archive.

---

### first_look()

Comprehensive health overview - the go-to tool for "what's wrong with my directory?"

```
first_look()
```

**Returns:** Multi-server health summary including:
- Server connectivity and basic health
- Connection and thread utilization
- Replication status and errors
- Cache efficiency (entry cache hit ratios)
- Disk space usage (local servers only)
- SSL certificate expiration (local servers only)

**Example prompts:**
- "Check the health of all servers"
- "What's wrong across all my servers?"
- "Give me a quick overview"

---

### run_healthcheck(checks?, exclude_checks?, server_name?)

Run comprehensive health checks equivalent to `dsctl <instance> healthcheck`.

```
run_healthcheck(
    checks: list = None,
    exclude_checks: list = None,
    server_name: str = None
)
```

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| checks | list | No | Specific checks to run (e.g., ['config:*', 'backends:mappingtree']) |
| exclude_checks | list | No | Checks to skip |
| server_name | str | No | Target server name |

**Returns:** Structured report with DSLE error codes, severity, and remediation steps.

**Note:** Some checks require local server access (is_local=True with serverid).

---

### list_healthchecks(server_name?)

List all available health checks that can be run.

```
list_healthchecks(server_name: str = None)
```

**Returns:** List of available checks in 'category:check_name' format.

---

### list_healthcheck_errors()

List all known DSLE error codes from lib389.

```
list_healthcheck_errors()
```

**Returns:** All possible error codes with severity and description.

---

## Replication

### get_replication_status(server_name?)

Get replication configuration, RUV, and agreement status for one server. LIVE only. Start here when replication is broken or misbehaving on a specific server; use `get_replication_topology` for a cross-server map and `check_replication_lag` for lag analysis.

```
get_replication_status(server_name: str = None)
```

**Returns:**
- Replica role (supplier/hub/consumer)
- Replica ID and RUV analysis
- All agreements with current status
- Findings for any issues detected

**Example prompts:**
- "Check replication status for ds-prod1"
- "Are there any replication issues?"
- "Show me replication lag"

---

### get_replication_topology()

Map the complete replication topology across all configured servers. LIVE only. Offline/archive servers are included as nodes but cannot report live agreement status.

```
get_replication_topology()
```

**Returns:**
- All servers and their roles
- Replication agreements between servers
- Potential issues (single points of failure, orphaned replicas)

**Example prompts:**
- "Show me the replication topology"
- "Map all replication agreements"

---

### check_replication_lag(suffix?, server_name?)

Measure replication lag by comparing supplier and consumer CSNs. LIVE only. Use this when `first_look` or `get_replication_status` indicates stale agreements.

```
check_replication_lag(suffix: str = None, server_name: str = None)
```

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| suffix | str | No | Specific suffix to check |
| server_name | str | No | Target server name |

**Returns:** Per-agreement lag status with CSN comparisons and severity assessment.

---

### list_replication_conflicts(base_dn?, server_name?)

Find replication conflict and glue entries that need resolution. LIVE only.

```
list_replication_conflicts(base_dn: str = None, server_name: str = None)
```

**Returns:**
- List of conflict entries with details
- List of glue entries
- Resolution recommendations

---

### get_agreement_status(agreement_name?, suffix?, server_name?)

Get detailed status for one or all replication agreements. LIVE only.

```
get_agreement_status(
    agreement_name: str = None,
    suffix: str = None,
    server_name: str = None
)
```

**Returns:** Agreement configuration, synchronization status, timestamps, and errors.

---

## Performance

### get_performance_summary(server_name?)

Combined performance overview — the first tool to reach for when the server is slow or for any performance question. LIVE only. Use the individual tools below to drill into specific areas.

```
get_performance_summary(server_name: str = None)
```

**Returns:**
- Overall health status
- Key metrics from cache, connections, operations, threads, resources
- Prioritized findings with recommendations

**Example prompts:**
- "Give me a performance summary for ds-prod1"
- "Is the server overloaded?"
- "Show me cache hit rates"

---

### get_cache_statistics(backend?, server_name?)

Analyze database and entry cache efficiency. LIVE only.

```
get_cache_statistics(backend: str = None, server_name: str = None)
```

**Returns:**
- Entry cache hit ratio and utilization
- DN cache statistics
- Database cache metrics
- Health assessment and recommendations

---

### get_connection_statistics(server_name?)

Analyze connection patterns and file descriptor usage. LIVE only.

```
get_connection_statistics(server_name: str = None)
```

**Returns:**
- Current vs max connections
- File descriptor utilization
- Connection state breakdown
- Recommendations for tuning

---

### get_operation_statistics(server_name?)

Get operation counts by type and bind method distribution. LIVE only.

```
get_operation_statistics(server_name: str = None)
```

**Returns:**
- Operations initiated vs completed
- Breakdown by type (search, bind, modify, etc.)
- Bind method distribution
- Error counts

---

### get_thread_statistics(server_name?)

Analyze worker thread utilization and contention. LIVE only.

```
get_thread_statistics(server_name: str = None)
```

**Returns:**
- Current thread count and configuration
- Connections at max threads
- Utilization assessment

---

### get_resource_utilization(server_name?)

Get memory, CPU, and disk usage for the Directory Server process. LIVE only.

```
get_resource_utilization(server_name: str = None)
```

**Returns:**
- Memory usage (RSS, VMS, swap) - LOCAL ONLY
- CPU utilization - LOCAL ONLY
- Disk space - LOCAL ONLY
- Server uptime

**Note:** Some metrics require local server access (is_local=True with serverid).

---

## Index Analysis

### list_indexes(backend?, server_name?)

List all configured indexes.

```
list_indexes(backend: str = None, server_name: str = None)
```

**Returns:**
- Per-backend index configuration
- Index types for each attribute
- System vs user-defined indexes
- VLV index definitions

---

### analyze_index_configuration(backend?, server_name?)

Analyze index configuration against best practices.

```
analyze_index_configuration(backend: str = None, server_name: str = None)
```

**Returns:**
- Missing recommended indexes
- Incomplete index configurations
- dsconf commands for remediation

**Example prompts:**
- "Check indexing for ds-prod1"
- "Are there missing indexes?"
- "Show me index recommendations"

---

### find_unindexed_searches(time_range?, limit?, server_name?)

Identify unindexed searches from access logs.

```
find_unindexed_searches(
    time_range: str = "1h",
    limit: int = 50,
    server_name: str = None
)
```

**Parameters:**
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| time_range | str | No | "1h" | How far back to analyze ("1h", "6h", "24h", "7d") |
| limit | int | No | 50 | Max patterns to return |
| server_name | str | No | - | Target server |

**Returns:** Search patterns causing unindexed searches with frequency and recommendations.

**Note:** Requires local or archive server access (reads log files directly).

---

## Configuration

### get_server_configuration(pattern?, server_name?)

Get server configuration from cn=config.

```
get_server_configuration(pattern: str = None, server_name: str = None)
```

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| pattern | str | No | Filter pattern (e.g., "nsslapd-security", "cache") |
| server_name | str | No | Target server |

**Returns:** All matching configuration attributes.

---

### compare_server_configurations(server1, server2, pattern?)

Compare configuration between two servers.

```
compare_server_configurations(
    server1: str,
    server2: str,
    pattern: str = None
)
```

**Returns:** Differences, attributes only on one server, and matching count.

---

### list_plugins(enabled_only?, server_name?)

List configured plugins.

```
list_plugins(enabled_only: bool = True, server_name: str = None)
```

**Returns:** Plugin list with name, type, enabled status, and details.

---

### get_backend_configuration(backend?, server_name?)

Get backend-specific configuration.

```
get_backend_configuration(backend: str = None, server_name: str = None)
```

**Returns:** Backend configuration including cache settings, statistics, and replication status.

---

## User Management

All user tools require a live server (they fail with `LiveServerRequired` on offline/archive servers). In privacy mode (default), the list/search tools return counts only, and `get_user_details` / `search_users_by_attribute` are disabled entirely.

### list_all_users(limit?, server_name?)

List all user accounts regardless of status, with computed lock/active status per user. Use `list_active_users` / `list_locked_users` to filter by status.

```
list_all_users(limit: int = 50, server_name: str = None)
```

**Parameters:**
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| limit | int | No | 50 | Maximum users to return |
| server_name | str | No | - | Target server |

**Returns:** List of users with attributes and computed lock/active status.

---

### search_users_by_name(name, limit?, server_name?)

Search users by name substring (or `*` wildcard) across uid, cn, givenName, sn, displayName, and mail.

```
search_users_by_name(name: str, limit: int = 50, server_name: str = None)
```

**Example prompts:**
- "Find users named John"
- "Search for smith@example.com"

---

### get_user_details(username, server_name?)

Get full attributes plus computed lock/expiry status for one user, looked up by uid.

```
get_user_details(username: str, server_name: str = None)
```

**Returns:** All user attributes plus computed status (lock state, policy parameters, calculation time).

---

### list_active_users(limit?, server_name?)

List only users whose computed account status is active (not locked or inactivity-expired).

```
list_active_users(limit: int = 50, server_name: str = None)
```

---

### list_locked_users(limit?, server_name?)

List users whose accounts are locked, whether directly or indirectly (account policy / inactivity). Lock reason is included per user.

```
list_locked_users(limit: int = 50, server_name: str = None)
```

---

### search_users_by_attribute(attribute, value, limit?, server_name?)

Search users by any single attribute=value match (e.g. departmentNumber, title, mail domain).

```
search_users_by_attribute(attribute: str, value: str, limit: int = 50, server_name: str = None)
```

**Example prompts:**
- "Find users in the Engineering department"
- "Search for users with title Manager"

---

## Group Management

### list_all_groups(limit?, server_name?)

List directory groups with their full attributes, including membership (member/uniqueMember). LIVE only. In privacy mode (default), returns a count only.

```
list_all_groups(limit: int = 50, server_name: str = None)
```

---

## Server Management

### list_servers()

List all configured servers with their mode and connection status.

```
list_servers()
```

**Returns:** All servers with name, mode (live/offline/archive), and provider type.

---

## Monitoring

### run_monitor(backend?, suffix?, server_name?)

Get raw cn=monitor attributes. LIVE only.

```
run_monitor(backend: str = "", suffix: str = "", server_name: str = None)
```

**Returns:** Monitor metrics including connections, operations, and backend statistics. In privacy mode, filtered to safe diagnostic keys only.

---

## Log Analysis

Log tools come in two variants:
- **parse_*** — Return full log entries (disabled in privacy mode)
- **analyze_*** — Return only statistics and counts (safe in privacy mode)

All log tools require local or archive server access. The `time_range` parameter supports: single date (`"2024-01-01"`), range (`"2024-01-01 to 2024-01-02"`), or relative (`"last 24h"`, `"last 30m"`).

### parse_access_log(server_name?, operation?, result_code?, time_range?, pattern?, include_archived_logs?, limit?)

Parse and filter access log entries. **Disabled in privacy mode** — use `analyze_access_log` instead.

```
parse_access_log(
    server_name: str = None,
    operation: str = None,
    result_code: int = None,
    time_range: str = None,
    pattern: str = None,
    include_archived_logs: bool = False,
    limit: int = 100
)
```

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| operation | str | No | Filter by operation type (SEARCH, BIND, MOD, etc.) |
| result_code | int | No | Filter by LDAP result code (e.g., 0 for success) |
| time_range | str | No | Time filter (e.g., "last 1h", "2024-01-01 to 2024-01-02") |
| pattern | str | No | Regex pattern to match against log lines |
| include_archived_logs | bool | No | Include rotated log files (default: false) |
| limit | int | No | Maximum entries to return (default: 100) |
| server_name | str | No | Target server |

**Returns:** Parsed log entries with operation statistics.

---

### parse_error_log(server_name?, severity?, component?, time_range?, pattern?, limit?)

Parse and filter error log entries. **Disabled in privacy mode** — use `analyze_error_log` instead.

```
parse_error_log(
    server_name: str = None,
    severity: str = None,
    component: str = None,
    time_range: str = None,
    pattern: str = None,
    limit: int = 100
)
```

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| severity | str | No | Minimum severity (ERR, WARN, INFO, DEBUG) |
| component | str | No | Filter by server component |
| time_range | str | No | Time filter |
| pattern | str | No | Regex pattern to match |
| limit | int | No | Maximum entries (default: 100) |
| server_name | str | No | Target server |

**Returns:** Parsed entries with severity distribution.

---

### parse_audit_log(server_name?, operation?, bind_dn?, target_dn?, time_range?, limit?)

Parse and filter audit log change records. **Disabled in privacy mode** — use `analyze_audit_log` instead.

```
parse_audit_log(
    server_name: str = None,
    operation: str = None,
    bind_dn: str = None,
    target_dn: str = None,
    time_range: str = None,
    limit: int = 100
)
```

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| operation | str | No | Filter by change type (add, modify, delete, modrdn) |
| target_dn | str | No | Filter by target DN (exact or subtree match) |
| bind_dn | str | No | Filter by who made the change |
| time_range | str | No | Time filter |
| limit | int | No | Maximum entries (default: 100) |
| server_name | str | No | Target server |

**Returns:** Parsed change records with operation and actor statistics.

---

### analyze_access_log(server_name?, operation?, result_code?, time_range?, pattern?, include_archived_logs?)

Statistics-only access log analysis. **Works in privacy mode** — returns counts and distributions without raw entries.

```
analyze_access_log(
    server_name: str = None,
    operation: str = None,
    result_code: int = None,
    time_range: str = None,
    pattern: str = None,
    include_archived_logs: bool = False
)
```

**Returns:** Operation counts, result code distribution, and time-based statistics.

---

### analyze_error_log(server_name?, severity?, component?, time_range?, pattern?)

Statistics-only error log analysis. **Works in privacy mode.**

```
analyze_error_log(
    server_name: str = None,
    severity: str = None,
    component: str = None,
    time_range: str = None,
    pattern: str = None
)
```

**Returns:** Severity distribution, component breakdown, and error frequency.

---

### analyze_audit_log(server_name?, operation?, bind_dn?, target_dn?, time_range?)

Statistics-only audit log analysis. **Works in privacy mode.**

```
analyze_audit_log(
    server_name: str = None,
    operation: str = None,
    bind_dn: str = None,
    target_dn: str = None,
    time_range: str = None
)
```

**Returns:** Operation type counts, actor statistics, and change frequency.

---

## Archive & Offline Analysis

### analyze_archive(server_name?)

Inventory available data in an offline instance or archive source, such as an SOS report or config extract. The first step when working with a new archive or offline instance. OFFLINE and ARCHIVE only.

```
analyze_archive(server_name: str = None)
```

**Returns:**
- Source type and instance name
- DS version and configuration summary (ports, backends, suffixes, plugins, replication)
- Available data inventory (config, logs, schema, certificates)
- SOS healthcheck output if available

**Example prompts:**
- "What's available in this SOS report?"
- "Summarize the archive data"

---

### validate_configuration(server_name?)

Run static lint checks on dse.ldif configuration.

```
validate_configuration(server_name: str = None)
```

**Returns:**
- Security findings (password schemes, TLS settings, access control)
- Plugin configuration issues
- Replication configuration analysis
- Overall health assessment

---

### compare_dse_configs(server1, server2, section?)

Full entry-by-entry dse.ldif comparison between two servers.

```
compare_dse_configs(
    server1: str,
    server2: str,
    section: str = None
)
```

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| server1 | str | Yes | First server name (offline or archive) |
| server2 | str | Yes | Second server name (offline or archive) |
| section | str | No | Filter: plugins, indexes, replication, security, backends, config, all |

**Returns:** Entry-level differences, additions, removals, and attribute changes.

---

## Advanced Search

### ldap_search(base_dn, scope?, filter?, attributes?, attrs_only?, limit?, server_name?)

Run an arbitrary LDAP search (any base DN, scope, and filter) when no specialized tool fits. Prefer the purpose-built tools (user/group/config/replication) first; this is the escape hatch for advanced queries. LIVE only. Disabled in privacy mode (default) — set `LDAP_MCP_EXPOSE_SENSITIVE_DATA=true` to enable.

```
ldap_search(
    base_dn: str,
    scope: str = "SUBTREE",
    filter: str = "(objectClass=*)",
    attributes: str = None,
    attrs_only: bool = False,
    limit: int = 100,
    server_name: str = None
)
```

**Parameters:**
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| base_dn | str | Yes | - | Base DN to search from; empty string searches the root DSE (use scope=BASE) |
| scope | str | No | "SUBTREE" | Search scope: BASE, ONELEVEL, or SUBTREE |
| filter | str | No | "(objectClass=*)" | LDAP filter in RFC 4515 syntax |
| attributes | str | No | None (all) | Comma-separated attribute list; `*` = all user attributes, `+` = operational attributes |
| attrs_only | bool | No | False | Return attribute names only, without values |
| limit | int | No | 100 | Maximum entries to return (hard cap 1000) |
| server_name | str | No | - | Target server |

**Returns:** Entries as `{dn, attrs}` (non-UTF-8 values are base64-encoded), plus `total_returned`, `limit_applied`, and `truncated` (true when the server stopped at the limit and more entries exist).

---

## Resources

MCP resources provide read-only access to configuration data.

### config://config-all

Returns all `cn=config` attributes.

### config://config-attribute/{attribute}

Returns a single `cn=config` attribute.

---

## Privacy Mode

**Privacy mode is enabled by default.** Set `LDAP_MCP_EXPOSE_SENSITIVE_DATA=true` only in trusted environments (local models or approved private cloud instances).

When privacy mode is enabled (default):
- Hostnames, DNs, and suffixes are anonymized
- Sensitive configuration values are redacted
- Tools like `get_user_details`, `ldap_search`, and `search_users_by_attribute` are disabled (the latter would otherwise act as an exact-count oracle for attribute values); the `pattern` parameter of the `analyze_*_log` tools is rejected for the same reason
- List tools return counts only
- Safe for use with cloud-hosted LLMs
- Server names (the `name` field in `servers.json`) are **never** redacted — they are user-chosen labels that must remain stable across tool calls. Do not put hostnames, IPs, or other private information in server names.

**Warning:** Avoid enabling with public LLMs when connected to production directories. Test/sample data is fine.

Regardless of mode, credential material (`userPassword`, `nsslapd-rootpw`, `nsds5ReplicaCredentials`, certificate/key attributes) is never returned by any tool — password hashes have no diagnostic value.

---

## Local vs Remote Servers

Most tools work via LDAP for all servers. However, some features require local server access:

| Feature | Requires Local |
|---------|----------------|
| Disk space monitoring | Yes |
| Certificate checking | Yes |
| Access log analysis | Yes |
| Process memory/CPU | Yes |

To enable local features, configure the server with:
```json
{
  "is_local": true,
  "serverid": "slapd-instance"
}
```

## Offline Mode

Offline mode allows analyzing a stopped DS instance's configuration and logs without any LDAP connection. This is useful for post-mortem analysis or examining instances that cannot be started.

To configure a server for offline mode:
```json
{
  "is_local": true,
  "serverid": "slapd-instance",
  "is_offline": true
}
```

In offline mode:
- **Available:** Health checks (`first_look`, `run_healthcheck`), configuration tools (`get_server_configuration`, `compare_server_configurations`, `list_plugins`, `get_backend_configuration`), index tools (`list_indexes`, `analyze_index_configuration`, `find_unindexed_searches`), log tools (`parse_*` and privacy-safe `analyze_access_log` / `analyze_error_log` / `analyze_audit_log`), and the archive-analysis tools (`analyze_archive`, `validate_configuration`, `compare_dse_configs`)
- **Unavailable:** Tools requiring a live LDAP connection (user/group management, monitoring, performance metrics, replication, search) will return a `LiveServerRequired` error

## Archive Mode

Archive mode allows analyzing SOS reports or extracted configs from any machine without a running DS instance or local installation.

To configure:
```json
{
  "is_archive": true,
  "archive_path": "/path/to/sosreport-host-2025/"
}
```

For SOS reports with multiple instances, specify which one:
```json
{
  "is_archive": true,
  "archive_path": "/path/to/sosreport-host-2025/",
  "instance_name": "slapd-supplier1"
}
```

Or with explicit paths:
```json
{
  "is_archive": true,
  "config_path": "/path/to/etc/dirsrv/slapd-instance/",
  "logs_path": "/path/to/var/log/dirsrv/slapd-instance/"
}
```

`archive_path` accepts both directories and `.tar.xz`/`.tar.gz` tarballs (auto-extracted to a temp directory).

Archive auto-detection supports:
- **SOS reports** (standard `etc/dirsrv/slapd-*/` + `var/log/dirsrv/` layout)
- **Direct instance directories** (`slapd-*/dse.ldif`)
- **Config-only** (directory containing just `dse.ldif`)

In archive mode:
- **Available:** The same tool set as offline mode (`analyze_archive`, `validate_configuration`, and `compare_dse_configs` work in both offline and archive modes)
- **Unavailable:** All tools requiring a live LDAP connection

---

## Example Workflows

### Health Check Workflow

```
You: "Check the health of all servers"
Assistant: [Calls first_look()]
Result: Summary of all server health status

You: "ds-prod1 shows high load, investigate"
Assistant: [Calls get_performance_summary("ds-prod1")]
Result: Detailed performance metrics and bottleneck analysis
```

### Replication Troubleshooting

```
You: "Check replication status"
Assistant: [Calls get_replication_status()]
Result: Replica status with any lag or errors

You: "Show me the topology"
Assistant: [Calls get_replication_topology()]
Result: Complete topology map with all agreements
```

### User Investigation

```
You: "Show me all locked users"
Assistant: [Calls list_locked_users()]
Result: List of locked accounts

You: "Show me details for jdoe"
Assistant: [Calls get_user_details("jdoe")]
Result: Full user details including lock reason
```

### Performance Tuning

```
You: "Is the cache configured well?"
Assistant: [Calls get_cache_statistics()]
Result: Cache hit ratios with recommendations

You: "Are there unindexed searches?"
Assistant: [Calls find_unindexed_searches()]
Result: Search patterns needing indexes
```

---

## Prompts

Prompts provide guided multi-step investigation workflows.

| Prompt | Description |
|--------|-------------|
| `tool_navigator(goal)` | Recommends which tools to use for a given goal |
| `diagnose_replication()` | Guided replication troubleshooting session |
| `performance_investigation()` | Guided performance investigation session |
| `daily_health_check()` | Comprehensive daily health check workflow |
| `troubleshoot_connectivity()` | Guided connectivity troubleshooting session |
| `archive_investigation()` | Guided SOS report / archive analysis session |
