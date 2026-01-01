# 389 Directory Server Tools Reference

Complete reference for all 389 DS MCP tools, resources, and prompts.

This documentation covers the `dirsrv_mcp` provider which uses [lib389](https://lib389.readthedocs.io/) for 389 Directory Server operations.

---

## Health & Diagnostics

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

Get comprehensive replication status for a server.

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

Map the complete replication topology across all configured servers.

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

Analyze replication lag across agreements by comparing CSN values.

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

Find all replication conflict and glue entries.

```
list_replication_conflicts(base_dn: str = None, server_name: str = None)
```

**Returns:**
- List of conflict entries with details
- List of glue entries
- Resolution recommendations

---

### get_agreement_status(agreement_name?, suffix?, server_name?)

Get detailed status for replication agreements.

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

Comprehensive performance overview in a single call.

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

Analyze database and entry cache efficiency.

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

Analyze connection patterns and resource usage.

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

Get operation counts and performance metrics.

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

Analyze worker thread utilization.

```
get_thread_statistics(server_name: str = None)
```

**Returns:**
- Current thread count and configuration
- Connections at max threads
- Utilization assessment

---

### get_resource_utilization(server_name?)

Get system resource usage.

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

**Note:** Requires local server access (is_local=True with serverid).

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

### list_all_users(limit?)

Enumerate all users in the directory.

```
list_all_users(limit: int = 50)
```

**Parameters:**
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| limit | int | No | 50 | Maximum users to return |

**Returns:** List of users with basic attributes (uid, cn, mail, status).

---

### search_users_by_name(name, limit?)

Search for users by name or email.

```
search_users_by_name(name: str, limit: int = 50)
```

**Example prompts:**
- "Find users named John"
- "Search for smith@example.com"

---

### get_user_details(username)

Get complete details for a specific user.

```
get_user_details(username: str)
```

**Returns:** All user attributes including account status and group memberships.

---

### list_active_users(limit?)

List only active (unlocked) users.

```
list_active_users(limit: int = 50)
```

---

### list_locked_users(limit?)

List only locked users with lock reason.

```
list_locked_users(limit: int = 50)
```

---

### search_users_by_attribute(attr, value, limit?)

Search for users by any LDAP attribute.

```
search_users_by_attribute(attr: str, value: str, limit: int = 50)
```

**Example prompts:**
- "Find users in the Engineering department"
- "Search for users with title Manager"

---

## Group Management

### list_all_groups(limit?)

Enumerate all groups with member counts.

```
list_all_groups(limit: int = 50)
```

---

## Monitoring

### run_monitor(backend?, suffix?)

Get server and backend monitor data.

```
run_monitor(backend: str = "", suffix: str = "")
```

**Returns:** Monitor metrics including connections, operations, and backend statistics.

---

## Advanced Search

### ldap_search(base_dn, scope?, filter?, attributes?, limit?)

Full LDAP search with complete control over parameters.

```
ldap_search(
    base_dn: str,
    scope: str = "subtree",
    filter: str = "(objectClass=*)",
    attributes: list = None,
    limit: int = 100
)
```

**Parameters:**
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| base_dn | str | Yes | - | Base DN to search from |
| scope | str | No | "subtree" | Search scope: base, onelevel, subtree |
| filter | str | No | "(objectClass=*)" | LDAP filter |
| attributes | list | No | None (all) | Attributes to return |
| limit | int | No | 100 | Maximum entries to return |

---

## Resources

MCP resources provide read-only access to configuration data.

### config://config-all

Returns all `cn=config` attributes.

### config://config-attribute/{attribute}

Returns a single `cn=config` attribute.

---

## Privacy Mode

Set `LDAP_MCP_EXPOSE_SENSITIVE_DATA=false` to enable privacy mode. When enabled:
- Server names, hostnames, and DNs are anonymized
- Sensitive configuration values are redacted
- Safe for sharing diagnostic output with external parties

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
