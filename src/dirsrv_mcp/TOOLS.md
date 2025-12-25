# 389 Directory Server Tools Reference

Complete reference for all 389 DS MCP tools, resources, and prompts.

This documentation covers the `dirsrv_mcp` provider which uses [lib389](https://lib389.readthedocs.io/) for 389 Directory Server operations.

## Health & Diagnostics

### first_look()

Quick health overview across all configured servers.

```
first_look()
```

**Returns:** Multi-server health summary including connectivity, basic metrics, and any critical issues.

**Example prompts:**
- "Check the health of all servers"
- "What's wrong across all my servers?"
- "Give me a quick overview"

---

### replication_status(server_name)

Check all replication agreements for a server, detecting lag and failures.

```
replication_status(server_name: str)
```

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| server_name | str | Yes | Name of the server to check |

**Returns:** Replication agreement status, lag detection, and failure analysis.

**Example prompts:**
- "Check replication status for ds-prod1"
- "Are there any replication issues?"
- "Show me replication lag"

---

### performance_summary(server_name)

Identify performance bottlenecks with thread, connection, and cache metrics.

```
performance_summary(server_name: str)
```

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| server_name | str | Yes | Name of the server to analyze |

**Returns:** Performance metrics including thread utilization, connection counts, and cache hit rates.

**Example prompts:**
- "Give me a performance summary for ds-prod1"
- "Is the server overloaded?"
- "Show me cache hit rates"

---

### indexing_analysis(server_name, attribute?, backend?)

Detect indexing issues and unindexed search problems.

```
indexing_analysis(server_name: str, attribute: str = None, backend: str = None)
```

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| server_name | str | Yes | Name of the server to analyze |
| attribute | str | No | Specific attribute to check |
| backend | str | No | Specific backend to check |

**Returns:** Index configuration, unindexed search detection, and recommendations.

**Example prompts:**
- "Check indexing for ds-prod1"
- "Are there unindexed searches?"
- "Show me index configuration for userRoot"

---

### aci_audit(server_name, base_dn?)

Validate access control configurations and identify security issues.

```
aci_audit(server_name: str, base_dn: str = None)
```

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| server_name | str | Yes | Name of the server to audit |
| base_dn | str | No | Base DN to start audit from |

**Returns:** ACI analysis, security findings, and recommendations.

**Example prompts:**
- "Audit ACIs on ds-prod1"
- "Check access control security"
- "Show me all ACIs under ou=People"

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

**Example prompts:**
- "Show me all users"
- "List the first 100 users"
- "Who are the users on this server?"

---

### search_users_by_name(name, limit?)

Search for users by name or email.

```
search_users_by_name(name: str, limit: int = 50)
```

**Parameters:**
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| name | str | Yes | - | Name or email to search for |
| limit | int | No | 50 | Maximum users to return |

**Returns:** Matching users with basic attributes.

**Example prompts:**
- "Find users named John"
- "Search for smith@example.com"
- "Who has 'admin' in their name?"

---

### get_user_details(username)

Get complete details for a specific user.

```
get_user_details(username: str)
```

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| username | str | Yes | Username (uid) to look up |

**Returns:** All user attributes including account status, group memberships, and metadata.

**Example prompts:**
- "Show me details for jdoe"
- "Get user info for admin"
- "What groups is jsmith in?"

---

### list_active_users(limit?)

List only active (unlocked) users.

```
list_active_users(limit: int = 50)
```

**Parameters:**
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| limit | int | No | 50 | Maximum users to return |

**Returns:** List of active users with basic attributes.

**Example prompts:**
- "Show me all active users"
- "List unlocked users"
- "Who can currently log in?"

---

### list_locked_users(limit?)

List only locked users.

```
list_locked_users(limit: int = 50)
```

**Parameters:**
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| limit | int | No | 50 | Maximum users to return |

**Returns:** List of locked users with lock reason when available.

**Example prompts:**
- "Show me all locked users"
- "Who is locked out?"
- "List disabled accounts"

---

### search_users_by_attribute(attr, value, limit?)

Search for users by any LDAP attribute.

```
search_users_by_attribute(attr: str, value: str, limit: int = 50)
```

**Parameters:**
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| attr | str | Yes | - | Attribute name to search |
| value | str | Yes | - | Value to match (supports wildcards) |
| limit | int | No | 50 | Maximum users to return |

**Returns:** Matching users with basic attributes.

**Example prompts:**
- "Find users in the Engineering department"
- "Search for users with title Manager"
- "Who has employeeNumber 12345?"

---

## Group Management

### list_all_groups(limit?)

Enumerate all groups in the directory.

```
list_all_groups(limit: int = 50)
```

**Parameters:**
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| limit | int | No | 50 | Maximum groups to return |

**Returns:** List of groups with member counts.

**Example prompts:**
- "Show me all groups"
- "List the first 100 groups"
- "What groups exist?"

---

## Monitoring

### run_monitor(backend?, suffix?)

Get server and backend monitor data.

```
run_monitor(backend: str = "", suffix: str = "")
```

**Parameters:**
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| backend | str | No | "" | Specific backend to monitor |
| suffix | str | No | "" | Suffix to filter by |

**Returns:** Monitor metrics including connections, operations, and backend statistics.

**Example prompts:**
- "Show me server monitor"
- "Get monitor data for userRoot backend"
- "What are the current connection stats?"

---

## Advanced

### ldap_search(base_dn, scope, filter, ...)

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

**Returns:** Raw LDAP search results.

**Example prompts:**
- "Search for all entries under ou=People"
- "Find objects with objectClass=groupOfNames"
- "Show me entries matching (mail=*@example.com)"

---

## Resources

MCP resources provide read-only access to configuration data.

### config://config-all

Returns all `cn=config` attributes.

**Example:** "Show me the server configuration"

### config://config-attribute/{attribute}

Returns a single `cn=config` attribute.

**Example:** "What is nsslapd-maxconnections set to?"

---

## Prompts

### Tool Navigator

Guides tool selection for directory tasks. Helps you choose the right tool based on what you're trying to accomplish.

**Invocation:** The assistant uses this automatically to select appropriate tools.

---

## Example Usage

### Health Check Workflow

```
You: "Check the health of all servers"
Assistant: [Calls first_look()]
Result: Summary of all server health status

You: "ds-prod1 shows high load, investigate"
Assistant: [Calls performance_summary("ds-prod1")]
Result: Detailed performance metrics and bottleneck analysis
```

### User Investigation Workflow

```
You: "Show me all locked users"
Assistant: [Calls list_locked_users()]
Result: List of locked accounts

You: "Show me details for jdoe"
Assistant: [Calls get_user_details("jdoe")]
Result: Full user details including lock reason
```

### Custom Search Workflow

```
You: "Find all users in the Engineering department who are managers"
Assistant: [Calls ldap_search with appropriate filter]
Result: Matching entries
```
