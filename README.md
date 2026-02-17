# LDAP Assistant MCP

[![Version](https://img.shields.io/badge/version-0.3.0-blue.svg)](CHANGELOG.md)

> **Experimental Project - Active Development**
> This is an experimental MCP server in early development. Current focus: building foundational architecture and health diagnostics for 389 Directory Server. Not production-ready.

## Overview

LDAP Assistant MCP is a **multi-directory health and diagnostics assistant** that transforms how support engineers and LDAP administrators troubleshoot directory services.

Instead of manually checking servers, ask:
- "What's wrong across all my servers?"
- "Show me all locked users"
- "Which servers have connection issues?"

The assistant:
- **Rapidly assesses** health across all configured LDAP servers
- **Identifies root causes** with actionable findings (severity, impact, remediation)
- **Guides troubleshooting** following "What's wrong?" → "Why?" → "How to fix?" workflow

## Capabilities

### Health & Diagnostics
- `first_look()` - Multi-server quick health overview with prioritized findings
- `run_healthcheck()` - Full health check equivalent to `dsctl healthcheck`
- Connection, thread, cache, disk, and certificate monitoring

### Replication
- `get_replication_status()` - Comprehensive status with RUV analysis
- `get_replication_topology()` - Map complete topology across all servers
- `check_replication_lag()` - CSN comparison and lag detection
- `list_replication_conflicts()` - Find conflict and glue entries

### Performance
- `get_performance_summary()` - Combined metrics with recommendations
- Cache, connection, operation, thread, and resource statistics
- Automatic bottleneck detection and tuning recommendations

### Index Analysis
- `list_indexes()` - Index listing with VLV support
- `analyze_index_configuration()` - Best practices analysis
- `find_unindexed_searches()` - Access log parsing for optimization

### Configuration
- `get_server_configuration()` - Dynamic cn=config retrieval
- `compare_server_configurations()` - Multi-server comparison
- `list_plugins()` - Plugin enumeration with status
- `get_backend_configuration()` - Backend-specific settings

### Log Analysis
- `parse_access_log()` / `parse_error_log()` / `parse_audit_log()` - Parse and filter log entries (disabled in privacy mode)
- `analyze_access_log()` / `analyze_error_log()` / `analyze_audit_log()` - Statistics-only log analysis (works in privacy mode)

### Archive & Offline Analysis
- `analyze_archive()` - Inventory and summarize SOS report / archive data
- `validate_configuration()` - Static config lint on dse.ldif
- `compare_dse_configs()` - Full entry-by-entry dse.ldif comparison

### User & Group Management
- List, search, and inspect users
- Filter by active/locked status
- Search by any LDAP attribute
- Enumerate groups

### Advanced
- Generic LDAP search with full control
- Configuration resource access
- Privacy mode for sensitive data protection

**Tools documentation:** [389 DS](src/dirsrv_mcp/TOOLS.md) | [OpenLDAP](src/openldap_mcp/TOOLS.md)

## Quick Start

### Prerequisites

- Python 3.13+
- `uv` package manager
- MCP client (Claude Desktop, Claude Code, Cursor, Gemini CLI, etc.)
- Access to LDAP server(s) (389 Directory Server only, for now)

### Step 1: Clone and Install Dependencies

```bash
git clone https://github.com/droideck/ldap-assistant-mcp.git
cd ldap-assistant-mcp

# Create virtual environment and install dependencies
uv venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
uv pip install -r requirements.txt
```

### Step 2: Configure Your Servers

Create a `servers.json` file with your LDAP server(s):

```json
{
  "servers": [
    {
      "name": "local-ds",
      "ldap_url": "ldap://localhost:389",
      "base_dn": "dc=example,dc=com",
      "bind_dn": "cn=Directory Manager",
      "bind_password": "your-password",
      "provider_type": "389ds",
      "is_local": true,
      "serverid": "slapd-localhost"
    },
    {
      "name": "remote-ds",
      "ldap_url": "ldap://ldap.example.com:389",
      "base_dn": "dc=example,dc=com",
      "bind_dn": "cn=Directory Manager",
      "bind_password": "your-password",
      "provider_type": "389ds"
    },
    {
      "name": "stopped-ds",
      "ldap_url": "ldap://localhost:389",
      "base_dn": "dc=example,dc=com",
      "bind_dn": "cn=Directory Manager",
      "bind_password": "unused-in-offline-mode",
      "provider_type": "389ds",
      "is_local": true,
      "serverid": "slapd-localhost",
      "is_offline": true
    },
    {
      "name": "sos-report",
      "provider_type": "389ds",
      "is_archive": true,
      "archive_path": "/path/to/sosreport-host-2025/",
      "instance_name": "slapd-instance"
    }
  ]
}
```

**Server modes:**
- **Remote servers** work via LDAP only - most tools work, but some local-only features are unavailable
- **Local servers** (`is_local: true` + `serverid`) enable additional diagnostics: disk space monitoring, certificate checking, access log analysis, and process metrics
- **Offline servers** (`is_offline: true` + `is_local: true` + `serverid`) analyze a stopped instance's configuration and logs without any LDAP connection. Useful for post-mortem analysis or examining instances that can't be started
- **Archive servers** (`is_archive: true` + `archive_path`) analyze SOS reports or extracted configs from any machine. Auto-detects archive structure (SOS layout, manual extracts, config-only). No LDAP connection, no local instance required

### Step 3: Install to MCP Client

```bash
# For Claude Desktop
fastmcp install claude-desktop fastmcp.json

# For Claude Code
fastmcp install claude-code fastmcp.json
```

### Step 4: Configure the MCP Client

After installation, edit your MCP client configuration to include the path to your `servers.json`:

**Claude Desktop** (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):
```json
{
  "mcpServers": {
    "ldap-assistant-mcp": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/ldap-assistant-mcp", "fastmcp", "run", "src/main.py:create_server"],
      "env": {
        "LDAP_SERVERS_CONFIG": "/path/to/your/servers.json"
      }
    }
  }
}
```

Alternatively, for a single server you can use environment variables instead of `servers.json`:
```json
{
  "env": {
    "LDAP_URL": "ldap://localhost:389",
    "LDAP_BASE_DN": "dc=example,dc=com",
    "LDAP_BIND_DN": "cn=Directory Manager",
    "LDAP_BIND_PASSWORD": "your-password"
  }
}
```

### Step 5: Restart Your MCP Client

Restart Claude Desktop or Claude Code to load the new MCP server. You should now see LDAP Assistant tools available.

### Verify Connection

Ask Claude Desktop:
- "Check the health of all servers"
- "Show me all users"
- "List all configured servers"

### No LDAP Server? Use the Dev Environment

If you don't have an LDAP server to connect to, see the [Development Guide](docs/DEVELOPMENT.md) to spin up test containers with Docker.

## Supported Platforms

- **389 Directory Server** - Full support
- **OpenLDAP** - In development

## Use Cases

### Support Engineers
- Rapid root cause analysis during incidents
- Quick health scans across customer topologies
- Immediate remediation guidance

### LDAP Administrators
- Proactive monitoring of production services
- Performance tuning with metrics
- Access control security audits

## Privacy Mode

By default, **privacy mode is enabled** - sensitive data (server names, DNs, hostnames, user details) is redacted from tool outputs. Tools that expose individual entries (`get_user_details`, `ldap_search`) are disabled; list tools return counts only.

To enable full data access in **trusted environments only**:

```json
{
  "env": {
    "LDAP_MCP_EXPOSE_SENSITIVE_DATA": "true"
  }
}
```

**Important:** Only enable this with local models, private cloud LLM instances, or when working with test/sample data. Avoid enabling with public LLMs when connected to production directories - your directory information could be included in their training data or logs.

When privacy mode is enabled (default):
- Server names, hostnames, and DNs are anonymized
- Configuration values are redacted
- Sensitive tools are disabled
- Diagnostic metrics (counts, ratios, percentages) remain visible

## Limitations

- **Experimental** - APIs subject to change, early-stage software
- **LLM interpretation** - Tools return accurate data, but the LLM interprets it. Hallucinations are possible. Always verify recommendations before acting.
- **Read-only** - No write operations yet
- **Plain text passwords** - Use restrictive file permissions on config files
- **STDIO transport only** - No HTTP/SSE support yet

## Documentation

| Document | Description |
|----------|-------------|
| [Changelog](CHANGELOG.md) | Version history and release notes |
| [Development Guide](docs/DEVELOPMENT.md) | Dev environment setup, configuration, architecture |
| [Testing Guide](docs/TESTING.md) | Running and writing tests |
| [Contributing Guide](docs/CONTRIBUTING.md) | How to contribute |
| [389 DS Tools](src/dirsrv_mcp/TOOLS.md) | 389 Directory Server tools reference |
| [OpenLDAP Tools](src/openldap_mcp/TOOLS.md) | OpenLDAP tools reference (in development) |

## References

- [Model Context Protocol](https://modelcontextprotocol.io/introduction)
- [389 Directory Server](https://www.port389.org/docs/389ds/documentation.html)
- [FastMCP 2.0](https://gofastmcp.com)

---

**Note:** This is an experimental project under active development. Features and APIs are subject to change.
