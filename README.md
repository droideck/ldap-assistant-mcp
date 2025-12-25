# LDAP Assistant MCP

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
- `first_look()` - Multi-server quick health overview
- `replication_status()` - Replication agreement health and lag detection
- `performance_summary()` - Thread/connection/cache metrics and bottlenecks
- `indexing_analysis()` - Index configuration and unindexed search detection
- `aci_audit()` - Access control validation and security checks

### User & Group Management
- List, search, and inspect users
- Filter by active/locked status
- Search by any LDAP attribute
- Enumerate groups

### Monitoring & Advanced
- Server and backend monitor data
- Generic LDAP search with full control
- Configuration resource access

**Tools documentation:** [389 DS](src/dirsrv_mcp/TOOLS.md) | [OpenLDAP](src/openldap_mcp/TOOLS.md)

## Quick Start

### Prerequisites

- Python 3.13+
- `uv` package manager
- MCP client (Claude Desktop, Claude Code, Cursor, Gemini CLI, etc.)
- Access to LDAP server(s) (389 Directory Server only, for now)

### Step 1: Configure Your Servers

Create a `servers.json` file with your LDAP server(s):

```json
{
  "servers": [
    {
      "name": "my-server",
      "ldap_url": "ldap://ldap.example.com:389",
      "base_dn": "dc=example,dc=com",
      "bind_dn": "cn=Directory Manager",
      "bind_password": "your-password",
      "provider_type": "389ds"
    }
  ]
}
```

### Step 2: Install to Claude Desktop

```bash
fastmcp install claude-desktop fastmcp.json
```

### Step 3: Restart Claude Desktop

Restart to load the new MCP server. You should now see LDAP Assistant tools available.

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

## Limitations

- **Experimental** - APIs subject to change
- **Not production-ready** - Designed for local/testing/support scenarios
- **Read-only** - No write operations yet
- **Plain text passwords** - Use restrictive file permissions on config files
- **STDIO transport only** - No HTTP/SSE support yet

## Documentation

| Document | Description |
|----------|-------------|
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
