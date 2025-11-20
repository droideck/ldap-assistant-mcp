# LDAP Assistant MCP

> **⚠️ Experimental Project - Active Development**
> This is an experimental MCP server in early development. Current focus: building foundational architecture and health diagnostics for 389 Directory Server. Not production-ready.

## Project Intent

LDAP Assistant MCP aims to be a **multi-directory health and diagnostics assistant** that transforms how support engineers and LDAP administrators troubleshoot directory services.

The assistant:
- **Rapidly assesses** health across all configured LDAP servers
- **Identifies root causes** with actionable findings (severity, impact, remediation)
- **Guides troubleshooting** following "What's wrong?" → "Why?" → "How to fix?" workflow

Instead of manually checking servers, ask:
- "What's wrong across all my servers?"
- "Show me all locked users"
- "Which servers have connection issues?"

## Current Status

### What's Implemented ✅

**Architecture & Foundation:**
- ✅ Modular server layout (`src/ldap_assistant_mcp/`, `src/dirsrv_mcp/`, `src/openldap_mcp/`)
- ✅ Multi-server connection management (concurrent server support)
- ✅ JSON-based multi-server configuration
- ✅ Shared utilities library
- ✅ MCP server with FastMCP

**389 Directory Server Provider:**
- ✅ Full implementation using lib389
- ✅ Connection pooling and management
- ✅ User account status computation with fallback logic

**Health & Diagnostics:**
- ✅ `first_look()` - Multi-server quick health overview
- `replication_status()` - Replication agreement health and lag detection
- `performance_summary()` - Thread/connection/cache metrics and bottlenecks
- `indexing_analysis()` - Index configuration and unindexed search detection
- `aci_audit()` - Access control validation and security checks

**User Management Tools:**
- ✅ `list_all_users()` - Enumerate all users
- ✅ `search_users_by_name()` - Search by name/email
- ✅ `get_user_details()` - Get full user details
- ✅ `list_active_users()` - List only active/unlocked users
- ✅ `list_locked_users()` - List only locked users
- ✅ `search_users_by_attribute()` - Search by any attribute

**Group & Directory Tools:**
- ✅ `list_all_groups()` - Enumerate groups
- ✅ `ldap_search()` - Generic LDAP search with full control
- ✅ `run_monitor()` - Server and backend monitoring

**MCP Resources:**
- ✅ `config://config-all` - All cn=config attributes
- ✅ `config://config-attribute/{attribute}` - Single cn=config attribute

**Supported Platforms:**
- ✅ **389 Directory Server**
- 🚧 **OpenLDAP**

## Getting Started

### Prerequisites

- Python 3.13+
- `uv` package manager
- 389 Directory Server or OpenLDAP
- Optional: MCP client (Claude Code, Cursor, Gemini CLI, etc.)

### Quick Setup

**1. Install dependencies:**
```bash
uv venv
uv pip install -r requirements.txt
```

**2. Configure servers:**

**Option A - Single Server (Environment Variables):**
```bash
export LDAP_URL="ldap://localhost:3389"
export LDAP_BASE_DN="dc=test,dc=com"
export LDAP_BIND_DN="cn=Directory Manager"
export LDAP_BIND_PASSWORD="TestPassword123"
```

**Option B - Multiple Servers (JSON Config):**
```json
{
  "servers": [
    {
      "name": "prod-ds1",
      "ldap_url": "ldap://ds1.example.com:389",
      "base_dn": "dc=example,dc=com",
      "bind_dn": "cn=Directory Manager",
      "bind_password": "secret",
      "provider_type": "389ds"
    }
  ]
}
```

```bash
export LDAP_SERVERS_CONFIG="./servers.json"
```

**3. Run the server (DirSrv by default):**
```bash
# DirSrv
uv run server.py

# Explicit provider choice (e.g., OpenLDAP)
uv run server.py openldap --hostname ldap.example.com --bind-dn "cn=admin,dc=example,dc=com"
```

### Testing with 389 DS Container

```bash
# All-in-one: create container, seed data, run tests
./scripts/dev-test.sh

# Or manually
./scripts/ds-create.sh --password TestPassword123 --base-dn dc=test,dc=com ds-test
```

## Example Usage

### Health Check Example

```bash
uv run mcp-cli cmd \
  --provider=ollama \
  --model=qwen3 \
  --server ldap-assistant \
  --prompt "Check the health of all servers"
```

### User Management Examples

```bash
# List locked accounts
uv run mcp-cli cmd --server ldap-assistant \
  --prompt "show me all locked users"

# Find specific users
uv run mcp-cli cmd --server ldap-assistant \
  --prompt "find users in the Engineering department"

# Get user details
uv run mcp-cli cmd --server ldap-assistant \
  --prompt "show me details for user jdoe"
```

## MCP Tools Reference

### Health & Diagnostics
- **`first_look()`** - Quick health overview across all configured servers
- **`replication_status(server_name)`** - Check all replication agreements for lag/failures
- **`performance_summary(server_name)`** - Identify performance bottlenecks
- **`indexing_analysis(server_name, attribute?, backend?)`** - Detect indexing issues
- **`aci_audit(server_name, base_dn?)`** - Validate access control configurations

### User Management
- **`list_all_users(limit=50)`** - Enumerate all users
- **`search_users_by_name(name, limit=50)`** - Search by name/email
- **`get_user_details(username)`** - Get full user details
- **`list_active_users(limit=50)`** - List active/unlocked users
- **`list_locked_users(limit=50)`** - List locked users
- **`search_users_by_attribute(attr, value, limit=50)`** - Search by any attribute

### Group Management
- **`list_all_groups(limit=50)`** - Enumerate groups

### Monitoring
- **`run_monitor(backend="", suffix="")`** - Get server/backend monitor data

### Advanced
- **`ldap_search(base_dn, scope, filter, ...)`** - Full LDAP search control

### Resources
- **`config://config-all`** - All cn=config attributes
- **`config://config-attribute/{attr}`** - Single cn=config attribute

### Prompts
- **`Tool Navigator`** - Guides tool selection for directory tasks

## Architecture

The project uses a **modular server architecture**:

```
ldap-assistant-mcp/
├── src/
│   ├── ldap_assistant_mcp/  # Base LDAP Assistant server + config dataclasses
│   ├── dirsrv_mcp/          # 389 DS implementation
│   ├── openldap_mcp/        # OpenLDAP implementation
│   ├── lib/                 # Shared utilities
│   └── config/              # Configuration management
├── src/main.py              # CLI entry point
├── server.py                # Legacy shim → src/main.py
└── tests/                # Test suite
```

## Client Configuration

### Claude Code
```bash
claude mcp add ldap-assistant \
  --env LDAP_BIND_PASSWORD=Password \
  -- uv run server.py
```

### MCP CLI
```json
{
  "mcpServers": {
    "ldap-assistant": {
      "command": "/path/to/uv",
      "args": ["--directory", "/path/to/ldap-assistant-mcp", "run", "server.py"],
      "env": {
        "LDAP_SERVERS_CONFIG": "/path/to/servers.json"
      }
    }
  }
}
```

## Use Cases

### Support Engineers
- ✅ Rapid root cause analysis during incidents
- ✅ Quick health scans across customer topologies
- 🚧 Identify replication failures (wireframes ready)
- 🚧 Performance bottleneck analysis (wireframes ready)
- 🚧 Get immediate remediation guidance

### LDAP Administrators
- ✅ Proactive monitoring of production services
- ✅ Catch issues before they become outages
- 🚧 Performance tuning with metrics (wireframes ready)
- 🚧 Access control security audits (wireframes ready)
- 🚧 Routine health checks with reports

### Advanced Users
- ✅ Self-service health checks
- ✅ Guided troubleshooting
- 🚧 Automated health reports

## Development & Testing

### Running Tests
```bash
# All-in-one: container + tests
./scripts/dev-test.sh

# Manual testing
export LDAP_URL="ldap://localhost:3389"
export LDAP_BASE_DN="dc=test,dc=com"
export LDAP_BIND_DN="cn=Directory Manager"
export LDAP_BIND_PASSWORD="TestPassword123"
uv run pytest tests/ -v -s
```

### Project Structure
- `src/ldap_assistant_mcp/` - Base FastMCP server + shared config objects
- `src/dirsrv_mcp/` - 389 DS implementation (connection manager, tools, health)
- `src/openldap_mcp/` - OpenLDAP implementation
- `src/lib/` - Shared utilities (datetime, formatting, LDAP helpers)
- `src/config/` - Configuration loader
- `src/main.py` - Argparse CLI (provider selection, overrides)
- `server.py` - Legacy shim to `src/main.py`
- `tests/` - Test suite

## Limitations & Constraints

**Current State:**
- ⚠️ **Experimental** - APIs subject to change
- ⚠️ **Not production-ready** - Designed for local/testing/support scenarios
- ⚠️ **Read-only** - No write operations yet (planned)
- ⚠️ **Advanced diagnostics in development** - Replication, performance, indexing, ACI tools  have wireframes ready
- ⚠️ **Plain text passwords** - Use restrictive file permissions on config files
- ⚠️ **STDIO transport only** - No HTTP/SSE support yet

**Design Decisions:**
- Single-shot connections (no persistent connection pooling per tool call)
- JSON configuration for multi-server setups
- Provider-based architecture for platform-specific implementations

## References

- [Model Context Protocol](https://modelcontextprotocol.io/introduction)
- [389 Directory Server](https://www.port389.org/docs/389ds/documentation.html)
- [MCP Python SDK](https://pypi.org/project/mcp/)
- [mcp-cli (example CLI)](https://github.com/chrishayuk/mcp-cli)

---

**Note:** This is an experimental project under active development. Features and APIs are subject to change. We recommend using it in local/testing environments until it reaches a stable release.
