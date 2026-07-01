# LDAP Assistant MCP

<!-- mcp-name: io.github.droideck/ldap-assistant-mcp -->

[![Version](https://img.shields.io/badge/version-0.4.0-blue.svg)](CHANGELOG.md)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)

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

**Tools documentation:** [389 DS](src/ldap_assistant_mcp/dirsrv_mcp/TOOLS.md) | [OpenLDAP](src/ldap_assistant_mcp/openldap_mcp/TOOLS.md)

## Quick Start

### Prerequisites

- Linux (primary) or macOS. Windows is not supported natively (python-ldap has no official Windows wheels) — use WSL2
- Python 3.11+ (3.13 is what CI tests against)
- `uv` package manager
- MCP client (Claude Desktop, Claude Code, Cursor, Gemini CLI, etc.)
- Access to LDAP server(s) (389 Directory Server only, for now)
- System development libraries (needed to build `python-ldap`):

  **Fedora / RHEL / CentOS:**
  ```bash
  sudo dnf install python3-devel openldap-devel cyrus-sasl-devel openssl-devel gcc
  ```

  **Ubuntu / Debian:**
  ```bash
  sudo apt install python3-dev libldap2-dev libsasl2-dev libssl-dev gcc
  ```

  **macOS (Homebrew):**
  ```bash
  brew install openldap
  export LDFLAGS="-L$(brew --prefix openldap)/lib"
  export CPPFLAGS="-I$(brew --prefix openldap)/include"
  ```

### Step 1: Clone and Install Dependencies

```bash
git clone https://github.com/droideck/ldap-assistant-mcp.git
cd ldap-assistant-mcp

# Create virtual environment and install dependencies
uv venv
source .venv/bin/activate
uv pip install -e .[dev]
```

### Step 2: Configure Your Servers

Create a `servers.json` file with your LDAP server(s). **Note:** The `name` field is never redacted in privacy mode — it is passed as-is to AI agents so they can reference servers across tool calls. Do not put hostnames, IPs, or other private information in server names.

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
      "serverid": "localhost"
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
      "serverid": "localhost",
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

**Note:** `serverid` is the instance name *without* the `slapd-` prefix (e.g. `localhost` for the instance `slapd-localhost`).

**Server modes:**
- **Remote servers** work via LDAP only - most tools work, but some local-only features are unavailable
- **Local servers** (`is_local: true` + `serverid`) enable additional diagnostics: disk space monitoring, certificate checking, access log analysis, and process metrics
- **Offline servers** (`is_offline: true` + `is_local: true` + `serverid`) analyze a stopped instance's configuration and logs without any LDAP connection. Useful for post-mortem analysis or examining instances that can't be started
- **Archive servers** (`is_archive: true` + `archive_path`) analyze SOS reports or extracted configs from any machine. Auto-detects archive structure (SOS layout, manual extracts, config-only). No LDAP connection, no local instance required

**Remote LDAPS certificate verification:** remote `ldaps://` servers verify the server certificate by default (`"tls_verify": true`, or the `LDAP_TLS_VERIFY` environment variable for env-based config). To connect to a server with a self-signed or otherwise untrusted certificate, set `"tls_verify": false` on that server entry — this disables certificate verification entirely, so use it only for trusted lab environments. Local instances (`is_local: true`) instead use the instance's own NSS certificate directory.

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
      "args": ["run", "--directory", "/path/to/ldap-assistant-mcp", "fastmcp", "run", "src/ldap_assistant_mcp/main.py:create_server"],
      "env": {
        "LDAP_SERVERS_CONFIG": "/path/to/your/servers.json"
      }
    }
  }
}
```

Use an **absolute path** for `LDAP_SERVERS_CONFIG` — relative paths resolve against the MCP client's working directory, which is usually not the repo root.

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

## Environment Variable Reference

| Variable | Default | Purpose |
|----------|---------|---------|
| `LDAP_SERVERS_CONFIG` | – | Absolute path to `servers.json` (multi-server config; preferred) |
| `LDAP_PROVIDER` | `dirsrv` | Server implementation: `dirsrv` (389 DS) or `openldap` (experimental) |
| `LDAP_MCP_EXPOSE_SENSITIVE_DATA` | `false` | Disable privacy mode (see [Privacy Mode](#privacy-mode)) |
| `LDAP_MCP_DEBUG` | `false` | Enable debug logging and tracebacks in tool errors |
| `LDAP_MCP_TOOL_TIMEOUT` | `30` | Per-tool-call timeout in seconds |
| `LDAP_MCP_MAX_TOOL_TIMEOUT` | `120` | Timeout ceiling for heavy tools (`first_look`, archive comparison, …) |
| `LDAP_CONNECT_TIMEOUT` | `30` | LDAP network/operation timeout in seconds (prevents hangs on unreachable servers) |

Single-server fallback (used only when `LDAP_SERVERS_CONFIG` is not set):

| Variable | Default | Purpose |
|----------|---------|---------|
| `LDAP_URL` | – | Full LDAP URL (alternative to hostname/port/SSL vars) |
| `LDAP_HOSTNAME` / `LDAP_PORT` / `LDAP_USE_SSL` | `localhost` / `389` / `false` | Connection parameters |
| `LDAP_BASE_DN` | – | Default search base |
| `LDAP_BIND_DN` / `LDAP_BIND_PASSWORD` | `cn=Directory Manager` / – | Bind credentials (no default password) |
| `LDAP_AUTH_METHOD` | `simple` | `simple`, `anonymous`, or `sasl_external` |
| `LDAP_IS_LOCAL` / `LDAP_SERVERID` | `false` / – | Enable local-instance features (logs, disk, certs) |
| `LDAP_USE_LDAPI` | `false` | Connect over the LDAPI unix socket |
| `LDAP_IS_OFFLINE` | `false` | Treat the local instance as stopped (offline mode) |
| `LDAP_TLS_VERIFY` | `true` | Verify the server certificate on remote `ldaps://` connections (set `false` only for trusted labs) |

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

By default, **privacy mode is enabled** - sensitive data (DNs, hostnames, user details) is redacted from tool outputs. Tools that expose individual entries (`get_user_details`, `ldap_search`) are disabled; list tools return counts only.

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
- Hostnames, DNs, and suffixes are anonymized
- Configuration values are redacted
- Sensitive tools are disabled
- Diagnostic metrics (counts, ratios, percentages) remain visible
- Server names (the `name` field in `servers.json`) are **never** redacted — they are user-chosen labels that must remain stable across tool calls. Do not put hostnames, IPs, or other private information in server names.

## Data Handling

- **No telemetry.** The server collects nothing and phones home to no one.
- **Everything runs locally.** Directory data is read from your LDAP servers, local instances, or archive files and returned only to your MCP client — which forwards tool results to whatever LLM you have configured. Privacy mode (on by default) redacts sensitive values before they leave the server process.
- **Credentials** stay in your local `servers.json` / environment variables; they are never included in tool output and tool errors are sanitized.

## Troubleshooting

| Symptom | Cause / Fix |
|---------|-------------|
| `python-ldap` fails to build during install | Missing system headers — install the packages from [Prerequisites](#prerequisites) |
| Tools report a default `localhost` server instead of your config | `LDAP_SERVERS_CONFIG` not set or not loadable in the MCP client config; use an absolute path and check the client's MCP logs |
| `list_*` tools return only counts; `ldap_search`/`get_user_details` refuse to run | That's privacy mode (default, working as intended) — see [Privacy Mode](#privacy-mode) |
| `LiveServerRequired` errors | The tool needs a running LDAP connection but the target server is offline/archive mode — use the `analyze_*` / `validate_configuration` / `compare_dse_configs` tools there |
| LDAPI connection fails for a local server | Check `serverid` has no `slapd-` prefix and the instance socket exists |

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
| [389 DS Tools](src/ldap_assistant_mcp/dirsrv_mcp/TOOLS.md) | 389 Directory Server tools reference |
| [OpenLDAP Tools](src/ldap_assistant_mcp/openldap_mcp/TOOLS.md) | OpenLDAP tools reference (in development) |

## License

[GPL-3.0-or-later](LICENSE). Built on [lib389](https://pypi.org/project/lib389/) (the official 389 Directory Server administration library) and [FastMCP](https://gofastmcp.com).

## References

- [Model Context Protocol](https://modelcontextprotocol.io/introduction)
- [389 Directory Server](https://www.port389.org/docs/389ds/documentation.html)
- [FastMCP 2.0](https://gofastmcp.com)

---

**Note:** This is an experimental project under active development. Features and APIs are subject to change.
