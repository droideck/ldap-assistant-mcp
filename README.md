# LDAP Assistant MCP

<!-- mcp-name: io.github.droideck/ldap-assistant-mcp -->

[![Version](https://img.shields.io/badge/version-0.5.0-blue.svg)](CHANGELOG.md)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)

> **Beta** — read-only 389 Directory Server diagnostics, suitable for evaluation and internal troubleshooting. Tool schemas, output formats, and configuration fields may still change before 1.0.0.

**LDAP Assistant MCP turns your AI assistant into a 389 Directory Server support engineer.** Point it at live servers, stopped instances, or an SOS report from a customer case, and ask:

- *"What's wrong with my directory servers?"*
- *"Summarize this SOS report before I open the case."*
- *"Replication looks broken between these servers — why?"*

It answers with prioritized findings (severity, impact, remediation) from 42 read-only diagnostic tools built on [lib389](https://pypi.org/project/lib389/), the official 389 DS administration library. **Privacy mode is on by default**: DNs, hostnames, and IPs are redacted before anything reaches the LLM.

**Supported provider: 389 Directory Server.** (OpenLDAP provider code exists experimentally behind an opt-in flag, with no privacy guarantees, and is not part of the support contract — see [Environment Variables](#environment-variable-reference).)

## Install

### Prerequisites

- Linux (primary) or macOS. Windows is not supported natively (python-ldap has no official Windows wheels) — use WSL2 (see the [install playbook](docs/playbooks/install-troubleshooting.md#windows-and-wsl2))
- Python 3.11+ (3.13 is what CI tests against)
- [`uv`](https://docs.astral.sh/uv/) package manager
- MCP client (Claude Desktop, Claude Code, Cursor, Gemini CLI, etc.)
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

Anything failing during install? → [Installation troubleshooting playbook](docs/playbooks/install-troubleshooting.md)

### From PyPI (recommended)

No clone needed — your MCP client runs the published package via `uvx`. Skip ahead to [Configure your servers](#configure-your-servers), then use this client configuration (Claude Desktop: `~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "ldap-assistant-mcp": {
      "command": "uvx",
      "args": ["ldap-assistant-mcp"],
      "env": {
        "LDAP_SERVERS_CONFIG": "/absolute/path/to/servers.json"
      }
    }
  }
}
```

Use an **absolute path** for `LDAP_SERVERS_CONFIG` — relative paths resolve against the MCP client's working directory, which is usually not where you think.

### From source (development)

```bash
git clone https://github.com/droideck/ldap-assistant-mcp.git
cd ldap-assistant-mcp
uv venv && source .venv/bin/activate
uv pip install -e .[dev]

# Register with your MCP client via FastMCP:
fastmcp install claude-desktop fastmcp.json   # or: fastmcp install claude-code fastmcp.json
```

Then set `LDAP_SERVERS_CONFIG` in the generated client entry as above. See the [Development Guide](docs/DEVELOPMENT.md) for test containers and architecture.

## Configure your servers

Create a `servers.json` with your LDAP server(s). **Note:** the `name` field is never redacted in privacy mode — it is passed as-is to AI agents so they can reference servers across tool calls. Do not put hostnames, IPs, or other private information in server names.

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

### The four server modes

| Mode | Config | What you get |
|------|--------|--------------|
| **Remote** | `ldap_url` only | Health, replication, performance, config, and entry tools over LDAP. No log/disk/cert access |
| **Local** | + `is_local: true`, `serverid` | Everything above **plus** log analysis, disk monitoring, certificate checks, process metrics |
| **Offline** | + `is_offline: true` | A stopped local instance, analyzed via dse.ldif and log files — no LDAP connection. For post-mortems and instances that won't start |
| **Archive** | `is_archive: true`, `archive_path` | An SOS report or config/log extract from **any** machine (tarball or directory, auto-detected layout). No LDAP, no local instance required |

Tools that need a live connection tell you so — the error names the tools that *do* work in that server's mode, so the investigation continues instead of dead-ending.

**Remote LDAPS certificate verification:** remote `ldaps://` servers verify the server certificate by default (`"tls_verify": true`, or the `LDAP_TLS_VERIFY` environment variable for env-based config). To connect to a server with a self-signed or otherwise untrusted certificate, set `"tls_verify": false` on that server entry — this disables certificate verification entirely, so use it only for trusted lab environments. Local instances (`is_local: true`) instead use the instance's own NSS certificate directory.

After editing the client config or `servers.json`, restart your MCP client, then verify: ask *"Which LDAP servers are configured?"*

## Privacy mode

By default, **privacy mode is enabled** — sensitive data (DNs, hostnames, IPs, user details) is redacted from tool outputs. Tools that expose individual entries (`get_user_details`, `ldap_search`) are disabled; list tools return counts only. Diagnostic metrics (counts, ratios, percentages) remain visible.

To enable full data access in **trusted environments only**:

```json
{
  "env": {
    "LDAP_MCP_EXPOSE_SENSITIVE_DATA": "true"
  }
}
```

**Important:** Only enable this with local models, private cloud LLM instances, or when working with test/sample data. Avoid enabling with public LLMs when connected to production directories — your directory information could be included in their training data or logs.

When privacy mode is enabled (default):
- Hostnames, DNs, IP addresses, and suffixes are anonymized
- Configuration values are redacted
- Sensitive tools are disabled
- Diagnostic metrics (counts, ratios, percentages) remain visible
- Server names (the `name` field in `servers.json`) are **never** redacted — they are user-chosen labels that must remain stable across tool calls. Do not put hostnames, IPs, or other private information in server names.

### Data handling

- **No telemetry.** The server collects nothing and phones home to no one.
- **Everything runs locally.** Directory data is read from your LDAP servers, local instances, or archive files and returned only to your MCP client — which forwards tool results to whatever LLM you have configured. Privacy mode (on by default) redacts sensitive values before they leave the server process.
- **Credentials** stay in your local `servers.json` / environment variables; they are never included in tool output and tool errors are sanitized.

## First questions to ask

| You want | Ask / use | Behind it |
|----------|-----------|-----------|
| A health overview of everything | *"What's wrong with my directory servers?"* | `first_look` |
| An SOS report summarized | *"Analyze the sos-report archive"* or the `archive_investigation` prompt | `analyze_archive` → [archive playbook](docs/playbooks/archive-sos.md) |
| To know which tool fits a goal | the `tool_navigator` prompt | tool map for a stated goal |
| Guided replication triage | the `diagnose_replication` prompt | replication tool sequence |
| Guided performance triage | the `performance_investigation` prompt | performance tool sequence |
| A morning ops review | the `daily_health_check` prompt | health + monitoring sweep |

**Playbooks** (symptom → tools → what they can't know → how to verify by hand):

- [Summarize an SOS report before opening the case](docs/playbooks/archive-sos.md)
- [Installation troubleshooting](docs/playbooks/install-troubleshooting.md)

## Tools by group

42 read-only tools — full reference with parameters in [TOOLS.md](src/ldap_assistant_mcp/dirsrv_mcp/TOOLS.md).

| Group | Tools | Highlights |
|-------|-------|-----------|
| Health | `first_look`, `run_healthcheck`, `list_healthchecks`, `server_health` | Multi-server overview; full `dsctl healthcheck` equivalent |
| Replication | `get_replication_status`, `get_replication_topology`, `check_replication_lag`, `list_replication_conflicts`, `get_agreement_status` | RUV/CSN analysis, topology mapping, conflict entries |
| Performance | `get_performance_summary`, cache/connection/operation/thread/resource statistics | Bottleneck detection and tuning recommendations |
| Indexes | `list_indexes`, `analyze_index_configuration`, `find_unindexed_searches` | Access-log-driven unindexed search hunting |
| Configuration | `get_server_configuration`, `compare_server_configurations`, `list_plugins`, `get_backend_configuration` | Live **and** offline (dse.ldif) paths |
| Logs | `analyze_access_log` / `analyze_error_log` / `analyze_audit_log` (stats, privacy-safe), `parse_*_log` (full entries, requires sensitive-data mode) | Traditional and JSON log formats |
| Archive / SOS | `analyze_archive`, `validate_configuration`, `compare_dse_configs` | Inventory, offline config lint, full dse.ldif diff |
| Users & Groups | list/search/inspect users, active/locked filters, groups | Count-only in privacy mode |
| Advanced | `ldap_search`, `run_monitor`, `list_servers`, cn=config resources | Generic search (sensitive-data mode only) |

## Environment Variable Reference

| Variable | Default | Purpose |
|----------|---------|---------|
| `LDAP_SERVERS_CONFIG` | – | Absolute path to `servers.json` (multi-server config; preferred) |
| `LDAP_PROVIDER` | `dirsrv` | Server implementation. Only `dirsrv` (389 DS) is supported; `openldap` requires the opt-in flag below |
| `LDAP_MCP_EXPERIMENTAL_OPENLDAP` | `false` | Opt in to the experimental OpenLDAP provider (two tools, **no privacy guarantees**) |
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
| `LDAP_AUTH_METHOD` | `simple` | `simple` or `anonymous` (the only implemented binds; LDAPI/SASL EXTERNAL is selected via `LDAP_USE_LDAPI`, not here) |
| `LDAP_IS_LOCAL` / `LDAP_SERVERID` | `false` / – | Enable local-instance features (logs, disk, certs) |
| `LDAP_USE_LDAPI` | `false` | Connect over the LDAPI unix socket |
| `LDAP_IS_OFFLINE` | `false` | Treat the local instance as stopped (offline mode) |
| `LDAP_TLS_VERIFY` | `true` | Verify the server certificate on remote `ldaps://` connections (set `false` only for trusted labs) |

## Troubleshooting

| Symptom | Cause / Fix |
|---------|-------------|
| `python-ldap` fails to build during install | Missing system headers — see the [install playbook](docs/playbooks/install-troubleshooting.md#python-ldap-build-failures) |
| Tools report a default `localhost` server instead of your config | `LDAP_SERVERS_CONFIG` not set or not loadable in the MCP client config — see [servers.json path resolution](docs/playbooks/install-troubleshooting.md#serversjson-path-resolution) |
| `list_*` tools return only counts; `ldap_search`/`get_user_details` refuse to run | That's privacy mode (default, working as intended) — see [Privacy Mode](#privacy-mode) |
| "requires a running server with a live LDAP connection" errors | The target is an offline/archive server — the error message lists the tools that do work there |
| LDAPI connection fails for a local server | Check `serverid` has no `slapd-` prefix and the instance socket exists |

No LDAP server to test against? The [Development Guide](docs/DEVELOPMENT.md) spins up test containers with Docker.

## Limitations

- **Beta** — Tool schemas, output formats, and configuration fields may change before 1.0.0
- **LLM interpretation** — Tools return accurate data, but the LLM interprets it. Hallucinations are possible. Always verify recommendations before acting.
- **Read-only** — No write operations yet
- **Plain text passwords** — Use restrictive file permissions on config files
- **STDIO transport only** — No HTTP/SSE support yet

## Documentation

| Document | Description |
|----------|-------------|
| [Changelog](CHANGELOG.md) | Version history and release notes |
| [Archive / SOS playbook](docs/playbooks/archive-sos.md) | Summarize an SOS report before opening the case |
| [Install playbook](docs/playbooks/install-troubleshooting.md) | python-ldap builds, WSL2, uvx, config path resolution |
| [Development Guide](docs/DEVELOPMENT.md) | Dev environment setup, configuration, architecture |
| [Testing Guide](docs/TESTING.md) | Running and writing tests |
| [Contributing Guide](docs/CONTRIBUTING.md) | How to contribute |
| [Release Checklist](docs/RELEASE.md) | How releases are cut and verified |
| [389 DS Tools](src/ldap_assistant_mcp/dirsrv_mcp/TOOLS.md) | 389 Directory Server tools reference |
| [OpenLDAP Tools](src/ldap_assistant_mcp/openldap_mcp/TOOLS.md) | OpenLDAP tools reference (experimental, opt-in only) |

## License

[GPL-3.0-or-later](LICENSE). Built on [lib389](https://pypi.org/project/lib389/) (the official 389 Directory Server administration library) and [FastMCP](https://gofastmcp.com).

## References

- [PyPI package](https://pypi.org/project/ldap-assistant-mcp/)
- [Official MCP Registry](https://registry.modelcontextprotocol.io) — listed as `io.github.droideck/ldap-assistant-mcp`
- [Model Context Protocol](https://modelcontextprotocol.io/introduction)
- [389 Directory Server](https://www.port389.org/docs/389ds/documentation.html)
- [FastMCP 2.0](https://gofastmcp.com)
