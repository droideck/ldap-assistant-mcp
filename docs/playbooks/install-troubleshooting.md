# Playbook: Installation Troubleshooting

**Symptom:** the install fails, the MCP client doesn't show the tools, or the
tools respond but talk to a phantom `localhost:389` server you never
configured.

Find your symptom, apply the fix, then run the [verification](#verify-the-install)
at the end.

| Symptom | Section |
|---------|---------|
| `pip`/`uv` install fails while building `python-ldap` | [python-ldap build failures](#python-ldap-build-failures) |
| Works on Linux/macOS, need it on Windows | [Windows and WSL2](#windows-and-wsl2) |
| `uvx ldap-assistant-mcp` fails or uses a stale version | [uv / uvx quirks](#uv--uvx-quirks) |
| Server starts but reports a default `localhost` server, or errors about `servers.json` | [servers.json path resolution](#serversjson-path-resolution) |
| Tools never appear in the MCP client | [Client-side checklist](#client-side-checklist) |

## python-ldap build failures

`python-ldap` compiles a C extension. There are no official wheels for most
platforms, so the build needs OpenLDAP/SASL/SSL headers and a compiler.

**Error signatures** during `pip install` / `uv pip install` / first `uvx` run:

```
Modules/errors.h:8:10: fatal error: lber.h: No such file or directory
fatal error: 'sasl.h' file not found
error: command 'gcc' failed: No such file or directory
```

**Fix — install the system packages, then retry:**

Fedora / RHEL / CentOS:
```bash
sudo dnf install python3-devel openldap-devel cyrus-sasl-devel openssl-devel gcc
```

Ubuntu / Debian:
```bash
sudo apt install python3-dev libldap2-dev libsasl2-dev libssl-dev gcc
```

macOS (Homebrew) — headers exist but the linker can't find Homebrew's
OpenLDAP without flags:
```bash
brew install openldap
export LDFLAGS="-L$(brew --prefix openldap)/lib"
export CPPFLAGS="-I$(brew --prefix openldap)/include"
```
The exports must be set in the shell that runs the install (including the
first `uvx` run, which builds the package in its own environment).

## Windows and WSL2

`python-ldap` has no official Windows wheels — native Windows is not
supported. Run the server inside **WSL2**:

1. Install a distro (`wsl --install -d Ubuntu`), then inside WSL install the
   build deps (Ubuntu block above) and `uv`.
2. Keep `servers.json` on the WSL filesystem (e.g.
   `/home/you/ldap/servers.json`) — not on `/mnt/c/...`, which has slow and
   permission-quirky file access.
3. A Windows MCP client launches the server through the `wsl` command:

```json
{
  "mcpServers": {
    "ldap-assistant-mcp": {
      "command": "wsl",
      "args": ["-e", "bash", "-lc", "LDAP_SERVERS_CONFIG=/home/you/ldap/servers.json uvx ldap-assistant-mcp"]
    }
  }
}
```

The `bash -lc` wrapper matters: `env` entries in the client config set
*Windows* environment variables, which do not propagate into WSL by default.
Putting the variable in the command line keeps it on the Linux side.

## uv / uvx quirks

- **First run builds python-ldap.** `uvx ldap-assistant-mcp` resolves the
  package into a cached environment on first use — the build deps above must
  already be installed or that first run fails.
- **Stale cached version.** `uvx` may keep serving a previously cached
  version. Force the one you want, or refresh:
  ```bash
  uvx ldap-assistant-mcp==0.5.0      # pin explicitly
  uv cache clean ldap-assistant-mcp  # or drop the cached build
  ```
- **Python version.** The package needs Python 3.11+. If your default
  interpreter is older: `uvx --python 3.13 ldap-assistant-mcp`.
- **Development install instead.** When working from a git checkout, skip
  uvx entirely:
  ```bash
  uv venv && source .venv/bin/activate
  uv pip install -e .[dev]
  ```

## servers.json path resolution

The single most common misconfiguration.

**How config is resolved,** in order:

1. `LDAP_SERVERS_CONFIG` environment variable → path to `servers.json`.
   If it is set but the file is missing or malformed, the server **fails at
   startup with the path and parse error** (it does not limp on).
2. If it is *not* set, the server falls back to the single-server `LDAP_URL` /
   `LDAP_BIND_DN` / … environment variables.
3. If those aren't set either, you get a default `localhost:389` /
   `cn=Directory Manager` placeholder — this is the "phantom server".

**Rules:**

- Always use an **absolute path** in `LDAP_SERVERS_CONFIG`. A relative path
  resolves against the MCP client's working directory, which is almost never
  your repo.
- The variable must be set in the **MCP client's** config (the `env` block of
  the server entry), not in your shell — the client launches the server with
  its own environment.
- A config that parses but contains an **empty `servers` list** currently
  falls back to the phantom default silently — if `list_servers` shows a
  server named `default` pointing at `localhost:389` that you never
  configured, your config file isn't being read or is empty.

**Diagnosis:** ask the assistant *"list the configured servers"*
(`list_servers`). The names must match your `servers.json`. If you see
`default`, fix the path/env plumbing.

## Client-side checklist

- **Restart the client** after any config change — MCP servers launch at
  client startup.
- **Check the client's MCP logs** for the server's stderr (startup config
  errors land there):
  - Claude Desktop (macOS): `~/Library/Logs/Claude/mcp*.log`
  - Claude Code: run `claude mcp list` to confirm registration; use
    `--debug` to see server stderr.
- The server logs an INFO line at startup naming the loaded config source
  and each configured server (and a WARNING if privacy mode is off). No such
  lines → the client never started the process.

## Verify the install

1. Terminal check — the process starts and waits on stdio (Ctrl+C to exit):
   ```bash
   LDAP_SERVERS_CONFIG=/absolute/path/servers.json uvx ldap-assistant-mcp
   ```
   Startup errors (bad config path, malformed JSON, missing serverid for an
   offline entry) print immediately.
2. In the MCP client, ask: *"Which LDAP servers are configured?"* —
   `list_servers` must return your server names.
3. Then: *"Describe the connection to `<name>`"* or *"Check the health of my
   servers"* (`first_look`) for an end-to-end round trip.

No LDAP server to test against? See the
[Development Guide](../DEVELOPMENT.md) for Docker test containers.
