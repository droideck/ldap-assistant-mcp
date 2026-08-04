#!/bin/bash -e

# Script to set up offline mode testing environment for Claude Desktop
# Extracts DS data from a container to the host, stops it, and creates
# a mixed live/offline servers.json configuration.
#
# Prerequisites: Run './scripts/ds-dev.sh create' first.
#
# Usage:
#   scripts/ds-offline-setup.sh setup   # Set up offline testing
#   scripts/ds-offline-setup.sh clean   # Restore all-live mode
#   scripts/ds-offline-setup.sh status  # Show current state

set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd)

# Sourced for $DS_CLI so this script honors the same runtime selection
source "$SCRIPT_DIR/ds-common.sh"

# Container to convert to offline mode
OFFLINE_CONTAINER="ds-dev-3"
OFFLINE_SERVER_NAME="ds-dev-3-offline"
SERVERID="localhost"

# PREFIX directory for defaults.inf (/usr/share is SIP-protected on macOS)
OFFLINE_PREFIX="$HOME/ds-offline"

# Host paths where DS data will be placed (macOS: /etc -> /private/etc, writable with sudo)
HOST_CONFIG_DIR="/etc/dirsrv/slapd-${SERVERID}"
HOST_LOG_DIR="/var/log/dirsrv/slapd-${SERVERID}"

print_usage() {
    cat <<EOF
Usage: scripts/ds-offline-setup.sh [command]

Commands:
  setup    Extract data from $OFFLINE_CONTAINER, stop it, configure offline mode (default)
  clean    Restore all-live mode (restart container, remove host data)
  status   Show current environment state
  help     Show this help

Container runtime:
  DS_CLI   Container CLI: docker (default) or podman

Prerequisites:
  Run './scripts/ds-dev.sh create' first to create the dev containers.

What this does:
  1. Copies dse.ldif, logs, and defaults.inf from $OFFLINE_CONTAINER to the host
  2. Stops $OFFLINE_CONTAINER to simulate an offline/stopped instance
  3. Updates servers.json with 2 live + 1 offline server
  4. Prints Claude Desktop configuration with PREFIX env var

The offline server will support:
  - DSE configuration analysis (dse.ldif parsing)
  - Log file analysis (access/error logs)
  - Index configuration review
  - Plugin listing
  - Health checks (offline subset)

It will NOT support (returns LiveServerRequired error):
  - User/group queries
  - Performance/connection stats
  - Replication status
  - LDAP searches

Cleanup:
  './scripts/ds-offline-setup.sh clean' reverses everything.
EOF
}

check_container_exists() {
    if ! "$DS_CLI" inspect "$OFFLINE_CONTAINER" > /dev/null 2>&1; then
        echo "ERROR: Container '$OFFLINE_CONTAINER' not found."
        echo "Run './scripts/ds-dev.sh create' first."
        exit 1
    fi
}

check_container_running() {
    local status
    status=$("$DS_CLI" inspect -f '{{.State.Status}}' "$OFFLINE_CONTAINER" 2>/dev/null || echo "not found")
    if [ "$status" != "running" ]; then
        echo "ERROR: Container '$OFFLINE_CONTAINER' is not running (status: $status)."
        echo "Start it with: ${DS_CLI} start $OFFLINE_CONTAINER"
        exit 1
    fi
}

setup() {
    echo "Setting up offline mode testing environment..."
    echo ""

    check_container_exists
    check_container_running

    # Step 1: Create PREFIX directory for defaults.inf
    echo "[1/5] Creating PREFIX directory for defaults.inf..."
    mkdir -p "$OFFLINE_PREFIX/share/dirsrv/inf"
    "$DS_CLI" cp "$OFFLINE_CONTAINER:/usr/share/dirsrv/inf/defaults.inf" \
        "$OFFLINE_PREFIX/share/dirsrv/inf/"
    echo "  -> $OFFLINE_PREFIX/share/dirsrv/inf/defaults.inf"

    # Step 2: Create host directories and copy dse.ldif (sudo required)
    echo ""
    echo "[2/5] Copying dse.ldif to host (sudo required)..."
    sudo mkdir -p "$HOST_CONFIG_DIR"
    "$DS_CLI" cp "$OFFLINE_CONTAINER:$HOST_CONFIG_DIR/dse.ldif" /tmp/ds-offline-dse.ldif
    sudo cp /tmp/ds-offline-dse.ldif "$HOST_CONFIG_DIR/dse.ldif"
    rm -f /tmp/ds-offline-dse.ldif
    sudo chown -R "$(whoami)" "$HOST_CONFIG_DIR"
    echo "  -> $HOST_CONFIG_DIR/dse.ldif"

    # Step 3: Copy log files
    echo ""
    echo "[3/5] Copying log files to host..."
    sudo mkdir -p "$HOST_LOG_DIR"
    rm -rf /tmp/ds-offline-logs
    mkdir -p /tmp/ds-offline-logs
    "$DS_CLI" cp "$OFFLINE_CONTAINER:$HOST_LOG_DIR/." /tmp/ds-offline-logs/ 2>/dev/null || true
    sudo cp -r /tmp/ds-offline-logs/* "$HOST_LOG_DIR/" 2>/dev/null || true
    rm -rf /tmp/ds-offline-logs
    sudo chown -R "$(whoami)" "$HOST_LOG_DIR"
    echo "  -> $HOST_LOG_DIR/ ($(ls "$HOST_LOG_DIR" 2>/dev/null | wc -l | tr -d ' ') files)"

    # Step 4: Stop the container
    echo ""
    echo "[4/5] Stopping $OFFLINE_CONTAINER..."
    "$DS_CLI" stop "$OFFLINE_CONTAINER" > /dev/null 2>&1
    echo "  Container stopped"

    # Step 5: Generate mixed servers.json
    echo ""
    echo "[5/5] Generating mixed servers.json..."
    generate_mixed_servers_json
    echo "  -> $REPO_ROOT/servers.json"

    # Print summary
    echo ""
    echo "=========================================="
    echo "  Offline mode testing environment ready"
    echo "=========================================="
    echo ""
    echo "Server configuration:"
    echo "  ds-dev-1           LIVE    ldap://localhost:3389"
    echo "  ds-dev-2           LIVE    ldap://localhost:3390"
    echo "  $OFFLINE_SERVER_NAME  OFFLINE file-based analysis"
    echo ""
    echo "Host files:"
    echo "  defaults.inf : $OFFLINE_PREFIX/share/dirsrv/inf/defaults.inf"
    echo "  dse.ldif     : $HOST_CONFIG_DIR/dse.ldif"
    echo "  logs         : $HOST_LOG_DIR/"
    echo ""
    print_claude_desktop_config
    echo ""
    echo "To restore all-live mode:"
    echo "  ./scripts/ds-offline-setup.sh clean"
}

clean() {
    echo "Cleaning up offline mode testing environment..."

    # Remove host files
    echo "Removing host DS data (sudo required)..."
    sudo rm -rf "$HOST_CONFIG_DIR" 2>/dev/null || true
    sudo rm -rf "$HOST_LOG_DIR" 2>/dev/null || true
    # Remove parent dirs if empty
    sudo rmdir /etc/dirsrv 2>/dev/null || true
    sudo rmdir /var/log/dirsrv 2>/dev/null || true

    # Remove PREFIX directory
    rm -rf "$OFFLINE_PREFIX"
    echo "  Removed host files"

    # Restart container
    if "$DS_CLI" inspect "$OFFLINE_CONTAINER" > /dev/null 2>&1; then
        echo "Restarting $OFFLINE_CONTAINER..."
        "$DS_CLI" start "$OFFLINE_CONTAINER" > /dev/null 2>&1 || true
        echo "  Container restarted"
    fi

    # Restore standard servers.json (all live)
    cat > "$REPO_ROOT/servers.json" <<EOF
{
  "servers": [
    {
      "name": "ds-dev-1",
      "ldap_url": "ldap://localhost:3389",
      "base_dn": "dc=example,dc=com",
      "bind_dn": "cn=Directory Manager",
      "bind_password": "Secret.123",
      "provider_type": "389ds"
    },
    {
      "name": "ds-dev-2",
      "ldap_url": "ldap://localhost:3390",
      "base_dn": "dc=example,dc=com",
      "bind_dn": "cn=Directory Manager",
      "bind_password": "Secret.123",
      "provider_type": "389ds"
    },
    {
      "name": "ds-dev-3",
      "ldap_url": "ldap://localhost:3391",
      "base_dn": "dc=example,dc=com",
      "bind_dn": "cn=Directory Manager",
      "bind_password": "Secret.123",
      "provider_type": "389ds"
    }
  ]
}
EOF
    chmod 600 "$REPO_ROOT/servers.json"
    echo "  Restored servers.json (all live)"

    echo ""
    echo "Cleanup complete. All servers restored to live mode."
    echo ""
    echo "NOTE: Remove the PREFIX env var from your Claude Desktop config,"
    echo "or run './scripts/ds-offline-setup.sh setup' again to re-enable offline mode."
}

show_status() {
    echo "Offline mode testing environment status:"
    echo ""

    # Check containers
    echo "Containers:"
    for name in ds-dev-1 ds-dev-2 ds-dev-3; do
        if "$DS_CLI" inspect "$name" > /dev/null 2>&1; then
            status=$("$DS_CLI" inspect -f '{{.State.Status}}' "$name")
            echo "  $name: $status"
        else
            echo "  $name: not created"
        fi
    done

    # Check host files
    echo ""
    echo "Host files:"
    if [ -f "$OFFLINE_PREFIX/share/dirsrv/inf/defaults.inf" ]; then
        echo "  defaults.inf: $OFFLINE_PREFIX/share/dirsrv/inf/defaults.inf (exists)"
    else
        echo "  defaults.inf: not found"
    fi
    if [ -f "$HOST_CONFIG_DIR/dse.ldif" ]; then
        echo "  dse.ldif:     $HOST_CONFIG_DIR/dse.ldif (exists)"
    else
        echo "  dse.ldif:     not found"
    fi
    if [ -d "$HOST_LOG_DIR" ]; then
        local count
        count=$(ls "$HOST_LOG_DIR" 2>/dev/null | wc -l | tr -d ' ')
        echo "  logs:         $HOST_LOG_DIR/ ($count files)"
    else
        echo "  logs:         not found"
    fi

    # Check servers.json
    echo ""
    echo "servers.json:"
    if [ -f "$REPO_ROOT/servers.json" ]; then
        if grep -q '"is_offline"' "$REPO_ROOT/servers.json" 2>/dev/null; then
            echo "  Mode: mixed (live + offline)"
        else
            echo "  Mode: all live"
        fi
    else
        echo "  Not found"
    fi

    echo ""
    echo "Claude Desktop config:"
    print_claude_desktop_config
}

generate_mixed_servers_json() {
    cat > "$REPO_ROOT/servers.json" <<EOF
{
  "servers": [
    {
      "name": "ds-dev-1",
      "ldap_url": "ldap://localhost:3389",
      "base_dn": "dc=example,dc=com",
      "bind_dn": "cn=Directory Manager",
      "bind_password": "Secret.123",
      "provider_type": "389ds"
    },
    {
      "name": "ds-dev-2",
      "ldap_url": "ldap://localhost:3390",
      "base_dn": "dc=example,dc=com",
      "bind_dn": "cn=Directory Manager",
      "bind_password": "Secret.123",
      "provider_type": "389ds"
    },
    {
      "name": "$OFFLINE_SERVER_NAME",
      "base_dn": "dc=example,dc=com",
      "bind_dn": "cn=Directory Manager",
      "bind_password": "Secret.123",
      "provider_type": "389ds",
      "is_local": true,
      "serverid": "$SERVERID",
      "is_offline": true
    }
  ]
}
EOF
    chmod 600 "$REPO_ROOT/servers.json"
}

print_claude_desktop_config() {
    echo "Add this to ~/Library/Application Support/Claude/claude_desktop_config.json:"
    echo ""
    cat <<CFGEOF
{
  "mcpServers": {
    "ldap-assistant": {
      "command": "uv",
      "args": [
        "run", "--directory", "$REPO_ROOT",
        "fastmcp", "run", "src/ldap_assistant_mcp/main.py:create_server"
      ],
      "env": {
        "LDAP_SERVERS_CONFIG": "$REPO_ROOT/servers.json",
        "PREFIX": "$OFFLINE_PREFIX"
      }
    }
  }
}
CFGEOF
}

# Main
COMMAND="${1:-setup}"

case "$COMMAND" in
    setup|clean|status)
        require_container_cli
        ;;
esac

case "$COMMAND" in
    setup)
        setup
        ;;
    clean)
        clean
        ;;
    status)
        show_status
        ;;
    -h|--help|help)
        print_usage
        ;;
    *)
        echo "Unknown command: $COMMAND"
        print_usage
        exit 1
        ;;
esac
