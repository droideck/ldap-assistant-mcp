#!/bin/bash -e

# Script to create multiple 389 Directory Server containers for development
# Creates 3 DS instances with replication for testing MCP diagnostic functionality

set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd)

# Source common functions
source "$SCRIPT_DIR/ds-common.sh"

# Dev environment defaults
DS_PASSWORD="Secret.123"
DS_BASE_DN="dc=example,dc=com"

# Server definitions: name:ldap_port:ldaps_port:replica_id
SERVERS=(
  "ds-dev-1:3389:3636:1"
  "ds-dev-2:3390:3637:2"
  "ds-dev-3:3391:3638:3"
)

# Number of sample users/groups to create
NUM_USERS=50
NUM_GROUPS=10

print_usage() {
  cat <<EOF
Usage: scripts/ds-dev.sh [command] [args]

Commands:
  create        Create and start all dev DS containers with replication (default)
  start         Start all existing containers
  stop          Stop all containers
  remove [--force-clean]
                Remove all containers and volumes (only containers created by
                these scripts; --force-clean removes them regardless)
  status        Show status of all containers and replication
  repl-status   Show detailed replication status
  generate [N]  Generate N operations (default: 100) for cache/stats testing
  populate      Add 100 more sample users to test replication

Container runtime:
  DS_CLI                Container CLI: docker (default) or podman
  DS_REPLICATION_HOST   Host alias used for replication agreements
                        (default: $DS_REPLICATION_HOST)

Dev environment configuration:
  Servers:     ${#SERVERS[@]} instances with multi-supplier replication
  Base DN:     $DS_BASE_DN
  Bind DN:     cn=Directory Manager
  Password:    $DS_PASSWORD
  Sample data: $NUM_USERS users, $NUM_GROUPS groups, locked users

Servers created:
  ds-dev-1  ldap://localhost:3389  ldaps://localhost:3636  (Supplier, Replica ID 1)
  ds-dev-2  ldap://localhost:3390  ldaps://localhost:3637  (Supplier, Replica ID 2)
  ds-dev-3  ldap://localhost:3391  ldaps://localhost:3638  (Supplier, Replica ID 3)

Features for testing diagnostics:
  - Multi-supplier replication topology
  - $NUM_USERS users (some locked, some with expired passwords)
  - $NUM_GROUPS groups with various member counts
  - Activity generation for cache/operation stats

After running 'create':
  1. servers.json is generated automatically
  2. Install to Claude Desktop:
     fastmcp install claude-desktop fastmcp.json
EOF
}

add_sample_data() {
  local name=$1

  echo "  Adding sample users and groups to $name..."

  # Create many users for cache testing
  for i in $(seq 1 $NUM_USERS); do
    # Determine department based on user number
    local dept="Engineering"
    [ $((i % 5)) -eq 0 ] && dept="Sales"
    [ $((i % 7)) -eq 0 ] && dept="Marketing"
    [ $((i % 11)) -eq 0 ] && dept="HR"

    # Add user
    "$DS_CLI" exec -i "$name" ldapadd \
      -H ldap://localhost:3389 \
      -D "cn=Directory Manager" \
      -w "$DS_PASSWORD" \
      -x 2>/dev/null <<EOF || true
dn: uid=user${i},ou=people,$DS_BASE_DN
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: user${i}
cn: User Number ${i}
sn: User${i}
givenName: Test
mail: user${i}@example.com
telephoneNumber: +1-555-${i}00-0000
departmentNumber: ${dept}
employeeNumber: EMP${i}
title: Employee
userPassword: password${i}
EOF
  done

  # Create groups with members
  for g in $(seq 1 $NUM_GROUPS); do
    local members=""
    # Add 5 members to each group
    for m in $(seq 1 5); do
      local uid=$((g * 5 + m))
      [ $uid -gt $NUM_USERS ] && uid=$((uid % NUM_USERS + 1))
      members="${members}member: uid=user${uid},ou=people,$DS_BASE_DN
"
    done

    "$DS_CLI" exec -i "$name" ldapadd \
      -H ldap://localhost:3389 \
      -D "cn=Directory Manager" \
      -w "$DS_PASSWORD" \
      -x 2>/dev/null <<EOF || true
dn: cn=group${g},ou=groups,$DS_BASE_DN
objectClass: top
objectClass: groupOfNames
cn: group${g}
description: Test group number ${g}
${members}
EOF
  done

  echo "  Added $NUM_USERS users and $NUM_GROUPS groups"
}

add_locked_users() {
  local name=$1

  echo "  Adding locked/inactive users to $name..."

  # Add a locked user (nsAccountLock=true)
  "$DS_CLI" exec -i "$name" ldapadd \
    -H ldap://localhost:3389 \
    -D "cn=Directory Manager" \
    -w "$DS_PASSWORD" \
    -x 2>/dev/null <<EOF || true
dn: uid=locked_user,ou=people,$DS_BASE_DN
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: locked_user
cn: Locked User
sn: Locked
givenName: Account
mail: locked@example.com
userPassword: lockedpassword
nsAccountLock: true

dn: uid=disabled_admin,ou=people,$DS_BASE_DN
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: disabled_admin
cn: Disabled Admin
sn: Admin
givenName: Disabled
mail: disabled.admin@example.com
userPassword: disabledpassword
nsAccountLock: true

dn: uid=inactive_user,ou=people,$DS_BASE_DN
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: inactive_user
cn: Inactive User
sn: Inactive
givenName: User
mail: inactive@example.com
userPassword: inactivepassword
nsAccountLock: true
EOF

  echo "  Added 3 locked users"
}

enable_replication() {
  local name=$1
  local replica_id=$2

  echo "  Enabling replication on $name (Replica ID: $replica_id)..."

  # Enable changelog
  "$DS_CLI" exec "$name" dsconf localhost replication enable \
    --suffix="$DS_BASE_DN" \
    --role=supplier \
    --replica-id="$replica_id" \
    --bind-dn="cn=replication manager,cn=config" \
    --bind-passwd="$DS_PASSWORD" 2>/dev/null || true
}

setup_replication_agreement() {
  local source_name=$1
  local target_name=$2
  local target_port=$3
  local agmt_name=$4

  echo "  Creating replication agreement: $source_name -> $target_name..."

  # Create replication agreement using repl-agmt command.
  #
  # All containers listen on 3389 internally, while this topology reaches
  # peers through their distinct published host ports. create_ds_container
  # adds an explicit Docker host-gateway mapping; Podman normally supplies the
  # compatibility alias. DS_REPLICATION_HOST remains overridable for custom
  # runtime or network configurations.
  "$DS_CLI" exec "$source_name" dsconf localhost repl-agmt create \
    --suffix="$DS_BASE_DN" \
    --host="$DS_REPLICATION_HOST" \
    --port="$target_port" \
    --bind-dn="cn=replication manager,cn=config" \
    --bind-passwd="$DS_PASSWORD" \
    --bind-method=SIMPLE \
    --conn-protocol=LDAP \
    "$agmt_name" 2>&1 || echo "    Warning: Agreement creation may have failed"

  # Initialize the agreement
  sleep 1
  "$DS_CLI" exec "$source_name" dsconf localhost repl-agmt init \
    --suffix="$DS_BASE_DN" \
    "$agmt_name" 2>&1 || echo "    Warning: Agreement init may have failed"
}

setup_full_mesh_replication() {
  echo ""
  echo "Setting up multi-supplier replication topology..."
  echo ""

  # Enable replication on all servers
  for server in "${SERVERS[@]}"; do
    IFS=':' read -r name ldap_port ldaps_port replica_id <<< "$server"
    enable_replication "$name" "$replica_id"
  done

  sleep 2

  # Create agreements: full mesh (each server replicates to all others)
  # ds-dev-1 -> ds-dev-2, ds-dev-3
  setup_replication_agreement "ds-dev-1" "ds-dev-2" "3390" "to-dev2"
  setup_replication_agreement "ds-dev-1" "ds-dev-3" "3391" "to-dev3"

  # ds-dev-2 -> ds-dev-1, ds-dev-3
  setup_replication_agreement "ds-dev-2" "ds-dev-1" "3389" "to-dev1"
  setup_replication_agreement "ds-dev-2" "ds-dev-3" "3391" "to-dev3"

  # ds-dev-3 -> ds-dev-1, ds-dev-2
  setup_replication_agreement "ds-dev-3" "ds-dev-1" "3389" "to-dev1"
  setup_replication_agreement "ds-dev-3" "ds-dev-2" "3390" "to-dev2"

  echo "  Replication topology configured (full mesh)"
}

generate_activity() {
  echo "Generating activity on servers..."
  echo ""

  local iterations=${1:-100}

  for i in $(seq 1 $iterations); do
    # Pick a random server
    local server_idx=$((RANDOM % 3))
    local ports=(3389 3390 3391)
    local port=${ports[$server_idx]}

    # Random operation: search, modify, or bind
    local op=$((RANDOM % 3))

    case $op in
      0)
        # Search operation
        local filter="(uid=user$((RANDOM % NUM_USERS + 1)))"
        ldapsearch -x -H "ldap://localhost:$port" \
          -D "cn=Directory Manager" -w "$DS_PASSWORD" \
          -b "$DS_BASE_DN" "$filter" cn mail >/dev/null 2>&1 || true
        ;;
      1)
        # Modify operation (update telephoneNumber)
        local uid=$((RANDOM % NUM_USERS + 1))
        ldapmodify -x -H "ldap://localhost:$port" \
          -D "cn=Directory Manager" -w "$DS_PASSWORD" 2>/dev/null <<EOF || true
dn: uid=user${uid},ou=people,$DS_BASE_DN
changetype: modify
replace: telephoneNumber
telephoneNumber: +1-555-${RANDOM}-0000
EOF
        ;;
      2)
        # Subtree search
        ldapsearch -x -H "ldap://localhost:$port" \
          -D "cn=Directory Manager" -w "$DS_PASSWORD" \
          -b "ou=people,$DS_BASE_DN" "(objectClass=inetOrgPerson)" cn >/dev/null 2>&1 || true
        ;;
    esac

    # Progress indicator
    [ $((i % 10)) -eq 0 ] && echo "  Generated $i operations..."
  done

  echo "  Completed $iterations operations"
}

populate_more_data() {
  echo "Adding more data to servers..."

  # Add more users to ds-dev-1 (will replicate to others)
  for i in $(seq $((NUM_USERS + 1)) $((NUM_USERS + 100))); do
    "$DS_CLI" exec -i "ds-dev-1" ldapadd \
      -H ldap://localhost:3389 \
      -D "cn=Directory Manager" \
      -w "$DS_PASSWORD" \
      -x 2>/dev/null <<EOF || true
dn: uid=extra_user${i},ou=people,$DS_BASE_DN
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: extra_user${i}
cn: Extra User ${i}
sn: Extra${i}
givenName: User
mail: extra${i}@example.com
userPassword: extrapass${i}
EOF
  done

  echo "  Added 100 extra users"
}

create_server() {
  local name=$1
  local ldap_port=$2
  local ldaps_port=$3
  local replica_id=$4

  echo "Creating $name (LDAP: $ldap_port, LDAPS: $ldaps_port, Replica ID: $replica_id)..."

  # Check if container already exists
  if "$DS_CLI" inspect "$name" >/dev/null 2>&1; then
    echo "  Container $name already exists, skipping..."
    return 0
  fi

  # Create container
  create_ds_container "$name" "$ldap_port" "$ldaps_port" "$DS_PASSWORD" "$DS_BASE_DN"

  # Wait for DS
  if ! wait_for_ds "$name"; then
    echo "  ERROR: $name failed to start"
    return 1
  fi

  # Wait for auth
  sleep 3
  if ! wait_for_auth "$name" "$DS_PASSWORD"; then
    echo "  ERROR: $name auth failed"
    return 1
  fi

  # Create backend and suffix
  create_backend "$name" "$DS_BASE_DN"

  # Create base OUs
  create_base_ous "$name" "$DS_BASE_DN" "$DS_PASSWORD"

  echo "  $name is ready"
}

generate_servers_json() {
  echo "Generating servers.json..."

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
  echo "  Created servers.json (chmod 600)"
}

create_all() {
  echo "Creating ${#SERVERS[@]} dev DS containers with replication..."
  echo ""

  # Create all servers first
  for server in "${SERVERS[@]}"; do
    IFS=':' read -r name ldap_port ldaps_port replica_id <<< "$server"
    create_server "$name" "$ldap_port" "$ldaps_port" "$replica_id"
    echo ""
  done

  # Add sample data to first server only (before replication, for speed)
  echo "Populating sample data on ds-dev-1..."
  add_sample_data "ds-dev-1"
  add_locked_users "ds-dev-1"
  echo ""

  # Set up multi-supplier replication
  setup_full_mesh_replication
  echo ""

  # Wait for replication to sync
  echo "Waiting for replication to sync..."
  sleep 5

  # Generate activity to populate stats
  echo "Generating initial activity for statistics..."
  generate_activity 50
  echo ""

  generate_servers_json

  echo ""
  echo "=========================================="
  echo "Dev environment is ready!"
  echo "=========================================="
  echo ""
  echo "Servers (multi-supplier replication):"
  for server in "${SERVERS[@]}"; do
    IFS=':' read -r name ldap_port ldaps_port replica_id <<< "$server"
    echo "  $name: ldap://localhost:$ldap_port (Replica ID: $replica_id)"
  done
  echo ""
  echo "Sample data:"
  echo "  - $NUM_USERS users (uid=user1 through uid=user$NUM_USERS)"
  echo "  - $NUM_GROUPS groups (cn=group1 through cn=group$NUM_GROUPS)"
  echo "  - 3 locked users (locked_user, disabled_admin, inactive_user)"
  echo ""
  echo "Configuration:"
  echo "  servers.json created in project root"
  echo "  Base DN:   $DS_BASE_DN"
  echo "  Bind DN:   cn=Directory Manager"
  echo "  Password:  $DS_PASSWORD"
  echo ""
  echo "Additional commands:"
  echo "  scripts/ds-dev.sh generate   # Generate more activity"
  echo "  scripts/ds-dev.sh populate   # Add more sample data"
  echo ""
  echo "Next step - install to Claude Desktop:"
  echo "  fastmcp install claude-desktop fastmcp.json"
  echo ""
}

start_all() {
  echo "Starting all dev containers..."
  for server in "${SERVERS[@]}"; do
    IFS=':' read -r name ldap_port ldaps_port replica_id <<< "$server"
    if "$DS_CLI" inspect "$name" >/dev/null 2>&1; then
      "$DS_CLI" start "$name" > /dev/null && echo "  Started $name"
    else
      echo "  $name does not exist"
    fi
  done
}

stop_all() {
  echo "Stopping all dev containers..."
  for server in "${SERVERS[@]}"; do
    IFS=':' read -r name ldap_port ldaps_port replica_id <<< "$server"
    "$DS_CLI" stop "$name" 2>/dev/null && echo "  Stopped $name" || true
  done
}

remove_all() {
  local force=false
  local failed=false
  [[ "${1:-}" == "--force-clean" ]] && force=true

  echo "Removing all dev containers and volumes..."
  for server in "${SERVERS[@]}"; do
    IFS=':' read -r name ldap_port ldaps_port replica_id <<< "$server"
    if ! remove_ds_container "$name" "$force"; then
      failed=true
    fi
  done

  if [[ "$failed" == true ]]; then
    echo "Error: cleanup was incomplete; preserving servers.json" >&2
    return 1
  fi

  if [[ -f "$REPO_ROOT/servers.json" ]]; then
    rm -f "$REPO_ROOT/servers.json"
    echo "  Removed servers.json"
  fi
}

show_status() {
  echo "Dev container status:"
  echo ""
  for server in "${SERVERS[@]}"; do
    IFS=':' read -r name ldap_port ldaps_port replica_id <<< "$server"
    if "$DS_CLI" inspect "$name" >/dev/null 2>&1; then
      status=$("$DS_CLI" inspect -f '{{.State.Status}}' "$name")
      echo "  $name: $status (ldap://localhost:$ldap_port, Replica ID: $replica_id)"
    else
      echo "  $name: not created"
    fi
  done

  # Show replication agreement count if servers are running
  echo ""
  echo "Replication agreements:"
  for server in "${SERVERS[@]}"; do
    IFS=':' read -r name ldap_port ldaps_port replica_id <<< "$server"
    if "$DS_CLI" inspect "$name" >/dev/null 2>&1; then
      container_status=$("$DS_CLI" inspect -f '{{.State.Status}}' "$name")
      if [ "$container_status" = "running" ]; then
        agmt_list=$("$DS_CLI" exec "$name" dsconf localhost repl-agmt list --suffix="$DS_BASE_DN" 2>/dev/null)
        if [ -n "$agmt_list" ]; then
          agmt_count=$(echo "$agmt_list" | grep -c "^cn:" 2>/dev/null || echo "0")
        else
          agmt_count="0"
        fi
        echo "  $name: $agmt_count agreement(s)"
      fi
    fi
  done
}

show_replication_status() {
  echo "Detailed replication status:"
  echo ""
  for server in "${SERVERS[@]}"; do
    IFS=':' read -r name ldap_port ldaps_port replica_id <<< "$server"
    echo "=== $name (Replica ID: $replica_id) ==="

    # Show replica config
    "$DS_CLI" exec "$name" dsconf localhost replication get \
      --suffix="$DS_BASE_DN" 2>/dev/null | grep -E "^(nsDS5Replica|nsds5replica)" | head -5 || echo "  (replication not enabled)"

    echo ""
    echo "  Agreements:"
    # List agreements with status
    "$DS_CLI" exec "$name" dsconf localhost repl-agmt list \
      --suffix="$DS_BASE_DN" 2>/dev/null | grep -E "^(cn:|nsds5replicaLastUpdateStatus:|nsds5replicaLastInitStatus:)" | \
      sed 's/^/    /' || echo "    (no agreements)"
    echo ""
  done
}

# Main
COMMAND="${1:-create}"
COMMAND_ARG="${2:-}"

case "$COMMAND" in
  create|start|stop|remove|status|repl-status|populate)
    require_container_cli
    ;;
esac

case "$COMMAND" in
  create)
    create_all
    ;;
  start)
    start_all
    ;;
  stop)
    stop_all
    ;;
  remove)
    remove_all "$COMMAND_ARG"
    ;;
  status)
    show_status
    ;;
  repl-status)
    show_replication_status
    ;;
  generate)
    iterations="${COMMAND_ARG:-100}"
    generate_activity "$iterations"
    ;;
  populate)
    populate_more_data
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
