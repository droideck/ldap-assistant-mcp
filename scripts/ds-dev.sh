#!/bin/bash -e

# Script to create multiple 389 Directory Server containers for development
# Creates 3 DS instances for testing multi-server MCP functionality

set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd)

# Dev environment defaults
DS_PASSWORD="Secret.123"
DS_BASE_DN="dc=example,dc=com"
DS_IMAGE="quay.io/389ds/dirsrv"

# Server definitions: name:ldap_port:ldaps_port
SERVERS=(
  "ds-dev-1:3389:3636"
  "ds-dev-2:3390:3637"
  "ds-dev-3:3391:3638"
)

print_usage() {
  cat <<EOF
Usage: scripts/ds-dev.sh [command]

Commands:
  create    Create and start all dev DS containers (default)
  start     Start all existing containers
  stop      Stop all containers
  remove    Remove all containers and volumes
  status    Show status of all containers

Dev environment configuration:
  Servers:   ${#SERVERS[@]} instances
  Base DN:   $DS_BASE_DN
  Bind DN:   cn=Directory Manager
  Password:  $DS_PASSWORD

Servers created:
  ds-dev-1  ldap://localhost:3389  ldaps://localhost:3636
  ds-dev-2  ldap://localhost:3390  ldaps://localhost:3637
  ds-dev-3  ldap://localhost:3391  ldaps://localhost:3638

After running 'create':
  1. servers.json is generated automatically
  2. Install to Claude Desktop:
     fastmcp install claude-desktop fastmcp.json
EOF
}

wait_for_ds() {
  local name=$1
  local port=$2
  local max_attempts=30
  local attempt=1

  echo "  Waiting for $name to be ready..."
  while [ $attempt -le $max_attempts ]; do
    if docker exec "$name" ldapsearch -x -H ldap://localhost:3389 -s base -b "" > /dev/null 2>&1; then
      return 0
    fi
    sleep 5
    attempt=$((attempt + 1))
  done
  return 1
}

wait_for_auth() {
  local name=$1
  local max_attempts=10
  local attempt=1

  echo "  Waiting for Directory Manager auth..."
  while [ $attempt -le $max_attempts ]; do
    if docker exec "$name" ldapwhoami -x -H ldap://localhost:3389 -D "cn=Directory Manager" -w "$DS_PASSWORD" > /dev/null 2>&1; then
      return 0
    fi
    sleep 5
    attempt=$((attempt + 1))
  done
  return 1
}

create_backend() {
  local name=$1

  echo "  Creating backend and suffix for $name..."
  # Create backend with suffix - this ensures dc=example,dc=com exists
  docker exec "$name" dsconf localhost backend create \
    --suffix="$DS_BASE_DN" \
    --be-name=userroot \
    --create-entries \
    --create-suffix 2>/dev/null || true

  # Verify suffix exists, create manually if needed
  if ! docker exec "$name" ldapsearch -x -H ldap://localhost:3389 -D "cn=Directory Manager" -w "$DS_PASSWORD" -b "$DS_BASE_DN" -s base > /dev/null 2>&1; then
    echo "  Creating base suffix manually..."
    # Extract dc value from base DN
    DC_VALUE=$(echo "$DS_BASE_DN" | sed -n 's/dc=\([^,]*\).*/\1/p')
    docker exec -i "$name" ldapadd \
      -H ldap://localhost:3389 \
      -D "cn=Directory Manager" \
      -w "$DS_PASSWORD" \
      -x <<EOF
dn: $DS_BASE_DN
objectClass: top
objectClass: domain
dc: $DC_VALUE
EOF
  fi
}

add_sample_users() {
  local name=$1
  local suffix=$2

  echo "  Adding sample users to $name..."
  docker exec -i "$name" ldapadd \
    -H ldap://localhost:3389 \
    -D "cn=Directory Manager" \
    -w "$DS_PASSWORD" \
    -x <<EOF || true
dn: uid=user${suffix},ou=people,$DS_BASE_DN
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: user${suffix}
cn: User ${suffix}
sn: User
givenName: Test
mail: user${suffix}@example.com

dn: cn=group${suffix},ou=groups,$DS_BASE_DN
objectClass: top
objectClass: groupOfNames
cn: group${suffix}
member: uid=user${suffix},ou=people,$DS_BASE_DN
EOF
}

create_server() {
  local name=$1
  local ldap_port=$2
  local ldaps_port=$3
  local suffix=$4

  echo "Creating $name (LDAP: $ldap_port, LDAPS: $ldaps_port)..."

  # Check if container already exists
  if docker inspect "$name" >/dev/null 2>&1; then
    echo "  Container $name already exists, skipping..."
    return 0
  fi

  # Create volume
  docker volume create "${name}-data" > /dev/null

  # Create and start container
  docker run -d \
    --name "$name" \
    --hostname localhost \
    -v "${name}-data:/data" \
    -e DS_DM_PASSWORD="$DS_PASSWORD" \
    -e DS_SUFFIX_NAME="$DS_BASE_DN" \
    -e DS_CREATE_SUFFIX_ENTRY=True \
    -p ${ldap_port}:3389 \
    -p ${ldaps_port}:3636 \
    "$DS_IMAGE" > /dev/null

  # Wait for DS
  if ! wait_for_ds "$name" "$ldap_port"; then
    echo "  ERROR: $name failed to start"
    return 1
  fi

  # Wait for auth
  sleep 3
  if ! wait_for_auth "$name"; then
    echo "  ERROR: $name auth failed"
    return 1
  fi

  # Create backend and suffix
  create_backend "$name"

  # Add sample data
  add_sample_users "$name" "$suffix"

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
  echo "Creating ${#SERVERS[@]} dev DS containers..."
  echo ""

  local suffix=1
  for server in "${SERVERS[@]}"; do
    IFS=':' read -r name ldap_port ldaps_port <<< "$server"
    create_server "$name" "$ldap_port" "$ldaps_port" "$suffix"
    echo ""
    suffix=$((suffix + 1))
  done

  generate_servers_json

  echo ""
  echo "=========================================="
  echo "Dev environment is ready!"
  echo "=========================================="
  echo ""
  echo "Servers:"
  for server in "${SERVERS[@]}"; do
    IFS=':' read -r name ldap_port ldaps_port <<< "$server"
    echo "  $name: ldap://localhost:$ldap_port"
  done
  echo ""
  echo "Configuration:"
  echo "  servers.json created in project root"
  echo "  Base DN:   $DS_BASE_DN"
  echo "  Bind DN:   cn=Directory Manager"
  echo "  Password:  $DS_PASSWORD"
  echo ""
  echo "Next step - install to Claude Desktop:"
  echo "  fastmcp install claude-desktop fastmcp.json"
  echo ""
}

start_all() {
  echo "Starting all dev containers..."
  for server in "${SERVERS[@]}"; do
    IFS=':' read -r name ldap_port ldaps_port <<< "$server"
    if docker inspect "$name" >/dev/null 2>&1; then
      docker start "$name" > /dev/null && echo "  Started $name"
    else
      echo "  $name does not exist"
    fi
  done
}

stop_all() {
  echo "Stopping all dev containers..."
  for server in "${SERVERS[@]}"; do
    IFS=':' read -r name ldap_port ldaps_port <<< "$server"
    docker stop "$name" 2>/dev/null && echo "  Stopped $name" || true
  done
}

remove_all() {
  echo "Removing all dev containers and volumes..."
  for server in "${SERVERS[@]}"; do
    IFS=':' read -r name ldap_port ldaps_port <<< "$server"
    docker rm -f "$name" 2>/dev/null && echo "  Removed $name" || true
    docker volume rm "${name}-data" 2>/dev/null || true
  done
  rm -f "$REPO_ROOT/servers.json" && echo "  Removed servers.json" || true
}

show_status() {
  echo "Dev container status:"
  echo ""
  for server in "${SERVERS[@]}"; do
    IFS=':' read -r name ldap_port ldaps_port <<< "$server"
    if docker inspect "$name" >/dev/null 2>&1; then
      status=$(docker inspect -f '{{.State.Status}}' "$name")
      echo "  $name: $status (ldap://localhost:$ldap_port)"
    else
      echo "  $name: not created"
    fi
  done
}

# Main
COMMAND="${1:-create}"

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
    remove_all
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
