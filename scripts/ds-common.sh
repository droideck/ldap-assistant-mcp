#!/bin/bash
# Common functions for 389 Directory Server container management
# Sourced by ds-dev.sh and ds-test.sh

# Default image
DS_IMAGE=${DS_IMAGE:-quay.io/389ds/dirsrv}

# Wait for DS to be ready (accepts connections)
wait_for_ds() {
  local name=$1
  local max_attempts=${2:-30}
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

# Wait for Directory Manager authentication to work
wait_for_auth() {
  local name=$1
  local password=$2
  local max_attempts=${3:-10}
  local attempt=1

  echo "  Waiting for Directory Manager auth..."
  while [ $attempt -le $max_attempts ]; do
    if docker exec "$name" ldapwhoami -x -H ldap://localhost:3389 -D "cn=Directory Manager" -w "$password" > /dev/null 2>&1; then
      return 0
    fi
    sleep 5
    attempt=$((attempt + 1))
  done
  return 1
}

# Create backend with suffix
create_backend() {
  local name=$1
  local base_dn=$2

  echo "  Creating backend and suffix..."
  docker exec "$name" dsconf localhost backend create \
    --suffix="$base_dn" \
    --be-name=userroot \
    --create-entries \
    --create-suffix 2>/dev/null || true
}

# Create base OUs (people, groups)
create_base_ous() {
  local name=$1
  local base_dn=$2
  local password=$3

  docker exec -i "$name" ldapadd \
    -H ldap://localhost:3389 \
    -D "cn=Directory Manager" \
    -w "$password" \
    -x <<EOF || true
dn: ou=people,$base_dn
objectClass: top
objectClass: organizationalUnit
ou: people

dn: ou=groups,$base_dn
objectClass: top
objectClass: organizationalUnit
ou: groups
EOF
}

# Create and start a DS container
create_ds_container() {
  local name=$1
  local ldap_port=$2
  local ldaps_port=$3
  local password=$4
  local base_dn=$5

  # Skip if already exists
  if docker inspect "$name" >/dev/null 2>&1; then
    echo "  Container $name already exists, starting..."
    docker start "$name" >/dev/null
    return 0
  fi

  # Create volume
  docker volume create "${name}-data" > /dev/null

  # Create and start container
  docker run -d \
    --name "$name" \
    --hostname localhost \
    -v "${name}-data:/data" \
    -e DS_DM_PASSWORD="$password" \
    -e DS_SUFFIX_NAME="$base_dn" \
    -e DS_CREATE_SUFFIX_ENTRY=True \
    -p ${ldap_port}:3389 \
    -p ${ldaps_port}:3636 \
    "$DS_IMAGE" > /dev/null

  return 0
}

# Remove a DS container and its volume
remove_ds_container() {
  local name=$1

  docker rm -f "$name" 2>/dev/null && echo "  Removed $name" || true
  docker volume rm "${name}-data" 2>/dev/null || true
}

# Check if docker is available
require_docker() {
  if ! command -v docker >/dev/null 2>&1; then
    echo "Error: docker command not found" >&2
    exit 1
  fi
}
