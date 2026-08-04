#!/bin/bash
# Common functions for 389 Directory Server container management
# Sourced by ds-dev.sh, ds-test.sh, ds-test-local.sh, and ds-offline-setup.sh

# Container runtime. Docker remains the deterministic default; opt into
# Podman for the whole shell session so every lifecycle command uses the
# same engine:
#
#   export DS_CLI=podman
#   ./scripts/ds-dev.sh create
#
DS_CLI=${DS_CLI:-docker}

# Replication reaches peer containers through their published host ports.
# Docker Engine receives an explicit host-gateway mapping when containers are
# created. Podman normally supplies this compatibility alias itself. Override
# the hostname when the local runtime/network configuration requires it.
DS_REPLICATION_HOST=${DS_REPLICATION_HOST:-host.docker.internal}

# Default image
DS_IMAGE=${DS_IMAGE:-quay.io/389ds/dirsrv}

# Ownership label stamped on containers/volumes created by these scripts.
# Cleanup only force-removes containers that carry this label, so the
# scripts never delete resources they did not create.
DS_OWNER_LABEL="ldap-assistant-mcp.owner"
DS_OWNER_VALUE="ds-scripts"

# Check whether a container was created by these scripts (carries the
# ownership label). Returns non-zero if it is missing or not ours.
container_is_script_owned() {
  local name=$1
  local owner

  owner=$("$DS_CLI" inspect -f "{{index .Config.Labels \"${DS_OWNER_LABEL}\"}}" "$name" 2>/dev/null) || return 1
  [[ "$owner" == "$DS_OWNER_VALUE" ]]
}

# Check whether a volume was created by these scripts. Docker and Podman both
# expose volume labels at the top-level Labels field.
volume_is_script_owned() {
  local name=$1
  local owner

  owner=$("$DS_CLI" volume inspect -f "{{index .Labels \"${DS_OWNER_LABEL}\"}}" "$name" 2>/dev/null) || return 1
  [[ "$owner" == "$DS_OWNER_VALUE" ]]
}

# Wait for DS to be ready (accepts connections)
wait_for_ds() {
  local name=$1
  local max_attempts=${2:-30}
  local attempt=1

  echo "  Waiting for $name to be ready..."
  while [ $attempt -le $max_attempts ]; do
    if "$DS_CLI" exec "$name" ldapsearch -x -H ldap://localhost:3389 -s base -b "" > /dev/null 2>&1; then
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
    if "$DS_CLI" exec "$name" ldapwhoami -x -H ldap://localhost:3389 -D "cn=Directory Manager" -w "$password" > /dev/null 2>&1; then
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
  "$DS_CLI" exec "$name" dsconf localhost backend create \
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

  "$DS_CLI" exec -i "$name" ldapadd \
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
  local runtime_name=${DS_CLI##*/}
  local -a runtime_args=()

  if [[ "$runtime_name" == "docker" ]]; then
    runtime_args=(--add-host "${DS_REPLICATION_HOST}:host-gateway")
  fi

  # Skip if already exists
  if "$DS_CLI" inspect "$name" >/dev/null 2>&1; then
    echo "  Container $name already exists, starting..."
    "$DS_CLI" start "$name" >/dev/null
    return 0
  fi

  # Create volume
  "$DS_CLI" volume create --label "${DS_OWNER_LABEL}=${DS_OWNER_VALUE}" "${name}-data" > /dev/null

  # Create and start container
  "$DS_CLI" run -d \
    --name "$name" \
    --hostname localhost \
    --label "${DS_OWNER_LABEL}=${DS_OWNER_VALUE}" \
    "${runtime_args[@]}" \
    -v "${name}-data:/data" \
    -e DS_DM_PASSWORD="$password" \
    -e DS_SUFFIX_NAME="$base_dn" \
    -e DS_CREATE_SUFFIX_ENTRY=True \
    -p ${ldap_port}:3389 \
    -p ${ldaps_port}:3636 \
    "$DS_IMAGE" > /dev/null

  return 0
}

# Remove a DS container and its volume.
# Refuses to remove a container that does not carry the ownership label
# (see DS_OWNER_LABEL) unless "true" is passed as the second argument.
remove_ds_container() {
  local name=$1
  local force=${2:-false}
  local volume_name="${name}-data"

  if "$DS_CLI" inspect "$name" >/dev/null 2>&1; then
    if [[ "$force" != true ]] && ! container_is_script_owned "$name"; then
      echo "Error: container '$name' exists but was not created by these scripts" >&2
      echo "  (missing container label ${DS_OWNER_LABEL}=${DS_OWNER_VALUE})." >&2
      echo "  Remove it manually, or pass --force-clean to remove it anyway." >&2
      return 1
    fi
    if ! "$DS_CLI" rm -f "$name" >/dev/null 2>&1; then
      echo "Error: failed to remove container '$name' with $DS_CLI" >&2
      return 1
    fi
    echo "  Removed $name"
  fi

  if "$DS_CLI" volume inspect "$volume_name" >/dev/null 2>&1; then
    if [[ "$force" != true ]] && ! volume_is_script_owned "$volume_name"; then
      echo "Error: volume '$volume_name' exists but was not created by these scripts" >&2
      echo "  (missing volume label ${DS_OWNER_LABEL}=${DS_OWNER_VALUE})." >&2
      echo "  Remove it manually, or pass --force-clean to remove it anyway." >&2
      return 1
    fi
    if ! "$DS_CLI" volume rm "$volume_name" >/dev/null 2>&1; then
      echo "Error: failed to remove volume '$volume_name' with $DS_CLI" >&2
      return 1
    fi
    echo "  Removed $volume_name"
  fi
}

# Check that the selected container runtime executable and engine are usable.
require_container_cli() {
  if ! command -v "$DS_CLI" >/dev/null 2>&1; then
    echo "Error: '$DS_CLI' command not found" >&2
    echo "  Install it, or select another runtime with DS_CLI=<docker|podman>." >&2
    return 1
  fi

  if ! "$DS_CLI" info >/dev/null 2>&1; then
    echo "Error: '$DS_CLI' is installed but its engine is unavailable" >&2
    echo "  Start Docker, or run 'podman machine start' when using Podman." >&2
    return 1
  fi
}
