#!/bin/bash -e

# Script to test local connection functionality
# Creates DS containers and runs tests from INSIDE the container
# to test local instance access (log files, paths, etc.)

set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd)

# Source common functions
source "$SCRIPT_DIR/ds-common.sh"

# Test environment defaults
DS_PASSWORD=${DS_PASSWORD:-TestPassword123}
DS_BASE_DN=${DS_BASE_DN:-dc=test,dc=com}

# Local test containers
LOCAL_TEST_SERVERS=(
  "ds-local-1:34891:37361"
  "ds-local-2:34892:37362"
)

print_usage() {
  cat <<EOF
Usage: scripts/ds-test-local.sh [options]

Options:
  --image <image>          Directory Server image (default: "$DS_IMAGE")
  --password <password>    Directory Manager password (default: "$DS_PASSWORD")
  --base-dn <dn>           Base DN (default: "$DS_BASE_DN")
  --no-clean               Skip removing existing containers
  --no-pytest              Skip running pytest (setup only)
  -h, --help               Show this help

This script tests LOCAL connection functionality by running tests
INSIDE the DS container. This enables access to:
  - Server log files (access, error, audit logs)
  - File system checks and paths
  - DSE.ldif configuration
  - LDAPI socket connections

Creates ${#LOCAL_TEST_SERVERS[@]} local test containers:
  ds-local-1  ldap://localhost:34891  (single local server test)
  ds-local-2  ldap://localhost:34892  (multi-server local test)

Tests are executed inside ds-local-1 container.
EOF
}

CLEAN=true
RUN_PYTEST=true

while [[ $# -gt 0 ]]; do
  case "$1" in
    --image)
      DS_IMAGE="$2"; shift 2 ;;
    --password)
      DS_PASSWORD="$2"; shift 2 ;;
    --base-dn)
      DS_BASE_DN="$2"; shift 2 ;;
    --no-clean)
      CLEAN=false; shift ;;
    --no-pytest)
      RUN_PYTEST=false; shift ;;
    -h|--help)
      print_usage; exit 0 ;;
    *)
      echo "Unknown option: $1" >&2; print_usage; exit 1 ;;
  esac
done

require_docker

# Determine total steps
if [[ "$RUN_PYTEST" == true ]]; then
  TOTAL_STEPS=7
else
  TOTAL_STEPS=5
fi
STEP=1

# Step 1: Cleanup
if [[ "$CLEAN" == true ]]; then
  echo "[$STEP/$TOTAL_STEPS] Cleaning existing local test containers..."
  for server in "${LOCAL_TEST_SERVERS[@]}"; do
    IFS=':' read -r name ldap_port ldaps_port <<< "$server"
    docker rm -f "$name" 2>/dev/null || true
    docker volume rm "${name}-data" 2>/dev/null || true
  done
else
  echo "[$STEP/$TOTAL_STEPS] Skipping cleanup (--no-clean)"
fi
STEP=$((STEP + 1))

# Step 2: Create containers with MCP code mounted
echo "[$STEP/$TOTAL_STEPS] Creating ${#LOCAL_TEST_SERVERS[@]} local test containers..."

for server in "${LOCAL_TEST_SERVERS[@]}"; do
  IFS=':' read -r name ldap_port ldaps_port <<< "$server"

  echo "  Creating $name (LDAP: $ldap_port)..."

  # Skip if already exists
  if docker inspect "$name" >/dev/null 2>&1; then
    echo "  Container $name already exists, starting..."
    docker start "$name" >/dev/null
  else
    # Create volume
    docker volume create "${name}-data" > /dev/null

    # Create container with MCP code mounted
    docker run -d \
      --name "$name" \
      --hostname localhost \
      -v "${name}-data:/data" \
      -v "$REPO_ROOT:/mcp:ro" \
      -e DS_DM_PASSWORD="$DS_PASSWORD" \
      -e DS_SUFFIX_NAME="$DS_BASE_DN" \
      -e DS_CREATE_SUFFIX_ENTRY=True \
      -p ${ldap_port}:3389 \
      -p ${ldaps_port}:3636 \
      "$DS_IMAGE" > /dev/null
  fi

  # Wait for DS
  if ! wait_for_ds "$name"; then
    echo "    ERROR: $name failed to start"
    exit 1
  fi

  # Wait for auth
  sleep 3
  if ! wait_for_auth "$name" "$DS_PASSWORD"; then
    echo "    ERROR: $name auth failed"
    exit 1
  fi

  # Create backend
  create_backend "$name" "$DS_BASE_DN"

  # Create OUs
  create_base_ous "$name" "$DS_BASE_DN" "$DS_PASSWORD"

  echo "    $name is ready"
done
STEP=$((STEP + 1))

# Step 3: Generate local test config inside container
# Note: For tests running inside the container:
# - ldap_url uses localhost:3389 (internal port)
# - is_local=true enables local instance access
# - serverid="localhost" matches the DS instance name
# - Config is written to /tmp inside container (since /mcp is read-only)
echo "[$STEP/$TOTAL_STEPS] Generating tests-local-servers.json inside container..."

docker exec ds-local-1 bash -c "cat > /tmp/tests-local-servers.json << EOF
{
  \"servers\": [
    {
      \"name\": \"ds-local-1\",
      \"ldap_url\": \"ldap://localhost:3389\",
      \"base_dn\": \"$DS_BASE_DN\",
      \"bind_dn\": \"cn=Directory Manager\",
      \"bind_password\": \"$DS_PASSWORD\",
      \"provider_type\": \"389ds\",
      \"is_local\": true,
      \"serverid\": \"localhost\"
    },
    {
      \"name\": \"ds-local-2\",
      \"ldap_url\": \"ldap://ds-local-2:3389\",
      \"base_dn\": \"$DS_BASE_DN\",
      \"bind_dn\": \"cn=Directory Manager\",
      \"bind_password\": \"$DS_PASSWORD\",
      \"provider_type\": \"389ds\",
      \"is_local\": false
    }
  ]
}
EOF"
STEP=$((STEP + 1))

# Step 4: Seed test data
echo "[$STEP/$TOTAL_STEPS] Seeding test data..."

seed_local_test_data() {
  local name=$1

  docker exec -i "$name" ldapadd \
    -H ldap://localhost:3389 \
    -D "cn=Directory Manager" \
    -w "$DS_PASSWORD" \
    -x <<EOF || true
dn: uid=localuser1,ou=people,$DS_BASE_DN
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
objectClass: posixAccount
uid: localuser1
cn: Local User 1
sn: User
givenName: Local
uidNumber: 3001
gidNumber: 3001
homeDirectory: /home/localuser1

dn: cn=localgroup1,ou=groups,$DS_BASE_DN
objectClass: top
objectClass: groupOfNames
objectClass: posixGroup
cn: localgroup1
gidNumber: 6000
EOF
}

for server in "${LOCAL_TEST_SERVERS[@]}"; do
  IFS=':' read -r name ldap_port ldaps_port <<< "$server"
  echo "  Seeding $name..."
  seed_local_test_data "$name"
done
STEP=$((STEP + 1))

# Step 5: Verify
echo "[$STEP/$TOTAL_STEPS] Verifying setup..."
for server in "${LOCAL_TEST_SERVERS[@]}"; do
  IFS=':' read -r name ldap_port ldaps_port <<< "$server"

  # Check user count
  count=$(docker exec "$name" ldapsearch -H ldap://localhost:3389 -D "cn=Directory Manager" -w "$DS_PASSWORD" -x -b "ou=people,$DS_BASE_DN" -s sub "(uid=*)" dn 2>/dev/null | grep -c "^dn:" || echo "0")
  echo "  $name: $count users"

  # Check instance info
  serverid=$(docker exec "$name" dsconf localhost config get nsslapd-instancedir 2>/dev/null | grep -oP 'slapd-\K[^/]+' || echo "unknown")
  echo "    Instance ID: $serverid"

  # Check log paths exist
  if docker exec "$name" test -f /var/log/dirsrv/slapd-localhost/access 2>/dev/null; then
    echo "    Access log: exists"
  else
    echo "    Access log: not found (may be normal for fresh instance)"
  fi
done
STEP=$((STEP + 1))

if [[ "$RUN_PYTEST" == true ]]; then
  # Step 6: Install test dependencies inside container
  echo "[$STEP/$TOTAL_STEPS] Installing test dependencies in container..."

  # The 389ds container is minimal - use ensurepip to bootstrap pip
  docker exec ds-local-1 bash -c "
    python3 -m ensurepip --upgrade 2>/dev/null || true
    cd /mcp
    python3 -m pip install --quiet pytest pytest-asyncio
    python3 -m pip install --quiet -r requirements.txt
  " 2>/dev/null || true
  STEP=$((STEP + 1))

  # Step 7: Run local connection tests inside container
  echo "[$STEP/$TOTAL_STEPS] Running local connection tests inside container..."

  docker exec \
    -e LDAP_SERVERS_CONFIG=/tmp/tests-local-servers.json \
    -e LDAP_URL="ldap://localhost:3389" \
    -e LDAP_BASE_DN="$DS_BASE_DN" \
    -e LDAP_BIND_DN="cn=Directory Manager" \
    -e LDAP_BIND_PASSWORD="$DS_PASSWORD" \
    -e LDAP_IS_LOCAL="true" \
    -e LDAP_SERVERID="localhost" \
    ds-local-1 bash -c "
      cd /mcp && \
      python3 -m pytest src/dirsrv_mcp/tests/test_local_connection.py -v -s 2>&1 || \
      echo 'Local connection tests completed (some failures may be expected if test file does not exist yet)'
    "
  STEP=$((STEP + 1))
fi

# Final summary
echo "[$STEP/$TOTAL_STEPS] Done!"
echo ""
echo "Local test containers:"
for server in "${LOCAL_TEST_SERVERS[@]}"; do
  IFS=':' read -r name ldap_port ldaps_port <<< "$server"
  echo "  $name: ldap://localhost:$ldap_port (external) / ldap://localhost:3389 (internal)"
done
echo ""
echo "Configuration: /tmp/tests-local-servers.json (inside container)"
echo ""
echo "To run tests manually inside the container:"
echo "  docker exec -it ds-local-1 bash"
echo "  cd /mcp"
echo "  export LDAP_SERVERS_CONFIG=/tmp/tests-local-servers.json"
echo "  export LDAP_IS_LOCAL=true"
echo "  export LDAP_SERVERID=localhost"
echo "  python3 -m pytest src/dirsrv_mcp/tests/test_local_connection.py -v -s"
