#!/bin/bash -e

set -euo pipefail

# Test environment defaults
DS_IMAGE=${DS_IMAGE:-quay.io/389ds/dirsrv}
DS_PASSWORD=${DS_PASSWORD:-TestPassword123}
DS_BASE_DN=${DS_BASE_DN:-dc=test,dc=com}

# Multiple test servers: name:ldap_port:ldaps_port
TEST_SERVERS=(
  "ds-test-1:33891:36361"
  "ds-test-2:33892:36362"
  "ds-test-3:33893:36363"
)

print_usage() {
  cat <<EOF
Usage: scripts/dev-test.sh [options]

Options:
  --image <image>          Directory Server image (default: "$DS_IMAGE")
  --password <password>    Directory Manager password (default: "$DS_PASSWORD")
  --base-dn <dn>           Base DN (default: "$DS_BASE_DN")
  --skip-seed              Skip adding example test data
  --no-clean               Skip removing existing containers
  -h, --help               Show this help

Creates ${#TEST_SERVERS[@]} test containers:
  ds-test-1  ldap://localhost:33891
  ds-test-2  ldap://localhost:33892
  ds-test-3  ldap://localhost:33893

All containers use:
  Base DN:   $DS_BASE_DN
  Bind DN:   cn=Directory Manager
  Password:  $DS_PASSWORD
EOF
}

SKIP_SEED=false
CLEAN=true

while [[ $# -gt 0 ]]; do
  case "$1" in
    --image)
      DS_IMAGE="$2"; shift 2 ;;
    --password)
      DS_PASSWORD="$2"; shift 2 ;;
    --base-dn)
      DS_BASE_DN="$2"; shift 2 ;;
    --skip-seed)
      SKIP_SEED=true; shift ;;
    --no-clean)
      CLEAN=false; shift ;;
    -h|--help)
      print_usage; exit 0 ;;
    *)
      echo "Unknown option: $1" >&2; print_usage; exit 1 ;;
  esac
done

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Error: required command not found: $1" >&2
    exit 1
  fi
}

require_cmd docker

SCRIPT_DIR=$(cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd)

# Step 1: Cleanup
if [[ "$CLEAN" == true ]]; then
  echo "[1/8] Cleaning existing test containers..."
  for server in "${TEST_SERVERS[@]}"; do
    IFS=':' read -r name ldap_port ldaps_port <<< "$server"
    docker rm -f "$name" 2>/dev/null || true
    docker volume rm "${name}-data" 2>/dev/null || true
  done
  rm -f "$REPO_ROOT/tests-servers.json" 2>/dev/null || true
else
  echo "[1/8] Skipping cleanup (--no-clean)"
fi

# Step 2: Create containers
echo "[2/8] Creating ${#TEST_SERVERS[@]} test containers..."

wait_for_ds() {
  local name=$1
  local max_attempts=30
  local attempt=1
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
  docker exec "$name" dsconf localhost backend create \
    --suffix="$DS_BASE_DN" \
    --be-name=userroot \
    --create-entries \
    --create-suffix 2>/dev/null || true
}

create_base_ous() {
  local name=$1
  docker exec -i "$name" ldapadd \
    -H ldap://localhost:3389 \
    -D "cn=Directory Manager" \
    -w "$DS_PASSWORD" \
    -x <<EOF || true
dn: ou=people,$DS_BASE_DN
objectClass: top
objectClass: organizationalUnit
ou: people

dn: ou=groups,$DS_BASE_DN
objectClass: top
objectClass: organizationalUnit
ou: groups
EOF
}

for server in "${TEST_SERVERS[@]}"; do
  IFS=':' read -r name ldap_port ldaps_port <<< "$server"

  echo "  Creating $name (LDAP: $ldap_port)..."

  # Skip if already exists
  if docker inspect "$name" >/dev/null 2>&1; then
    echo "    Container exists, starting..."
    docker start "$name" >/dev/null
    continue
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
  if ! wait_for_ds "$name"; then
    echo "    ERROR: $name failed to start"
    exit 1
  fi

  # Wait for auth
  sleep 3
  if ! wait_for_auth "$name"; then
    echo "    ERROR: $name auth failed"
    exit 1
  fi

  # Create backend
  create_backend "$name"

  # Create OUs
  create_base_ous "$name"

  echo "    $name is ready"
done

# Step 3: Generate test servers.json
echo "[3/8] Generating tests-servers.json..."
cat > "$REPO_ROOT/tests-servers.json" <<EOF
{
  "servers": [
    {
      "name": "ds-test-1",
      "ldap_url": "ldap://localhost:33891",
      "base_dn": "$DS_BASE_DN",
      "bind_dn": "cn=Directory Manager",
      "bind_password": "$DS_PASSWORD",
      "provider_type": "389ds"
    },
    {
      "name": "ds-test-2",
      "ldap_url": "ldap://localhost:33892",
      "base_dn": "$DS_BASE_DN",
      "bind_dn": "cn=Directory Manager",
      "bind_password": "$DS_PASSWORD",
      "provider_type": "389ds"
    },
    {
      "name": "ds-test-3",
      "ldap_url": "ldap://localhost:33893",
      "base_dn": "$DS_BASE_DN",
      "bind_dn": "cn=Directory Manager",
      "bind_password": "$DS_PASSWORD",
      "provider_type": "389ds"
    }
  ]
}
EOF
chmod 600 "$REPO_ROOT/tests-servers.json"

# Step 4: Seed test data
if [[ "$SKIP_SEED" != true ]]; then
  echo "[4/8] Seeding test data into all containers..."

  seed_test_data() {
    local name=$1
    local suffix=$2

    docker exec -i "$name" ldapadd \
      -H ldap://localhost:3389 \
      -D "cn=Directory Manager" \
      -w "$DS_PASSWORD" \
      -x <<EOF || true
dn: uid=testuser1,ou=people,$DS_BASE_DN
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
objectClass: nsPerson
objectClass: nsAccount
objectClass: nsOrgPerson
objectClass: posixAccount
uid: testuser1
cn: Test User 1
sn: User
givenName: Test
displayName: Test User 1
mail: testuser1@test.com
uidNumber: 1001
gidNumber: 1001
homeDirectory: /home/testuser1

dn: uid=testuser2,ou=people,$DS_BASE_DN
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
objectClass: nsPerson
objectClass: nsAccount
objectClass: nsOrgPerson
objectClass: posixAccount
uid: testuser2
cn: Test User 2
sn: User
givenName: Test
displayName: Test User 2
mail: testuser2@test.com
uidNumber: 1002
gidNumber: 1002
homeDirectory: /home/testuser2
departmentNumber: Engineering

dn: uid=lockeduser,ou=people,$DS_BASE_DN
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
objectClass: nsPerson
objectClass: nsAccount
objectClass: nsOrgPerson
objectClass: posixAccount
uid: lockeduser
cn: Locked User
sn: User
givenName: Locked
displayName: Locked User
mail: lockeduser@test.com
uidNumber: 1003
gidNumber: 1003
homeDirectory: /home/lockeduser
nsAccountLock: true

dn: uid=contractor,ou=people,$DS_BASE_DN
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
objectClass: nsPerson
objectClass: nsAccount
objectClass: nsOrgPerson
objectClass: posixAccount
uid: contractor
cn: Contractor User
sn: User
givenName: Contractor
displayName: Contractor User
mail: contractor@test.com
uidNumber: 1004
gidNumber: 1004
homeDirectory: /home/contractor
employeeType: Contractor

dn: uid=server${suffix}user,ou=people,$DS_BASE_DN
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
objectClass: nsPerson
objectClass: nsAccount
objectClass: nsOrgPerson
objectClass: posixAccount
uid: server${suffix}user
cn: Server ${suffix} User
sn: User
givenName: Server${suffix}
displayName: Server ${suffix} Unique User
mail: server${suffix}user@test.com
uidNumber: 200${suffix}
gidNumber: 200${suffix}
homeDirectory: /home/server${suffix}user

dn: cn=testgroup1,ou=groups,$DS_BASE_DN
objectClass: top
objectClass: groupOfNames
objectClass: posixGroup
objectClass: nsMemberOf
cn: testgroup1
gidNumber: 5000

dn: cn=testgroup2,ou=groups,$DS_BASE_DN
objectClass: top
objectClass: groupOfNames
objectClass: posixGroup
objectClass: nsMemberOf
cn: testgroup2
gidNumber: 5001
EOF
  }

  suffix=1
  for server in "${TEST_SERVERS[@]}"; do
    IFS=':' read -r name ldap_port ldaps_port <<< "$server"
    echo "  Seeding $name..."
    seed_test_data "$name" "$suffix"
    suffix=$((suffix + 1))
  done
else
  echo "[4/8] Skipping seed (--skip-seed)"
fi

# Step 5: Verify
echo "[5/8] Verifying test data..."
for server in "${TEST_SERVERS[@]}"; do
  IFS=':' read -r name ldap_port ldaps_port <<< "$server"
  count=$(docker exec "$name" ldapsearch -H ldap://localhost:3389 -D "cn=Directory Manager" -w "$DS_PASSWORD" -x -b "ou=people,$DS_BASE_DN" -s sub "(uid=*)" dn 2>/dev/null | grep -c "^dn:" || echo "0")
  echo "  $name: $count users found"
done

# Step 6: Python environment
echo "[6/8] Preparing Python environment..."
if ! command -v uv >/dev/null 2>&1; then
  echo "Installing uv..."
  curl -LsSf https://astral.sh/uv/install.sh | sh
  export PATH="$HOME/.cargo/bin:$PATH"
fi

cd "$REPO_ROOT"
uv venv
uv pip install -r requirements.txt
uv pip install pytest pytest-asyncio

# Step 7: Run tests
echo "[7/8] Running pytest..."
export LDAP_SERVERS_CONFIG="$REPO_ROOT/tests-servers.json"
# Also set single-server env vars for backward compatibility
export LDAP_URL="ldap://localhost:33891"
export LDAP_BASE_DN="$DS_BASE_DN"
export LDAP_BIND_DN="cn=Directory Manager"
export LDAP_BIND_PASSWORD="$DS_PASSWORD"

uv run pytest -v -s

# Step 8: Summary
echo "[8/8] Done!"
echo ""
echo "Test containers:"
for server in "${TEST_SERVERS[@]}"; do
  IFS=':' read -r name ldap_port ldaps_port <<< "$server"
  echo "  $name: ldap://localhost:$ldap_port"
done
echo ""
echo "Configuration: tests-servers.json"
echo "LDAP_SERVERS_CONFIG=$REPO_ROOT/tests-servers.json"
