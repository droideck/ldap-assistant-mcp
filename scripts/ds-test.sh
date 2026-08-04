#!/bin/bash -e

# Script to create test containers and optionally run pytest
# Creates 3 DS instances for multi-server testing

set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd)

# Source common functions
source "$SCRIPT_DIR/ds-common.sh"

# Test environment defaults
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
Usage: scripts/ds-test.sh [options]

Options:
  --image <image>          Directory Server image (default: "$DS_IMAGE")
  --password <password>    Directory Manager password (default: "$DS_PASSWORD")
  --base-dn <dn>           Base DN (default: "$DS_BASE_DN")
  --skip-seed              Skip adding example test data
  --no-clean               Skip removing existing containers
  --force-clean            Remove existing containers even if they were not
                           created by these scripts (no ownership label)
  --no-pytest              Skip running pytest (useful for CI)
  -h, --help               Show this help

Container runtime:
  DS_CLI                    Container CLI: docker (default) or podman

Creates ${#TEST_SERVERS[@]} test containers:
  ds-test-1  ldap://localhost:33891
  ds-test-2  ldap://localhost:33892
  ds-test-3  ldap://localhost:33893

All containers use:
  Base DN:   $DS_BASE_DN
  Bind DN:   cn=Directory Manager
  Password:  $DS_PASSWORD

Environment variables exported (for running pytest separately):
  LDAP_SERVERS_CONFIG  Path to tests-servers.json
  LDAP_URL             First server URL (single-server compat)
  LDAP_BASE_DN         Base DN
  LDAP_BIND_DN         Bind DN
  LDAP_BIND_PASSWORD   Bind password
EOF
}

SKIP_SEED=false
CLEAN=true
FORCE_CLEAN=false
RUN_PYTEST=true

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
    --force-clean)
      FORCE_CLEAN=true; shift ;;
    --no-pytest)
      RUN_PYTEST=false; shift ;;
    -h|--help)
      print_usage; exit 0 ;;
    *)
      echo "Unknown option: $1" >&2; print_usage; exit 1 ;;
  esac
done

require_container_cli

# Determine total steps based on options
if [[ "$RUN_PYTEST" == true ]]; then
  TOTAL_STEPS=8
else
  TOTAL_STEPS=6
fi
STEP=1

# Step 1: Cleanup
if [[ "$CLEAN" == true ]]; then
  echo "[$STEP/$TOTAL_STEPS] Cleaning existing test containers..."
  for server in "${TEST_SERVERS[@]}"; do
    IFS=':' read -r name ldap_port ldaps_port <<< "$server"
    remove_ds_container "$name" "$FORCE_CLEAN"
  done
  rm -f "$REPO_ROOT/tests-servers.json" 2>/dev/null || true
else
  echo "[$STEP/$TOTAL_STEPS] Skipping cleanup (--no-clean)"
fi
STEP=$((STEP + 1))

# Step 2: Create containers
echo "[$STEP/$TOTAL_STEPS] Creating ${#TEST_SERVERS[@]} test containers..."

for server in "${TEST_SERVERS[@]}"; do
  IFS=':' read -r name ldap_port ldaps_port <<< "$server"

  echo "  Creating $name (LDAP: $ldap_port)..."

  # Create container using common function
  create_ds_container "$name" "$ldap_port" "$ldaps_port" "$DS_PASSWORD" "$DS_BASE_DN"

  # Skip waiting if container already existed
  if "$DS_CLI" inspect "$name" >/dev/null 2>&1; then
    status=$("$DS_CLI" inspect -f '{{.State.Status}}' "$name")
    if [[ "$status" == "running" ]]; then
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
    fi
  fi
done
STEP=$((STEP + 1))

# Step 3: Generate test servers.json
echo "[$STEP/$TOTAL_STEPS] Generating tests-servers.json..."
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
STEP=$((STEP + 1))

# Step 4: Seed test data
if [[ "$SKIP_SEED" != true ]]; then
  echo "[$STEP/$TOTAL_STEPS] Seeding test data into all containers..."

  seed_test_data() {
    local name=$1
    local suffix=$2

    "$DS_CLI" exec -i "$name" ldapadd \
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
  echo "[$STEP/$TOTAL_STEPS] Skipping seed (--skip-seed)"
fi
STEP=$((STEP + 1))

# Step 5: Verify
echo "[$STEP/$TOTAL_STEPS] Verifying test data..."
for server in "${TEST_SERVERS[@]}"; do
  IFS=':' read -r name ldap_port ldaps_port <<< "$server"
  count=$("$DS_CLI" exec "$name" ldapsearch -H ldap://localhost:3389 -D "cn=Directory Manager" -w "$DS_PASSWORD" -x -b "ou=people,$DS_BASE_DN" -s sub "(uid=*)" dn 2>/dev/null | grep -c "^dn:" || echo "0")
  echo "  $name: $count users found"
done
STEP=$((STEP + 1))

# Export environment variables (useful for --no-pytest mode)
export LDAP_SERVERS_CONFIG="$REPO_ROOT/tests-servers.json"
export LDAP_URL="ldap://localhost:33891"
export LDAP_BASE_DN="$DS_BASE_DN"
export LDAP_BIND_DN="cn=Directory Manager"
export LDAP_BIND_PASSWORD="$DS_PASSWORD"

if [[ "$RUN_PYTEST" == true ]]; then
  # Step 6: Python environment
  echo "[$STEP/$TOTAL_STEPS] Preparing Python environment..."
  if ! command -v uv >/dev/null 2>&1; then
    echo "Installing uv..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
    export PATH="$HOME/.cargo/bin:$PATH"
  fi

  cd "$REPO_ROOT"
  # Install exactly what uv.lock pins (fails if uv.lock is out of date with
  # pyproject.toml). --no-sync below then reuses this environment, mirroring
  # CI (.github/workflows/pytest.yml), so a single dependency set is used.
  uv sync --locked --extra dev
  STEP=$((STEP + 1))

  # Step 7: Run tests
  echo "[$STEP/$TOTAL_STEPS] Running pytest..."
  uv run --no-sync pytest -v -s
  STEP=$((STEP + 1))
fi

# Final step: Summary
echo "[$STEP/$TOTAL_STEPS] Done!"
echo ""
echo "Test containers:"
for server in "${TEST_SERVERS[@]}"; do
  IFS=':' read -r name ldap_port ldaps_port <<< "$server"
  echo "  $name: ldap://localhost:$ldap_port"
done
echo ""
echo "Configuration: tests-servers.json"
echo ""
echo "Environment variables for pytest:"
echo "  export LDAP_SERVERS_CONFIG=\"$REPO_ROOT/tests-servers.json\""
echo "  export LDAP_URL=\"ldap://localhost:33891\""
echo "  export LDAP_BASE_DN=\"$DS_BASE_DN\""
echo "  export LDAP_BIND_DN=\"cn=Directory Manager\""
echo "  export LDAP_BIND_PASSWORD=\"$DS_PASSWORD\""
