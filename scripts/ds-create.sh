#!/bin/bash -e

# Script to create 389 Directory Server containers for MCP testing
# Adapted for LDAP Assistent MCP Server testing

SCRIPT_PATH=$(readlink -f "$0")
SCRIPT_NAME=$(basename "$SCRIPT_PATH")
SCRIPT_DIR=$(dirname "$SCRIPT_PATH")

BASE_DN=

VERBOSE=
DEBUG=

usage() {
    echo "Usage: $SCRIPT_NAME [OPTIONS] <name>"
    echo
    echo "Options:"
    echo "    --image=<image>          Container image (default: quay.io/389ds/dirsrv)"
    echo "    --hostname=<hostname>    Container hostname"
    echo "    --network=<network>      Container network"
    echo "    --network-alias=<alias>  Container network alias"
    echo "    --password=<password>    Directory Manager password"
    echo "    --base-dn=<DN>           Base DN (default: dc=example,dc=com)"
    echo " -v,--verbose                Run in verbose mode."
    echo "    --debug                  Run in debug mode."
    echo "    --help                   Show help message."
}

while getopts v-: arg ; do
    case $arg in
    v)
        VERBOSE=true
        ;;
    -)
        LONG_OPTARG="${OPTARG#*=}"

        case $OPTARG in
        image=?*)
            IMAGE="$LONG_OPTARG"
            ;;
        hostname=?*)
            HOSTNAME="$LONG_OPTARG"
            ;;
        network=?*)
            NETWORK="$LONG_OPTARG"
            ;;
        network-alias=?*)
            ALIAS="$LONG_OPTARG"
            ;;
        password=?*)
            PASSWORD="$LONG_OPTARG"
            ;;
        base-dn=?*)
            BASE_DN="$LONG_OPTARG"
            ;;
        verbose)
            VERBOSE=true
            ;;
        debug)
            VERBOSE=true
            DEBUG=true
            ;;
        help)
            usage
            exit
            ;;
        '')
            break # "--" terminates argument processing
            ;;
        image* | hostname* | network* | network-alias* | password* | \
        base-dn*)
            echo "ERROR: Missing argument for --$OPTARG option" >&2
            exit 1
            ;;
        *)
            echo "ERROR: Illegal option --$OPTARG" >&2
            exit 1
            ;;
        esac
        ;;
    \?)
        exit 1 # getopts already reported the illegal option
        ;;
    esac
done

create_container() {

    echo "Creating DS volume"

    docker volume create $NAME-data > /dev/null

    echo "Creating DS container"

    OPTIONS=()
    OPTIONS+=(--name $NAME)
    OPTIONS+=(--hostname $HOSTNAME)
    OPTIONS+=(-v $NAME-data:/data)

    if [ "$SHARED" != "" ]; then
        OPTIONS+=(-v $GITHUB_WORKSPACE:$SHARED)
    fi

    OPTIONS+=(-e DS_DM_PASSWORD=$PASSWORD)
    OPTIONS+=(-e DS_SUFFIX_NAME=$BASE_DN)
    OPTIONS+=(-e DS_CREATE_SUFFIX_ENTRY=True)
    OPTIONS+=(-p 3389)
    OPTIONS+=(-p 3636)

    if [ "$NETWORK" != "" ]
    then
        OPTIONS+=(--network $NETWORK)
    fi

    if [ "$ALIAS" != "" ]
    then
        OPTIONS+=(--network-alias $ALIAS)
    fi

    docker create "${OPTIONS[@]}" $IMAGE > /dev/null

    OPTIONS=()
    OPTIONS+=(--image=$IMAGE)
    OPTIONS+=(--password=$PASSWORD)

    $SCRIPT_DIR/ds-start.sh "${OPTIONS[@]}" $NAME
}

add_base_entries() {

    echo "Adding base entries"

    # Wait for Directory Manager password to be properly set by container
    echo "Waiting for Directory Manager password configuration..."
    sleep 5

    # Verify we can authenticate with Directory Manager
    MAX_AUTH_ATTEMPTS=10
    AUTH_ATTEMPT=1

    while [ $AUTH_ATTEMPT -le $MAX_AUTH_ATTEMPTS ]; do
        if docker exec $NAME ldapwhoami -x -H ldap://$HOSTNAME:3389 -D "cn=Directory Manager" -w $PASSWORD > /dev/null 2>&1; then
            echo "Directory Manager authentication successful"
            break
        fi

        echo "Waiting for Directory Manager password... (attempt $AUTH_ATTEMPT/$MAX_AUTH_ATTEMPTS)"
        sleep 5
        AUTH_ATTEMPT=$((AUTH_ATTEMPT + 1))
    done

    if [ $AUTH_ATTEMPT -gt $MAX_AUTH_ATTEMPTS ]; then
        echo "ERROR: Directory Manager authentication failed"
        exit 1
    fi

    # Create backend if it doesn't exist
    echo "Creating backend for $BASE_DN"
    docker exec $NAME dsconf localhost backend create --suffix="$BASE_DN" --be-name userroot --create-entries --create-suffix || true

    # Check if base DN exists, if not create it manually
    if ! docker exec $NAME ldapsearch -x -H ldap://$HOSTNAME:3389 -D "cn=Directory Manager" -w $PASSWORD -b "$BASE_DN" -s base > /dev/null 2>&1; then
        echo "Creating base DN manually: $BASE_DN"

        # Extract the domain component (dc) values from BASE_DN
        if [[ "$BASE_DN" =~ dc=([^,]+) ]]; then
            DC_VALUE="${BASH_REMATCH[1]}"
        else
            DC_VALUE="example"
        fi

        docker exec -i $NAME ldapadd \
            -H ldap://$HOSTNAME:3389 \
            -D "cn=Directory Manager" \
            -w $PASSWORD \
            -x << EOF
dn: $BASE_DN
objectClass: top
objectClass: domain
dc: $DC_VALUE
EOF
    fi

    # Check if ou=people exists, if not create it
    if ! docker exec $NAME ldapsearch -x -H ldap://$HOSTNAME:3389 -D "cn=Directory Manager" -w $PASSWORD -b "ou=people,$BASE_DN" -s base > /dev/null 2>&1; then
        echo "Creating ou=people,$BASE_DN"
        docker exec -i $NAME ldapadd \
            -H ldap://$HOSTNAME:3389 \
            -D "cn=Directory Manager" \
            -w $PASSWORD \
            -x << EOF
dn: ou=people,$BASE_DN
objectClass: top
objectClass: organizationalUnit
ou: people
EOF
    fi

    # Check if ou=groups exists, if not create it
    if ! docker exec $NAME ldapsearch -x -H ldap://$HOSTNAME:3389 -D "cn=Directory Manager" -w $PASSWORD -b "ou=groups,$BASE_DN" -s base > /dev/null 2>&1; then
        echo "Creating ou=groups,$BASE_DN"
        docker exec -i $NAME ldapadd \
            -H ldap://$HOSTNAME:3389 \
            -D "cn=Directory Manager" \
            -w $PASSWORD \
            -x << EOF
dn: ou=groups,$BASE_DN
objectClass: top
objectClass: organizationalUnit
ou: groups
EOF
    fi
}

# remove parsed options and args from $@ list
shift $((OPTIND-1))

NAME=$1

if [ "$NAME" = "" ]
then
    echo "ERROR: Missing container name"
    exit 1
fi

if [ "$PASSWORD" = "" ]
then
    echo "ERROR: Missing Directory Manager password"
    exit 1
fi

if [ "$IMAGE" = "" ]
then
    IMAGE=quay.io/389ds/dirsrv
fi

if [ "$BASE_DN" = "" ]
then
    BASE_DN="dc=example,dc=com"
fi

if [ "$DEBUG" = true ] ; then
    echo "NAME: $NAME"
    echo "IMAGE: $IMAGE"
    echo "HOSTNAME: $HOSTNAME"
    echo "BASE_DN: $BASE_DN"
    echo "PASSWORD: $PASSWORD"
fi

create_container

add_base_entries

echo "Verifying DS installation"
docker exec $NAME ldapsearch \
    -H ldap://$HOSTNAME:3389 \
    -D "cn=Directory Manager" \
    -w $PASSWORD \
    -x \
    -b "$BASE_DN" \
    -s base

# allow more time to connect to network
sleep 5

echo "DS container is ready for MCP testing"