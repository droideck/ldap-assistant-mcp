"""User management tools for 389 Directory Server."""

import json
import logging
from typing import Dict, Any
from datetime import datetime
from lib389.idm.user import nsUserAccounts
from lib389.idm.account import Accounts
from src.lib.datetime_utils import convert_datetimes_to_strings
from ..connection import get_connection, get_connection_manager

logger = logging.getLogger(__name__)


def _get_base_dn(server_name: str) -> str:
    """
    Get the base DN for a server.

    Args:
        server_name: Name of the server

    Returns:
        Base DN string
    """
    manager = get_connection_manager()
    config = manager.get_config(server_name)
    return config.base_dn


def get_user_status(ds_instance, user_dn: str, basedn: str) -> Dict[str, Any]:
    """
    Get comprehensive user status using proper 389 DS API.

    Args:
        ds_instance: DirSrv connection instance
        user_dn: Distinguished name of the user
        basedn: Base DN for the directory

    Returns:
        Dict containing user status information with keys:
            - simple_status: 'active', 'locked', 'inactive', or 'unknown'
            - detailed_status: Detailed state from 389 DS
            - status_params: Additional parameters from status check
            - calc_time: Time when status was calculated
    """
    try:
        accounts = Accounts(ds_instance, basedn)
        acct = accounts.get(dn=user_dn)
        status_data = acct.status()

        # Extract status information
        account_state = status_data.get('state', 'unknown')
        params = status_data.get('params', {})
        calc_time = status_data.get('calc_time', None)

        # Convert calc_time to string if it's a datetime object
        if isinstance(calc_time, datetime):
            calc_time_str = calc_time.isoformat()
        else:
            calc_time_str = calc_time

        # Ensure params are serializable
        serializable_params = convert_datetimes_to_strings(params)

        # Map 389 DS AccountState to our simplified status
        if hasattr(account_state, 'name'):
            state_name = account_state.name
        elif hasattr(account_state, 'value'):
            state_name = str(account_state.value)
        else:
            state_name = str(account_state)

        if state_name in ['DIRECTLY_LOCKED', 'INDIRECTLY_LOCKED']:
            simple_status = 'locked'
        elif state_name == 'INACTIVITY_LIMIT_EXCEEDED':
            simple_status = 'inactive'
        elif state_name == 'ACTIVATED':
            simple_status = 'active'
        else:
            simple_status = 'unknown'

        return {
            'simple_status': simple_status,
            'detailed_status': state_name,
            'status_params': serializable_params,
            'calc_time': calc_time_str
        }

    except Exception as e:
        logger.warning(f"Error getting user status for {user_dn}: {str(e)}")
        # Fallback to basic status check
        try:
            accounts = Accounts(ds_instance, basedn)
            acct = accounts.get(dn=user_dn)
            # Check nsAccountLock attribute directly
            attrs = acct.get_all_attrs()
            if 'nsAccountLock' in attrs and attrs['nsAccountLock'] and attrs['nsAccountLock'][0].lower() == 'true':
                return {
                    'simple_status': 'locked',
                    'detailed_status': 'DIRECTLY_LOCKED',
                    'status_params': {},
                    'calc_time': None
                }
            else:
                return {
                    'simple_status': 'active',
                    'detailed_status': 'ACTIVATED',
                    'status_params': {},
                    'calc_time': None
                }
        except Exception as fallback_error:
            logger.error(f"Fallback status check failed for {user_dn}: {str(fallback_error)}")
            return {
                'simple_status': 'unknown',
                'detailed_status': f'error: {str(e)}',
                'status_params': {},
                'calc_time': None
            }


def list_all_users(limit: int = 50, server_name: str = "default") -> Dict[str, Any]:
    """
    List all users in the directory.

    Args:
        limit: Maximum number of users to return (default: 50)
        server_name: Name of the server to query (default: "default")

    Returns:
        Dict containing user list with metadata
    """
    ds = None
    try:
        logger.info(f"Listing all users with limit {limit} on server {server_name}")
        ds = get_connection(server_name)
        base_dn = _get_base_dn(server_name)

        users = nsUserAccounts(ds, base_dn)
        user_entries = users.list()

        results = []
        count = 0

        for user in user_entries:
            if count >= limit:
                break

            try:
                user_data_json = user.get_all_attrs_json()
                user_data = json.loads(user_data_json)
                user_dn = user_data.get('dn', '')

                # Convert datetime objects
                if 'attrs' in user_data and isinstance(user_data['attrs'], dict):
                    user_data['attrs'] = convert_datetimes_to_strings(user_data['attrs'])

                # Add status information
                status_info = get_user_status(ds, user_dn, base_dn)
                user_data['attrs']['computed_status'] = status_info

                results.append(user_data)
                count += 1

            except Exception as user_error:
                logger.error(f"Error processing user: {str(user_error)}")
                continue

        response_data = {
            "type": "user_list",
            "server": server_name,
            "total_returned": len(results),
            "limit_applied": limit,
            "items": results
        }

        logger.info(f"Successfully returned {len(results)} users from {server_name}")
        return response_data

    except Exception as e:
        logger.error(f"Error listing users: {str(e)}")
        raise
    finally:
        # Clean up connection
        if ds is not None:
            try:
                ds.close()
            except:
                pass


def search_users_by_name(name: str, limit: int = 50, server_name: str = "default") -> Dict[str, Any]:
    """
    Search for users by name (uid, cn, givenName, sn, or displayName).

    Args:
        name: Name to search for (supports wildcards with *)
        limit: Maximum number of users to return (default: 50)
        server_name: Name of the server to query

    Returns:
        Dict containing matching user entries
    """
    ds = None
    try:
        logger.info(f"Searching users by name: {name} on server {server_name}")
        ds = get_connection(server_name)
        base_dn = _get_base_dn(server_name)

        # Build search filter for name
        if '*' in name:
            # User provided wildcards
            search_filter = f"(|(uid={name})(cn={name})(givenName={name})(sn={name})(displayName={name})(mail={name}))"
        else:
            # Add wildcards for partial matching
            search_filter = f"(|(uid=*{name}*)(cn=*{name}*)(givenName=*{name}*)(sn=*{name}*)(displayName=*{name}*)(mail=*{name}*))"

        users = nsUserAccounts(ds, base_dn)
        user_entries = users.filter(search_filter)

        results = []
        count = 0

        for user in user_entries:
            if count >= limit:
                break

            try:
                user_data_json = user.get_all_attrs_json()
                user_data = json.loads(user_data_json)
                user_dn = user_data.get('dn', '')

                # Convert datetime objects
                if 'attrs' in user_data and isinstance(user_data['attrs'], dict):
                    user_data['attrs'] = convert_datetimes_to_strings(user_data['attrs'])

                # Add status information
                status_info = get_user_status(ds, user_dn, base_dn)
                user_data['attrs']['computed_status'] = status_info

                results.append(user_data)
                count += 1

            except Exception as user_error:
                logger.error(f"Error processing user: {str(user_error)}")
                continue

        response_data = {
            "type": "user_search",
            "server": server_name,
            "search_term": name,
            "filter_used": search_filter,
            "total_returned": len(results),
            "limit_applied": limit,
            "items": results
        }

        logger.info(f"Found {len(results)} users matching '{name}' on {server_name}")
        return response_data

    except Exception as e:
        logger.error(f"Error searching users by name '{name}': {str(e)}")
        raise
    finally:
        # Clean up connection
        if ds is not None:
            try:
                ds.close()
            except:
                pass


def get_user_details(username: str, server_name: str = "default") -> Dict[str, Any]:
    """
    Get detailed information about a specific user.

    Args:
        username: Username (uid) to get details for
        server_name: Name of the server to query

    Returns:
        Dict containing detailed user information
    """
    ds = None
    try:
        logger.info(f"Getting details for user: {username} on server {server_name}")
        ds = get_connection(server_name)
        base_dn = _get_base_dn(server_name)

        users = nsUserAccounts(ds, base_dn)
        user = users.get(username)
        user_data_json = user.get_all_attrs_json()
        user_data = json.loads(user_data_json)
        user_dn = user_data.get('dn', '')

        # Convert datetime objects
        if 'attrs' in user_data and isinstance(user_data['attrs'], dict):
            user_data['attrs'] = convert_datetimes_to_strings(user_data['attrs'])

        # Add status information
        status_info = get_user_status(ds, user_dn, base_dn)
        user_data['attrs']['computed_status'] = status_info

        response_data = {
            "type": "user_details",
            "server": server_name,
            "username": username,
            "user": user_data
        }

        logger.info(f"Successfully retrieved details for user: {username} on {server_name}")
        return response_data

    except Exception as e:
        logger.error(f"Error getting user details for '{username}': {str(e)}")
        raise
    finally:
        # Clean up connection
        if ds is not None:
            try:
                ds.close()
            except:
                pass


def list_active_users(limit: int = 50, server_name: str = "default") -> Dict[str, Any]:
    """
    List all active (unlocked) users in the directory.

    Args:
        limit: Maximum number of users to return (default: 50)
        server_name: Name of the server to query

    Returns:
        Dict containing active user entries
    """
    ds = None
    try:
        logger.info(f"Listing active users with limit {limit} on server {server_name}")
        ds = get_connection(server_name)
        base_dn = _get_base_dn(server_name)

        users = nsUserAccounts(ds, base_dn)
        user_entries = users.list()

        results = []
        count = 0
        processed = 0

        for user in user_entries:
            if count >= limit:
                break

            try:
                processed += 1
                user_data_json = user.get_all_attrs_json()
                user_data = json.loads(user_data_json)
                user_dn = user_data.get('dn', '')

                # Convert datetime objects
                if 'attrs' in user_data and isinstance(user_data['attrs'], dict):
                    user_data['attrs'] = convert_datetimes_to_strings(user_data['attrs'])

                # Add status information
                status_info = get_user_status(ds, user_dn, base_dn)
                user_data['attrs']['computed_status'] = status_info

                # Only include active users
                if status_info.get('simple_status') == 'active':
                    results.append(user_data)
                    count += 1

            except Exception as user_error:
                logger.error(f"Error processing user: {str(user_error)}")
                continue

        response_data = {
            "type": "active_users",
            "server": server_name,
            "total_processed": processed,
            "active_users_found": len(results),
            "limit_applied": limit,
            "items": results
        }

        logger.info(f"Successfully returned {len(results)} active users out of {processed} processed on {server_name}")
        return response_data

    except Exception as e:
        logger.error(f"Error listing active users: {str(e)}")
        raise
    finally:
        # Clean up connection
        if ds is not None:
            try:
                ds.close()
            except:
                pass


def list_locked_users(limit: int = 50, server_name: str = "default") -> Dict[str, Any]:
    """
    List all locked users in the directory.

    Args:
        limit: Maximum number of users to return (default: 50)
        server_name: Name of the server to query

    Returns:
        Dict containing locked user entries
    """
    ds = None
    try:
        logger.info(f"Listing locked users with limit {limit} on server {server_name}")
        ds = get_connection(server_name)
        base_dn = _get_base_dn(server_name)

        users = nsUserAccounts(ds, base_dn)
        user_entries = users.list()

        results = []
        count = 0
        processed = 0

        for user in user_entries:
            if count >= limit:
                break

            try:
                processed += 1
                user_data_json = user.get_all_attrs_json()
                user_data = json.loads(user_data_json)
                user_dn = user_data.get('dn', '')

                # Convert datetime objects
                if 'attrs' in user_data and isinstance(user_data['attrs'], dict):
                    user_data['attrs'] = convert_datetimes_to_strings(user_data['attrs'])

                # Add status information
                status_info = get_user_status(ds, user_dn, base_dn)
                user_data['attrs']['computed_status'] = status_info

                # Only include locked users
                if status_info.get('simple_status') == 'locked':
                    results.append(user_data)
                    count += 1

            except Exception as user_error:
                logger.error(f"Error processing user: {str(user_error)}")
                continue

        response_data = {
            "type": "locked_users",
            "server": server_name,
            "total_processed": processed,
            "locked_users_found": len(results),
            "limit_applied": limit,
            "items": results
        }

        logger.info(f"Successfully returned {len(results)} locked users out of {processed} processed on {server_name}")
        return response_data

    except Exception as e:
        logger.error(f"Error listing locked users: {str(e)}")
        raise
    finally:
        # Clean up connection
        if ds is not None:
            try:
                ds.close()
            except:
                pass


def search_users_by_attribute(attribute: str, value: str, limit: int = 50, server_name: str = "default") -> Dict[str, Any]:
    """
    Search for users by a specific attribute value.

    Args:
        attribute: LDAP attribute name to search (e.g., 'employeeType', 'department', 'title')
        value: Value to search for (supports wildcards with *)
        limit: Maximum number of users to return (default: 50)
        server_name: Name of the server to query

    Returns:
        Dict containing matching user entries
    """
    ds = None
    try:
        logger.info(f"Searching users by attribute {attribute}={value} on server {server_name}")
        ds = get_connection(server_name)
        base_dn = _get_base_dn(server_name)

        # Build search filter
        if '*' in value:
            search_filter = f"({attribute}={value})"
        else:
            search_filter = f"({attribute}=*{value}*)"

        users = nsUserAccounts(ds, base_dn)
        user_entries = users.filter(search_filter)

        results = []
        count = 0

        for user in user_entries:
            if count >= limit:
                break

            try:
                user_data_json = user.get_all_attrs_json()
                user_data = json.loads(user_data_json)
                user_dn = user_data.get('dn', '')

                # Convert datetime objects
                if 'attrs' in user_data and isinstance(user_data['attrs'], dict):
                    user_data['attrs'] = convert_datetimes_to_strings(user_data['attrs'])

                # Add status information
                status_info = get_user_status(ds, user_dn, base_dn)
                user_data['attrs']['computed_status'] = status_info

                results.append(user_data)
                count += 1

            except Exception as user_error:
                logger.error(f"Error processing user: {str(user_error)}")
                continue

        response_data = {
            "type": "attribute_search",
            "server": server_name,
            "attribute": attribute,
            "value": value,
            "filter_used": search_filter,
            "total_returned": len(results),
            "limit_applied": limit,
            "items": results
        }

        logger.info(f"Found {len(results)} users with {attribute}={value} on {server_name}")
        return response_data

    except Exception as e:
        logger.error(f"Error searching users by attribute {attribute}={value}: {str(e)}")
        raise
    finally:
        # Clean up connection
        if ds is not None:
            try:
                ds.close()
            except:
                pass
