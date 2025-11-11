"""Group management tools for 389 Directory Server."""

import json
import logging
from typing import Dict, Any
from lib389.idm.group import Groups
from src.lib.datetime_utils import convert_datetimes_to_strings
from ..connection import get_connection, get_connection_manager

logger = logging.getLogger(__name__)


def _get_base_dn(server_name: str) -> str:
    """Get the base DN for a server."""
    manager = get_connection_manager()
    config = manager.get_config(server_name)
    return config.base_dn


def list_all_groups(limit: int = 50, server_name: str = "default") -> Dict[str, Any]:
    """
    List all groups in the directory.

    Args:
        limit: Maximum number of groups to return (default: 50)
        server_name: Name of the server to query (default: "default")

    Returns:
        Dict containing group list with metadata
    """
    ds = None
    try:
        logger.info(f"Listing all groups with limit {limit} on server {server_name}")
        ds = get_connection(server_name)
        base_dn = _get_base_dn(server_name)

        groups = Groups(ds, base_dn)
        group_entries = groups.list()

        results = []
        count = 0

        for group in group_entries:
            if count >= limit:
                break

            try:
                group_data_json = group.get_all_attrs_json()
                group_data = json.loads(group_data_json)

                # Convert datetime objects
                if 'attrs' in group_data and isinstance(group_data['attrs'], dict):
                    group_data['attrs'] = convert_datetimes_to_strings(group_data['attrs'])

                results.append(group_data)
                count += 1

            except Exception as group_error:
                logger.error(f"Error processing group: {str(group_error)}")
                continue

        response_data = {
            "type": "group_list",
            "server": server_name,
            "total_returned": len(results),
            "limit_applied": limit,
            "items": results
        }

        logger.info(f"Successfully returned {len(results)} groups from {server_name}")
        return response_data

    except Exception as e:
        logger.error(f"Error listing groups: {str(e)}")
        raise
    finally:
        if ds:
            try:
                ds.unbind_s()
            except:
                pass
