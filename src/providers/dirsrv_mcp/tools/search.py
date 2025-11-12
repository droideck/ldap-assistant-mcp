"""Generic LDAP search tools for 389 Directory Server."""

import json
import logging
import base64
from typing import Dict, Any, Optional
import ldap
from ..connection import get_connection

logger = logging.getLogger(__name__)


def ldap_search(
    base_dn: str,
    scope: str = 'SUBTREE',
    filter: str = '(objectClass=*)',
    attributes: Optional[str] = None,
    attrs_only: bool = False,
    limit: int = 100,
    server_name: str = "default"
) -> Dict[str, Any]:
    """
    Perform a general LDAP search with full control over search parameters.

    This tool provides direct access to LDAP search functionality for cases where
    the specialized search tools (user/group specific) are not sufficient. It allows
    searching for any type of LDAP entry with complete control over the search scope,
    filter, and attributes returned.

    Args:
        base_dn: The base DN to start the search from (e.g., 'dc=example,dc=com' or 'cn=config')
        scope: Search scope - must be one of: 'BASE', 'ONELEVEL', or 'SUBTREE'
               - BASE: Search only the base DN entry itself
               - ONELEVEL: Search only immediate children of the base DN
               - SUBTREE: Search the entire subtree starting from base DN
        filter: LDAP search filter (e.g., '(objectClass=*)', '(&(uid=*)(mail=*))', '(cn=admin*)')
                Default: '(objectClass=*)' to return all entries
        attributes: Comma-separated list of attributes to return (e.g., 'cn,mail,uid')
                    Default: None (returns all attributes)
                    Special values: '*' for all user attributes, '+' for all operational attributes
        attrs_only: If True, return only attribute names without values (default: False)
        limit: Maximum number of entries to return (default: 100, max: 1000)
        server_name: Name of the server to query (default: "default")

    Returns:
        Dict containing the search results with full entry details

    Raises:
        ValueError: If scope is invalid
        Exception: If search fails
    """
    ds = None
    try:
        logger.info(f"Performing LDAP search on {server_name} - base: {base_dn}, scope: {scope}, filter: {filter}")

        # Store original scope string for response
        original_scope = scope.upper()

        # Validate and convert scope
        scope_map = {
            'BASE': ldap.SCOPE_BASE,
            'ONELEVEL': ldap.SCOPE_ONELEVEL,
            'SUBTREE': ldap.SCOPE_SUBTREE
        }

        if original_scope not in scope_map:
            raise ValueError(f"Invalid scope '{scope}'. Must be one of: BASE, ONELEVEL, SUBTREE")

        search_scope = scope_map[original_scope]

        # Validate limit
        if limit < 1:
            limit = 1
        elif limit > 1000:
            limit = 1000
            logger.warning("Limit exceeded maximum of 1000, capping at 1000")

        # Parse attributes
        attrlist = None
        if attributes:
            # Handle special cases and comma-separated list
            if attributes.strip() in ['*', '+', '*,+', '+,*']:
                attrlist = attributes.strip().split(',')
            else:
                attrlist = [attr.strip() for attr in attributes.split(',') if attr.strip()]

        # Connect to LDAP
        ds = get_connection(server_name)

        # Perform the search
        try:
            # Use search_s which returns a list of (dn, attrs) tuples
            search_results = ds.search_s(
                base_dn,
                search_scope,
                filter,
                attrlist=attrlist,
                attrsonly=1 if attrs_only else 0
            )
        except ldap.NO_SUCH_OBJECT:
            raise Exception(f"Base DN '{base_dn}' does not exist")
        except ldap.INVALID_SYNTAX as e:
            raise Exception(f"Invalid LDAP filter syntax: {str(e)}")

        results = []
        for item in search_results:
            if len(results) >= limit:
                break

            if isinstance(item, tuple) and len(item) == 2:
                dn, attrs = item
            else:
                dn = getattr(item, 'dn', None)
                attrs = getattr(item, 'data', None)

            if not dn or attrs is None:
                continue

            attrs_out = {}
            if hasattr(attrs, 'items'):
                for attr_name, attr_values in attrs.items():
                    values_iter = attr_values if isinstance(attr_values, (list, tuple)) else [attr_values]
                    converted_values = []
                    for val in values_iter:
                        if isinstance(val, bytes):
                            try:
                                converted_values.append(val.decode('utf-8'))
                            except UnicodeDecodeError:
                                converted_values.append(base64.b64encode(val).decode('ascii'))
                        else:
                            converted_values.append(str(val))
                    attrs_out[attr_name] = converted_values

            results.append({'dn': dn, 'attrs': attrs_out})

        response_data = {
            "type": "ldap_search",
            "server": server_name,
            "base_dn": base_dn,
            "scope": original_scope,
            "filter": filter,
            "attributes_requested": attributes if attributes else "all",
            "attrs_only": attrs_only,
            "total_returned": len(results),
            "limit_applied": limit,
            "items": results
        }

        logger.info(f"LDAP search on {server_name} completed, returned {len(results)} entries")
        return response_data

    except ldap.LDAPError as e:
        logger.error(f"LDAP search failed on {server_name}: {str(e)}")
        raise Exception(f"LDAP search failed: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error during LDAP search on {server_name}: {str(e)}")
        raise
    finally:
        # Clean up connection
        if ds is not None:
            try:
                ds.close()
            except:
                pass
