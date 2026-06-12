"""Common LDAP utility functions."""

from typing import Optional, List


def normalize_dn(dn: str) -> str:
    """
    Normalize a Distinguished Name for comparison.

    Args:
        dn: The DN to normalize

    Returns:
        Normalized DN (lowercase, stripped whitespace)

    Examples:
        >>> normalize_dn("CN=John Doe, OU=Users, DC=example, DC=com")
        'cn=john doe,ou=users,dc=example,dc=com'
    """
    if not dn:
        return ""
    return dn.strip().lower()


def parse_dn_components(dn: str) -> List[tuple]:
    """
    Parse a DN into its component RDNs.

    Args:
        dn: The DN to parse

    Returns:
        List of (attribute, value) tuples

    Examples:
        >>> parse_dn_components("cn=John Doe,ou=Users,dc=example,dc=com")
        [('cn', 'John Doe'), ('ou', 'Users'), ('dc', 'example'), ('dc', 'com')]
    """
    if not dn:
        return []

    components = []
    parts = dn.split(',')

    for part in parts:
        part = part.strip()
        if '=' in part:
            attr, value = part.split('=', 1)
            components.append((attr.strip(), value.strip()))

    return components


def get_rdn_value(dn: str) -> Optional[str]:
    """
    Extract the value from the first RDN component.

    Args:
        dn: The DN to extract from

    Returns:
        The value of the first RDN, or None if invalid

    Examples:
        >>> get_rdn_value("uid=jdoe,ou=people,dc=example,dc=com")
        'jdoe'
    """
    components = parse_dn_components(dn)
    if components:
        return components[0][1]
    return None


def is_dn_in_subtree(dn: str, subtree_base: str) -> bool:
    """
    Check if a DN is within a given subtree.

    Args:
        dn: The DN to check
        subtree_base: The base DN of the subtree

    Returns:
        True if dn is within the subtree, False otherwise

    Examples:
        >>> is_dn_in_subtree("uid=jdoe,ou=people,dc=example,dc=com", "dc=example,dc=com")
        True
        >>> is_dn_in_subtree("uid=jdoe,ou=people,dc=test,dc=com", "dc=example,dc=com")
        False
    """
    norm_dn = normalize_dn(dn)
    norm_base = normalize_dn(subtree_base)

    return norm_dn.endswith(norm_base)
