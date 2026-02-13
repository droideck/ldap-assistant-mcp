"""Shared DSE/LDIF helpers for offline and archive tools.

Centralises DN handling (using ``ldap.dn`` for proper parsing) and the
low-level ``DSEldif._contents`` helpers that were previously duplicated
across config.py, indexes.py, health.py, and archive.py.
"""

from __future__ import annotations

import os
from typing import Dict, List

import ldap.dn
from lib389.dseldif import DSEldif


def _parse_ldif_value(line: str) -> str:
    """Extract the value from an LDIF attribute line.

    Handles ``attr: value\\n``, ``attr:: base64\\n``, and ``attr:\\n`` (empty).
    """
    colon_pos = line.index(":")
    rest = line[colon_pos + 1:].rstrip("\n")
    if rest.startswith(": "):
        return rest[2:]
    if rest.startswith(":"):
        return rest[1:].lstrip(" ")
    return rest.lstrip(" ")


# lib389 DSEldif._find_attr assumes "attr: value\n" format and crashes with
# IndexError on empty values ("attr:\n").  Patch it to use proper LDIF parsing.
def _find_attr(self, entry_dn, attr):
    entry_dn_i = self._contents.index("dn: {}\n".format(entry_dn.lower()))
    attr_data = {}

    try:
        dn_end_i = self._contents[entry_dn_i:].index("\n")
    except ValueError:
        dn_end_i = len(self._contents)

    entry_slice = self._contents[entry_dn_i:entry_dn_i + dn_end_i]
    prefix = "{}:".format(attr)

    for line in entry_slice:
        if line.startswith(prefix):
            attr_data[entry_slice.index(line)] = _parse_ldif_value(line)

    if not attr_data:
        raise ValueError(
            "Attribute {} wasn't found under dn: {}".format(attr, entry_dn.lower())
        )

    return entry_dn_i, attr_data


DSEldif._find_attr = _find_attr


def normalize_dn(dn_str: str) -> str:
    """Normalize a DN for case-insensitive comparison using ``ldap.dn``."""
    try:
        parsed = ldap.dn.str2dn(dn_str)
        normalized = [
            [(a.lower(), v.lower(), t) for a, v, t in rdn]
            for rdn in parsed
        ]
        return ldap.dn.dn2str(normalized)
    except Exception:
        return dn_str.lower()


def dn_equals(dn1: str, dn2: str) -> bool:
    """Case-insensitive DN equality check."""
    return normalize_dn(dn1) == normalize_dn(dn2)


def is_direct_child_of(child_dn: str, parent_dn: str) -> bool:
    """Check if *child_dn* is a direct (depth-1) child of *parent_dn*."""
    try:
        child_parsed = ldap.dn.str2dn(child_dn)
        parent_parsed = ldap.dn.str2dn(parent_dn)
        if len(child_parsed) != len(parent_parsed) + 1:
            return False
        for c_rdn, p_rdn in zip(child_parsed[1:], parent_parsed):
            if [(a.lower(), v.lower(), t) for a, v, t in c_rdn] != \
               [(a.lower(), v.lower(), t) for a, v, t in p_rdn]:
                return False
        return True
    except Exception:
        return False


def is_under_dn(dn: str, parent_dn: str) -> bool:
    """Check if *dn* is anywhere under *parent_dn* (any depth)."""
    try:
        dn_parsed = ldap.dn.str2dn(dn)
        parent_parsed = ldap.dn.str2dn(parent_dn)
        if len(dn_parsed) <= len(parent_parsed):
            return False
        tail = dn_parsed[-len(parent_parsed):]
        for c_rdn, p_rdn in zip(tail, parent_parsed):
            if [(a.lower(), v.lower(), t) for a, v, t in c_rdn] != \
               [(a.lower(), v.lower(), t) for a, v, t in p_rdn]:
                return False
        return True
    except Exception:
        return False


def get_rdn_value(dn: str) -> tuple:
    """Return ``(attr, value)`` of the leftmost RDN, lowercased.

    Returns ``("", "")`` on parse failure.
    """
    try:
        parsed = ldap.dn.str2dn(dn)
        if parsed:
            attr, val, _ = parsed[0][0]
            return attr.lower(), val.lower()
    except Exception:
        pass
    return "", ""


def get_dse_ldif_path(ds) -> str:
    """Get path to dse.ldif from DirSrv or ArchiveDirSrv."""
    if hasattr(ds, "dse_ldif_path") and ds.dse_ldif_path:
        return ds.dse_ldif_path
    return os.path.join(ds.ds_paths.config_dir, "dse.ldif")


def find_child_dns(dse, parent_dn: str) -> List[str]:
    """Find direct child entry DNs under *parent_dn* from ``DSEldif._contents``."""
    children = []
    for line in dse._contents:
        if not line.startswith("dn: "):
            continue
        dn = line[4:].rstrip("\n")
        if is_direct_child_of(dn, parent_dn):
            children.append(dn)
    return children


def get_all_entry_attrs(dse, entry_dn: str) -> Dict[str, List[str]]:
    """Get all attributes of an entry from ``DSEldif._contents``.

    Returns ``{attr_name: [values]}`` where values are strings.
    Uses :func:`normalize_dn` for matching so that case differences in the
    DN do not prevent a hit.
    """
    target_norm = normalize_dn(entry_dn)
    start_idx = None
    for idx, line in enumerate(dse._contents):
        if line.startswith("dn: "):
            dn = line[4:].rstrip("\n")
            if normalize_dn(dn) == target_norm:
                start_idx = idx
                break

    if start_idx is None:
        return {}

    attrs: Dict[str, List[str]] = {}
    for i in range(start_idx + 1, len(dse._contents)):
        line = dse._contents[i]
        if line == "\n" or line.startswith("dn: "):
            break
        colon_idx = line.find(":")
        if colon_idx <= 0:
            continue
        attr_name = line[:colon_idx]
        value = _parse_ldif_value(line)
        attrs.setdefault(attr_name, []).append(value)
    return attrs
