"""Archive discovery and loading for SOS reports and extracted configs."""

from __future__ import annotations

import glob
import logging
import os
import tarfile
import tempfile
from dataclasses import dataclass, field
from typing import List, Optional

logger = logging.getLogger(__name__)

@dataclass
class ArchiveLayout:
    """Discovered paths within an archive or extract."""

    archive_type: str  # "sos_report", "manual_extract", "config_only"
    instance_name: Optional[str] = None
    config_dir: Optional[str] = None
    logs_dir: Optional[str] = None
    schema_dir: Optional[str] = None
    cert_dir: Optional[str] = None
    sos_commands_dir: Optional[str] = None
    dse_ldif_path: Optional[str] = None

def detect_archive_layout(
    archive_path: Optional[str] = None,
    config_path: Optional[str] = None,
    logs_path: Optional[str] = None,
) -> ArchiveLayout:
    """Auto-detect archive structure and return discovered paths.

    Supports:
    - Explicit config_path / logs_path (manual extract)
    - archive_path pointing to a .tar.xz/.tar.gz (auto-extracted)
    - archive_path pointing to an SOS report directory
    """
    # Explicit paths provided
    if config_path or logs_path:
        return _layout_from_explicit_paths(config_path, logs_path)

    if not archive_path:
        raise ValueError("Either archive_path or config_path must be provided")

    # Compressed archive — extract first
    if os.path.isfile(archive_path) and _is_tarball(archive_path):
        archive_path = extract_archive(archive_path)

    if not os.path.isdir(archive_path):
        raise FileNotFoundError(f"Archive path is not a directory: {archive_path}")

    return _scan_directory(archive_path)

def extract_archive(archive_file: str) -> str:
    """Extract .tar.xz or .tar.gz to a temporary directory.

    Returns path to the extracted directory. Caller is responsible for cleanup.
    """
    if not os.path.isfile(archive_file):
        raise FileNotFoundError(f"Archive file not found: {archive_file}")

    tmp_dir = tempfile.mkdtemp(prefix="ldap-mcp-archive-")
    logger.info("Extracting %s to %s", archive_file, tmp_dir)

    with tarfile.open(archive_file, "r:*") as tar:
        tar.extractall(tmp_dir, filter="data")

    return tmp_dir

def _is_tarball(path: str) -> bool:
    lower = path.lower()
    return any(lower.endswith(ext) for ext in (".tar.xz", ".tar.gz", ".tar.bz2", ".tgz"))

def _layout_from_explicit_paths(
    config_path: Optional[str],
    logs_path: Optional[str],
) -> ArchiveLayout:
    """Build layout from explicit user-provided paths."""
    layout = ArchiveLayout(archive_type="manual_extract")

    if config_path:
        config_path = os.path.realpath(config_path)
        if not os.path.isdir(config_path):
            raise FileNotFoundError(f"Config path is not a directory: {config_path}")
        layout.config_dir = config_path
        layout.instance_name = _extract_instance_name(config_path)

        dse = os.path.join(config_path, "dse.ldif")
        if os.path.isfile(dse):
            layout.dse_ldif_path = dse

        schema = os.path.join(config_path, "schema")
        if os.path.isdir(schema):
            layout.schema_dir = schema

        layout.cert_dir = config_path

    if logs_path:
        logs_path = os.path.realpath(logs_path)
        if not os.path.isdir(logs_path):
            raise FileNotFoundError(f"Logs path is not a directory: {logs_path}")
        layout.logs_dir = logs_path
        if not layout.instance_name:
            layout.instance_name = _extract_instance_name(logs_path)

    if not layout.config_dir and not layout.logs_dir:
        raise ValueError("At least config_path or logs_path must point to a valid directory")

    if layout.config_dir and not layout.logs_dir:
        layout.archive_type = "config_only"

    return layout

def _scan_directory(root: str) -> ArchiveLayout:
    """Scan a directory for SOS report or DS instance structure."""
    nested = sorted(glob.glob(os.path.join(root, "sosreport-*")))
    if nested and os.path.isdir(nested[0]):
        root = nested[0]

    # Pattern 1: Standard SOS layout — etc/dirsrv/slapd-*/dse.ldif
    dse_matches = sorted(glob.glob(os.path.join(root, "etc", "dirsrv", "slapd-*", "dse.ldif")))
    if dse_matches:
        return _build_sos_layout(root, dse_matches[0])

    # Pattern 2: Direct slapd-* directory (user extracted just the instance dir)
    dse_direct = sorted(glob.glob(os.path.join(root, "slapd-*", "dse.ldif")))
    if dse_direct:
        config_dir = os.path.dirname(dse_direct[0])
        return ArchiveLayout(
            archive_type="manual_extract",
            instance_name=_extract_instance_name(config_dir),
            config_dir=config_dir,
            dse_ldif_path=dse_direct[0],
            cert_dir=config_dir,
            schema_dir=os.path.join(config_dir, "schema") if os.path.isdir(os.path.join(config_dir, "schema")) else None,
        )

    # Pattern 3: dse.ldif directly in root
    dse_root = os.path.join(root, "dse.ldif")
    if os.path.isfile(dse_root):
        return ArchiveLayout(
            archive_type="config_only",
            config_dir=root,
            dse_ldif_path=dse_root,
            cert_dir=root,
            schema_dir=os.path.join(root, "schema") if os.path.isdir(os.path.join(root, "schema")) else None,
        )

    raise FileNotFoundError(
        f"No dse.ldif found in archive at '{root}'. "
        "Expected SOS report structure (etc/dirsrv/slapd-*/dse.ldif) "
        "or a directory containing dse.ldif."
    )

def _build_sos_layout(root: str, dse_path: str) -> ArchiveLayout:
    """Build ArchiveLayout from a standard SOS report directory."""
    config_dir = os.path.dirname(dse_path)
    instance_name = _extract_instance_name(config_dir)

    logs_dir = None
    if instance_name:
        candidate = os.path.join(root, "var", "log", "dirsrv", instance_name)
        if os.path.isdir(candidate):
            logs_dir = candidate

    sos_commands_dir = None
    for dirname in ("dirsrv", "ds"):
        candidate = os.path.join(root, "sos_commands", dirname)
        if os.path.isdir(candidate):
            sos_commands_dir = candidate
            break

    schema_dir = os.path.join(config_dir, "schema")

    return ArchiveLayout(
        archive_type="sos_report",
        instance_name=instance_name,
        config_dir=config_dir,
        logs_dir=logs_dir,
        schema_dir=schema_dir if os.path.isdir(schema_dir) else None,
        cert_dir=config_dir,
        sos_commands_dir=sos_commands_dir,
        dse_ldif_path=dse_path,
    )

def _extract_instance_name(path: str) -> Optional[str]:
    """Extract instance name (e.g. 'slapd-localhost') from a path component."""
    basename = os.path.basename(path.rstrip("/"))
    if basename.startswith("slapd-"):
        return basename
    # Walk up one level
    parent_base = os.path.basename(os.path.dirname(path.rstrip("/")))
    if parent_base.startswith("slapd-"):
        return parent_base
    return None
