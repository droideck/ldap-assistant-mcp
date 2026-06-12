"""Archive discovery and loading for SOS reports and extracted configs."""

from __future__ import annotations

import atexit
import glob
import logging
import os
import shutil
import tarfile
import tempfile
from dataclasses import dataclass, field
from typing import List, Optional

logger = logging.getLogger(__name__)

_temp_dirs: List[str] = []
_extraction_cache: dict[str, str] = {}  # resolved archive path -> extracted dir

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
    instance_name: Optional[str] = None,
) -> ArchiveLayout:
    """Auto-detect archive structure and return discovered paths.

    Supports:
    - Explicit config_path / logs_path (manual extract)
    - archive_path pointing to a .tar.xz/.tar.gz (auto-extracted)
    - archive_path pointing to an SOS report directory

    Args:
        instance_name: Optional instance to select (e.g. 'slapd-supplier1')
            when archive contains multiple DS instances. If omitted and
            multiple instances exist, raises ValueError listing them.
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

    return _scan_directory(archive_path, instance_name=instance_name)

def extract_archive(archive_file: str) -> str:
    """Extract .tar.xz or .tar.gz to a temporary directory.

    Returns the path to the extracted directory.  Repeated calls with
    the same archive file return the cached result instead of
    re-extracting.  Tracked for cleanup via :func:`cleanup_temp_dirs`
    (also registered as an ``atexit`` handler).
    """
    if not os.path.isfile(archive_file):
        raise FileNotFoundError(f"Archive file not found: {archive_file}")

    real_path = os.path.realpath(archive_file)
    cached = _extraction_cache.get(real_path)
    if cached and os.path.isdir(cached):
        logger.debug("Reusing cached extraction for %s at %s", archive_file, cached)
        return cached

    tmp_dir = tempfile.mkdtemp(prefix="ldap-mcp-archive-")
    _temp_dirs.append(tmp_dir)
    logger.info("Extracting %s to %s", archive_file, tmp_dir)

    with tarfile.open(archive_file, "r:*") as tar:
        tar.extractall(tmp_dir, filter="data")

    _extraction_cache[real_path] = tmp_dir
    return tmp_dir


def cleanup_temp_dirs() -> None:
    """Remove all tracked temporary archive directories."""
    for d in list(_temp_dirs):
        shutil.rmtree(d, ignore_errors=True)
        logger.debug("Cleaned up temp dir: %s", d)
    _temp_dirs.clear()
    _extraction_cache.clear()


atexit.register(cleanup_temp_dirs)

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

def _scan_directory(
    root: str,
    instance_name: Optional[str] = None,
) -> ArchiveLayout:
    """Scan a directory for SOS report or DS instance structure.

    Args:
        root: Directory to scan.
        instance_name: Optional instance to select when multiple are present.
            If omitted and multiple instances exist, raises ValueError.
    """
    nested = sorted(glob.glob(os.path.join(root, "sosreport-*")))
    if nested and os.path.isdir(nested[0]):
        root = nested[0]

    # Pattern 1: Standard SOS layout — etc/dirsrv/slapd-*/dse.ldif
    dse_matches = sorted(glob.glob(os.path.join(root, "etc", "dirsrv", "slapd-*", "dse.ldif")))
    if dse_matches:
        dse_path = _select_instance(dse_matches, instance_name)
        return _build_sos_layout(root, dse_path)

    # Pattern 2: Direct slapd-* directory (user extracted just the instance dir)
    dse_direct = sorted(glob.glob(os.path.join(root, "slapd-*", "dse.ldif")))
    if dse_direct:
        dse_path = _select_instance(dse_direct, instance_name)
        config_dir = os.path.dirname(dse_path)
        return ArchiveLayout(
            archive_type="manual_extract",
            instance_name=_extract_instance_name(config_dir),
            config_dir=config_dir,
            dse_ldif_path=dse_path,
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

def _select_instance(
    dse_paths: List[str],
    instance_name: Optional[str] = None,
) -> str:
    """Pick the right dse.ldif when an archive contains multiple instances.

    Args:
        dse_paths: Sorted list of dse.ldif paths found in the archive.
        instance_name: Optional instance selector (e.g. 'slapd-supplier1').

    Returns:
        The selected dse.ldif path.

    Raises:
        ValueError: If instance_name doesn't match any found instance, or
            if multiple instances exist and no instance_name was given.
    """
    if len(dse_paths) == 1:
        if instance_name:
            found = _extract_instance_name(os.path.dirname(dse_paths[0]))
            if found and found != instance_name:
                raise ValueError(
                    f"instance_name '{instance_name}' does not match the "
                    f"only instance found: '{found}'"
                )
        return dse_paths[0]

    # Multiple instances — build name→path map
    instance_map = {}
    for dse_path in dse_paths:
        name = _extract_instance_name(os.path.dirname(dse_path))
        if name:
            instance_map[name] = dse_path

    available = sorted(instance_map.keys())

    if not instance_name:
        raise ValueError(
            f"Archive contains {len(available)} DS instances: "
            f"{', '.join(available)}. "
            f"Set instance_name in the server config to select one."
        )

    if instance_name not in instance_map:
        raise ValueError(
            f"instance_name '{instance_name}' not found in archive. "
            f"Available instances: {', '.join(available)}"
        )

    return instance_map[instance_name]


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
