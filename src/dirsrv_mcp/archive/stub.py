"""Minimal DirSrv-compatible stub for archive analysis.

lib389's offline classes (DSEldif, DirsrvAccessLog, FSChecks, etc.) take a
DirSrv instance to discover file paths. This stub provides just enough of
the DirSrv interface so those classes work with archive data.

For offline instances (stopped local DS), use a real DirSrv with
local_simple_allocate() and skip open(). No stub needed there.

This stub is ONLY for archive mode where files are in non-standard
locations (SOS reports, manual extracts).
"""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from src.dirsrv_mcp.archive.loader import ArchiveLayout

logger = logging.getLogger(__name__)


class ArchivePaths:
    """Paths object pointing at archive locations.

    Mimics the interface of lib389.paths.Paths used by offline lib389 classes.
    """

    def __init__(
        self,
        config_dir: str,
        log_dir: Optional[str] = None,
        schema_dir: Optional[str] = None,
        cert_dir: Optional[str] = None,
    ):
        self._config_dir = config_dir
        self._log_dir = log_dir
        self._schema_dir = schema_dir or os.path.join(config_dir, "schema")
        self._cert_dir = cert_dir or config_dir

    @property
    def config_dir(self) -> str:
        return self._config_dir

    @property
    def log_dir(self) -> Optional[str]:
        return self._log_dir

    @property
    def schema_dir(self) -> str:
        return self._schema_dir

    @property
    def cert_dir(self) -> str:
        return self._cert_dir

    @property
    def access_log(self) -> Optional[str]:
        if self._log_dir:
            return os.path.join(self._log_dir, "access")
        return None

    @property
    def error_log(self) -> Optional[str]:
        if self._log_dir:
            return os.path.join(self._log_dir, "errors")
        return None

    @property
    def audit_log(self) -> Optional[str]:
        if self._log_dir:
            return os.path.join(self._log_dir, "audit")
        return None

    @property
    def security_log(self) -> Optional[str]:
        if self._log_dir:
            return os.path.join(self._log_dir, "security")
        return None


class ArchiveDirSrv:
    """Minimal DirSrv-compatible object for archive analysis.

    Provides just enough interface for lib389 offline classes:
    - self.serverid — instance name (used by DSEldif, Paths)
    - self.ds_paths — Paths-like object with file locations
    - self.log — logger (used by DSEldif for debug output)
    - self.verbose — flag (used by DirsrvLog parse methods)
    """

    def __init__(self, layout: ArchiveLayout):
        self.serverid = layout.instance_name
        self.ds_paths = ArchivePaths(
            config_dir=layout.config_dir,
            log_dir=layout.logs_dir,
            schema_dir=layout.schema_dir,
            cert_dir=layout.cert_dir,
        )
        self.log = logger
        self.verbose = False
        self._layout = layout

    @property
    def dse_ldif_path(self) -> Optional[str]:
        """Return path to dse.ldif (convenience for DSEldif(stub, path=...))."""
        if self._layout.dse_ldif_path:
            return self._layout.dse_ldif_path
        if self.ds_paths.config_dir:
            p = os.path.join(self.ds_paths.config_dir, "dse.ldif")
            if os.path.isfile(p):
                return p
        return None

    def get_cert_dir(self) -> str:
        """Return certificate directory (used by FSChecks)."""
        return self.ds_paths.cert_dir

    def open(self):
        raise RuntimeError(
            "Cannot open LDAP connection to archive. "
            "This is an offline analysis stub."
        )

    def close(self):
        pass  # No-op

    def search_s(self, *args, **kwargs):
        raise RuntimeError(
            "Cannot perform LDAP search on archive. "
            "Use DSEldif or LDIFConn for offline config queries."
        )
