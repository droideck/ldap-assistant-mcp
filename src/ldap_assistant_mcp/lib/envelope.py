"""Typed error and evidence vocabulary for MCP tool results.

Central registry of stable machine-readable error codes and categories,
plus the evidence-status vocabulary used by diagnostic tools. Every
expected failure a tool can return carries a stable ``error_code`` so
clients and workflows can branch on failures without parsing prose.

The full EvidenceEnvelope migration (per-probe records, evidence indexes,
coverage accounting) is planned for a later release; the truthfulness
fields tools already emit (``evidence_status``, ``probe_failures``,
``checks_failed``, ``evidence_gaps``) use the vocabulary defined here.
"""

from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel

# ---------------------------------------------------------------------------
# Evidence-status vocabulary (shared by diagnostic tools)
# ---------------------------------------------------------------------------

EVIDENCE_COMPLETE = "complete"
EVIDENCE_PARTIAL = "partial"
EVIDENCE_UNAVAILABLE = "unavailable"

# ---------------------------------------------------------------------------
# Stable error codes
# ---------------------------------------------------------------------------

CODE_MODE_MISMATCH = "LAMCP-MODE-001"
CODE_LOCAL_REQUIRED = "LAMCP-MODE-002"
CODE_CONNECTION_FAILED = "LAMCP-CONN-001"
CODE_UNKNOWN_SERVER = "LAMCP-CONFIG-001"
CODE_INVALID_CONFIG = "LAMCP-CONFIG-002"
CODE_PRIVACY_RESTRICTED = "LAMCP-PRIVACY-001"
CODE_RESPONSE_TOO_LARGE = "LAMCP-OVERSIZE-001"
CODE_TIMEOUT = "LAMCP-TIMEOUT-001"
CODE_INVALID_INPUT = "LAMCP-INPUT-001"
CODE_UNEXPECTED = "LAMCP-UNEXPECTED-001"


class ToolErrorEnvelope(BaseModel):
    """Schema of the standard error dict returned by tools.

    Mirrors the shape produced by ``format_tool_error`` so contract tests
    can validate error results against one model.
    """

    type: str
    error: str
    error_code: str = CODE_UNEXPECTED
    category: str = "unexpected"
    retryable: bool = False
    server: Optional[str] = None
    try_instead: Optional[List[str]] = None

    model_config = {"extra": "allow"}


def classify_exception(exc: BaseException) -> tuple:
    """Map an exception to ``(error_code, category, retryable)``.

    Imported types are resolved lazily to keep this module free of
    dependency cycles (connection.py imports core, tools import this).
    """
    from ldap_assistant_mcp.dirsrv_mcp.connection import (
        ConnectionFailed,
        LiveServerRequired,
        UnknownServer,
    )

    if isinstance(exc, LiveServerRequired):
        return CODE_MODE_MISMATCH, "mode_mismatch", False
    if isinstance(exc, ConnectionFailed):
        return CODE_CONNECTION_FAILED, "connection_failed", True
    if isinstance(exc, UnknownServer):
        return CODE_UNKNOWN_SERVER, "unknown_server", False
    if isinstance(exc, TimeoutError):
        return CODE_TIMEOUT, "timeout", True
    if isinstance(exc, (ValueError, TypeError, KeyError)):
        return CODE_INVALID_INPUT, "invalid_input", False
    if isinstance(exc, (OSError, IOError)):
        return CODE_CONNECTION_FAILED, "io_error", True
    return CODE_UNEXPECTED, "unexpected", False
