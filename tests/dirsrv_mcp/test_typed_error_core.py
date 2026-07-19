"""Regression tests: typed error core and honest middleware semantics.

Covers:

- Every standard error dict carries a stable machine-readable
  ``error_code`` / ``category`` / ``retryable`` classification.
- The logging middleware reports error-shaped results as errors, not ok.
- Oversized structured results raise a real tool error (covered in
  test_middleware_runtime.py) and timeouts state cancellation truth.
"""

from __future__ import annotations

import logging
from unittest.mock import MagicMock

import pytest
from fastmcp.exceptions import ToolError

from ldap_assistant_mcp.dirsrv_mcp.connection import (
    ConnectionFailed,
    LiveServerRequired,
    UnknownServer,
)
from ldap_assistant_mcp.dirsrv_mcp.middleware import LoggingMiddleware, TimeoutMiddleware
from ldap_assistant_mcp.dirsrv_mcp.tools.error_utils import format_tool_error
from ldap_assistant_mcp.lib.envelope import (
    CODE_CONNECTION_FAILED,
    CODE_MODE_MISMATCH,
    CODE_UNEXPECTED,
    CODE_UNKNOWN_SERVER,
    ToolErrorEnvelope,
    classify_exception,
)
from ldap_assistant_mcp.lib.privacy import create_privacy_error


def _mcp():
    mcp = MagicMock()
    mcp.privacy_enabled = False
    mcp.debug_enabled = False
    return mcp


class TestClassification:
    def test_mode_mismatch(self):
        exc = LiveServerRequired("log parsing", "srv1", try_instead=["first_look"])
        code, category, retryable = classify_exception(exc)
        assert code == CODE_MODE_MISMATCH
        assert category == "mode_mismatch"
        assert retryable is False

    def test_connection_failed_is_retryable(self):
        code, category, retryable = classify_exception(ConnectionFailed("down"))
        assert code == CODE_CONNECTION_FAILED
        assert retryable is True

    def test_unknown_server(self):
        code, _, _ = classify_exception(UnknownServer("nope"))
        assert code == CODE_UNKNOWN_SERVER

    def test_unexpected_fallback(self):
        code, category, retryable = classify_exception(RuntimeError("boom"))
        assert code == CODE_UNEXPECTED
        assert retryable is False


class TestErrorDictContract:
    def test_format_tool_error_carries_code(self):
        result = format_tool_error(ConnectionFailed("down"), _mcp(), "test_type", server="srv1")
        assert result["error_code"] == CODE_CONNECTION_FAILED
        assert result["category"] == "connection_failed"
        assert result["retryable"] is True
        # Validates against the published envelope model
        ToolErrorEnvelope.model_validate(result)

    def test_privacy_error_carries_code(self):
        result = create_privacy_error("parse_access_log")
        assert result["error_code"] == "LAMCP-PRIVACY-001"
        assert result["category"] == "privacy_restricted"
        assert result["retryable"] is False

    def test_existing_keys_preserved(self):
        exc = LiveServerRequired("log parsing", "srv1", try_instead=["first_look"])
        result = format_tool_error(exc, _mcp(), "test_type", server="srv1")
        assert result["type"] == "test_type"
        assert result["server"] == "srv1"
        assert "error" in result
        assert result["try_instead"] == ["first_look"]


class _FakeContext:
    def __init__(self, name="some_tool"):
        self.message = MagicMock()
        self.message.name = name


class TestLoggingMiddleware:
    async def test_error_dict_result_logged_as_error(self, caplog):
        mw = LoggingMiddleware()
        result = MagicMock()
        result.structured_content = {"type": "x", "error": "failed", "error_code": "LAMCP-CONN-001"}

        async def call_next(_ctx):
            return result

        with caplog.at_level(logging.INFO, logger="ldap_assistant_mcp.dirsrv_mcp.middleware"):
            await mw.on_call_tool(_FakeContext(), call_next)
        messages = [r.getMessage() for r in caplog.records]
        assert any("status=error_result" in m and "LAMCP-CONN-001" in m for m in messages)
        assert not any("status=ok" in m for m in messages)

    async def test_ok_result_logged_as_ok(self, caplog):
        mw = LoggingMiddleware()
        result = MagicMock()
        result.structured_content = {"type": "x", "value": 1}

        async def call_next(_ctx):
            return result

        with caplog.at_level(logging.INFO, logger="ldap_assistant_mcp.dirsrv_mcp.middleware"):
            await mw.on_call_tool(_FakeContext(), call_next)
        assert any("status=ok" in r.getMessage() for r in caplog.records)


class TestTimeoutTruth:
    async def test_timeout_error_states_continuation(self):
        import asyncio

        mw = TimeoutMiddleware(default_timeout=0.05, cleanup_grace=0.05)

        async def call_next(_ctx):
            await asyncio.sleep(5)

        with pytest.raises(ToolError) as exc:
            await mw.on_call_tool(_FakeContext(), call_next)
        message = str(exc.value)
        assert "timed out" in message
        assert "LAMCP-TIMEOUT-001" in message
        # Cancellation truth is stated either way
        assert ("cancelled and cleaned up" in message) or ("may still be running" in message)
