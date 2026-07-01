"""Evaluate tool selection accuracy against the eval dataset.

This harness measures whether tool schemas and descriptions are
sufficient for an LLM to select the correct tool for a given query.
No live LLM is required — it uses keyword / description overlap scoring.

Usage::

    pytest tests/eval/run_eval.py -v
    # or standalone:
    python tests/eval/run_eval.py
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from unittest.mock import patch

from fastmcp import Client

from ldap_assistant_mcp.dirsrv_mcp.server import DirSrvMCP
from ldap_assistant_mcp.core import LDAPServerConfig, MCPSettings

DATASET_PATH = Path(__file__).with_name("eval_dataset.json")


def _load_dataset():
    with open(DATASET_PATH) as fh:
        return json.load(fh)


@pytest.fixture
def eval_dataset():
    return _load_dataset()


@pytest.fixture
def mcp_server():
    """Create a DirSrvMCP for schema introspection (no live connection needed)."""
    env_vars = {
        "LDAP_URL": "ldap://localhost:389",
        "LDAP_BASE_DN": "dc=example,dc=com",
        "LDAP_BIND_DN": "cn=Directory Manager",
        "LDAP_BIND_PASSWORD": "secret",
        "LDAP_MCP_EXPOSE_SENSITIVE_DATA": "true",
    }
    with patch.dict(os.environ, env_vars):
        config = LDAPServerConfig.from_env()
        return DirSrvMCP(
            servers=[config],
            settings=MCPSettings(expose_sensitive_data=True),
            include_env_fallback=False,
        )


def _score_tool_selection(query: str, expected_tools: list[str], tools: list) -> float:
    """Score how well tool metadata supports selecting the right tool.

    Returns 1.0 if the expected tool's name or description tokens overlap
    strongly with the query, 0.0 otherwise.

    This is a heuristic proxy: if the tool name or description contains
    the key terms from the query, an LLM should be able to select it.
    """
    query_tokens = set(query.lower().split())
    # Remove stop words
    stop_words = {"the", "a", "an", "my", "me", "is", "are", "in", "of", "for", "to", "and", "or", "all", "any"}
    query_tokens -= stop_words

    tool_map = {t.name: t for t in tools}

    for expected in expected_tools:
        if expected not in tool_map:
            return 0.0

        tool = tool_map[expected]
        tool_name_tokens = set(expected.lower().replace("_", " ").split())
        description = (tool.description or "").lower()
        desc_tokens = set(description.split())

        # Score: how many query tokens appear in the tool name or description?
        combined = tool_name_tokens | desc_tokens
        overlap = query_tokens & combined
        if len(query_tokens) > 0 and len(overlap) / len(query_tokens) >= 0.3:
            return 1.0

    return 0.0


@pytest.mark.asyncio
async def test_tool_selection_accuracy(mcp_server, eval_dataset):
    """All expected tools should be discoverable from their names/descriptions."""
    async with Client(mcp_server) as client:
        tools = await client.list_tools()

    scores = []
    failures = []
    for case in eval_dataset:
        score = _score_tool_selection(case["query"], case["expected_tools"], tools)
        scores.append(score)
        if score < 1.0:
            failures.append(f"  FAIL: {case['query']!r} -> expected {case['expected_tools']}")

    accuracy = sum(scores) / len(scores) if scores else 0.0
    print(f"\nEval accuracy: {accuracy:.0%} ({int(sum(scores))}/{len(scores)})")
    if failures:
        print("Failures:")
        for f in failures:
            print(f)

    assert accuracy >= 0.80, f"Tool selection accuracy {accuracy:.0%} below 80% threshold"


@pytest.mark.asyncio
async def test_all_tools_have_annotations(mcp_server):
    """Every tool should have readOnlyHint=True annotation."""
    async with Client(mcp_server) as client:
        tools = await client.list_tools()

    missing = []
    for tool in tools:
        annotations = tool.annotations
        if not annotations or not getattr(annotations, "readOnlyHint", False):
            missing.append(tool.name)

    assert not missing, f"Tools missing readOnlyHint=True: {missing}"


@pytest.mark.asyncio
async def test_all_tools_have_tags(mcp_server):
    """Every tool should have at least one tag."""
    async with Client(mcp_server) as client:
        tools = await client.list_tools()

    missing = []
    for tool in tools:
        meta = tool.meta or {}
        tags = (meta.get("_fastmcp") or meta.get("fastmcp") or {}).get("tags", [])
        if not tags:
            missing.append(tool.name)
    assert not missing, f"Tools missing tags: {missing}"


if __name__ == "__main__":
    import asyncio

    async def main():
        env_vars = {
            "LDAP_URL": "ldap://localhost:389",
            "LDAP_BASE_DN": "dc=example,dc=com",
            "LDAP_BIND_DN": "cn=Directory Manager",
            "LDAP_BIND_PASSWORD": "secret",
            "LDAP_MCP_EXPOSE_SENSITIVE_DATA": "true",
        }
        with patch.dict(os.environ, env_vars):
            config = LDAPServerConfig.from_env()
            server = DirSrvMCP(
                servers=[config],
                settings=MCPSettings(expose_sensitive_data=True),
                include_env_fallback=False,
            )

        dataset = _load_dataset()
        async with Client(server) as client:
            tools = await client.list_tools()

        scores = []
        for case in dataset:
            score = _score_tool_selection(case["query"], case["expected_tools"], tools)
            scores.append(score)
            status = "OK" if score >= 1.0 else "FAIL"
            print(f"  [{status}] {case['query']!r} -> {case['expected_tools']}")

        accuracy = sum(scores) / len(scores) if scores else 0.0
        print(f"\nAccuracy: {accuracy:.0%} ({int(sum(scores))}/{len(scores)})")

    asyncio.run(main())
