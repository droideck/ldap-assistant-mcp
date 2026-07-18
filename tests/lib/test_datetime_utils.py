"""Unit tests for lib/datetime_utils.py."""

from __future__ import annotations

from datetime import datetime, timezone

from ldap_assistant_mcp.lib.datetime_utils import convert_datetimes_to_strings


def test_converts_bare_datetime():
    dt = datetime(2024, 1, 1, 12, 0)
    assert convert_datetimes_to_strings(dt) == "2024-01-01T12:00:00"


def test_converts_timezone_aware_datetime():
    dt = datetime(2024, 1, 1, 12, 0, tzinfo=timezone.utc)
    assert convert_datetimes_to_strings(dt) == "2024-01-01T12:00:00+00:00"


def test_converts_datetimes_in_dict():
    data = {"created": datetime(2024, 1, 1, 12, 0), "count": 5}
    assert convert_datetimes_to_strings(data) == {
        "created": "2024-01-01T12:00:00",
        "count": 5,
    }


def test_converts_datetimes_in_list():
    data = [datetime(2024, 1, 1), "text", 42]
    assert convert_datetimes_to_strings(data) == ["2024-01-01T00:00:00", "text", 42]


def test_converts_nested_structures():
    data = {
        "outer": {
            "inner": [
                {"ts": datetime(2024, 6, 15, 8, 30, 45)},
            ],
        },
    }
    result = convert_datetimes_to_strings(data)
    assert result["outer"]["inner"][0]["ts"] == "2024-06-15T08:30:45"


def test_primitives_pass_through_unchanged():
    for value in (None, True, 42, 3.14, "text", b"bytes"):
        assert convert_datetimes_to_strings(value) == value


def test_empty_containers():
    assert convert_datetimes_to_strings({}) == {}
    assert convert_datetimes_to_strings([]) == []
