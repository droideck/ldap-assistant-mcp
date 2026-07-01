"""Tests for value_utils module."""

from ldap_assistant_mcp.lib.value_utils import safe_int, safe_float, format_bytes


class TestSafeInt:
    def test_int_value(self):
        assert safe_int(42) == 42

    def test_string_value(self):
        assert safe_int("123") == 123

    def test_none_returns_default(self):
        assert safe_int(None) == 0
        assert safe_int(None, 99) == 99

    def test_list_extracts_first(self):
        assert safe_int(["42"]) == 42
        assert safe_int([100, 200]) == 100

    def test_empty_list_returns_default(self):
        assert safe_int([]) == 0
        assert safe_int([], 99) == 99

    def test_invalid_string_returns_default(self):
        assert safe_int("invalid") == 0
        assert safe_int("invalid", 99) == 99

    def test_float_truncates(self):
        assert safe_int(3.7) == 3


class TestSafeFloat:
    def test_float_value(self):
        assert safe_float(3.14) == 3.14

    def test_string_value(self):
        assert safe_float("3.14") == 3.14

    def test_int_value(self):
        assert safe_float(42) == 42.0

    def test_none_returns_default(self):
        assert safe_float(None) == 0.0
        assert safe_float(None, 1.5) == 1.5

    def test_list_extracts_first(self):
        assert safe_float(["3.14"]) == 3.14

    def test_invalid_string_returns_default(self):
        assert safe_float("invalid") == 0.0


class TestFormatBytes:
    def test_bytes(self):
        assert format_bytes(500) == "500 B"

    def test_kilobytes(self):
        assert format_bytes(2048) == "2.0 KB"

    def test_megabytes(self):
        assert format_bytes(1048576) == "1.0 MB"

    def test_gigabytes(self):
        assert format_bytes(1073741824) == "1.0 GB"

    def test_negative_returns_zero(self):
        assert format_bytes(-100) == "0 B"

    def test_zero(self):
        assert format_bytes(0) == "0 B"
