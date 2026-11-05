"""
test_schema_guard.py - Unit tests for forgiving MCP schema normalizer.
"""

from superghidra.core.schema_guard import (
    normalize_mcp_args,
    parse_address_or_symbol,
    set_active_binaries,
)


def test_parse_address_or_symbol():
    assert parse_address_or_symbol("0x00E6DE9C") == 0xE6DE9C
    assert parse_address_or_symbol("00E6DE9C") == 0xE6DE9C
    assert parse_address_or_symbol(15130268) == 15130268
    assert parse_address_or_symbol("15130268") == 15130268
    assert parse_address_or_symbol("sub_E6DD40+0x15c") == 0xE6DD40 + 0x15C
    assert parse_address_or_symbol("my_func") == "my_func"


def test_normalize_mcp_args_alias():
    @normalize_mcp_args
    def dummy_tool(name_or_address: int | str, binary_name: str = "app.so") -> dict:
        return {"target": name_or_address, "binary": binary_name}

    # Pass 'address' instead of 'name_or_address'
    res = dummy_tool(address="0x1000")
    assert res["target"] == 0x1000
    assert res["binary"] == "app.so"

    # Pass 'rva'
    res2 = dummy_tool(rva="0x2000")
    assert res2["target"] == 0x2000


def test_normalize_mcp_args_auto_binary():
    set_active_binaries(["single_target.so"])

    @normalize_mcp_args
    def dummy_tool(address: int, binary_name: str) -> dict:
        return {"address": address, "binary": binary_name}

    # Omit binary_name
    res = dummy_tool(addr="0x4000")
    assert res["address"] == 0x4000
    assert res["binary"] == "single_target.so"


def test_missing_required_recovery_hint():
    set_active_binaries(["target.so"])

    @normalize_mcp_args
    def dummy_tool(required_param: str) -> dict:
        return {"ok": required_param}

    res = dummy_tool()
    assert res["status"] == "error"
    assert "Missing required parameter" in res["error"]
    assert "recovery_hint" in res
