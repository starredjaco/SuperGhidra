"""
schema_guard.py - Forgiving MCP parameter normalization and schema coercion layer.

Provides parameter alias mapping, integer/hex string coercion, and automatic binary_name
resolution to prevent MCP JSON-RPC schema rejection during autonomous agent operations.
"""

from __future__ import annotations

import functools
import inspect
import re
from typing import Any, Callable, Dict, List

ADDRESS_ALIASES = ("address", "rva", "addr", "offset", "target", "symbol", "name_or_address")

# Global session tracker for active binaries
_ACTIVE_BINARIES: List[str] = []
_LAST_ACCESSED_BINARY: str | None = None


def set_active_binaries(binaries: List[str]) -> None:
    """Sets the list of active project binaries in the current session."""
    global _ACTIVE_BINARIES, _LAST_ACCESSED_BINARY
    _ACTIVE_BINARIES = list(binaries)
    if _ACTIVE_BINARIES and not _LAST_ACCESSED_BINARY:
        _LAST_ACCESSED_BINARY = _ACTIVE_BINARIES[0]


def record_binary_access(binary_name: str) -> None:
    """Records the most recently accessed binary name in the session."""
    global _LAST_ACCESSED_BINARY
    _LAST_ACCESSED_BINARY = binary_name
    if binary_name not in _ACTIVE_BINARIES:
        _ACTIVE_BINARIES.append(binary_name)


def get_default_binary_name() -> str | None:
    """Returns the single active binary, or the most recently accessed binary."""
    if len(_ACTIVE_BINARIES) == 1:
        return _ACTIVE_BINARIES[0]
    return _LAST_ACCESSED_BINARY


def parse_address_or_symbol(val: Any) -> int | str:
    """Parses hex strings ('0x00E6DE9C', '00E6DE9C'), decimals, or symbol expressions."""
    if isinstance(val, int):
        return val
    if not isinstance(val, str):
        return str(val)

    s = val.strip()

    # Hex prefixed: "0x..." or "-0x..."
    if s.lower().startswith("0x") or s.lower().startswith("-0x"):
        try:
            return int(s, 16)
        except ValueError:
            pass

    # Pure decimal integer string
    if re.fullmatch(r"-?\d+", s):
        try:
            return int(s, 10)
        except ValueError:
            pass

    # Pure hex without prefix but containing hex letters (e.g. "00E6DE9C" or "E6DE9C")
    if re.fullmatch(r"[0-9a-fA-F]{6,16}", s) and re.search(r"[a-fA-F]", s):
        try:
            return int(s, 16)
        except ValueError:
            pass

    # Symbol + offset: e.g. "sub_E6DD40+0x15c" or "main+20"
    m = re.fullmatch(r"([a-zA-Z_.$][a-zA-Z0-9_.$]*)\s*([+-])\s*(0x[0-9a-fA-F]+|\d+)", s)
    if m:
        base_sym, sign, off_str = m.groups()
        off_val = int(off_str, 16) if off_str.lower().startswith("0x") else int(off_str, 10)
        # If base_sym itself is a hex address, compute directly
        if re.fullmatch(r"sub_[0-9a-fA-F]+", base_sym, re.IGNORECASE):
            base_addr = int(base_sym[4:], 16)
            return base_addr + off_val if sign == "+" else base_addr - off_val

    return s


def normalize_mcp_args(func: Callable) -> Callable:
    """Decorator that normalizes argument aliases, coercing address/binary_name before validation."""
    sig = inspect.signature(func)
    params = sig.parameters

    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        bound_kwargs: Dict[str, Any] = dict(kwargs)

        # 1. Alias normalization for addresses / symbols
        target_param = None
        for p in params:
            if p in ADDRESS_ALIASES:
                target_param = p
                break

        # Check if an alias was provided in kwargs
        alias_val = None
        found_alias = None
        for alias in ADDRESS_ALIASES:
            if alias in bound_kwargs:
                alias_val = bound_kwargs[alias]
                found_alias = alias
                break

        if alias_val is not None:
            normalized_val = parse_address_or_symbol(alias_val)
            if target_param:
                bound_kwargs[target_param] = normalized_val
                if found_alias != target_param and found_alias in bound_kwargs:
                    del bound_kwargs[found_alias]
            else:
                bound_kwargs[found_alias] = normalized_val

        # 2. Optional binary_name auto-resolution
        if "binary_name" in params and ("binary_name" not in bound_kwargs or not bound_kwargs["binary_name"]):
            def_bin = get_default_binary_name()
            if def_bin:
                bound_kwargs["binary_name"] = def_bin

        # Track binary access if provided
        if "binary_name" in bound_kwargs and bound_kwargs["binary_name"]:
            record_binary_access(bound_kwargs["binary_name"])

        # 3. Actionable schema validation check
        missing_required = []
        for p_name, p in params.items():
            if p.default is inspect.Parameter.empty and p.kind in (
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
                inspect.Parameter.KEYWORD_ONLY,
            ):
                if p_name not in bound_kwargs and p_name != "args" and p_name != "kwargs":
                    missing_required.append(p_name)

        if missing_required:
            return {
                "status": "error",
                "error": f"Missing required parameter(s): {', '.join(missing_required)}",
                "active_binaries": list(_ACTIVE_BINARIES),
                "expected_signature": str(sig),
                "recovery_hint": (
                    f"Provide {missing_required[0]}. Active binary: '{get_default_binary_name() or 'None'}'. "
                    f"Address aliases supported: {list(ADDRESS_ALIASES)}."
                ),
            }

        return func(*args, **bound_kwargs)

    return wrapper
