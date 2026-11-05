"""
test_interior_rva_resolver.py - Unit tests for four-stage address normalizer and interior RVA resolver.
"""

import struct

from superghidra.core.interior_rva_resolver import (
    resolve_interior_rva,
)


def _build_test_binary():
    buf = bytearray(256)
    # Function at 0x1000..0x1030
    # 0x00: stp x29, x30, [sp, #-0x60]! (prologue)
    # 0x04: mov x29, sp
    # 0x08: ldr w8, [x0, #0x7c]
    # 0x0C: cbz w8, 0x20
    # 0x10: ldr w1, [x19, #0x84]
    # 0x14: bl 0x1050
    # 0x18: ret
    struct.pack_into("<I", buf, 0x00, 0xA9BA7BFD)  # stp x29, x30, [sp, #-0x60]!
    struct.pack_into("<I", buf, 0x04, 0x910003FD)  # mov x29, sp
    struct.pack_into("<I", buf, 0x08, 0xB9407C08)  # ldr w8, [x0, #0x7c]
    struct.pack_into("<I", buf, 0x0C, 0x340000A8)  # cbz w8, 0x20
    struct.pack_into("<I", buf, 0x10, 0xB9408661)  # ldr w1, [x19, #0x84]
    struct.pack_into("<I", buf, 0x14, 0x9400000F)  # bl
    struct.pack_into("<I", buf, 0x18, 0xD65F03C0)  # ret
    return bytes(buf)


def test_tier1_enclosing_range():
    data = _build_test_binary()
    known = {0x00: 0x20}
    # Query interior RVA 0x10
    ctx = resolve_interior_rva(0x10, data, known_functions=known)
    assert ctx.resolution_method == "enclosing_range"
    assert ctx.resolved_entry_rva == 0x00


def test_tier2_heuristic_prologue_sweep():
    data = _build_test_binary()
    # No known functions provided, interior query at 0x10
    ctx = resolve_interior_rva(0x10, data, known_functions=None)
    assert ctx.resolution_method == "heuristic_prologue_sweep"
    assert ctx.resolved_entry_rva == 0x00
    assert "stp" in (ctx.prologue_insn or "")


def test_tier4_basic_block_slice():
    # Construct sequence with no prologue:
    # 0x40: ldr w0, [x1]
    # 0x44: add w0, w0, #1
    # 0x48: ret
    buf = bytearray(256)
    struct.pack_into("<I", buf, 0x40, 0xB9400020)
    struct.pack_into("<I", buf, 0x44, 0x11000400)
    struct.pack_into("<I", buf, 0x48, 0xD65F03C0)

    ctx = resolve_interior_rva(0x44, bytes(buf), known_functions=None, max_sweep_bytes=16)
    # Since there's no prologue within 16 bytes, falls back to basic block slice
    assert ctx.resolution_method == "basic_block_slice"
    assert ctx.enclosing_basic_block is not None
    assert ctx.enclosing_basic_block[0] <= 0x44 < ctx.enclosing_basic_block[1]
