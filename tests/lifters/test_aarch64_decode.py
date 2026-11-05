"""
test_aarch64_decode.py - Unit tests for zero-dependency AArch64 instruction decoder and PC-relative resolver.
"""

import struct

from superghidra.lifters.aarch64_decode import (
    Aarch64Category,
    decode_aarch64,
    disasm_range_fast,
    resolve_adrp_pair,
    resolve_branch_target,
    scan_prologue_backward,
)


def test_decode_b_and_bl():
    # B +0x20 at RVA 0x1000: imm26 = 8 -> target 0x1020
    # b: 0x14000008
    insn_b = decode_aarch64(0x14000008, 0x1000)
    assert insn_b.category == Aarch64Category.BRANCH
    assert insn_b.mnemonic == "b"
    assert insn_b.target_rva == 0x1020

    # BL -0x10 at RVA 0x2000: imm26 = -4 (0x03FFFFFC) -> target 0x1FF0
    # bl: 0x97FFFFFC
    insn_bl = decode_aarch64(0x97FFFFFC, 0x2000)
    assert insn_bl.category == Aarch64Category.CALL
    assert insn_bl.mnemonic == "bl"
    assert insn_bl.target_rva == 0x1FF0
    assert resolve_branch_target(0x2000, 0x97FFFFFC) == 0x1FF0


def test_decode_bcond_and_cbz():
    # b.eq +0x14: 0x540000A0
    insn = decode_aarch64(0x540000A0, 0x4000)
    assert insn.mnemonic == "b.eq"
    assert insn.target_rva == 0x4014

    # cbz x0, +0x10: 0xB4000080
    insn_cbz = decode_aarch64(0xB4000080, 0x5000)
    assert insn_cbz.mnemonic == "cbz"
    assert insn_cbz.target_rva == 0x5010


def test_decode_adrp_and_add_pair():
    # Real instructions from AArch64 trace:
    # 0x00E6DEAC: adrp x8, #0x01692000
    # 0x00E6DEB0: add  x8, x8, #0x310
    # adrp x8: 0x90004128 at 0x00E6DEAC -> page 0x01692000
    # add x8, x8, #0x310: 0x910C4108
    rva_adrp = 0x00E6DEAC
    word_adrp = 0x90004128
    rva_add = 0x00E6DEB0
    word_add = 0x910C4108

    target = resolve_adrp_pair(rva_adrp, word_adrp, rva_add, word_add)
    assert target == (decode_aarch64(word_adrp, rva_adrp).target_rva + 0x310)


def test_decode_memory_loads_and_stores():
    # strb w8, [x19, #0x124]
    # size=0, opc=0, rn=19, rt=8, imm12=0x124 -> 0x39049268
    word_strb = 0x39049268
    insn_strb = decode_aarch64(word_strb, 0x1000)
    assert insn_strb.category == Aarch64Category.MEM_STORE
    assert insn_strb.mnemonic == "strb"
    assert insn_strb.mem_offset == 0x124
    assert insn_strb.mem_base_reg == "x19"
    assert insn_strb.mem_is_write is True

    # ldr w10, [x19, #0x80] -> imm12 = 0x80 >> 2 = 0x20
    # size=2, opc=1, rn=19, rt=10, imm12=0x20 -> 0xB940826A
    word_ldr = 0xB940826A
    insn_ldr = decode_aarch64(word_ldr, 0x1004)
    assert insn_ldr.category == Aarch64Category.MEM_LOAD
    assert insn_ldr.mnemonic == "ldr"
    assert insn_ldr.mem_offset == 0x80
    assert insn_ldr.mem_base_reg == "x19"
    assert insn_ldr.mem_is_write is False


def test_prologue_and_epilogue_sweep():
    # Construct a synthetic function buffer:
    # 0x00: stp x29, x30, [sp, #-0x60]! (prologue: 0xA9BA7BFD)
    # 0x04: mov x29, sp
    # 0x08: ldr w8, [x0, #0x7c]
    # 0x0C: cbz w8, +0x10
    # 0x10: nop
    # 0x14: ret (0xD65F03C0)
    buf = bytearray()
    buf += struct.pack("<I", 0xA9BA7BFD)  # stp x29, x30, [sp, #-0x60]!
    buf += struct.pack("<I", 0x910003FD)  # mov x29, sp
    buf += struct.pack("<I", 0xB9407C08)  # ldr w8, [x0, #0x7c]
    buf += struct.pack("<I", 0x34000088)  # cbz w8, 0x18
    buf += struct.pack("<I", 0xD503201F)  # nop
    buf += struct.pack("<I", 0xD65F03C0)  # ret

    # Sweep backward from interior offset 0x0C
    prologue_rva = scan_prologue_backward(bytes(buf), target_rva=0x0C, max_bytes=64)
    assert prologue_rva == 0x00

    # Test disassembly output
    lines = disasm_range_fast(bytes(buf), 0x00, 0x18)
    assert len(lines) == 6
    assert "stp" in lines[0]
    assert "ret" in lines[5]
