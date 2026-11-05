"""
test_scan_arm64_insns.py - Unit tests for vectorized ARM64 instruction scanner.
"""

import struct

from superghidra.acceleration.scan_arm64_insns import (
    Arm64VectorScanner,
    scan_arm64_insns,
)


def test_scan_arm64_mem_offset():
    # Build buffer containing a strb to offset 0x124 and dummy instructions
    # strb w8, [x19, #0x124]: 0x39049268
    buf = bytearray()
    buf += struct.pack("<I", 0xD503201F)  # nop
    buf += struct.pack("<I", 0x39049268)  # strb w8, [x19, #0x124] at offset 4
    buf += struct.pack("<I", 0xD503201F)  # nop
    buf += struct.pack("<I", 0x39449268)  # ldrb w8, [x19, #0x124] at offset 12

    # Search for write to 0x124
    matches_write = scan_arm64_insns(bytes(buf), base_rva=0x1000, mem_offset=0x124, access_type="write")
    assert len(matches_write) == 1
    assert matches_write[0].rva == 0x1004
    assert matches_write[0].mnemonic == "strb"
    assert matches_write[0].mem_offset == 0x124

    # Search for read from 0x124
    matches_read = scan_arm64_insns(bytes(buf), base_rva=0x1000, mem_offset=0x124, access_type="read")
    assert len(matches_read) == 1
    assert matches_read[0].rva == 0x100C
    assert matches_read[0].mnemonic == "ldrb"

    # Search for any access to 0x124
    matches_any = scan_arm64_insns(bytes(buf), base_rva=0x1000, mem_offset=0x124, access_type="any")
    assert len(matches_any) == 2


def test_scan_arm64_immediate():
    # Immediate 792 (0x318):
    # mov w11, #0x318 -> movz w11, #0x318: 0x5280630B
    buf = bytearray()
    buf += struct.pack("<I", 0x5280630B)  # movz w11, #0x318 at 0
    buf += struct.pack("<I", 0xD503201F)  # nop

    matches = scan_arm64_insns(bytes(buf), base_rva=0x2000, immediate=0x318)
    assert len(matches) == 1
    assert matches[0].rva == 0x2000
    assert matches[0].immediate == 0x318


def test_scan_arm64_fusion_immediate():
    # 32-bit constant 0x41C64E6D:
    # movz w0, #0x4E6D -> 0x5289CDA0
    # movk w0, #0x41C6, lsl #16 -> 0x72A838C0
    buf = bytearray()
    buf += struct.pack("<I", 0x5289CDA0)
    buf += struct.pack("<I", 0xD503201F)  # intermediate instruction
    buf += struct.pack("<I", 0x72A838C0)

    matches = scan_arm64_insns(bytes(buf), base_rva=0x3000, immediate=0x41C64E6D)
    assert len(matches) == 1
    assert matches[0].rva == 0x3000


def test_arm64_vector_scanner():
    buf = bytearray()
    buf += struct.pack("<I", 0x5280630B)  # movz w11, #0x318 (792) at 0x1000
    buf += struct.pack("<I", 0x39049268)  # strb w8, [x19, #0x124] at 0x1004
    buf += struct.pack("<I", 0x39449268)  # ldrb w8, [x19, #0x124] at 0x1008

    scanner = Arm64VectorScanner(bytes(buf), text_base_rva=0x1000)

    # Struct offset scan
    hits_offset = scanner.scan_struct_offset(byte_offset=0x124)
    assert len(hits_offset) == 2
    assert hits_offset[0]["rva"] == hex(0x1004)
    assert hits_offset[1]["rva"] == hex(0x1008)

    # Immediate scan
    hits_imm = scanner.scan_immediate(imm_value=792)
    assert len(hits_imm) == 1
    assert hits_imm[0]["rva"] == hex(0x1000)
    assert hits_imm[0]["immediate"] == 792
