"""
test_elf_vtable_recovery.py - Unit tests for ELF vtable recovery engine and stripped .rela.dyn indexer.
"""

import struct

from superghidra.formats.elf_vtable_recovery import (
    R_AARCH64_RELATIVE,
    ElfVTableRecoveryEngine,
)


def _build_synthetic_elf():
    """Builds a minimal synthetic ELF64 containing .rela.dyn and vtable slots."""
    buf = bytearray(1024)
    # ELF64 Header
    buf[:4] = b"\x7fELF"
    buf[4] = 2  # 64-bit
    buf[5] = 1  # Little endian
    buf[6] = 1  # Version 1

    # Text segment: 0x1000..0x2000
    # Data segment: 0x3000..0x4000
    # Program headers offset at 64
    struct.pack_into("<Q", buf, 32, 64)  # e_phoff
    struct.pack_into("<H", buf, 54, 56)  # e_phentsize
    struct.pack_into("<H", buf, 56, 2)   # e_phnum = 2

    # PH 0: .text (p_type=1, p_flags=5, p_vaddr=0x1000, p_memsz=0x1000)
    struct.pack_into("<IIQQQQQQ", buf, 64, 1, 5, 0, 0x1000, 0x1000, 0x1000, 0x1000, 0x1000)
    # PH 1: .data (p_type=1, p_flags=6, p_vaddr=0x3000, p_memsz=0x1000)
    struct.pack_into("<IIQQQQQQ", buf, 120, 1, 6, 0, 0x3000, 0x3000, 0x1000, 0x1000, 0x1000)

    # Let's append an Elf64_Rela entry table
    # VTable at 0x3100 with 3 virtual method slots pointing to 0x1050, 0x1080, 0x10B0
    rela_table = bytearray()
    slots = [(0x3100, 0x1050), (0x3108, 0x1080), (0x3110, 0x10B0)]
    for r_offset, r_addend in slots:
        r_info = R_AARCH64_RELATIVE
        rela_table += struct.pack("<QQq", r_offset, r_info, r_addend)

    # Put rela table in the buffer at offset 0x200
    rela_offset = 0x200
    buf[rela_offset : rela_offset + len(rela_table)] = rela_table

    # Add section headers so it can parse .rela.dyn
    shoff = 0x300
    struct.pack_into("<Q", buf, 40, shoff)  # e_shoff
    struct.pack_into("<H", buf, 58, 64)    # e_shentsize
    struct.pack_into("<H", buf, 60, 2)     # e_shnum = 2
    struct.pack_into("<H", buf, 62, 0)     # e_shstrndx = 0

    # Section 1: SHT_RELA (type=4)
    # sh_name=0, sh_type=4, sh_flags=2, sh_addr=0, sh_offset=rela_offset, sh_size=len(rela_table), entsize=24
    struct.pack_into("<IIQQQQIIQQ", buf, shoff + 64, 0, 4, 2, 0, rela_offset, len(rela_table), 0, 0, 8, 24)

    return bytes(buf)


def test_elf_vtable_recovery():
    data = _build_synthetic_elf()
    engine = ElfVTableRecoveryEngine(data)

    assert len(engine.relocs) >= 3
    assert engine.relocs.get(0x3100) == 0x1050
    assert engine.relocs.get(0x3108) == 0x1080
    assert engine.relocs.get(0x3110) == 0x10B0

    # VTable Lookup test
    target_0 = engine.vtable_lookup(0x3100, slot_offset=0x0)
    target_8 = engine.vtable_lookup(0x3100, slot_offset=0x8)
    target_16 = engine.vtable_lookup(0x3100, slot_offset=0x10)

    assert target_0 == 0x1050
    assert target_8 == 0x1080
    assert target_16 == 0x10B0

    # VTable object retrieval
    vt = engine.get_vtable(0x3100)
    assert vt is not None
    assert vt.slot_count == 3
    assert len(vt.slots) == 3

    # Synthetic C struct generation
    c_struct = engine.generate_synthetic_vtable_struct(vt)
    assert "struct" in c_struct
    assert "slot_0x0_target_0x1050" in c_struct
    assert "slot_0x8_target_0x1080" in c_struct
