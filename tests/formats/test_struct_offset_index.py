"""
test_struct_offset_index.py - Unit tests for global struct-offset xref indexer and CSV constant correlator.
"""

import struct

from superghidra.formats.struct_offset_index import (
    StructOffsetIndexer,
)


def _build_test_stream():
    buf = bytearray()
    # strb w8, [x19, #0x124]: 0x39049268
    buf += struct.pack("<I", 0x39049268)
    # ldr w10, [x19, #0x80]: 0xB940826A
    buf += struct.pack("<I", 0xB940826A)
    # mov w11, #0x318 (792): 0x5280630B
    buf += struct.pack("<I", 0x5280630B)
    return bytes(buf)


def test_struct_offset_indexing():
    data = _build_test_stream()
    indexer = StructOffsetIndexer(data, base_rva=0x1000)

    # Query offset 0x124
    writes_124 = indexer.get_offset_accesses(offset=0x124, is_write=True)
    assert len(writes_124) == 1
    assert writes_124[0].insn_rva == 0x1000
    assert writes_124[0].mnemonic == "strb"
    assert writes_124[0].base_reg == "x19"

    # Query offset 0x80
    reads_80 = indexer.get_offset_accesses(offset=0x80, is_write=False)
    assert len(reads_80) == 1
    assert reads_80[0].insn_rva == 0x1004
    assert reads_80[0].mnemonic == "ldr"


def test_csv_constant_correlation():
    data = _build_test_stream()
    indexer = StructOffsetIndexer(data, base_rva=0x2000)

    csv_data = """Name,UnlockLevel,EdgeSpawnTileX,EdgeSpawnTileY,BirdExtraTiles
AmbientAnimalSpawner,1,792,16,10
"""
    results = indexer.correlate_data_table(csv_data, min_constant_val=50)
    assert len(results) >= 1
    hit = results[0]
    assert hit.matched_constant == 792
    assert hit.insn_rva == 0x2008
    assert "Row 1 (EdgeSpawnTileX)" in hit.table_context
