"""
test_dump_workspace.py - Unit tests for DumpWorkspace multi-snapshot memory dump overlay.
"""

import struct

from superghidra.formats.elf_vtable_recovery import ElfVTableRecoveryEngine, RecoveredVTable
from superghidra.integrations.dump_workspace import DumpWorkspace


def test_dump_module_mounting_and_aslr():
    ws = DumpWorkspace()
    # Dummy libnative.so module of size 0x10000 mounted at 0x7600000000
    mod_data = bytearray(0x10000)
    ws.mount_dump_module("dump3", "libnative.so", bytes(mod_data), runtime_base=0x7600000000)

    # Translate runtime address 0x7600001234 to static RVA
    rva = ws.runtime_to_static_rva("dump3", "libnative.so", 0x7600001234)
    assert rva == 0x1234

    # Translate static RVA 0x1234 back to runtime
    rt = ws.static_to_runtime("dump3", "libnative.so", 0x1234)
    assert rt == 0x7600001234


def test_dump_inspect_heap_object():
    ws = DumpWorkspace()
    # Mount module
    ws.mount_dump_module("dump3", "libnative.so", bytes(0x10000), runtime_base=0x7600000000)

    # Mount heap page at 0x7638C4A20000
    heap_page = bytearray(0x4000)
    # At offset 0x1200: Heap object
    # offset 0x00: vtable pointer -> 0x7600000500 (RVA 0x500)
    # offset 0x18: PRNG seed -> 0x123456789ABCDEF0
    # offset 0x124: flags -> 0x01
    obj_runtime_addr = 0x7638C4A21200
    struct.pack_into("<Q", heap_page, 0x1200, 0x7600000500)
    struct.pack_into("<Q", heap_page, 0x1200 + 0x18, 0x123456789ABCDEF0)
    struct.pack_into("<B", heap_page, 0x1200 + 0x124, 0x01)

    ws.mount_heap_segment("dump3", runtime_base=0x7638C4A20000, data=bytes(heap_page))

    # Mock VTable engine with vtable at 0x500
    engine = ElfVTableRecoveryEngine(b"")
    vt = RecoveredVTable(vtable_rva=0x500, slot_count=2, slots=[], class_name="LogicAmbientAnimal")
    engine.vtables[0x500] = vt

    schema = {0x18: "prng_seed_u64", 0x124: "flags_u8"}
    obj = ws.inspect_heap_object("dump3", obj_runtime_addr, vtable_engine=engine, schema=schema)

    assert obj is not None
    assert obj.vtable_rva == 0x500
    assert obj.class_name == "LogicAmbientAnimal"
    assert obj.fields.get("prng_seed_u64") == 0x123456789ABCDEF0
    assert obj.fields.get("flags_u8") == 1


def test_dump_diff_objects():
    ws = DumpWorkspace()
    # Dump 3 vs Dump 4: object at 0x7000 has seed change from 100 to 200
    page_a = bytearray(512)
    page_b = bytearray(512)

    struct.pack_into("<Q", page_a, 0x18, 100)
    struct.pack_into("<Q", page_b, 0x18, 200)

    ws.mount_heap_segment("dump3", 0x7000, bytes(page_a))
    ws.mount_heap_segment("dump4", 0x7000, bytes(page_b))

    schema = {0x18: "prng_seed_u64"}
    res = ws.diff_heap_objects("dump3", "dump4", 0x7000, schema=schema)

    assert len(res.diffs) == 1
    assert res.diffs[0].field_name == "prng_seed_u64"
    assert res.diffs[0].val_a == 100
    assert res.diffs[0].val_b == 200
