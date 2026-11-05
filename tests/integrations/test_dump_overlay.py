"""
test_dump_overlay.py - Unit tests for live dump overlay manager and heap object inspector.
"""

import struct

from superghidra.integrations.dump_overlay import LiveDumpOverlayManager


class DummyVTableResolver:
    def resolve_vtable(self, vptr_rva: int, slot_offset: int = 0) -> dict:
        return {
            "vptr_address_point_rva": hex(vptr_rva),
            "target_function_rva": hex(vptr_rva + 0x2000 + slot_offset),
        }


def test_live_dump_overlay_manager():
    vtable_res = DummyVTableResolver()
    mgr = LiveDumpOverlayManager(vtable_resolver=vtable_res)

    # Synthetic memory segment at 0x760000000000
    base_va = 0x760000000000
    seg_bytes = bytearray(0x1000)

    # Object at offset 0x200 (va = base_va + 0x200)
    obj_off = 0x200
    obj_va = base_va + obj_off

    # Pack vptr pointing to module_base + 0x3100
    module_base = 0x760010000000
    vptr_va = module_base + 0x3100
    struct.pack_into("<Q", seg_bytes, obj_off, vptr_va)

    # Pack fields: offset +0x124 = 1 (u8), +0x18 = 792 (u32)
    struct.pack_into("<B", seg_bytes, obj_off + 0x124, 1)
    struct.pack_into("<I", seg_bytes, obj_off + 0x18, 792)

    # Register dump 1
    reg_res = mgr.register_dump("dump_1", module_base, [(base_va, bytes(seg_bytes))])
    assert reg_res["dump_id"] == "dump_1"

    # Inspect live object
    inspect_res = mgr.inspect_live_object(
        "dump_1",
        obj_va,
        field_spec={"+0x124": "u8", "+0x18": "u32"},
        vtable_slots_to_resolve=[0x88],
    )
    assert inspect_res["vptr_static_rva"] == hex(0x3100)
    assert inspect_res["fields"]["+0x124"] == 1
    assert inspect_res["fields"]["+0x18"] == 792
    assert "0x88" in inspect_res["resolved_vtable_slots"]

    # Register dump 2 with mutated field (+0x124: 1 -> 0)
    seg_bytes2 = bytearray(seg_bytes)
    struct.pack_into("<B", seg_bytes2, obj_off + 0x124, 0)
    mgr.register_dump("dump_2", module_base, [(base_va, bytes(seg_bytes2))])

    # Diff across dump 1 and dump 2
    diff_res = mgr.diff_live_objects(["dump_1", "dump_2"], [obj_va], field_spec={"+0x124": "u8"})
    assert len(diff_res) == 1
    timeline = diff_res[0]["timeline"]
    assert len(timeline) == 2
    assert "+0x124" in timeline[1]["diff_from_previous"]
    assert "0x1 -> 0x0" in timeline[1]["diff_from_previous"]["+0x124"]
