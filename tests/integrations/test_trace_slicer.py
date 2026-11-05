"""
test_trace_slicer.py - Unit tests for concolic ARM64 trace slicer and PRNG draw evaluator.
"""

import struct

from superghidra.integrations.dump_overlay import LiveDumpOverlayManager
from superghidra.integrations.trace_slicer import (
    evaluate_function_on_dump,
    trace_concolic_draws,
)


def _build_test_routine():
    """Builds a test function at 0x1000:

    0x1000: ldrb w8, [x0, #0x124]
    0x1004: cbz w8, 0x1014 (early exit to ret)
    0x1008: bl 0x2000 (PRNG draw)
    0x100C: add x0, x0, #1
    0x1010: b 0x1018
    0x1014: nop (dead exit path)
    0x1018: ret
    """
    buf = bytearray(0x100)
    # 0x00: ldrb w8, [x0, #0x124] -> 0x39449008
    struct.pack_into("<I", buf, 0x00, 0x39449008)
    # 0x04: cbz w8, +0x10 (target 0x1014) -> 0x34000088
    struct.pack_into("<I", buf, 0x04, 0x34000088)
    # 0x08: bl 0x2000 (target RVA 0x2000 from 0x1008: imm26 = (0x2000 - 0x1008)/4 = 0x3FE) -> 0x940003FE
    struct.pack_into("<I", buf, 0x08, 0x940003FE)
    # 0x0C: add x0, x0, #1 -> 0x91000400
    struct.pack_into("<I", buf, 0x0C, 0x91000400)
    # 0x10: b +8 (target 0x1018) -> 0x14000002
    struct.pack_into("<I", buf, 0x10, 0x14000002)
    # 0x14: nop -> 0xD503201F
    struct.pack_into("<I", buf, 0x14, 0xD503201F)
    # 0x18: ret -> 0xD65F03C0
    struct.pack_into("<I", buf, 0x18, 0xD65F03C0)
    return bytes(buf)


def test_evaluate_function_on_dump():
    text_data = _build_test_routine()
    mgr = LiveDumpOverlayManager()

    # Create dump with two objects:
    # Obj 1 at 0x760000001000: offset 0x124 is 1 (Active -> should consume PRNG)
    # Obj 2 at 0x760000002000: offset 0x124 is 0 (Dead -> should hit cbz and exit early)
    seg_bytes = bytearray(0x3000)
    base_va = 0x760000000000
    struct.pack_into("<B", seg_bytes, 0x1000 + 0x124, 1)
    struct.pack_into("<B", seg_bytes, 0x2000 + 0x124, 0)

    mgr.register_dump("test_dump", module_base=0x10000, segments=[(base_va, bytes(seg_bytes))])

    # 1. Evaluate Active Object (0x760000001000)
    res_active = evaluate_function_on_dump(
        dump_manager=mgr,
        dump_id="test_dump",
        entry_rva=0x1000,
        object_addr=0x760000001000,
        text_bytes=text_data,
        text_base_rva=0x1000,
        prng_rvas=[0x2000],
    )
    assert res_active["prng_draws_consumed"] == 1
    assert res_active["final_status"] == "consumed_rng"

    # 2. Evaluate Dead Object (0x760000002000)
    res_dead = evaluate_function_on_dump(
        dump_manager=mgr,
        dump_id="test_dump",
        entry_rva=0x1000,
        object_addr=0x760000002000,
        text_bytes=text_data,
        text_base_rva=0x1000,
        prng_rvas=[0x2000],
    )
    assert res_dead["prng_draws_consumed"] == 0
    assert res_dead["final_status"] == "dead_draw"
    assert res_dead["early_exit_branch"] is not None
    assert res_dead["early_exit_branch"]["mnemonic"] == "cbz"
    assert res_dead["early_exit_branch"]["concrete_val"] == 0

    # 3. Batch evaluation
    batch_res = trace_concolic_draws(
        dump_manager=mgr,
        dump_id="test_dump",
        entry_rva=0x1000,
        object_addrs=[0x760000001000, 0x760000002000],
        text_bytes=text_data,
        text_base_rva=0x1000,
        prng_rvas=[0x2000],
    )
    assert len(batch_res) == 2
    assert batch_res[0]["final_status"] == "consumed_rng"
    assert batch_res[1]["final_status"] == "dead_draw"
