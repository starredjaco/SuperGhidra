"""
test_concolic_edge_cases.py - End-to-end regression benchmark for AArch64 fast-paths and concolic bridge.

Validates the 4 core architectural friction fixes from the implementation plan:
  1. Interior RVA Resolution & Decompiled C Target Annotation (< 50 ms).
  2. Stripped ELF64 .rela.dyn C++ VTable & Virtual Method Slot Devirtualization.
  3. Vectorized Instruction Scanner for Struct Offsets and Immediate Constants (< 25 ms).
  4. Dump-Seeded Concolic Trace Evaluator for Active vs. Dead PRNG Draw Partitions.
"""

import struct
import time

from superghidra.acceleration.scan_arm64_insns import Arm64VectorScanner
from superghidra.core.interior_rva_resolver import (
    AArch64InteriorResolver,
    annotate_decompiled_c,
)
from superghidra.formats.elf_vtable_recovery import (
    R_AARCH64_RELATIVE,
    Elf64AArch64VTableResolver,
)
from superghidra.integrations.dump_overlay import LiveDumpOverlayManager
from superghidra.integrations.trace_slicer import (
    trace_concolic_draws,
)


def _build_edge_case_binary() -> tuple[bytes, int, int]:
    """Builds synthetic ELF image containing .text and .data.rel.ro for testing."""
    # Size: 0x8000 (32 KB)
    buf = bytearray(0x8000)

    # 1. Function at 0x1000..0x1080
    # Entry at 0x1000:
    # 0x1000: stp x29, x30, [sp, #-0x30]!
    # 0x1004: mov x29, sp
    # 0x1008: movz w11, #0x318 (792)
    # 0x100C: strb w8, [x19, #0x124] (interior target 0x100C)
    # 0x1010: ldrb w9, [x0, #0x124]
    # 0x1014: cbz w9, +0x14 (branch to 0x1028: early return)
    # 0x1018: bl 0x2000 (PRNG draw routine)
    # 0x101C: b +0x0C (branch to 0x1028)
    # 0x1028: ret
    struct.pack_into("<I", buf, 0x1000, 0xA9BD7BFD)  # stp x29, x30, [sp, #-0x30]!
    struct.pack_into("<I", buf, 0x1004, 0x910003FD)  # mov x29, sp
    struct.pack_into("<I", buf, 0x1008, 0x5280630B)  # movz w11, #0x318 (792)
    struct.pack_into("<I", buf, 0x100C, 0x39049268)  # strb w8, [x19, #0x124]
    struct.pack_into("<I", buf, 0x1010, 0x39449009)  # ldrb w9, [x0, #0x124]
    struct.pack_into("<I", buf, 0x1014, 0x340000A9)  # cbz w9, 0x1028
    struct.pack_into("<I", buf, 0x1018, 0x940003FA)  # bl 0x2000
    struct.pack_into("<I", buf, 0x101C, 0x14000003)  # b 0x1028
    struct.pack_into("<I", buf, 0x1028, 0xD65F03C0)  # ret

    # 2. VTable Relocations at offset 0x4000:
    # VTable at RVA 0x5000:
    # slot +0x00: target 0x1000
    # slot +0x88: target 0x1050
    rela_off = 0x4000
    rela_count = 2
    # R_AARCH64_RELATIVE = 0x403
    # slot 0 (+0x00): vaddr 0x5000 -> target 0x1000
    struct.pack_into("<QQq", buf, rela_off, 0x5000, R_AARCH64_RELATIVE, 0x1000)
    # slot 17 (+0x88): vaddr 0x5088 -> target 0x1050
    struct.pack_into("<QQq", buf, rela_off + 24, 0x5088, R_AARCH64_RELATIVE, 0x1050)

    return bytes(buf), rela_off, rela_count * 24


def test_assertion_1_interior_rva_resolution():
    """Assertion 1: Interior RVA resolves backward to enclosing function and annotates decompiled C (< 50 ms)."""
    t0 = time.perf_counter()
    bin_bytes, _, _ = _build_edge_case_binary()

    resolver = AArch64InteriorResolver(
        text_bytes=bin_bytes,
        text_base_rva=0,
        eh_frame_starts=[0x1000],
    )

    # Query interior RVA 0x100C (the strb instruction)
    target = resolver.resolve(0x100C)
    elapsed_ms = (time.perf_counter() - t0) * 1000

    assert target.queried_rva == 0x100C
    assert target.entry_rva == 0x1000
    assert target.offset_from_entry == 0x0C
    assert elapsed_ms < 50.0

    # Annotate mock decompiled C code
    mock_c = "void sub_1000(void* p) {\n    int a = 792;\n    *((char*)p + 0x124) = 1;\n    return;\n}"
    annotated = annotate_decompiled_c(mock_c, target_rva=0x100C, entry_rva=0x1000)
    assert "TARGET RVA 0x0000100C (+0xC)" in annotated


def test_assertion_2_vtable_rela_lookup():
    """Assertion 2: vtable_lookup(address=vptr, slot_offset=0x88) matches exact R_AARCH64_RELATIVE addend."""
    bin_bytes, rela_off, rela_sz = _build_edge_case_binary()

    resolver = Elf64AArch64VTableResolver(
        elf_bytes=bin_bytes,
        rela_dyn_offset=rela_off,
        rela_dyn_size=rela_sz,
        text_range=(0x1000, 0x3000),
    )

    # VTable at 0x5000, query slot +0x88
    slot_res = resolver.resolve_vtable(0x5000, slot_offset=0x88)
    assert slot_res["target_function_rva"] == hex(0x1050)
    assert slot_res["slot_index"] == 17
    assert "rela.dyn" in slot_res["resolution_source"]


def test_assertion_3_vector_scanner_speed_and_accuracy():
    """Assertion 3: Vectorized scan for struct offset 0x124 and immediate 792 returns exact RVAs (< 25 ms)."""
    bin_bytes, _, _ = _build_edge_case_binary()
    scanner = Arm64VectorScanner(bin_bytes, text_base_rva=0)

    t0 = time.perf_counter()
    # Scan for store to offset 0x124
    hits_offset = scanner.scan_struct_offset(byte_offset=0x124, op_filter="strb")
    # Scan for immediate 792
    hits_imm = scanner.scan_immediate(imm_value=792)
    elapsed_ms = (time.perf_counter() - t0) * 1000

    assert len(hits_offset) == 1
    assert hits_offset[0]["rva"] == hex(0x100C)

    assert len(hits_imm) == 1
    assert hits_imm[0]["rva"] == hex(0x1008)
    assert elapsed_ms < 25.0


def test_assertion_4_trace_concolic_draws():
    """Assertion 4: trace_concolic_draws over live memory partitions active vs. dead PRNG drawers."""
    bin_bytes, _, _ = _build_edge_case_binary()
    mgr = LiveDumpOverlayManager()

    # Create memory dump containing 3 objects:
    # Obj A at 0x760000001000: offset 0x124 == 1 (Active -> consumes PRNG at 0x2000)
    # Obj B at 0x760000002000: offset 0x124 == 0 (Dead -> early exit at 0x1014)
    # Obj C at 0x760000003000: offset 0x124 == 1 (Active -> consumes PRNG at 0x2000)
    base_va = 0x760000000000
    seg_bytes = bytearray(0x5000)
    struct.pack_into("<B", seg_bytes, 0x1000 + 0x124, 1)
    struct.pack_into("<B", seg_bytes, 0x2000 + 0x124, 0)
    struct.pack_into("<B", seg_bytes, 0x3000 + 0x124, 1)

    mgr.register_dump("dump_tick", module_base=0x0, segments=[(base_va, bytes(seg_bytes))])

    results = trace_concolic_draws(
        dump_manager=mgr,
        dump_id="dump_tick",
        entry_rva=0x1000,
        object_addrs=[0x760000001000, 0x760000002000, 0x760000003000],
        text_bytes=bin_bytes,
        text_base_rva=0,
        prng_rvas=[0x2000],
    )

    assert len(results) == 3
    # Obj A
    assert results[0]["final_status"] == "consumed_rng"
    assert results[0]["prng_draws_consumed"] == 1
    # Obj B
    assert results[1]["final_status"] == "dead_draw"
    assert results[1]["prng_draws_consumed"] == 0
    assert results[1]["early_exit_branch"]["concrete_val"] == 0
    # Obj C
    assert results[2]["final_status"] == "consumed_rng"
    assert results[2]["prng_draws_consumed"] == 1
