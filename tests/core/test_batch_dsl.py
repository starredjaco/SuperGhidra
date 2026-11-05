"""
test_batch_dsl.py - Unit tests for transactional batch DSL executor (superghidra_batch).
"""

import struct

from superghidra.core.batch_dsl import BatchPipelineExecutor


def _build_test_stream():
    buf = bytearray(64)
    # 0x00: stp x29, x30, [sp, #-0x60]! (prologue)
    # 0x04: mov x29, sp
    # 0x08: strb w8, [x19, #0x124]
    # 0x0C: ret
    struct.pack_into("<I", buf, 0x00, 0xA9BA7BFD)
    struct.pack_into("<I", buf, 0x04, 0x910003FD)
    struct.pack_into("<I", buf, 0x08, 0x39049268)  # strb w8, [x19, #0x124]
    struct.pack_into("<I", buf, 0x0C, 0xD65F03C0)
    return bytes(buf)


def test_batch_pipeline_execution():
    data = _build_test_stream()
    executor = BatchPipelineExecutor(data, base_rva=0x1000)

    # 2-step pipeline:
    # 1. Scan for strb at offset 0x124
    # 2. Resolve interior RVA of all matches
    pipeline = [
        {
            "id": "stores_124",
            "op": "scan_arm64_insns",
            "params": {"mem_offset": "0x124", "access_type": "write"},
        },
        {
            "id": "enclosing_funcs",
            "op": "resolve_interior_rva",
            "params": {"addresses": "$stores_124.matches[*].rva"},
        },
    ]

    res = executor.execute_pipeline(pipeline)
    assert res.success is True
    assert "stores_124" in res.results
    assert res.results["stores_124"]["count"] == 1
    assert res.results["stores_124"]["matches"][0].rva == 0x1008

    assert "enclosing_funcs" in res.results
    resolved_list = res.results["enclosing_funcs"]["resolved"]
    assert len(resolved_list) == 1
    # Should resolve to prologue at 0x1000!
    assert resolved_list[0].resolved_entry_rva == 0x1000
    assert resolved_list[0].resolution_method == "heuristic_prologue_sweep"
