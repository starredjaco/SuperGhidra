"""
trace_slicer.py - Concrete/concolic ARM64 P-code stepper and PRNG call-site slicer.

Executes micro-traces seeded with live heap memory dumps to determine which object instances
consumed PRNG draws vs. which instances exited early on branch guards.
"""

from __future__ import annotations

import struct
from typing import Dict, List

from superghidra.integrations.dump_overlay import LiveDumpOverlayManager
from superghidra.lifters.aarch64_decode import decode_aarch64


def evaluate_function_on_dump(
    dump_manager: LiveDumpOverlayManager,
    dump_id: str,
    entry_rva: int,
    object_addr: int | str,
    text_bytes: bytes,
    text_base_rva: int = 0,
    prng_rvas: List[int] | None = None,
    max_steps: int = 2000,
) -> dict:
    """Executes a concrete micro-trace of entry_rva seeded with object_addr from dump_id."""
    obj_va = int(str(object_addr), 0)
    prng_set = set(prng_rvas or [])

    # Seed registers
    regs: Dict[str, int] = {f"x{i}": 0 for i in range(31)}
    regs["x0"] = obj_va
    regs["sp"] = 0x7FFF0000

    pc = entry_rva
    steps = 0
    prng_calls: List[dict] = []
    early_exit_branch: dict | None = None

    while steps < max_steps:
        steps += 1
        rel = pc - text_base_rva
        if rel < 0 or rel + 4 > len(text_bytes):
            break

        w = struct.unpack_from("<I", text_bytes, rel)[0]
        insn = decode_aarch64(w, pc)

        # RET / Epilogue check
        if insn.is_epilogue or insn.mnemonic == "ret":
            break

        # PRNG Call Detection (BL or BLR)
        if insn.is_call:
            target = insn.target_rva
            if target is not None and target in prng_set:
                prng_calls.append({
                    "call_site_rva": hex(pc),
                    "target_rva": hex(target),
                    "draw_index": len(prng_calls),
                })
                # Simulate return value in x0
                regs["x0"] = (regs["x0"] * 1103515245 + 12345) & 0x7FFFFFFF
                pc += 4
                continue

        # Concrete Memory Load: LDR / LDRB / LDRH [Xn, #offset]
        if insn.category.value == "mem_load" and insn.mem_base_reg:
            base_val = regs.get(insn.mem_base_reg, 0)
            off = insn.mem_offset or 0
            load_va = base_val + off

            # Determine read size from mnemonic
            size = 4
            fmt = "<I"
            if "b" in insn.mnemonic:
                size = 1
                fmt = "<B"
            elif "h" in insn.mnemonic:
                size = 2
                fmt = "<H"
            elif insn.mnemonic in ("ldr", "ldur") and insn.operands.startswith("x"):
                size = 8
                fmt = "<Q"

            raw_val = dump_manager.read_bytes(dump_id, load_va, size)
            if raw_val is not None:
                val = struct.unpack(fmt, raw_val)[0]
                dest = insn.operands.split(",")[0].strip()
                dest_x = f"x{dest[1:]}" if dest.startswith(("w", "x")) else dest
                regs[dest_x] = val

        # Conditional Branches: CBZ / CBNZ / B.cond / TBZ / TBNZ
        if insn.is_branch and insn.mnemonic != "b":
            # For CBZ / CBNZ
            if insn.mnemonic in ("cbz", "cbnz"):
                parts = [p.strip() for p in insn.operands.split(",")]
                reg_name = parts[0]
                reg_x = f"x{reg_name[1:]}" if reg_name.startswith(("w", "x")) else reg_name
                reg_val = regs.get(reg_x, 0)

                taken = (reg_val == 0) if insn.mnemonic == "cbz" else (reg_val != 0)
                if not early_exit_branch and not prng_calls:
                    early_exit_branch = {
                        "branch_rva": hex(pc),
                        "mnemonic": insn.mnemonic,
                        "tested_reg": reg_name,
                        "concrete_val": reg_val,
                        "branch_taken": taken,
                        "target_rva": hex(insn.target_rva) if insn.target_rva else None,
                    }

                if taken and insn.target_rva is not None:
                    pc = insn.target_rva
                    continue

        # Advance PC sequentially if not branched
        pc += 4

    return {
        "dump_id": dump_id,
        "object_addr_hex": hex(obj_va),
        "entry_rva": hex(entry_rva),
        "prng_draws_consumed": len(prng_calls),
        "prng_calls": prng_calls,
        "early_exit_branch": early_exit_branch if len(prng_calls) == 0 else None,
        "steps_executed": steps,
        "final_status": "dead_draw" if len(prng_calls) == 0 else "consumed_rng",
    }


def trace_concolic_draws(
    dump_manager: LiveDumpOverlayManager,
    dump_id: str,
    entry_rva: int,
    object_addrs: List[int | str],
    text_bytes: bytes,
    text_base_rva: int = 0,
    prng_rvas: List[int] | None = None,
    max_steps: int = 2000,
) -> List[dict]:
    """Batch-evaluates candidate objects in a dump to partition active vs. dead RNG drawers."""
    results: List[dict] = []
    for obj in object_addrs:
        res = evaluate_function_on_dump(
            dump_manager=dump_manager,
            dump_id=dump_id,
            entry_rva=entry_rva,
            object_addr=obj,
            text_bytes=text_bytes,
            text_base_rva=text_base_rva,
            prng_rvas=prng_rvas,
            max_steps=max_steps,
        )
        results.append(res)
    return results
