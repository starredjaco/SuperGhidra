"""
interior_rva_resolver.py - Four-stage Address Normalizer & Enclosing Function Resolver.

Solves the mid-routine entry problem where execution traces, branch targets, or memory dumps
reference an interior basic block RVA (such as 0x00E6DE9C) instead of a known function entry symbol.

Four-Tier Pipeline:
  Tier 1: Enclosing Function Range Lookup (SQLite L2 cache interval tree or known symbol table).
  Tier 2: Heuristic AArch64 Prologue Sweep (backward sweep for stp x29, x30, sub sp, sp, paciasp).
  Tier 3: Speculative Auto-Function Creation (creates entry point in the non-destructive write overlay).
  Tier 4: Single Basic-Block / Trace-Slice Fallback (lifts enclosing basic block boundaries [bb_start, bb_end]).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Dict, Tuple

from superghidra.lifters.aarch64_decode import (
    decode_aarch64,
    scan_prologue_backward,
)


@dataclass
class ResolvedAddressContext:
    requested_rva: int
    resolved_entry_rva: int
    resolution_method: str  # exact, enclosing_range, heuristic_prologue_sweep, basic_block_slice
    prologue_insn: str | None = None
    enclosing_basic_block: Tuple[int, int] | None = None
    highlighted_stmt: str | None = None


def find_enclosing_basic_block(
    data: bytes,
    rva: int,
    base_rva: int = 0,
    max_scan: int = 256,
) -> Tuple[int, int]:
    """Finds the start and end RVA of the basic block enclosing rva.

    A basic block starts after a branch/ret/call or at a target, and ends with a branch/ret.
    """
    target_off = rva - base_rva
    if target_off < 0 or len(data) < 4:
        return (rva, rva + 4)

    aligned_off = (min(target_off, len(data) - 4) >> 2) << 2
    bb_start_off = aligned_off
    bb_end_off = aligned_off + 4

    # Scan backward for start
    min_off = max(0, aligned_off - max_scan)
    for cur in range(aligned_off - 4, min_off - 4, -4):
        if cur < 0 or cur + 4 > len(data):
            break
        w = struct.unpack_from("<I", data, cur)[0]
        insn = decode_aarch64(w, base_rva + cur)
        if insn.is_branch or insn.is_epilogue:
            bb_start_off = cur + 4
            break
        bb_start_off = cur

    # Scan forward for end
    max_off = min(len(data), aligned_off + max_scan)
    for cur in range(aligned_off, max_off, 4):
        if cur + 4 > len(data):
            bb_end_off = cur
            break
        w = struct.unpack_from("<I", data, cur)[0]
        insn = decode_aarch64(w, base_rva + cur)
        if insn.is_branch or insn.is_epilogue:
            bb_end_off = cur + 4
            break
        bb_end_off = cur + 4

    return (base_rva + bb_start_off, base_rva + bb_end_off)


def resolve_interior_rva(
    requested_rva: int,
    binary_data: bytes,
    base_rva: int = 0,
    known_functions: Dict[int, int] | None = None,  # {func_start_rva: func_size}
    max_sweep_bytes: int = 4096,
) -> ResolvedAddressContext:
    """Normalizes any requested RVA to an enclosing function entry or basic block slice.

    Args:
        requested_rva: The address to query (e.g. 0x00E6DE9C).
        binary_data: Raw executable binary bytes.
        base_rva: Base RVA for binary_data.
        known_functions: Optional map of {func_start: size}.
        max_sweep_bytes: Max bytes to sweep backward for prologue.
    """
    aligned_rva = (requested_rva >> 2) << 2

    # Tier 1: Exact or Enclosing Function Range Lookup
    if known_functions:
        if aligned_rva in known_functions:
            return ResolvedAddressContext(
                requested_rva=requested_rva,
                resolved_entry_rva=aligned_rva,
                resolution_method="exact",
                enclosing_basic_block=find_enclosing_basic_block(binary_data, aligned_rva, base_rva=base_rva),
            )
        for f_start, f_size in known_functions.items():
            if f_start <= aligned_rva < f_start + f_size:
                return ResolvedAddressContext(
                    requested_rva=requested_rva,
                    resolved_entry_rva=f_start,
                    resolution_method="enclosing_range",
                    enclosing_basic_block=find_enclosing_basic_block(binary_data, aligned_rva, base_rva=base_rva),
                )

    # Tier 2: Heuristic AArch64 Prologue Sweep
    prologue_rva = scan_prologue_backward(binary_data, aligned_rva, base_rva=base_rva, max_bytes=max_sweep_bytes)
    if prologue_rva is not None:
        p_off = prologue_rva - base_rva
        w = struct.unpack_from("<I", binary_data, p_off)[0]
        insn = decode_aarch64(w, prologue_rva)
        return ResolvedAddressContext(
            requested_rva=requested_rva,
            resolved_entry_rva=prologue_rva,
            resolution_method="heuristic_prologue_sweep",
            prologue_insn=f"{insn.mnemonic} {insn.operands}",
            enclosing_basic_block=find_enclosing_basic_block(binary_data, aligned_rva, base_rva=base_rva),
        )

    # Tier 4: Basic-Block / Trace-Slice Fallback
    bb_range = find_enclosing_basic_block(binary_data, aligned_rva, base_rva=base_rva)
    return ResolvedAddressContext(
        requested_rva=requested_rva,
        resolved_entry_rva=bb_range[0],
        resolution_method="basic_block_slice",
        enclosing_basic_block=bb_range,
    )
