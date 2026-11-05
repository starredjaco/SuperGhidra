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

import bisect
import struct
from dataclasses import dataclass
from typing import Dict, List, Tuple

from superghidra.lifters.aarch64_decode import (
    decode_aarch64,
    scan_prologue_backward,
)


@dataclass(frozen=True)
class ResolvedFunctionTarget:
    queried_rva: int
    entry_rva: int
    offset_from_entry: int
    resolution_method: str  # "exact", "eh_frame", "interval_cache", "prologue_sweep", "basic_block"
    enclosing_block_start: int
    enclosing_block_end: int


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


class AArch64InteriorResolver:
    """Resolves arbitrary interior RVAs to their enclosing function entry and basic block."""

    def __init__(self, text_bytes: bytes, text_base_rva: int, eh_frame_starts: List[int] | None = None):
        self.text = text_bytes
        self.base = text_base_rva
        self.eh_starts = sorted(eh_frame_starts or [])

    @staticmethod
    def _is_prologue_word(w: int) -> bool:
        # PACIASP / PACIBSP
        if w in (0xD503233F, 0xD503237F):
            return True
        # STP X29, X30, [SP, #-imm]! (pre-index)
        if (w & 0xFFC07FFF) == 0xA9807BFD:
            return True
        # STP X29, X30, [SP, #imm] (signed offset after SUB SP, SP, #imm)
        if (w & 0xFFC07FFF) == 0xA9007BFD:
            return True
        return False

    @staticmethod
    def _is_terminator_word(w: int) -> bool:
        # RET (0xD65F03C0) or RETA/RETB (0xD65F0BFF / 0xD65F0FFF) or UDF #0
        return w in (0xD65F03C0, 0xD65F0BFF, 0xD65F0FFF) or (w & 0xFFFF0000) == 0x00000000

    def resolve(self, rva: int, max_backtrack: int = 0x4000) -> ResolvedFunctionTarget:
        # 1. Check .eh_frame FDE table first if present
        if self.eh_starts:
            idx = bisect.bisect_right(self.eh_starts, rva) - 1
            if idx >= 0 and (rva - self.eh_starts[idx]) <= max_backtrack:
                entry = self.eh_starts[idx]
                bb_start, bb_end = self._find_enclosing_basic_block(rva, entry)
                return ResolvedFunctionTarget(
                    queried_rva=rva,
                    entry_rva=entry,
                    offset_from_entry=rva - entry,
                    resolution_method="exact" if entry == rva else "eh_frame",
                    enclosing_block_start=bb_start,
                    enclosing_block_end=bb_end,
                )

        # 2. Sweep backward through .text for prologue
        rel = rva - self.base
        min_rel = max(0, rel - max_backtrack)
        candidate_entry = rva
        for cur in range(rel, min_rel - 4, -4):
            if cur + 4 > len(self.text):
                continue
            w = struct.unpack_from("<I", self.text, cur)[0]
            if cur < rel and self._is_terminator_word(w):
                # Stopped at previous function's RET; step forward 4 bytes
                candidate_entry = self.base + cur + 4
                break
            if self._is_prologue_word(w):
                if cur >= 4:
                    prev_w = struct.unpack_from("<I", self.text, cur - 4)[0]
                    if (prev_w & 0xFF0003FF) == 0xD10003FF or prev_w in (0xD503233F, 0xD503237F):
                        cur -= 4
                candidate_entry = self.base + cur
                break
        else:
            if min_rel == 0:
                candidate_entry = self.base

        bb_start, bb_end = self._find_enclosing_basic_block(rva, candidate_entry)
        return ResolvedFunctionTarget(
            queried_rva=rva,
            entry_rva=candidate_entry,
            offset_from_entry=rva - candidate_entry,
            resolution_method="exact" if candidate_entry == rva else "prologue_sweep",
            enclosing_block_start=bb_start,
            enclosing_block_end=bb_end,
        )

    def _find_enclosing_basic_block(self, rva: int, min_rva: int) -> Tuple[int, int]:
        rel = rva - self.base
        min_rel = max(0, min_rva - self.base)
        start_rel = rel
        for cur in range(rel - 4, min_rel - 4, -4):
            if cur < 0 or cur + 4 > len(self.text):
                break
            w = struct.unpack_from("<I", self.text, cur)[0]
            if self._is_branch_or_ret(w):
                start_rel = cur + 4
                break
        else:
            start_rel = min_rel

        end_rel = rel + 4
        max_rel = min(len(self.text) - 4, rel + 0x400)
        for cur in range(rel, max_rel + 4, 4):
            if cur + 4 > len(self.text):
                end_rel = len(self.text)
                break
            w = struct.unpack_from("<I", self.text, cur)[0]
            if self._is_branch_or_ret(w):
                end_rel = cur + 4
                break
        return (self.base + start_rel, self.base + end_rel)

    @staticmethod
    def _is_branch_or_ret(w: int) -> bool:
        if (w & 0x7C000000) == 0x14000000:
            return (w & 0x80000000) == 0
        if (w & 0xFF000010) == 0x54000000:
            return True
        if (w & 0x7E000000) in (0x34000000, 0x36000000):
            return True
        if (w & 0xFFFFFC1F) in (0xD61F0000, 0xD65F0000):
            return True
        return False


def annotate_decompiled_c(c_source: str, target_rva: int, entry_rva: int) -> str:
    """Injects an inline target highlight comment into decompiled C output."""
    offset = target_rva - entry_rva
    tag = f"/* >>> TARGET RVA 0x{target_rva:08X} (+0x{offset:X}) <<< */"
    target_pattern = f"0x{target_rva:x}"
    target_pattern_upper = f"0x{target_rva:X}"

    lines = c_source.splitlines()
    injected = False
    new_lines = []
    for line in lines:
        new_lines.append(line)
        if not injected and (target_pattern in line.lower() or f"+ 0x{offset:x}" in line.lower() or f"+0x{offset:x}" in line.lower()):
            new_lines.append(f"    {tag}")
            injected = True

    if not injected:
        # Prepend after function signature or at top
        if len(new_lines) > 2 and "{" in new_lines[1]:
            new_lines.insert(2, f"    {tag}")
        else:
            new_lines.insert(0, tag)

    return "\n".join(new_lines)
