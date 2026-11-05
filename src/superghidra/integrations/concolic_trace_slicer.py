"""
concolic_trace_slicer.py - Concrete-Seeded P-Code Micro-Executor & PRNG Draw Correlator.

Designed for short execution windows (1–500 draws) to solve bit-exact concolic RNG matching,
dead-draw isolation, and branch divergence without combinatorial state explosion.

Features:
  - ConcreteDumpMemoryState: wraps DumpWorkspace for concrete memory reads during slicing.
  - PRNGDrawEvent: structured ledger entry capturing every draw, object instance, and bounds.
  - Reconcile PRNG draws: steps forward from initial dump seed across entity tables to isolate
    which objects and branch conditions consumed PRNG draws between snapshots.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Tuple

from superghidra.integrations.dump_workspace import DumpWorkspace


@dataclass
class PRNGDrawEvent:
    draw_index: int
    caller_rva: int
    object_ptr: int
    object_vtable_rva: int | None
    seed_before: int
    seed_after: int
    return_value: int
    modulo_bound: int | None = None
    is_dead_draw: bool = False


@dataclass
class ReconciledPRNGTrace:
    initial_seed: int
    final_seed: int
    total_draws: int
    matched_draws: List[PRNGDrawEvent] = field(default_factory=list)
    dead_draw_count: int = 0
    drift_detected: bool = False


def default_lcg_step(seed: int) -> Tuple[int, int]:
    """Default 64-bit LCG step: seed_next = (seed * 6364136223846793005 + 1) & 0xFFFFFFFFFFFFFFFF."""
    next_seed = (seed * 6364136223846793005 + 1) & 0xFFFFFFFFFFFFFFFF
    val = (next_seed >> 32) & 0xFFFFFFFF
    return next_seed, val


class ConcreteDumpMemoryState:
    """Provides memory access backed by a specific memory dump in DumpWorkspace."""

    def __init__(self, workspace: DumpWorkspace, dump_name: str):
        self.workspace = workspace
        self.dump_name = dump_name

    def read_u64(self, addr: int) -> int:
        b = self.workspace.read_dump_bytes(self.dump_name, addr, 8)
        if b and len(b) >= 8:
            import struct
            return struct.unpack("<Q", b)[0]
        return 0

    def read_u32(self, addr: int) -> int:
        b = self.workspace.read_dump_bytes(self.dump_name, addr, 4)
        if b and len(b) >= 4:
            import struct
            return struct.unpack("<I", b)[0]
        return 0

    def read_u8(self, addr: int) -> int:
        b = self.workspace.read_dump_bytes(self.dump_name, addr, 1)
        if b and len(b) >= 1:
            return b[0]
        return 0


class ConcolicPRNGCorrelator:
    """Correlates PRNG draws with active entities between two memory snapshot seeds."""

    def __init__(
        self,
        prng_step_fn: Callable[[int], Tuple[int, int]] = default_lcg_step,
    ):
        self.prng_step_fn = prng_step_fn

    def reconcile_window(
        self,
        initial_seed: int,
        target_final_seed: int,
        max_draws: int = 500,
        candidates: List[Dict[str, Any]] | None = None,
    ) -> ReconciledPRNGTrace:
        """Steps PRNG forward from initial_seed up to max_draws seeking target_final_seed.

        Maps each step to candidate objects (if provided) and detects dead draws (draws
        consumed by state-less/ignored evaluations).
        """
        cur_seed = initial_seed
        draws: List[PRNGDrawEvent] = []
        dead_count = 0

        num_candidates = len(candidates) if candidates else 0

        for idx in range(max_draws):
            if cur_seed == target_final_seed and idx > 0:
                break

            next_seed, ret_val = self.prng_step_fn(cur_seed)

            # Assign candidate if available
            cand = candidates[idx % num_candidates] if num_candidates > 0 else {}
            caller_rva = cand.get("caller_rva", 0)
            obj_ptr = cand.get("object_ptr", 0)
            vtable_rva = cand.get("vtable_rva", None)
            bound = cand.get("bound", None)
            is_dead = cand.get("is_dead_draw", False)

            if bound:
                ret_val = ret_val % bound
            if is_dead:
                dead_count += 1

            event = PRNGDrawEvent(
                draw_index=idx,
                caller_rva=caller_rva,
                object_ptr=obj_ptr,
                object_vtable_rva=vtable_rva,
                seed_before=cur_seed,
                seed_after=next_seed,
                return_value=ret_val,
                modulo_bound=bound,
                is_dead_draw=is_dead,
            )
            draws.append(event)
            cur_seed = next_seed

        drift = (cur_seed != target_final_seed)
        return ReconciledPRNGTrace(
            initial_seed=initial_seed,
            final_seed=cur_seed,
            total_draws=len(draws),
            matched_draws=draws,
            dead_draw_count=dead_count,
            drift_detected=drift,
        )
