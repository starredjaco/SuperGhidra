"""
batch_dsl.py - Transactional Multi-Query Pipeline DSL (superghidra_batch).

Collapses 5–10 sequential MCP roundtrips into a single atomic in-memory pipeline execution.
Supports declarative JSONPath-style variable substitution ($step_id.field[*].subfield).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List

from superghidra.acceleration.scan_arm64_insns import scan_arm64_insns
from superghidra.core.interior_rva_resolver import resolve_interior_rva
from superghidra.formats.elf_vtable_recovery import ElfVTableRecoveryEngine
from superghidra.formats.struct_offset_index import StructOffsetIndexer
from superghidra.lifters.aarch64_decode import (
    disasm_range_fast,
)


@dataclass
class BatchPipelineStep:
    id: str
    op: str
    params: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BatchPipelineResult:
    success: bool
    results: Dict[str, Any] = field(default_factory=dict)
    error: str | None = None


class BatchPipelineExecutor:
    """Executes multi-step declarative query pipelines against binary context."""

    def __init__(
        self,
        binary_data: bytes,
        base_rva: int = 0,
        vtable_engine: ElfVTableRecoveryEngine | None = None,
    ):
        self.binary_data = binary_data
        self.base_rva = base_rva
        self.vtable_engine = vtable_engine or ElfVTableRecoveryEngine(binary_data, base_rva=base_rva)
        self.offset_indexer = StructOffsetIndexer(binary_data, base_rva=base_rva)

    def _substitute_param(self, val: Any, step_results: Dict[str, Any]) -> Any:
        """Resolves variable references like '$step1.matches[*].rva' or '$step1.target'."""
        if isinstance(val, str) and val.startswith("$"):
            # Example: $step1.matches[*].rva
            match = re.match(r"^\$([a-zA-Z0-9_]+)\.([a-zA-Z0-9_\.\[\]\*]+)$", val)
            if match:
                step_id, path = match.group(1), match.group(2)
                res = step_results.get(step_id)
                if res is None:
                    return []
                # Traverse path
                parts = path.split(".")
                cur = res
                for p in parts:
                    if p.endswith("[*]"):
                        field_name = p[:-3]
                        if isinstance(cur, dict):
                            cur = cur.get(field_name, [])
                        elif hasattr(cur, field_name):
                            cur = getattr(cur, field_name)
                    else:
                        if isinstance(cur, list):
                            cur = [getattr(item, p, item.get(p) if isinstance(item, dict) else None) for item in cur]
                        elif isinstance(cur, dict):
                            cur = cur.get(p)
                        elif hasattr(cur, p):
                            cur = getattr(cur, p)
                return cur
        elif isinstance(val, dict):
            return {k: self._substitute_param(v, step_results) for k, v in val.items()}
        elif isinstance(val, list):
            return [self._substitute_param(item, step_results) for item in val]
        return val

    def execute_pipeline(self, steps: List[Dict[str, Any]]) -> BatchPipelineResult:
        """Executes a list of pipeline step dictionaries."""
        step_results: Dict[str, Any] = {}

        for step_dict in steps:
            s_id = step_dict.get("id", "step")
            op = step_dict.get("op", "")
            raw_params = step_dict.get("params", {})
            params = self._substitute_param(raw_params, step_results)

            try:
                res = self._execute_op(op, params)
                step_results[s_id] = res
            except Exception as e:
                return BatchPipelineResult(
                    success=False,
                    results=step_results,
                    error=f"Step '{s_id}' (op '{op}') failed: {e}",
                )

        return BatchPipelineResult(success=True, results=step_results)

    def _execute_op(self, op: str, params: Dict[str, Any]) -> Any:
        """Dispatches an individual operation."""
        if op == "scan_arm64_insns":
            mem_offset = params.get("mem_offset")
            if isinstance(mem_offset, str) and mem_offset.startswith("0x"):
                mem_offset = int(mem_offset, 16)
            immediate = params.get("immediate")
            if isinstance(immediate, str) and immediate.startswith("0x"):
                immediate = int(immediate, 16)

            matches = scan_arm64_insns(
                self.binary_data,
                base_rva=self.base_rva,
                mask=params.get("mask"),
                expected=params.get("expected"),
                mem_offset=mem_offset,
                access_type=params.get("access_type", "any"),
                immediate=immediate,
                mnemonic=params.get("mnemonic"),
                max_matches=params.get("max_matches", 100),
            )
            return {"matches": matches, "count": len(matches)}

        elif op in ("resolve_interior_rva", "decompile_function"):
            addrs = params.get("addresses") or [params.get("address")]
            results = []
            for addr in addrs:
                if isinstance(addr, str) and addr.startswith("0x"):
                    addr = int(addr, 16)
                if addr is not None:
                    ctx = resolve_interior_rva(addr, self.binary_data, base_rva=self.base_rva)
                    results.append(ctx)
            return {"resolved": results}

        elif op in ("vtable_lookup", "find_vtable_refs"):
            vtable_rva = params.get("vtable_rva")
            if isinstance(vtable_rva, str) and vtable_rva.startswith("0x"):
                vtable_rva = int(vtable_rva, 16)
            slot = params.get("slot_offset", 0)
            target = self.vtable_engine.vtable_lookup(vtable_rva or 0, slot)
            return {"target_rva": target}

        elif op == "disasm_fast":
            start = params.get("start_rva", self.base_rva)
            count = params.get("count", 10)
            end = start + count * 4
            lines = disasm_range_fast(self.binary_data, start, end)
            return {"lines": lines}

        else:
            raise ValueError(f"Unknown pipeline op '{op}'")
