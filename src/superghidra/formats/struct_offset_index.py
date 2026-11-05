"""
struct_offset_index.py - Global Struct-Offset Xref Index & Game-Data Constant Linker.

Features:
  - Global base+offset access indexing across .text:
      (insn_rva, func_rva, mnemonic, is_write, access_size, byte_offset, base_reg).
  - High-speed offset queries: get_offset_accesses(offset=0x124, is_write=True).
  - Co-occurrence struct layout fingerprinting across register access clusters.
  - CSV / Game-Asset Constant Correlator (correlate_data_table):
      Extracts distinctive numeric constants from CSV tables and ranks functions in .text.
"""

from __future__ import annotations

import csv
import io
import struct
from dataclasses import dataclass
from typing import Dict, List, Set

from superghidra.acceleration.scan_arm64_insns import scan_arm64_insns
from superghidra.lifters.aarch64_decode import (
    decode_aarch64,
)


@dataclass
class OffsetAccess:
    insn_rva: int
    func_rva: int | None
    mnemonic: str
    is_write: bool
    access_size: int
    byte_offset: int
    base_reg: str


@dataclass
class TableCorrelationResult:
    matched_constant: int
    constant_hex: str
    insn_rva: int
    func_rva: int | None
    mnemonic: str
    operands: str
    table_context: str


class StructOffsetIndexer:
    """Indexes memory accesses and game data constants across binary code sections."""

    def __init__(self, data: bytes, base_rva: int = 0):
        self.data = data
        self.base_rva = base_rva
        self.accesses: List[OffsetAccess] = []
        self._offset_map: Dict[int, List[OffsetAccess]] = {}
        self._build_index()

    def _build_index(self) -> None:
        """Indexes all immediate-offset loads and stores across the buffer."""
        for off in range(0, len(self.data) - 3, 4):
            w = struct.unpack_from("<I", self.data, off)[0]
            rva = self.base_rva + off
            insn = decode_aarch64(w, rva)

            if insn.is_memory_access and insn.mem_offset is not None and insn.mem_base_reg:
                entry = OffsetAccess(
                    insn_rva=rva,
                    func_rva=None,
                    mnemonic=insn.mnemonic,
                    is_write=insn.mem_is_write,
                    access_size=insn.mem_size,
                    byte_offset=insn.mem_offset,
                    base_reg=insn.mem_base_reg,
                )
                self.accesses.append(entry)
                self._offset_map.setdefault(insn.mem_offset, []).append(entry)

    def get_offset_accesses(
        self,
        offset: int,
        is_write: bool | None = None,
        access_size: int | None = None,
    ) -> List[OffsetAccess]:
        """Queries all memory access sites touching a given struct offset."""
        candidates = self._offset_map.get(offset, [])
        results = []
        for c in candidates:
            if is_write is not None and c.is_write != is_write:
                continue
            if access_size is not None and c.access_size != access_size:
                continue
            results.append(c)
        return results

    def fingerprint_base_reg_offsets(self, func_start: int, func_size: int) -> Dict[str, Set[int]]:
        """Extracts the set of offsets accessed off each base register within a function."""
        reg_clusters: Dict[str, Set[int]] = {}
        for acc in self.accesses:
            if func_start <= acc.insn_rva < func_start + func_size:
                reg_clusters.setdefault(acc.base_reg, set()).add(acc.byte_offset)
        return reg_clusters

    def correlate_data_table(
        self,
        csv_text_or_path: str,
        min_constant_val: int = 16,
    ) -> List[TableCorrelationResult]:
        """Correlates numeric constants from a game data CSV with immediate instructions in code."""
        # 1. Parse CSV to extract integers >= min_constant_val
        numbers: Dict[int, List[str]] = {}
        content = csv_text_or_path
        if "\n" not in csv_text_or_path and (csv_text_or_path.endswith(".csv") or csv_text_or_path.endswith(".txt")):
            with open(csv_text_or_path, encoding="utf-8", errors="ignore") as f:
                content = f.read()

        reader = csv.reader(io.StringIO(content))
        header: List[str] = []
        for row_idx, row in enumerate(reader):
            if row_idx == 0:
                header = row
                continue
            for col_idx, cell in enumerate(row):
                cell_str = cell.strip()
                try:
                    val = int(cell_str)
                    if val >= min_constant_val and val < 0x10000000:
                        col_name = header[col_idx] if col_idx < len(header) else f"col_{col_idx}"
                        numbers.setdefault(val, []).append(f"Row {row_idx} ({col_name})")
                except ValueError:
                    pass

        # 2. Search binary for each extracted constant using scan_arm64_insns
        results: List[TableCorrelationResult] = []
        for num, contexts in numbers.items():
            matches = scan_arm64_insns(self.data, base_rva=self.base_rva, immediate=num, max_matches=100)
            for m in matches:
                results.append(
                    TableCorrelationResult(
                        matched_constant=num,
                        constant_hex=f"0x{num:x}",
                        insn_rva=m.rva,
                        func_rva=None,
                        mnemonic=m.mnemonic,
                        operands=m.operands,
                        table_context="; ".join(contexts[:3]),
                    )
                )

        return results
