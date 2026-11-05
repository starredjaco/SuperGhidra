"""
elf_vtable_recovery.py - Stripped ELF AArch64 C++ Virtual Table & Relocation Recovery Engine.

Features:
  - Vectorized and streaming ingestion of ELF64 .rela.dyn / PT_DYNAMIC relocations.
  - O(1) relocation query map: filters R_AARCH64_RELATIVE (0x403) and R_AARCH64_ABS64 (0x101) addends.
  - Stripped C++ vtable boundary detection in .data.rel.ro / .rodata.
  - Constructor ADRP + ADD analysis to associate class constructors with vtable RVAs.
  - Fast devirtualization lookup: vtable_lookup(vtable_rva, slot_offset) -> function target RVA.
  - Itanium ABI vptr address point normalization and synthetic C struct generation.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np

from superghidra.lifters.aarch64_decode import (
    decode_aarch64,
    resolve_adrp_pair,
)

R_AARCH64_ABS64 = 0x101
R_AARCH64_RELATIVE = 0x403
R_AARCH64_GLOB_DAT = 0x401
R_AARCH64_JUMP_SLOT = 0x402

DT_NULL = 0
DT_PLTGOT = 3
DT_RELA = 7
DT_RELASZ = 8
DT_RELAENT = 9

ELF64_RELA_DTYPE = np.dtype([
    ("r_offset", "<u8"),
    ("r_info", "<u8"),
    ("r_addend", "<i8"),
])


@dataclass(frozen=True)
class VTableSlotEntry:
    slot_index: int
    byte_offset: int          # Offset relative to vptr (e.g. +0x88)
    slot_vaddr: int           # Address of the slot inside .data.rel.ro
    target_rva: int           # Resolved function RVA from .rela.dyn r_addend or static qword
    source: str               # "rela.dyn (R_AARCH64_RELATIVE)", "static_qword", or "dynsym"
    prologue_preview: str = ""


@dataclass
class VTableSlot:
    slot_offset: int  # 0x0, 0x8, 0x10, etc.
    slot_rva: int     # Address of the slot in .data.rel.ro / .rodata
    target_rva: int   # Function pointer (relocation addend)
    symbol_name: str | None = None


@dataclass
class RecoveredVTable:
    vtable_rva: int
    slot_count: int
    slots: List[VTableSlot] = field(default_factory=list)
    class_name: str | None = None
    constructor_rvas: List[int] = field(default_factory=list)
    offset_to_top: int = 0
    typeinfo_rva: int = 0

    def get_slot_target(self, slot_offset: int) -> int | None:
        for s in self.slots:
            if s.slot_offset == slot_offset:
                return s.target_rva
        return None


class Elf64AArch64VTableResolver:
    """Fast .rela.dyn-aware Itanium ABI C++ vtable resolver for stripped AArch64 ELFs."""

    def __init__(
        self,
        elf_bytes: bytes,
        rela_dyn_offset: int,
        rela_dyn_size: int,
        text_range: Tuple[int, int],
    ):
        self.elf = elf_bytes
        self.text_start, self.text_end = text_range

        # Parse dynsym symbol values if section headers are present
        dynsym: Dict[int, int] = {}
        if len(elf_bytes) >= 64 and elf_bytes[:4] == b"\x7fELF":
            e_shoff = struct.unpack_from("<Q", elf_bytes, 40)[0]
            e_shentsize = struct.unpack_from("<H", elf_bytes, 58)[0]
            e_shnum = struct.unpack_from("<H", elf_bytes, 60)[0]
            if e_shoff > 0 and e_shnum > 0:
                for i in range(e_shnum):
                    s_off = e_shoff + i * e_shentsize
                    if s_off + 64 <= len(elf_bytes):
                        sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size = struct.unpack_from(
                            "<IIQQQQ", elf_bytes, s_off
                        )
                        if sh_type == 11:  # SHT_DYNSYM
                            sym_cnt = sh_size // 24
                            for s_i in range(sym_cnt):
                                sym_p = sh_offset + s_i * 24
                                if sym_p + 24 <= len(elf_bytes):
                                    dynsym[s_i] = struct.unpack_from("<Q", elf_bytes, sym_p + 8)[0]

        if rela_dyn_size > 0 and rela_dyn_offset + rela_dyn_size <= len(elf_bytes):
            count = rela_dyn_size // 24
            raw_rela = np.frombuffer(
                elf_bytes,
                dtype=ELF64_RELA_DTYPE,
                count=count,
                offset=rela_dyn_offset,
            )
            r_types = raw_rela["r_info"] & 0xFFFFFFFF
            mask = (r_types == R_AARCH64_RELATIVE) | (r_types == R_AARCH64_ABS64) | (r_types == R_AARCH64_GLOB_DAT)
            filtered = raw_rela[mask]
            order = np.argsort(filtered["r_offset"])
            self.offsets = filtered["r_offset"][order]
            resolved_targets = np.copy(filtered["r_addend"][order])
            filt_types = (filtered["r_info"][order]) & 0xFFFFFFFF
            filt_syms = (filtered["r_info"][order]) >> 32
            for idx, r_type in enumerate(filt_types):
                if r_type in (R_AARCH64_ABS64, R_AARCH64_GLOB_DAT):
                    s_idx = int(filt_syms[idx])
                    if s_idx in dynsym:
                        resolved_targets[idx] = dynsym[s_idx] + resolved_targets[idx]
            self.addends = resolved_targets
        else:
            self.offsets = np.empty(0, dtype="<u8")
            self.addends = np.empty(0, dtype="<i8")

    def resolve_pointer_at(self, vaddr: int, file_offset: int | None = None) -> Tuple[int, str]:
        if len(self.offsets) > 0:
            idx = int(np.searchsorted(self.offsets, vaddr))
            if idx < len(self.offsets) and self.offsets[idx] == vaddr:
                return int(self.addends[idx]), "rela.dyn (R_AARCH64_RELATIVE)"
        if file_offset is not None and 0 <= file_offset <= len(self.elf) - 8:
            val = struct.unpack_from("<Q", self.elf, file_offset)[0]
            if val != 0:
                return val, "static_qword"
        return 0, "unresolved"

    def resolve_vtable(
        self,
        base_vaddr: int,
        slot_offset: int | None = None,
        max_slots: int = 64,
        vaddr_to_file_offset=None,
    ) -> dict:
        first_target, _ = self.resolve_pointer_at(
            base_vaddr, vaddr_to_file_offset(base_vaddr) if vaddr_to_file_offset else None
        )
        plus16_target, _ = self.resolve_pointer_at(
            base_vaddr + 0x10, vaddr_to_file_offset(base_vaddr + 0x10) if vaddr_to_file_offset else None
        )
        if not (self.text_start <= first_target < self.text_end) and (self.text_start <= plus16_target < self.text_end):
            vptr_vaddr = base_vaddr + 0x10
            header_vaddr = base_vaddr
        else:
            vptr_vaddr = base_vaddr
            header_vaddr = base_vaddr - 0x10

        rtti_target, _ = self.resolve_pointer_at(
            header_vaddr + 8, vaddr_to_file_offset(header_vaddr + 8) if vaddr_to_file_offset else None
        )

        if slot_offset is not None:
            slot_vaddr = vptr_vaddr + slot_offset
            foff = vaddr_to_file_offset(slot_vaddr) if vaddr_to_file_offset else None
            target, src = self.resolve_pointer_at(slot_vaddr, foff)
            return {
                "vtable_header_rva": hex(header_vaddr),
                "vptr_address_point_rva": hex(vptr_vaddr),
                "rtti_rva": hex(rtti_target) if rtti_target else None,
                "requested_slot_offset": hex(slot_offset),
                "slot_index": slot_offset // 8,
                "target_function_rva": hex(target),
                "resolution_source": src,
            }

        slots = []
        for idx in range(max_slots):
            off = idx * 8
            sv = vptr_vaddr + off
            foff = vaddr_to_file_offset(sv) if vaddr_to_file_offset else None
            target, src = self.resolve_pointer_at(sv, foff)
            if not (self.text_start <= target < self.text_end):
                break
            slots.append({
                "slot_index": idx,
                "byte_offset": hex(off),
                "slot_rva": hex(sv),
                "target_function_rva": hex(target),
                "source": src,
            })
        return {
            "vtable_header_rva": hex(header_vaddr),
            "vptr_address_point_rva": hex(vptr_vaddr),
            "rtti_rva": hex(rtti_target) if rtti_target else None,
            "slot_count": len(slots),
            "slots": slots,
        }


class ElfVTableRecoveryEngine:
    """Fast in-memory parser and indexer for ELF64 dynamic relocations and C++ vtables."""

    def __init__(self, data: bytes, base_rva: int = 0):
        self.data = data
        self.base_rva = base_rva
        self.relocs: Dict[int, int] = {}  # r_offset -> target address
        self.dynsym: Dict[int, int] = {}  # sym_idx -> st_value
        self.vtables: Dict[int, RecoveredVTable] = {}  # vtable_rva -> RecoveredVTable
        self.text_ranges: List[Tuple[int, int]] = []
        self.ro_ranges: List[Tuple[int, int]] = []

        if len(self.data) >= 64 and self.data[:4] == b"\x7fELF":
            self.parse_rela_dyn()
            self.detect_vtable_runs()

    @classmethod
    def from_file(cls, path: str | Path, base_rva: int = 0) -> ElfVTableRecoveryEngine:
        with open(path, "rb") as f:
            data = f.read()
        return cls(data, base_rva=base_rva)

    def parse_rela_dyn(self) -> None:
        """Parses program headers, dynamic segment, and section headers for relocations."""
        if len(self.data) < 64:
            return

        ei_class = self.data[4]
        if ei_class != 2:  # Not ELF64
            return

        # ELF64 Header fields
        e_phoff = struct.unpack_from("<Q", self.data, 32)[0]
        e_shoff = struct.unpack_from("<Q", self.data, 40)[0]
        e_phentsize = struct.unpack_from("<H", self.data, 54)[0]
        e_phnum = struct.unpack_from("<H", self.data, 56)[0]
        e_shentsize = struct.unpack_from("<H", self.data, 58)[0]
        e_shnum = struct.unpack_from("<H", self.data, 60)[0]
        e_shstrndx = struct.unpack_from("<H", self.data, 62)[0]

        rela_offset = 0
        rela_size = 0
        rela_ent = 24

        for i in range(e_phnum):
            off = e_phoff + i * e_phentsize
            if off + 56 > len(self.data):
                break
            p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack_from(
                "<IIQQQQQQ", self.data, off
            )
            if p_type == 1:  # PT_LOAD
                if (p_flags & 1) != 0:  # Executable (.text)
                    self.text_ranges.append((p_vaddr, p_vaddr + p_memsz))
                else:  # Read-only or data (.rodata, .data.rel.ro)
                    self.ro_ranges.append((p_vaddr, p_vaddr + p_memsz))
            elif p_type == 2:  # PT_DYNAMIC
                # Parse dynamic tags
                dyn_pos = p_offset
                while dyn_pos + 16 <= len(self.data) and dyn_pos < p_offset + p_filesz:
                    d_tag, d_val = struct.unpack_from("<Qq", self.data, dyn_pos)
                    dyn_pos += 16
                    if d_tag == DT_NULL:
                        break
                    elif d_tag == DT_RELA:
                        rela_offset = d_val
                    elif d_tag == DT_RELASZ:
                        rela_size = d_val
                    elif d_tag == DT_RELAENT:
                        rela_ent = d_val

        # 2. Parse Section Headers if available
        if e_shnum > 0 and e_shoff > 0 and e_shstrndx < e_shnum:
            strtab_hdr_off = e_shoff + e_shstrndx * e_shentsize
            if strtab_hdr_off + 64 <= len(self.data):
                _, _, _, _, strtab_offset, strtab_sz, _, _, _, _ = struct.unpack_from(
                    "<IIQQQQIIQQ", self.data, strtab_hdr_off
                )
                shstrtab = self.data[strtab_offset : strtab_offset + strtab_sz]

                rela_sections: List[Tuple[int, int, int]] = []
                for i in range(e_shnum):
                    s_off = e_shoff + i * e_shentsize
                    if s_off + 64 > len(self.data):
                        break
                    (
                        sh_name,
                        sh_type,
                        sh_flags,
                        sh_addr,
                        sh_offset,
                        sh_size,
                        sh_link,
                        sh_info,
                        sh_addralign,
                        sh_entsize,
                    ) = struct.unpack_from("<IIQQQQIIQQ", self.data, s_off)

                    name_end = shstrtab.find(b"\x00", sh_name)
                    sec_name = (
                        shstrtab[sh_name:name_end].decode("latin-1", errors="replace")
                        if name_end != -1
                        else ""
                    )

                    if sh_type == 11 or sec_name == ".dynsym":  # SHT_DYNSYM
                        sym_ent = sh_entsize or 24
                        sym_cnt = sh_size // sym_ent
                        for s_i in range(sym_cnt):
                            sym_p = sh_offset + s_i * sym_ent
                            if sym_p + 24 <= len(self.data):
                                self.dynsym[s_i] = struct.unpack_from("<Q", self.data, sym_p + 8)[0]
                    elif sec_name in (".rela.dyn", ".rela.plt") or sh_type == 4:  # SHT_RELA
                        rela_sections.append((sh_offset, sh_size, sh_entsize or 24))

                for r_off, r_sz, r_ent in rela_sections:
                    self._parse_rela_section(r_off, r_sz, r_ent)

        # If relocations not found via section headers, parse from PT_DYNAMIC
        if not self.relocs and rela_offset > 0 and rela_size > 0:
            self._parse_rela_section(rela_offset, rela_size, rela_ent)

        # Fallback: scan binary for Elf64_Rela structures if stripped
        if not self.relocs:
            self._scan_raw_rela_fallback()

    def _parse_rela_section(self, offset: int, size: int, entsize: int) -> None:
        """Parses an Elf64_Rela table into self.relocs."""
        end = min(len(self.data), offset + size)
        for cur in range(offset, end - entsize + 1, entsize):
            r_offset, r_info, r_addend = struct.unpack_from("<QQq", self.data, cur)
            rel_type = r_info & 0xFFFFFFFF
            sym_idx = r_info >> 32
            if rel_type == R_AARCH64_RELATIVE:
                self.relocs[r_offset] = r_addend
            elif rel_type in (R_AARCH64_ABS64, R_AARCH64_GLOB_DAT, R_AARCH64_JUMP_SLOT):
                sym_val = self.dynsym.get(sym_idx, 0)
                self.relocs[r_offset] = sym_val + r_addend

    def _scan_raw_rela_fallback(self) -> None:
        """Heuristic sweep for contiguous Elf64_Rela entries when section headers are absent."""
        for off in range(0, min(len(self.data) - 24, 10 * 1024 * 1024), 24):
            r_offset, r_info, r_addend = struct.unpack_from("<QQq", self.data, off)
            rel_type = r_info & 0xFFFFFFFF
            if rel_type in (R_AARCH64_RELATIVE, R_AARCH64_ABS64):
                if 0 < r_offset < 0x10000000 and 0 < r_addend < 0x10000000:
                    self.relocs[r_offset] = r_addend

    def _is_text_target(self, target: int) -> bool:
        """Checks if a target address falls in executable code."""
        if self.text_ranges:
            return any(start <= target < end for start, end in self.text_ranges)
        # Heuristic fallback: target is reasonably non-zero
        return target > 0

    def detect_vtable_runs(self) -> None:
        """Groups contiguous relocations in .data.rel.ro into candidate virtual method tables."""
        if not self.relocs:
            return

        sorted_addrs = sorted(self.relocs.keys())
        n = len(sorted_addrs)
        i = 0

        while i < n:
            addr = sorted_addrs[i]
            target = self.relocs[addr]

            if not self._is_text_target(target):
                i += 1
                continue

            # Check for contiguous 8-byte relocations
            run: List[Tuple[int, int]] = [(addr, target)]
            j = i + 1
            while j < n and sorted_addrs[j] == run[-1][0] + 8:
                next_target = self.relocs[sorted_addrs[j]]
                if self._is_text_target(next_target):
                    run.append((sorted_addrs[j], next_target))
                    j += 1
                else:
                    break

            # A vtable typically has at least 2 virtual methods
            if len(run) >= 2:
                vtable_base = run[0][0]
                slots = [
                    VTableSlot(
                        slot_offset=idx * 8,
                        slot_rva=slot_addr,
                        target_rva=slot_target,
                    )
                    for idx, (slot_addr, slot_target) in enumerate(run)
                ]
                vtable = RecoveredVTable(
                    vtable_rva=vtable_base,
                    slot_count=len(slots),
                    slots=slots,
                    class_name=f"Class_VTable_0x{vtable_base:x}",
                )
                self.vtables[vtable_base] = vtable
                i = j
            else:
                i += 1

    def vtable_lookup(self, vtable_rva: int, slot_offset: int) -> int | None:
        """Looks up the target function RVA for a specific virtual method slot."""
        # 1. Exact vtable match
        if vtable_rva in self.vtables:
            target = self.vtables[vtable_rva].get_slot_target(slot_offset)
            if target is not None:
                return target

        # 2. Direct relocation lookup at (vtable_rva + slot_offset)
        slot_addr = vtable_rva + slot_offset
        return self.relocs.get(slot_addr)

    def get_vtable(self, vtable_rva: int, max_slots: int = 64) -> RecoveredVTable | None:
        """Returns the recovered vtable object at a given address."""
        if vtable_rva in self.vtables:
            return self.vtables[vtable_rva]

        # On-demand synthesis if base has relocations
        if vtable_rva in self.relocs:
            slots: List[VTableSlot] = []
            for slot_idx in range(max_slots):
                addr = vtable_rva + slot_idx * 8
                if addr in self.relocs:
                    slots.append(
                        VTableSlot(
                            slot_offset=slot_idx * 8,
                            slot_rva=addr,
                            target_rva=self.relocs[addr],
                        )
                    )
                else:
                    break
            if slots:
                vt = RecoveredVTable(
                    vtable_rva=vtable_rva,
                    slot_count=len(slots),
                    slots=slots,
                    class_name=f"Class_VTable_0x{vtable_rva:x}",
                )
                self.vtables[vtable_rva] = vt
                return vt
        return None

    def find_all_vtables(self) -> List[RecoveredVTable]:
        """Returns all detected virtual tables."""
        return list(self.vtables.values())

    def find_constructor_vtable_stores(self) -> Dict[int, int]:
        """Scans .text for constructors storing vtable pointers into [x0].

        Returns a mapping: {constructor_func_rva: vtable_rva}
        """
        ctor_map: Dict[int, int] = {}
        if not self.text_ranges:
            return ctor_map

        for text_start, text_end in self.text_ranges:
            end = min(len(self.data), text_end)
            for off in range(text_start, end - 8, 4):
                if off + 8 > len(self.data):
                    break
                w1 = struct.unpack_from("<I", self.data, off)[0]
                w2 = struct.unpack_from("<I", self.data, off + 4)[0]

                target_vtable = resolve_adrp_pair(off, w1, off + 4, w2)
                if target_vtable and (target_vtable in self.vtables or target_vtable in self.relocs):
                    # Check next instruction for str [x0]
                    if off + 12 <= len(self.data):
                        w3 = struct.unpack_from("<I", self.data, off + 8)[0]
                        insn3 = decode_aarch64(w3, off + 8)
                        if insn3.category.value == "mem_store" and insn3.mem_base_reg == "x0":
                            ctor_map[off] = target_vtable

        return ctor_map

    def generate_synthetic_vtable_struct(self, vtable: RecoveredVTable) -> str:
        """Generates a compilable C struct definition for the vtable layout."""
        name = vtable.class_name or f"VTable_0x{vtable.vtable_rva:x}"
        lines = [f"struct {name} {{"]
        for slot in vtable.slots:
            func_name = f"slot_0x{slot.slot_offset:x}_target_0x{slot.target_rva:x}"
            lines.append(f"    void (*{func_name})(void* this_ptr);")
        lines.append("};")
        return "\n".join(lines)
