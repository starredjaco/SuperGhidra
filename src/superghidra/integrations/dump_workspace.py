"""
dump_workspace.py - Multi-Dump Heap & Live Object Overlay Engine.

Connects offline static binary analysis and decompilation with multi-snapshot
runtime process memory dumps (e.g., dumps 3, 4, 14..17).

Features:
  - ASLR module base normalization (Runtime Virtual Address <-> Static Binary RVA).
  - Live heap object inspection: resolves vtable pointer to C++ class via ElfVTableRecoveryEngine.
  - Struct projection and typed field extraction over live heap addresses.
  - Vectorized cross-dump object and field diffing to isolate mutating tick state and PRNG consumers.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple

from superghidra.formats.elf_vtable_recovery import ElfVTableRecoveryEngine, RecoveredVTable


@dataclass
class DumpModule:
    name: str
    runtime_base: int
    size: int
    data: bytes = field(repr=False)

    def contains_runtime_addr(self, addr: int) -> bool:
        return self.runtime_base <= addr < self.runtime_base + self.size

    def to_rva(self, runtime_addr: int) -> int | None:
        if self.contains_runtime_addr(runtime_addr):
            return runtime_addr - self.runtime_base
        return None

    def to_runtime(self, rva: int) -> int:
        return self.runtime_base + rva


@dataclass
class InspectedHeapObject:
    dump_name: str
    runtime_addr: int
    vtable_runtime_ptr: int
    vtable_rva: int | None
    class_name: str | None
    vtable: RecoveredVTable | None
    fields: Dict[str, Any] = field(default_factory=dict)
    raw_bytes: bytes = field(default=b"", repr=False)


@dataclass
class FieldDiff:
    offset: int
    field_name: str
    val_a: Any
    val_b: Any


@dataclass
class ObjectDiffResult:
    runtime_addr: int
    class_name: str | None
    diffs: List[FieldDiff] = field(default_factory=list)


class DumpWorkspace:
    """Manages memory dumps, modules, ASLR translations, and heap object inspection."""

    def __init__(self):
        self.dumps: Dict[str, Dict[str, DumpModule]] = {}  # {dump_name: {module_name: DumpModule}}
        self.heap_segments: Dict[str, List[Tuple[int, int, bytes]]] = {}  # {dump_name: [(base, size, data)]}

    def mount_dump_module(
        self,
        dump_name: str,
        module_name: str,
        data: bytes,
        runtime_base: int,
    ) -> DumpModule:
        """Mounts an executable module (e.g. libnative.so) within a named memory dump."""
        mod = DumpModule(name=module_name, runtime_base=runtime_base, size=len(data), data=data)
        self.dumps.setdefault(dump_name, {})[module_name] = mod
        return mod

    def mount_heap_segment(
        self,
        dump_name: str,
        runtime_base: int,
        data: bytes,
    ) -> None:
        """Mounts a heap memory page or segment for a named dump."""
        self.heap_segments.setdefault(dump_name, []).append((runtime_base, len(data), data))

    def read_dump_bytes(self, dump_name: str, runtime_addr: int, size: int) -> bytes | None:
        """Reads raw bytes from any mounted heap or module segment in the given dump."""
        # 1. Check heap segments
        for base, seg_sz, data in self.heap_segments.get(dump_name, []):
            if base <= runtime_addr < base + seg_sz:
                off = runtime_addr - base
                avail = min(size, seg_sz - off)
                return data[off : off + avail]

        # 2. Check modules
        for mod in self.dumps.get(dump_name, {}).values():
            if mod.contains_runtime_addr(runtime_addr):
                off = runtime_addr - mod.runtime_base
                avail = min(size, mod.size - off)
                return mod.data[off : off + avail]

        return None

    def runtime_to_static_rva(self, dump_name: str, module_name: str, runtime_addr: int) -> int | None:
        """Translates a runtime address to static module RVA."""
        mod = self.dumps.get(dump_name, {}).get(module_name)
        if mod:
            return mod.to_rva(runtime_addr)
        return None

    def static_to_runtime(self, dump_name: str, module_name: str, rva: int) -> int | None:
        """Translates a static module RVA to runtime address."""
        mod = self.dumps.get(dump_name, {}).get(module_name)
        if mod:
            return mod.to_runtime(rva)
        return None

    def inspect_heap_object(
        self,
        dump_name: str,
        runtime_addr: int,
        vtable_engine: ElfVTableRecoveryEngine | None = None,
        module_name: str | None = None,
        schema: Dict[int, str] | None = None,  # {offset: "type_or_name"}
        object_size: int = 512,
    ) -> InspectedHeapObject | None:
        """Inspects a live heap object, resolving its vtable and unpacking fields."""
        obj_bytes = self.read_dump_bytes(dump_name, runtime_addr, object_size)
        if not obj_bytes or len(obj_bytes) < 8:
            return None

        vtable_ptr = struct.unpack_from("<Q", obj_bytes, 0)[0]
        vtable_rva: int | None = None
        class_name: str | None = None
        vtable: RecoveredVTable | None = None

        # Resolve vtable pointer to static RVA
        if module_name:
            vtable_rva = self.runtime_to_static_rva(dump_name, module_name, vtable_ptr)
        else:
            # Try all modules in dump
            for m_name in self.dumps.get(dump_name, {}):
                vtable_rva = self.runtime_to_static_rva(dump_name, m_name, vtable_ptr)
                if vtable_rva is not None:
                    break

        if vtable_rva is not None and vtable_engine:
            vtable = vtable_engine.get_vtable(vtable_rva)
            if vtable:
                class_name = vtable.class_name

        # Decode fields according to schema
        fields: Dict[str, Any] = {}
        if schema:
            for off, f_type in schema.items():
                if off + 4 <= len(obj_bytes):
                    if "u64" in f_type or f_type.endswith("*"):
                        val = struct.unpack_from("<Q", obj_bytes, off)[0]
                    elif "u8" in f_type or "flags" in f_type:
                        val = struct.unpack_from("<B", obj_bytes, off)[0]
                    else:
                        val = struct.unpack_from("<I", obj_bytes, off)[0]
                    fields[f_type] = val

        return InspectedHeapObject(
            dump_name=dump_name,
            runtime_addr=runtime_addr,
            vtable_runtime_ptr=vtable_ptr,
            vtable_rva=vtable_rva,
            class_name=class_name,
            vtable=vtable,
            fields=fields,
            raw_bytes=obj_bytes,
        )

    def diff_heap_objects(
        self,
        dump_a: str,
        dump_b: str,
        runtime_addr: int,
        schema: Dict[int, str] | None = None,
        object_size: int = 512,
    ) -> ObjectDiffResult:
        """Diffs fields of the same heap object across two memory snapshots (dump A vs dump B)."""
        bytes_a = self.read_dump_bytes(dump_a, runtime_addr, object_size) or b""
        bytes_b = self.read_dump_bytes(dump_b, runtime_addr, object_size) or b""

        diffs: List[FieldDiff] = []
        if schema:
            for off, f_name in schema.items():
                if off + 4 <= min(len(bytes_a), len(bytes_b)):
                    if "u64" in f_name or f_name.endswith("*"):
                        va = struct.unpack_from("<Q", bytes_a, off)[0]
                        vb = struct.unpack_from("<Q", bytes_b, off)[0]
                    elif "u8" in f_name or "flags" in f_name:
                        va = struct.unpack_from("<B", bytes_a, off)[0]
                        vb = struct.unpack_from("<B", bytes_b, off)[0]
                    else:
                        va = struct.unpack_from("<I", bytes_a, off)[0]
                        vb = struct.unpack_from("<I", bytes_b, off)[0]

                    if va != vb:
                        diffs.append(FieldDiff(offset=off, field_name=f_name, val_a=va, val_b=vb))
        else:
            limit = min(len(bytes_a), len(bytes_b))
            for off in range(0, limit - 3, 4):
                va = struct.unpack_from("<I", bytes_a, off)[0]
                vb = struct.unpack_from("<I", bytes_b, off)[0]
                if va != vb:
                    diffs.append(FieldDiff(offset=off, field_name=f"word_0x{off:x}", val_a=va, val_b=vb))

        return ObjectDiffResult(runtime_addr=runtime_addr, class_name=None, diffs=diffs)
