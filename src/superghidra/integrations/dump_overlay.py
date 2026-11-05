"""
dump_overlay.py - Live memory dump registry, runtime-to-static RVA normalizer, and heap inspector.

Bridges runtime process memory dumps with static ELF RVAs and Itanium C++ vtables,
enabling virtual method devirtualization and typed struct field inspection.
"""

from __future__ import annotations

import mmap
import struct
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple


@dataclass
class DumpSegment:
    start_va: int
    end_va: int
    file_path: str
    mm: mmap.mmap | None = None
    data: bytes | None = None


class LiveDumpOverlayManager:
    """Bridges runtime memory dumps with static ELF RVAs and vtables."""

    def __init__(self, vtable_resolver: Any = None):
        self.vtable_resolver = vtable_resolver
        self.dumps: Dict[str, dict] = {}  # dump_id -> {"module_base": int, "segments": list[DumpSegment]}

    def register_dump(
        self,
        dump_id: str,
        module_base: int,
        segments: List[Tuple[int, str]] | List[Tuple[int, bytes]],
    ) -> dict:
        """Registers a memory dump snapshot composed of one or more address segments."""
        loaded_segs: List[DumpSegment] = []
        for item in segments:
            base_va = item[0]
            source = item[1]
            if isinstance(source, (bytes, bytearray)):
                loaded_segs.append(
                    DumpSegment(
                        start_va=base_va,
                        end_va=base_va + len(source),
                        file_path="",
                        mm=None,
                        data=bytes(source),
                    )
                )
            elif isinstance(source, str):
                f = open(source, "rb")
                mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
                loaded_segs.append(
                    DumpSegment(
                        start_va=base_va,
                        end_va=base_va + len(mm),
                        file_path=source,
                        mm=mm,
                        data=None,
                    )
                )
        loaded_segs.sort(key=lambda s: s.start_va)
        self.dumps[dump_id] = {"module_base": module_base, "segments": loaded_segs}
        return {
            "dump_id": dump_id,
            "module_base": hex(module_base),
            "segment_count": len(loaded_segs),
        }

    def read_bytes(self, dump_id: str, va: int, size: int) -> bytes | None:
        """Reads size bytes from the virtual address va in dump_id, stripping TBI bits."""
        if dump_id not in self.dumps:
            return None
        clean_va = va & 0x00FFFFFFFFFFFFFF
        for seg in self.dumps[dump_id]["segments"]:
            if seg.start_va <= clean_va:
                off = clean_va - seg.start_va
                if off + size <= (seg.end_va - seg.start_va):
                    if seg.mm is not None:
                        return seg.mm[off : off + size]
                    elif seg.data is not None:
                        return seg.data[off : off + size]
        return None

    def inspect_live_object(
        self,
        dump_id: str,
        object_addr: int | str,
        field_spec: Dict[str, str] | None = None,
        vtable_slots_to_resolve: List[int] | None = None,
    ) -> dict:
        """Inspects a heap object in a dump: reads vptr, resolves vtable slots, and unpacks fields."""
        if isinstance(object_addr, str):
            va = int(object_addr, 16 if object_addr.startswith(("0x", "0X")) else 10)
        else:
            va = int(object_addr)

        if dump_id not in self.dumps:
            return {"error": f"Dump '{dump_id}' not registered"}

        mod_base = self.dumps[dump_id]["module_base"]
        raw_head = self.read_bytes(dump_id, va, 0x400)
        if raw_head is None:
            return {"error": f"Address {hex(va)} ({va}) not mapped in {dump_id}"}

        raw_vptr = struct.unpack_from("<Q", raw_head, 0)[0] & 0x00FFFFFFFFFFFFFF
        vptr_rva = raw_vptr - mod_base

        resolved_slots = {}
        if self.vtable_resolver is not None:
            slots = vtable_slots_to_resolve or [0x0, 0x8, 0x10, 0x88]
            for slot_off in slots:
                if hasattr(self.vtable_resolver, "resolve_vtable"):
                    res = self.vtable_resolver.resolve_vtable(vptr_rva, slot_offset=slot_off)
                    resolved_slots[hex(slot_off)] = res.get("target_function_rva")
                elif hasattr(self.vtable_resolver, "vtable_lookup"):
                    resolved_slots[hex(slot_off)] = hex(self.vtable_resolver.vtable_lookup(vptr_rva, slot_off) or 0)

        decoded_fields: Dict[str, Any] = {}
        fmt_map = {
            "u8": "<B", "i8": "<b", "u16": "<H", "i16": "<h",
            "u32": "<I", "i32": "<i", "u64": "<Q", "i64": "<q",
            "f32": "<f", "ptr": "<Q",
        }
        spec = field_spec or {"+0x124": "u8"}
        for off_str, ftype in spec.items():
            off_val = int(off_str.lstrip("+"), 16 if "0x" in off_str.lower() else 10)
            fmt = fmt_map.get(ftype, "<I")
            sz = struct.calcsize(fmt)
            if 0 <= off_val + sz <= len(raw_head):
                val = struct.unpack_from(fmt, raw_head, off_val)[0]
                decoded_fields[off_str] = val

        return {
            "dump_id": dump_id,
            "object_va_hex": hex(va),
            "object_va_dec": str(va),
            "raw_vptr": hex(raw_vptr),
            "vptr_static_rva": hex(vptr_rva),
            "resolved_vtable_slots": resolved_slots,
            "fields": decoded_fields,
        }

    def diff_live_objects(
        self,
        dump_ids: List[str],
        object_addrs: List[int | str],
        field_spec: Dict[str, str] | None = None,
    ) -> List[dict]:
        """Diffs struct fields of multiple objects across consecutive memory dump snapshots."""
        results: List[dict] = []
        for obj in object_addrs:
            transitions = []
            prev_fields = None
            for d_id in dump_ids:
                inspection = self.inspect_live_object(d_id, obj, field_spec=field_spec)
                if "error" in inspection:
                    transitions.append({"dump_id": d_id, "error": inspection["error"]})
                    continue
                cur_fields = inspection.get("fields", {})
                diffs = {}
                if prev_fields is not None:
                    for k, v in cur_fields.items():
                        old_v = prev_fields.get(k)
                        if old_v != v:
                            diffs[k] = f"{hex(old_v) if isinstance(old_v, int) else old_v} -> {hex(v) if isinstance(v, int) else v}"
                transitions.append({
                    "dump_id": d_id,
                    "fields": cur_fields,
                    "diff_from_previous": diffs,
                })
                prev_fields = cur_fields

            results.append({
                "object_addr": hex(int(str(obj), 0)),
                "timeline": transitions,
            })
        return results
