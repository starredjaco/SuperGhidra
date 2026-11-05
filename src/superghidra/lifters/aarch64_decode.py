"""
aarch64_decode.py - Zero-dependency ARM64 / AArch64 instruction decoder and PC-relative resolver.

Zero-dependency decoder designed for:
  - High-speed zero-JVM AArch64 instruction classification (branch, call, load, store, immediate).
  - PC-relative addressing & branch target calculation (B, BL, B.cond, CBZ, CBNZ, TBZ, TBNZ, ADR, ADRP).
  - ADRP + ADD / LDR pair resolution to 64-bit absolute target RVAs.
  - Memory displacement extraction for struct shift analysis and offset xrefs:
      LDR, STR, LDRB, STRB, LDRH, STRH, LDRSB, LDRSH, LDRSW, LDP, STP [Xn, #imm].
  - Function entry / prologue & epilogue detection:
      Prologue: STP x29, x30, [sp, #-imm]!, SUB sp, sp, #imm, PACIASP, PACIBSP.
      Epilogue: LDP x29, x30, [sp], #imm, RET, AUTIASP, AUTIBSP.
  - Backward prologue sweeps for orphan/interior RVA recovery.
  - Fast-path string disassembly formatting without external toolchain requirements.
"""

from __future__ import annotations

import enum
import struct
from dataclasses import dataclass
from typing import Iterator, List

__all__ = [
    "Aarch64Category",
    "Aarch64Insn",
    "AARCH64_REG_NAMES",
    "AARCH64_COND_NAMES",
    "decode_aarch64",
    "iter_decode_aarch64",
    "resolve_branch_target",
    "resolve_adrp_pair",
    "resolve_arm64_xref_at",
    "scan_prologue_backward",
    "disasm_insn_fast",
    "disasm_range_fast",
    "disassemble_batch",
]

AARCH64_REG_NAMES = tuple(f"x{i}" for i in range(31)) + ("sp", "xzr")
AARCH64_WREG_NAMES = tuple(f"w{i}" for i in range(31)) + ("wsp", "wzr")

AARCH64_COND_NAMES = (
    "eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
    "hi", "ls", "ge", "lt", "gt", "le", "al", "nv",
)


class Aarch64Category(str, enum.Enum):
    BRANCH = "branch"
    CALL = "call"
    MEM_LOAD = "mem_load"
    MEM_STORE = "mem_store"
    ALU_IMM = "alu_imm"
    PROLOGUE = "prologue"
    EPILOGUE = "epilogue"
    SYSTEM = "system"
    OTHER = "other"


@dataclass
class Aarch64Insn:
    rva: int
    word: int
    category: Aarch64Category
    mnemonic: str
    operands: str = ""
    target_rva: int | None = None
    mem_base_reg: str | None = None
    mem_offset: int | None = None
    mem_is_write: bool = False
    mem_size: int = 4
    immediate: int | None = None

    @property
    def is_branch(self) -> bool:
        return self.category in (Aarch64Category.BRANCH, Aarch64Category.CALL)

    @property
    def is_call(self) -> bool:
        return self.category == Aarch64Category.CALL

    @property
    def is_memory_access(self) -> bool:
        return self.category in (Aarch64Category.MEM_LOAD, Aarch64Category.MEM_STORE)

    @property
    def is_prologue(self) -> bool:
        return self.category == Aarch64Category.PROLOGUE

    @property
    def is_epilogue(self) -> bool:
        return self.category == Aarch64Category.EPILOGUE


def _sign_extend(val: int, bits: int) -> int:
    sign_bit = 1 << (bits - 1)
    return (val & (sign_bit - 1)) - (val & sign_bit)


def decode_aarch64(word: int, rva: int = 0) -> Aarch64Insn:
    """Decodes a single 32-bit AArch64 instruction word at a given RVA."""
    w = word & 0xFFFFFFFF

    # 1. PAC Instructions (PACIASP, PACIBSP, AUTIASP, AUTIBSP)
    if w == 0xD503233F:
        return Aarch64Insn(rva, w, Aarch64Category.PROLOGUE, "paciasp")
    if w == 0xD503237F:
        return Aarch64Insn(rva, w, Aarch64Category.PROLOGUE, "pacibsp")
    if w == 0xD50323BF:
        return Aarch64Insn(rva, w, Aarch64Category.EPILOGUE, "autiasp")
    if w == 0xD50323FF:
        return Aarch64Insn(rva, w, Aarch64Category.EPILOGUE, "autibsp")

    # 2. Return (RET)
    if (w & 0xFFFFFC1F) == 0xD65F0000:
        rn = (w >> 5) & 0x1F
        reg = "x30" if rn == 30 else f"x{rn}"
        ops = "" if rn == 30 else reg
        return Aarch64Insn(rva, w, Aarch64Category.EPILOGUE, "ret", ops)

    # 3. Unconditional Branch / Branch with Link (B, BL)
    # B:  0x14000000 (mask 0xFC000000)
    # BL: 0x94000000 (mask 0xFC000000)
    if (w & 0xFC000000) == 0x14000000:
        imm26 = _sign_extend(w & 0x03FFFFFF, 26)
        target = rva + (imm26 << 2)
        return Aarch64Insn(rva, w, Aarch64Category.BRANCH, "b", f"0x{target:x}", target_rva=target)
    if (w & 0xFC000000) == 0x94000000:
        imm26 = _sign_extend(w & 0x03FFFFFF, 26)
        target = rva + (imm26 << 2)
        return Aarch64Insn(rva, w, Aarch64Category.CALL, "bl", f"0x{target:x}", target_rva=target)

    # 4. Conditional Branch (B.cond)
    # 0x54000000 (mask 0xFF000010 == 0x54000000)
    if (w & 0xFF000010) == 0x54000000:
        cond_idx = w & 0x0F
        cond = AARCH64_COND_NAMES[cond_idx]
        imm19 = _sign_extend((w >> 5) & 0x7FFFF, 19)
        target = rva + (imm19 << 2)
        return Aarch64Insn(rva, w, Aarch64Category.BRANCH, f"b.{cond}", f"0x{target:x}", target_rva=target)

    # 5. Compare & Branch (CBZ, CBNZ)
    # mask 0x7E000000 in [0x34000000, 0x35000000]
    if (w & 0x7E000000) in (0x34000000, 0x35000000):
        is_cbnz = bool(w & 0x01000000)
        sf = bool(w & 0x80000000)
        rt = w & 0x1F
        reg = f"x{rt}" if sf else f"w{rt}"
        imm19 = _sign_extend((w >> 5) & 0x7FFFF, 19)
        target = rva + (imm19 << 2)
        mnem = "cbnz" if is_cbnz else "cbz"
        return Aarch64Insn(rva, w, Aarch64Category.BRANCH, mnem, f"{reg}, 0x{target:x}", target_rva=target)

    # 6. Test & Branch (TBZ, TBNZ)
    # mask 0x7E000000 in [0x36000000, 0x37000000]
    if (w & 0x7E000000) in (0x36000000, 0x37000000):
        is_tbnz = bool(w & 0x01000000)
        b40 = (w >> 19) & 0x1F
        b5 = ((w >> 31) & 1) << 5
        bit_idx = b5 | b40
        rt = w & 0x1F
        reg = f"x{rt}" if (w & 0x80000000) else f"w{rt}"
        imm14 = _sign_extend((w >> 5) & 0x3FFF, 14)
        target = rva + (imm14 << 2)
        mnem = "tbnz" if is_tbnz else "tbz"
        return Aarch64Insn(rva, w, Aarch64Category.BRANCH, mnem, f"{reg}, #{bit_idx}, 0x{target:x}", target_rva=target)

    # 7. Indirect Branch / Register Call (BR, BLR)
    if (w & 0xFFFFFC1F) == 0xD61F0000:
        rn = (w >> 5) & 0x1F
        return Aarch64Insn(rva, w, Aarch64Category.BRANCH, "br", f"x{rn}")
    if (w & 0xFFFFFC1F) == 0xD63F0000:
        rn = (w >> 5) & 0x1F
        return Aarch64Insn(rva, w, Aarch64Category.CALL, "blr", f"x{rn}")

    # 8. PC-Relative Addressing: ADR / ADRP
    # ADR:  (w & 0x9F000000) == 0x10000000
    # ADRP: (w & 0x9F000000) == 0x90000000
    if (w & 0x9F000000) == 0x10000000:
        rd = w & 0x1F
        immlo = (w >> 29) & 3
        immhi = (w >> 5) & 0x7FFFF
        imm21 = _sign_extend((immhi << 2) | immlo, 21)
        target = rva + imm21
        return Aarch64Insn(rva, w, Aarch64Category.ALU_IMM, "adr", f"x{rd}, 0x{target:x}", target_rva=target)
    if (w & 0x9F000000) == 0x90000000:
        rd = w & 0x1F
        immlo = (w >> 29) & 3
        immhi = (w >> 5) & 0x7FFFF
        imm21 = _sign_extend((immhi << 2) | immlo, 21)
        target_page = ((rva >> 12) << 12) + (imm21 << 12)
        return Aarch64Insn(rva, w, Aarch64Category.ALU_IMM, "adrp", f"x{rd}, 0x{target_page:x}", target_rva=target_page)

    # 9. Load/Store Pair (LDP / STP)
    # mask 0x7E400000 == 0x28000000 (pre/post-index or signed offset)
    if (w & 0x7E400000) == 0x28000000:
        opc = (w >> 30) & 3
        l_bit = bool(w & 0x00400000)
        rt = w & 0x1F
        rn = (w >> 5) & 0x1F
        rt2 = (w >> 10) & 0x1F
        imm7 = _sign_extend((w >> 15) & 0x7F, 7)
        scale = 3 if opc == 2 else 2
        offset = imm7 << scale
        size = 8 if opc == 2 else 4
        rn_str = "sp" if rn == 31 else f"x{rn}"
        reg_type = "x" if opc == 2 else "w"
        r1_str = f"{reg_type}{rt}"
        r2_str = f"{reg_type}{rt2}"

        is_write = not l_bit
        # Detect frame setup: STP x29, x30, [sp, #-imm]! or STP x29, x30, [sp, #imm]
        is_pre_index = bool((w >> 23) & 1) and bool((w >> 24) & 1)
        category = Aarch64Category.MEM_STORE if is_write else Aarch64Category.MEM_LOAD
        if is_write and rn == 31 and rt == 29 and rt2 == 30:
            category = Aarch64Category.PROLOGUE
        elif not is_write and rn == 31 and rt == 29 and rt2 == 30:
            category = Aarch64Category.EPILOGUE

        mnem = "ldp" if l_bit else "stp"
        ops = f"{r1_str}, {r2_str}, [{rn_str}, #{offset}]"
        return Aarch64Insn(
            rva, w, category, mnem, ops,
            mem_base_reg=rn_str, mem_offset=offset, mem_is_write=is_write, mem_size=size * 2
        )

    # 10. Load/Store Register (unsigned immediate)
    # mask 0x3B000000 == 0x39000000
    if (w & 0x3B000000) == 0x39000000:
        size_bits = (w >> 30) & 3
        v_bit = bool(w & 0x04000000)
        opc = (w >> 22) & 3
        rn = (w >> 5) & 0x1F
        rt = w & 0x1F
        imm12 = (w >> 10) & 0xFFF
        scale = size_bits
        offset = imm12 << scale
        is_load = bool(opc & 1)
        rn_str = "sp" if rn == 31 else f"x{rn}"

        if not v_bit:
            # GPR loads/stores
            if size_bits == 0:
                mnem = "ldrb" if is_load else "strb"
                reg_name = f"w{rt}"
                sz = 1
            elif size_bits == 1:
                mnem = "ldrh" if is_load else "strh"
                reg_name = f"w{rt}"
                sz = 2
            elif size_bits == 2:
                mnem = "ldr" if is_load else "str"
                reg_name = f"w{rt}"
                sz = 4
            else:
                mnem = "ldr" if is_load else "str"
                reg_name = f"x{rt}"
                sz = 8
        else:
            mnem = "ldr" if is_load else "str"
            reg_name = f"v{rt}"
            sz = 1 << size_bits

        category = Aarch64Category.MEM_LOAD if is_load else Aarch64Category.MEM_STORE
        ops = f"{reg_name}, [{rn_str}, #{offset}]"
        return Aarch64Insn(
            rva, w, category, mnem, ops,
            mem_base_reg=rn_str, mem_offset=offset, mem_is_write=not is_load, mem_size=sz
        )

    # 11. Move Wide Immediate: MOVZ, MOVN, MOVK
    # MOVZ: (w & 0x1F800000) == 0x52800000
    # MOVN: (w & 0x1F800000) == 0x12800000
    # MOVK: (w & 0x1F800000) == 0x72800000
    if (w & 0x1F800000) in (0x52800000, 0x12800000, 0x72800000):
        sf = bool(w & 0x80000000)
        opc = (w >> 29) & 3
        hw = (w >> 21) & 3
        imm16 = (w >> 5) & 0xFFFF
        rt = w & 0x1F
        reg = f"x{rt}" if sf else f"w{rt}"
        shift = hw * 16
        imm_val = imm16 << shift

        if opc == 0:  # MOVN
            mnem = "movn"
            imm_val = (~imm_val) & (0xFFFFFFFFFFFFFFFF if sf else 0xFFFFFFFF)
        elif opc == 2:  # MOVZ
            mnem = "movz"
        else:  # MOVK
            mnem = "movk"

        ops = f"{reg}, #{hex(imm16)}" + (f", lsl #{shift}" if shift else "")
        return Aarch64Insn(rva, w, Aarch64Category.ALU_IMM, mnem, ops, immediate=imm_val)

    # 12. Add/Subtract (immediate)
    # ADD: (w & 0x1F000000) == 0x11000000
    # SUB: (w & 0x1F000000) == 0x51000000
    # SUBS/CMP: (w & 0x1F000000) == 0x71000000
    if (w & 0x1F000000) in (0x11000000, 0x51000000, 0x71000000):
        sf = bool(w & 0x80000000)
        op_type = (w >> 29) & 3
        sh = bool(w & 0x00400000)
        imm12 = (w >> 10) & 0xFFF
        val = imm12 << 12 if sh else imm12
        rn = (w >> 5) & 0x1F
        rd = w & 0x1F
        rn_str = "sp" if rn == 31 else (f"x{rn}" if sf else f"w{rn}")
        rd_str = "sp" if rd == 31 else (f"x{rd}" if sf else f"w{rd}")

        if op_type == 0:
            mnem = "add"
            category = Aarch64Category.ALU_IMM
        elif op_type == 2:
            mnem = "sub"
            # SUB sp, sp, #imm is a prologue pattern
            category = Aarch64Category.PROLOGUE if (rd == 31 and rn == 31) else Aarch64Category.ALU_IMM
        else:
            mnem = "cmp" if rd == 31 else "subs"
            category = Aarch64Category.ALU_IMM

        ops = f"{rd_str}, {rn_str}, #{hex(imm12)}" if mnem != "cmp" else f"{rn_str}, #{hex(imm12)}"
        return Aarch64Insn(rva, w, category, mnem, ops, immediate=val)

    return Aarch64Insn(rva, w, Aarch64Category.OTHER, "unknown", f"0x{w:08x}")


def iter_decode_aarch64(data: bytes, base_rva: int = 0) -> Iterator[Aarch64Insn]:
    """Iterates through 32-bit aligned ARM64 instruction words in a buffer."""
    for off in range(0, len(data) - 3, 4):
        w = struct.unpack_from("<I", data, off)[0]
        yield decode_aarch64(w, base_rva + off)


def resolve_branch_target(rva: int, word: int) -> int | None:
    """Resolves branch or call target for B, BL, B.cond, CBZ, CBNZ, TBZ, TBNZ, ADR, ADRP."""
    insn = decode_aarch64(word, rva)
    return insn.target_rva


def resolve_adrp_pair(
    rva_adrp: int,
    word_adrp: int,
    rva_add_or_ldr: int,
    word_add_or_ldr: int,
    is_ldr: bool = False,
) -> int | None:
    """Computes the 64-bit target address formed by an ADRP + ADD or ADRP + LDR pair.

    Example:
        adrp x8, 0x1692000
        add  x8, x8, #0x310  -> 0x01692310
    """
    insn_adrp = decode_aarch64(word_adrp, rva_adrp)
    if insn_adrp.mnemonic != "adrp" or insn_adrp.target_rva is None:
        return None

    page = insn_adrp.target_rva
    insn_add = decode_aarch64(word_add_or_ldr, rva_add_or_ldr)

    if insn_add.mnemonic == "add" and insn_add.immediate is not None:
        return page + insn_add.immediate
    elif insn_add.mnemonic in ("ldr", "ldrb", "ldrh") and insn_add.mem_offset is not None:
        return page + insn_add.mem_offset

    # Fallback raw imm12 decode for add
    w = word_add_or_ldr & 0xFFFFFFFF
    if (w & 0x1F000000) == 0x11000000:
        imm12 = (w >> 10) & 0xFFF
        return page + imm12
    return None


def scan_prologue_backward(
    data: bytes,
    target_rva: int,
    base_rva: int = 0,
    max_bytes: int = 4096,
) -> int | None:
    """Sweeps backward from target_rva up to max_bytes to locate the nearest function prologue.

    Detects:
      - STP x29, x30, [sp, #-imm]!
      - SUB sp, sp, #imm followed by STP x29, x30
      - PACIASP / PACIBSP
    Stops early if a function return (RET) or unconditional jump is encountered prior to candidate prologue.
    """
    target_off = target_rva - base_rva
    if target_off < 0 or len(data) < 4:
        return None

    aligned_off = (min(target_off, len(data) - 4) >> 2) << 2
    start_off = max(0, aligned_off - max_bytes)
    step = 4

    # Sweep backward in 4-byte steps
    candidate_prologue: int | None = None
    for cur_off in range(aligned_off, start_off - 4, -step):
        if cur_off < 0 or cur_off + 4 > len(data):
            continue
        w = struct.unpack_from("<I", data, cur_off)[0]
        cur_rva = base_rva + cur_off
        insn = decode_aarch64(w, cur_rva)

        if insn.is_prologue:
            candidate_prologue = cur_rva
            # If preceded by ret or unconditional branch, this is definitely a boundary
            if cur_off >= 4:
                prev_w = struct.unpack_from("<I", data, cur_off - 4)[0]
                prev_insn = decode_aarch64(prev_w, cur_rva - 4)
                if prev_insn.is_epilogue or prev_insn.mnemonic == "b":
                    return cur_rva

        # If we hit an epilogue between target and start, stop
        if insn.is_epilogue and cur_off < aligned_off:
            if candidate_prologue is not None and candidate_prologue > cur_rva:
                return candidate_prologue
            break

    return candidate_prologue


def disasm_insn_fast(word: int, rva: int = 0) -> str:
    """Disassembles a single word into a clean GNU/LLVM-style disassembly string."""
    insn = decode_aarch64(word, rva)
    if insn.operands:
        return f"{insn.mnemonic:<8} {insn.operands}"
    return insn.mnemonic


def disasm_range_fast(data: bytes, start_rva: int, end_rva: int) -> List[str]:
    """Fast in-memory disassembly of an RVA range in pure Python."""
    lines: List[str] = []
    end = min(len(data), end_rva)
    for off in range(start_rva, end, 4):
        if off + 4 > len(data):
            break
        w = struct.unpack_from("<I", data, off)[0]
        dis = disasm_insn_fast(w, off)
        lines.append(f"0x{off:08x}: {w:08x}  {dis}")
    return lines


def resolve_arm64_xref_at(
    text_bytes: bytes,
    text_base_rva: int,
    insn_rva: int,
    vtable_resolver=None,
    vaddr_to_file_offset=None,
    lookahead_insns: int = 8,
) -> dict:
    """Resolves B, BL, B.cond, CBZ/CBNZ, TBZ/TBNZ, ADR, and ADRP + (ADD|LDR) pairs at insn_rva."""
    rel = insn_rva - text_base_rva
    if rel < 0 or rel + 4 > len(text_bytes):
        return {"rva": hex(insn_rva), "error": "insn_rva out of text bounds"}

    w = struct.unpack_from("<I", text_bytes, rel)[0]

    # 1. Unconditional B / BL (imm26)
    if (w & 0x7C000000) == 0x14000000:
        is_bl = bool(w & 0x80000000)
        imm26 = w & 0x03FFFFFF
        if imm26 & (1 << 25):
            imm26 -= (1 << 26)
        target = insn_rva + (imm26 << 2)
        return {"rva": hex(insn_rva), "mnemonic": "bl" if is_bl else "b", "target_rva": hex(target)}

    # 2. Conditional B.cond (imm19)
    if (w & 0xFF000010) == 0x54000000:
        cond_idx = w & 0xF
        cond_name = AARCH64_COND_NAMES[cond_idx] if cond_idx < len(AARCH64_COND_NAMES) else f"cond{cond_idx}"
        imm19 = (w >> 5) & 0x7FFFF
        if imm19 & (1 << 18):
            imm19 -= (1 << 19)
        target = insn_rva + (imm19 << 2)
        return {"rva": hex(insn_rva), "mnemonic": f"b.{cond_name}", "target_rva": hex(target)}

    # 3. CBZ / CBNZ (imm19)
    if (w & 0x7E000000) == 0x34000000:
        is_cbnz = bool(w & 0x01000000)
        rt = w & 0x1F
        imm19 = (w >> 5) & 0x7FFFF
        if imm19 & (1 << 18):
            imm19 -= (1 << 19)
        target = insn_rva + (imm19 << 2)
        return {
            "rva": hex(insn_rva),
            "mnemonic": "cbnz" if is_cbnz else "cbz",
            "reg": f"x{rt}",
            "target_rva": hex(target),
        }

    # 4. TBZ / TBNZ (imm14)
    if (w & 0x7E000000) == 0x36000000:
        is_tbnz = bool(w & 0x01000000)
        rt = w & 0x1F
        imm14 = (w >> 5) & 0x3FFF
        if imm14 & (1 << 13):
            imm14 -= (1 << 14)
        target = insn_rva + (imm14 << 2)
        return {
            "rva": hex(insn_rva),
            "mnemonic": "tbnz" if is_tbnz else "tbz",
            "reg": f"x{rt}",
            "target_rva": hex(target),
        }

    # 5. ADR (imm21)
    if (w & 0x9F000000) == 0x10000000:
        rd = w & 0x1F
        immlo = (w >> 29) & 0x3
        immhi = (w >> 5) & 0x7FFFF
        imm21 = (immhi << 2) | immlo
        if imm21 & (1 << 20):
            imm21 -= (1 << 21)
        target = insn_rva + imm21
        return {"rva": hex(insn_rva), "mnemonic": "adr", "dest_reg": f"x{rd}", "target_rva": hex(target)}

    # 6. ADRP Xd, #page (bit[31]=1, bits[28:24]=10000)
    if (w & 0x9F000000) == 0x90000000:
        rd = w & 0x1F
        immlo = (w >> 29) & 0x3
        immhi = (w >> 5) & 0x7FFFF
        imm21 = (immhi << 2) | immlo
        if imm21 & (1 << 20):
            imm21 -= (1 << 21)
        page_base = (insn_rva & ~0xFFF) + (imm21 << 12)

        consumers = []
        for step in range(1, lookahead_insns + 1):
            cur_rel = rel + step * 4
            if cur_rel + 4 > len(text_bytes):
                break
            cw = struct.unpack_from("<I", text_bytes, cur_rel)[0]
            cur_rva = insn_rva + step * 4
            rn = (cw >> 5) & 0x1F
            crd = cw & 0x1F

            # ADD Xd, Xn, #imm12
            if rn == rd and (cw & 0xFF800000) == 0x91000000:
                sh = (cw >> 22) & 0x1
                imm12 = ((cw >> 10) & 0xFFF) << (12 if sh else 0)
                resolved_addr = page_base + imm12
                consumers.append({
                    "consumer_rva": hex(cur_rva),
                    "type": "ADRP+ADD",
                    "dest_reg": f"x{crd}",
                    "computed_rva": hex(resolved_addr),
                })

            # LDR Xt, [Xn, #imm12] (64-bit unsigned offset: 0xF9400000)
            elif rn == rd and (cw & 0xFFC00000) == 0xF9400000:
                imm12 = ((cw >> 10) & 0xFFF) << 3
                ptr_addr = page_base + imm12
                deref_target = None
                deref_src = None
                if vtable_resolver is not None:
                    foff = vaddr_to_file_offset(ptr_addr) if vaddr_to_file_offset else None
                    deref_target, deref_src = vtable_resolver.resolve_pointer_at(ptr_addr, foff)
                consumers.append({
                    "consumer_rva": hex(cur_rva),
                    "type": "ADRP+LDR",
                    "dest_reg": f"x{crd}",
                    "pointer_slot_rva": hex(ptr_addr),
                    "dereferenced_target_rva": hex(deref_target) if deref_target else None,
                    "deref_source": deref_src,
                })

            # Stop tracking if base register rd is clobbered by an unrelated instruction
            if crd == rd and not consumers:
                break

        return {
            "rva": hex(insn_rva),
            "mnemonic": "adrp",
            "base_reg": f"x{rd}",
            "page_base_rva": hex(page_base),
            "paired_consumers": consumers,
        }

    return {"rva": hex(insn_rva), "word_hex": f"0x{w:08x}", "note": "Not a direct branch or ADRP instruction"}


def disassemble_batch(
    text_bytes: bytes | None = None,
    text_base_rva: int = 0,
    addresses: List[int] | None = None,
    raw_words: List[int] | None = None,
    count: int | None = None,
) -> List[dict]:
    """Batch disassembly of addresses, ranges, or raw instruction words in pure Python."""
    results: List[dict] = []

    if raw_words is not None:
        for idx, w in enumerate(raw_words):
            rva = text_base_rva + idx * 4
            insn = decode_aarch64(w, rva)
            dis = disasm_insn_fast(w, rva)
            results.append({
                "rva": hex(rva),
                "word_hex": f"0x{w:08x}",
                "mnemonic": insn.mnemonic,
                "operands": insn.operands,
                "disasm": dis,
            })
        return results

    if text_bytes is None:
        return results

    if addresses is not None:
        for addr in addresses:
            rel = addr - text_base_rva
            if 0 <= rel and rel + 4 <= len(text_bytes):
                w = struct.unpack_from("<I", text_bytes, rel)[0]
                insn = decode_aarch64(w, addr)
                dis = disasm_insn_fast(w, addr)
                results.append({
                    "rva": hex(addr),
                    "word_hex": f"0x{w:08x}",
                    "mnemonic": insn.mnemonic,
                    "operands": insn.operands,
                    "disasm": dis,
                })
            else:
                results.append({
                    "rva": hex(addr),
                    "error": "Address out of bounds",
                })
        return results

    # Disassemble sequential count instructions from text_base_rva
    n = count if count is not None else len(text_bytes) // 4
    for i in range(min(n, len(text_bytes) // 4)):
        off = i * 4
        w = struct.unpack_from("<I", text_bytes, off)[0]
        rva = text_base_rva + off
        insn = decode_aarch64(w, rva)
        dis = disasm_insn_fast(w, rva)
        results.append({
            "rva": hex(rva),
            "word_hex": f"0x{w:08x}",
            "mnemonic": insn.mnemonic,
            "operands": insn.operands,
            "disasm": dis,
        })

    return results

