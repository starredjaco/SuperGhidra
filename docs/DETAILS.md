# SuperGhidra: Details

Deep-dive material moved out of the main [README](../README.md) to keep it short. Nothing here was removed from the project docs; it is the same text as before, regrouped.

## Contents

- [Choose Your Operating Mode](#choose-your-operating-mode-first)
- [How SuperGhidra Compares](#how-superghidra-compares-to-stock-headless--existing-ghidra-mcp-bridges)
- [Architecture & Zero Lock Contention](#architecture--zero-lock-contention)
- [5-Minute End-to-End Quickstart](#5-minute-end-to-end-quickstart)
- [Agent & MCP Configuration](#agent--mcp-configuration-claude-desktop-cursor-antigravity)
- [Subsystem Capabilities](#subsystem-capabilities--hardware-matrix)
- [Real-World Benchmark Methodology](#real-world-benchmark-methodology)
- [Synthetic Benchmarks](#synthetic-benchmarks)
- [Installation, CLI & Configuration](#installation-cli--configuration)
- [Troubleshooting](#troubleshooting--common-gotchas)
- [Repository Layout](#repository-layout)


## Choose Your Operating Mode First

SuperGhidra spans four distinct execution paths. Pick the entry point that matches your task before running commands:

| What You Want to Do | Entry Point / Command | Requires Ghidra + JVM? | Writes to `.rep` Directly? |
| :--- | :--- | :---: | :---: |
| **Decompile real functions, query xrefs, or rename symbols** | `python -m superghidra.core.ghidra_oracle <subcommand>` | **Yes** (Ghidra 11/12 + OpenJDK 21 + PyGhidra) | **No** (writes go to JSON overlay / fork journal) |
| **Recover MSVC RTTI, MFC `CRuntimeClass`, `Serialize()`, or PE/ELF/Mach-O headers** | `python -m superghidra.formats.msvc_class_recovery <binary>` or `superghidra rtti-recover <binary> -o classes.json` | **No** (standalone Python) | **No** (exports JSON, DWARF 5, Breakpad, or `.map`) |
| **Audit compiled Rust crates (.dep-v0) or Go dependencies (.go.buildinfo / pclntab)** | `superghidra crate-audit <binary> -o audit.json` | **No** (standalone Python) | **No** (exports JSON report) |
| **Recover Unity IL2CPP assemblies, types, methods, and string pools** | `superghidra il2cpp-recover <metadata> [--binary <bin>] -o il2cpp.json` | **No** (standalone Python) | **No** (exports JSON report) |
| **Formally prove ARM64 switch jump tables with Z3 SMT solver** | `from superghidra.acceleration import ARM64JumpTableProver` | **No** (requires `[smt]`) | **No** (in-memory extraction / JSON) |
| **Connect Claude Desktop, Cursor, or Antigravity to an open target** | MCP Server (`superghidra-mcp` via [SuperghidraMCP](https://github.com/yuatemycat/SuperGhidraMCP)) | **Yes** (connects to running daemon) | **No** (commits gated by validation + overlay sync) |
| **Run GPU/SIMD ARM64 scans, LZ4/Zstd buffer compression, or Z3 P-code checks** | Python API / standalone modules (or MCP tools) | **No** (standalone Python / NumPy / WGPU / Z3) | **No** |

> [!WARNING]
> **The `superghidra decompile` CLI Subcommand is an Experimental Prototype**
>
> Do **not** use `superghidra decompile` to decompile production binaries. The standalone `superghidra decompile` CLI subcommand invokes an experimental research prototype: on real Windows binaries, only 11 of 154 exports across four test DLLs decompile, and only 7 of those compile cleanly. It uses a zero-JVM P-code lifter supporting basic integer register operations, function prologues, direct calls, and preliminary ARM64 lowering (any unhandled opcode or complex control flow exits non-zero). It will exit non-zero or return incomplete output on real functions containing complex branches, floats, or unhandled instructions.
>
> **To decompile real functions from a Ghidra project, use the Ghidra-backed oracle:**
> ```bash
> python -m superghidra.core.ghidra_oracle decompile <addr>
> ```

## How SuperGhidra Compares to Stock Headless & Existing Ghidra MCP Bridges

Most Ghidra automation scripts and MCP servers either pay a 5–15 second JVM cold-start penalty per invocation or bind directly to a single mutable GUI session where concurrent agent edits can corrupt the `.rep` database or trigger `LockException`. **[SuperGhidra](https://github.com/yuatemycat/SuperGhidra)** separates read-only oracle queries (`127.0.0.1:5073`) from non-destructive overlay writes (`ghidra_overlay.json`), while executing bulk binary sweeps and C++/MFC recovery in pure Python, NumPy SIMD, and WGPU without touching the JVM.

| Capability / Architecture | Stock Ghidra Headless | [LaurieWired/GhidraMCP](https://github.com/lauriewired/ghidramcp) | [bethington/ghidra-mcp](https://github.com/bethington/ghidra-mcp) / [GhydraMCP](https://github.com/starsong-consulting/GhydraMCP) | [SuperGhidra](https://github.com/yuatemycat/SuperGhidra) + [SuperGhidraMCP](https://github.com/yuatemycat/SuperGhidraMCP) |
| :--- | :--- | :--- | :--- | :--- |
| **JVM Startup Overhead** | 5–15 s per script run | None (requires open GUI) | None (requires open GUI/plugin) | **0 ms** after initial daemon boot (`127.0.0.1:5073`) |
| **Concurrent GUI + Multi-Agent Access** | Blocked by `.rep` project lock | Single mutable GUI state | Single/HTTP bridged GUI state | **Lock-free `readOnly=True` daemon + isolated session forks** |
| **Mutation Safety & Conflict Resolution** | Direct `.rep` writes | Direct in-place renames | Direct in-place tool mutations | **Non-destructive `ghidra_overlay.json` + `merge_fork` conflict detection** |
| **Semantic Verification Gate** | None | None | None | **Z3 P-code equivalence prover + Obligation Ledger Gate** (vtable/offset checks) |
| **Query & IPC Latency** | Seconds per batch | HTTP / Socket bridge | HTTP / REST bridge | **< 50 µs** L1 SHM ring buffer & **< 0.01 ms** L2 SQLite cache |
| **Compilable C Post-Processing** | Raw Ghidra pseudo-C (`8.23%` pass) | Raw Ghidra pseudo-C | Raw Ghidra pseudo-C | **`compilable_filter.py` rewriter (`22.62%` pass across 1,300 functions, `25.26%` on held-out test split)** |
| **Zero-JVM Binary & C++ Recovery** | None (JVM required) | None (JVM required) | None (JVM required) | **Pure-Python PE/ELF/Mach-O loader, MSVC RTTI, MFC `CRuntimeClass` & `Serialize()`** |
| **Hardware-Accelerated Sweeps** | Single-threaded Java | None | None | **143.95 M insn/s NumPy SIMD & 127.25 M insn/s WGPU ARM64 `ADRP` scanners** |
| **Database Compression** | Standard `.rep` 16 KB pages | Standard `.rep` | Standard `.rep` | **LZ4 (`442.9 MB/s`, 79.3% savings) & Zstd (`206.5 MB/s`, 86.5% savings) BufferFile codecs** |

## Architecture & Zero Lock Contention

Ghidra locks `.rep` projects exclusively, meaning standard headless scripts fail whenever the project is open in the Ghidra GUI. SuperGhidra avoids lock contention by separating **reads** (served from a warm daemon or read-only session) from **writes** (recorded in a JSON overlay and transaction journal):

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/architecture-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset="assets/architecture-light.svg">
    <img alt="SuperGhidra Architecture &amp; Zero Lock Contention" src="assets/architecture-light.svg" width="100%">
  </picture>
</p>

## 5-Minute End-to-End Quickstart

> [!TIP]
> **2-Minute End-to-End Walkthrough:** Follow [`docs/WALKTHROUGH_MSVC_MFC_RECOVERY.md`](WALKTHROUGH_MSVC_MFC_RECOVERY.md) for a step-by-step example recovering MSVC RTTI and MFC `Serialize()` archive layouts, validating candidate renames through `ReconstructionObligationLedger`, and syncing them live into an open Ghidra CodeBrowser window (`superghidra overlay-sync --watch`).

### Workflow A: Standalone C++ / MSVC / MFC Class Recovery (No Ghidra Required)

Recover MSVC RTTI hierarchies, MFC `CRuntimeClass` descriptors, and virtual function tables directly from raw PE binaries without requiring Ghidra or a JVM:

```bash
# Direct module execution
python -m superghidra.formats.msvc_class_recovery target.dll

# Or recover classes and export to JSON via unified CLI
superghidra rtti-recover target.dll -o classes.json

# Trace MFC Serialize() archive field layouts
python -m superghidra.formats.serialize_trace target.dll CMyDoc
```

### Workflow B: Ghidra Daemon + Oracle Decompilation + GUI Sync

#### 1. Set Environment Variables
Point SuperGhidra to NSA Ghidra (11.x or 12.x) and OpenJDK 21:

```bash
# Linux / macOS
export GHIDRA_INSTALL_DIR="/opt/ghidra"
export JAVA_HOME="/usr/lib/jvm/java-21-openjdk"

# Windows (PowerShell)
$env:GHIDRA_INSTALL_DIR = "C:\tools\ghidra"
$env:JAVA_HOME = "C:\Program Files\Eclipse Adoptium\jdk-21"
```

#### 2. Launch or Query the Persistent Daemon
Verify the daemon status or launch it with project coordinates:

```bash
# Check daemon status (auto-reports uptime, cache hit rate, and loaded binary)
python -m superghidra.core.ghidra_oracle status

# Run daemon with explicit project paths
python -m superghidra.core.ghidra_oracle --project-dir ~/re/proj --project-name game --program-name libgame.so status

# Or launch as a dedicated background server on port 5073
python -m superghidra.core.ghidra_oracle serve --project-dir ~/re/proj --project-name game --program-name libgame.so --mode balanced
```

You can also define candidate projects globally via `SUPERGHIDRA_PROJECTS="dir,name[,program]"`.

#### 3. Decompile and Propose Renames
Subsequent queries execute in `< 0.01 ms` when served from the SQLite L2 cache:

```bash
# Decompile target function by virtual address
python -m superghidra.core.ghidra_oracle decompile 0x140001000

# Propose function rename (committed safely to the JSON write overlay)
python -m superghidra.core.ghidra_oracle rename 0x140001000 ProcessPacketHeader

# Add an address comment
python -m superghidra.core.ghidra_oracle comment 0x140001000 "Validated packet parser entry point"
```

#### 4. Sync Overlay Back to Ghidra GUI
Mutations are recorded in `ghidra_overlay.json` to prevent `.rep` lock collisions. Sync them back into the Ghidra GUI session:

* **Option 1 — Live Ghidra GUI Sync (`ghidra_gui_overlay_sync.py`):**
  1. Generate a one-shot sync script or a live background watcher (`--watch`):
     ```bash
     # One-shot atomic transaction script
     superghidra overlay-sync --overlay ghidra_overlay.json --out ghidra_gui_overlay_sync.py

     # Or generate a continuous background watcher script (polls every 1000 ms)
     superghidra overlay-sync --overlay ghidra_overlay.json --watch --poll-ms 1000 --out ghidra_gui_overlay_sync.py
     ```
  2. In Ghidra's CodeBrowser, navigate to **Window → Script Manager**.
  3. Add the output directory to Script Paths and run `ghidra_gui_overlay_sync.py`. All renames, comments, and type definitions apply atomically inside your active GUI session.

* **Option 2 — Headless Journal Replay & Auto-Discard (`merge_fork`):**
  Close the project in the Ghidra GUI to release the `.rep` lock, then replay the journal or merge session forks using `merge_fork(fork_id, auto_discard=True)`.
  When `auto_discard=True`, once all operations merge cleanly with zero pending conflicts (`pending_ops == 0`), SuperGhidra automatically deletes the fork's isolated directory and transaction journal to reclaim disk storage. Unneeded or stale forks can also be deleted directly via `discard_fork(fork_id)`.

### Workflow C: Standalone Rust & Go Binary Auditing (No Ghidra Required)

Audit compiled binaries to recover dependency trees, toolchain metadata, and runtime symbols across ELF, PE, and Mach-O:

```bash
# Audit compiled Rust crate dependencies (.dep-v0) or Go modules (.go.buildinfo / pclntab)
superghidra crate-audit target.bin -o crate_audit.json
```

- **Rust:** Extracts cargo-auditable `.dep-v0` JSON payloads (crate names, versions, enabled features) and matches `/rustc/<hash>/` toolchain commit signatures.
- **Go:** Locates `\xff Go buildinf:` headers and versioned `pclntab` tables to recover Go compiler version, main module path, dependency replacements, VCS revision info, and function descriptors.

### Workflow D: Unity IL2CPP Metadata Recovery (No Ghidra Required)

Extract structural metadata from Unity games and applications without running Ghidra:

```bash
# Parse global-metadata.dat
superghidra il2cpp-recover global-metadata.dat -o unity_metadata.json

# Correlate metadata method definitions with native binary RVAs
superghidra il2cpp-recover global-metadata.dat --binary libil2cpp.so -o unity_metadata.json
```

- Recovers assemblies, namespaces, type definitions, method signatures, field offsets, and string literal pools across metadata versions 24, 27, 29, 31, and 39.
- *Test status:* Tested on synthetic fixtures and Android packages; untested on public Unity iOS builds due to the absence of legal public Unity iOS sample binaries.

### Workflow E: Z3-Proven ARM64 Jump Table Recovery

Disassemble and formally prove switch dispatch tables and case bounds in ARM64 binaries:

```python
from superghidra.acceleration import ARM64JumpTableProver

prover = ARM64JumpTableProver()
candidates = prover.scan_candidates(code_bytes, base_va=0x1000)
for cand in candidates:
    recovered = prover.recover_jump_table(cand, memory_data=image_bytes, memory_base_va=0x1000)
    if recovered.proven:
        print(f"Proven switch at {recovered.base_pc:#x}: {recovered.bounds_n} cases -> {recovered.targets}")
```

- Discovers table patterns (`CMP`, `B.cond`, `ADR`/`ADRP+ADD`, `LDRSW`/`LDRB`/`LDRH`/`LDR`, `BR indirect`).
- Lowered byte-offset tables (shift 0 from LLVM/Swift/Chromium) and word-offset tables (shift 2 from Apple Clang) resolve exact case counts N and target mappings.
- **Requires `pip install "superghidra[smt]"`:** If `z3-solver` is absent, candidate patterns are detected but cannot be formally proven, issuing a warning.


## Agent & MCP Configuration (Claude Desktop, Cursor, Antigravity)

SuperGhidra exposes 56 registered reverse-engineering tools (61 defined in SuperghidraMCP) via the Model Context Protocol (MCP) using [SuperghidraMCP](https://github.com/yuatemycat/SuperGhidraMCP) (including `recover_cpp_classes`, `trace_serialize`, `diff_binaries`, `verify_smt_equivalence`, and `gpu_adrp_scan`). This enables AI coding agents to inspect binaries, query call graphs, and propose validated renames autonomously.

Install the MCP server from source:

```bash
pip install superghidra-mcp
```

### Claude Desktop (`claude_desktop_config.json`)

```json
{
  "mcpServers": {
    "superghidra": {
      "command": "superghidra-mcp",
      "args": [
        "-t",
        "stdio",
        "--project-path",
        "<path_to_gpr_or_binary>"
      ],
      "env": {
        "GHIDRA_INSTALL_DIR": "/opt/ghidra",
        "JAVA_HOME": "/path/to/jdk-21"
      }
    }
  }
}
```

*Alternative using `uvx`:* Replace `"command": "superghidra-mcp"` with `"command": "uvx"` and set `"args"` to:
```json
["--from", "git+https://github.com/yuatemycat/SuperGhidraMCP.git", "superghidra-mcp", "-t", "stdio", "--project-path", "<path_to_gpr_or_binary>"]
```

### Cursor (`.cursor/mcp.json`) & Antigravity (`~/.gemini/config/mcp_config.json`)

Both Cursor and Antigravity use standard JSON `mcpServers` configuration:

```json
{
  "mcpServers": {
    "superghidra": {
      "command": "superghidra-mcp",
      "args": [
        "-t",
        "stdio",
        "--project-path",
        "<path_to_gpr_or_binary>"
      ],
      "env": {
        "GHIDRA_INSTALL_DIR": "/opt/ghidra",
        "JAVA_HOME": "/path/to/jdk-21"
      }
    }
  }
}
```

### Claude Code CLI & Streamable HTTP Transport

If running the server via HTTP (`superghidra-mcp --transport streamable-http --port 8000`):

* **Claude Code CLI:**
  ```bash
  claude mcp add --transport http superghidra http://127.0.0.1:8000/mcp
  ```

* **HTTP URL Config (Antigravity / Cursor / Claude Desktop):**
  ```json
  {
    "mcpServers": {
      "superghidra": {
        "url": "http://127.0.0.1:8000/mcp"
      }
    }
  }
  ```

## Subsystem Capabilities & Hardware Matrix

### 1. Core Production Toolkit

These subsystems form the daily-driver reverse-engineering, C rewriting, and agent-guardrail workflow:

| Package / Subsystem | What It Does | Hardware / Dependency Behavior |
| :--- | :--- | :--- |
| **`core` (Daemon, Cache, Overlay & `CompilableDecompilerFilter`)** | Persistent RPC server on `127.0.0.1:5073`, 64 KB shared-memory ring buffer (`< 50 µs` latency in tests), SQLite L2 cache (`>100k req/s`), JSON write overlay (`ghidra_overlay.json`), conflict-aware `merge_fork`, deterministic `CompilableDecompilerFilter` C rewriter, and resource governor (`eco` / `balanced` / `turbo` / `auto`). | Runs on Windows, Linux, and macOS. `CompilableDecompilerFilter` is pure Python; PyGhidra + OpenJDK 21 are required only when attached to a live `.rep`. |
| **`formats` (Binary Loader, MSVC RTTI, MFC `Serialize()`, Rust/Go, IL2CPP & DWARF5)** | ELF / PE / Mach-O loader, MSVC RTTI & MFC `CRuntimeClass` recovery, Mach-O Objective-C recovery, `Serialize()` layout tracing, `CArchive` stream decoder, Rust `.dep-v0` crate auditor, Go `.go.buildinfo`/`pclntab` dependency auditor, Unity IL2CPP `global-metadata.dat` recovery, DWARF 5 / Breakpad / `.map` export, and experimental PDB export. | Pure Python; no JVM or Ghidra dependency. |
| **`diff` (Cross-Version CFG Matcher & Struct Shift Migrator)** | Matches functions across binary builds using CFG feature vectors, detects shifted struct field offsets across patches, and rewrites displaced field accesses. | Runs on CPU (NumPy accelerated). |
| **`integrations` (56 Guardrailed MCP Tools & Mobile Sidecar)** | Exposes 56 registered (61 defined) MCP tools (`SuperghidraMCP`), APK ↔ JNI cross-referencer, allow-listed Android emulator memory reader, live CodeBrowser overlay sync (`ghidra_gui_overlay_sync.py`), and `ReconstructionObligationLedger` commit guards (`VTableSlotVerifier`, `FieldDisplacementVerifier`, `AllocationSizeVerifier`). | Commits symbols and structs **only** after deterministic verification of vtable slots, field displacements, and allocation sizes. |

### 2. Optional & Experimental Backends

These modules target specific scale bottlenecks or standalone verification tasks and have explicit scope boundaries:

| Package / Subsystem | What It Does | Scope & Hardware Caveats |
| :--- | :--- | :--- |
| **`storage` (`[storage]` — Synthetic 16 KB Page Codec)** | Compresses 16 KB `BufferFile` pages using LZ4 (`442.9 MB/s`, `79.32%` savings) or Zstd Level 3 (`206.5 MB/s`, `86.47%` savings) and packages `SuperGhidraCodec.jar`. | **Experimental / External `.sgdb` only:** Measured on synthetic pages from `GhidraPageSimulator`. Ghidra hardcodes `LocalManagedBufferFile` without an SPI hook, so it does not transparently compress live `.rep` `.gbf` databases without patching Ghidra's jar. |
| **`acceleration` (`[gpu]`, `[smt]` — ARM64 Sweeps & Bounds-Proven Jump Tables)** | Scans ARM64 binaries for `ADRP + ADD/LDR` pairs and function prologues (`20 MB` / `5.2M` insns in `41.20 ms` = `127.25 M insn/s` on RTX A5500). Formal Z3 jump table bounds proving (`ARM64JumpTableProver`) extracts switch targets and case counts N. | GPU sweeps optional for ≥ 5 MB (NumPy SIMD handles < 5 MB). Formal jump table bounds proving requires `[smt]` (`z3-solver`). |
| **`lifters` (`[smt]` — Zero-JVM P-Code Lifter & Z3 Prover)** | Pure-Python ARM64/x86_64 → P-code lifter (integer, exclusive memory, SIMD vector math, ARMv8.1-A atomics) and Z3 equivalence prover (`SMTPcodeVerifier`). | **Bounded Subset / Sound `UNKNOWN`:** Standalone lifting covers bounded instruction subsets; `SMTPcodeVerifier` intentionally returns `UNKNOWN` (`equivalent=False`) on floating-point ops, unhandled instructions, or loops exceeding the unroll bound. |

Each package has its own README under [`src/superghidra/`](../src/superghidra/).

## Real-World Benchmark Methodology

Summary results are in the main [README](../README.md#tested-on-real-macos--ios-binaries-v107--108).


**Methodology:** all runs used `pip install "superghidra[smt]==1.0.7"` on Linux x86_64 (8-core Intel Xeon), with no Ghidra installed.
- **Fixups:** compared one by one with [LIEF](https://github.com/lief-project/LIEF) 1.0.0 (address, kind, target), plus 20 random values per slice checked by hand. On some arm64e executables, LIEF adds the image base twice to plain rebases. Those cases were decoded from the raw pointers by hand, and SuperGhidra was correct.
- **Jump tables:** every proven table's destinations were recomputed by an independent capstone-based decoder. Tables it flagged were disassembled and checked by hand; all were decoder artifacts.
- **Go / Rust:** Go results were checked against an independent `.go.buildinfo` parser. Rust results were checked against `cargo-auditable` (`.dep-v0`) data where present, otherwise against crate names in panic paths.
- **Install:** `[smt]` (Z3) is required. With a plain `pip install superghidra`, every jump table comes back unproven.

**Coverage, not completeness:** "100%" means every table SuperGhidra *proves* is right. It does not mean it finds every switch. As a rough upper bound, a capstone heuristic counts likely switch dispatches (with a bounds check), and SuperGhidra proves fewer:

| Binary | Proven tables | Capstone count |
| :--- | :---: | :---: |
| Electron | 1,427 | ~2,392 |
| SideStore | 166 | ~329 |
| hugo arm64 | 408 | ~426 |

## Synthetic Benchmarks

All benchmarks are measured on physical hardware (Intel Core i9-12950HX, 64 GB DDR5, NVIDIA RTX A5500 Laptop GPU) and across the multi-platform CI matrix. Full empirical data and logs are in [`docs/benchmarks/`](benchmarks/).

### Hardware & Throughput Matrix

| Workload / Benchmark | Input Size / Target | Engine / Backend | Measured Time | Measured Throughput / Result | Status |
| :--- | :--- | :--- | :---: | :---: | :--- |
| **ARM64 ADRP + ADD/LDR Sweep** | 4.0 MB ARM64 block (1,048,576 insns) | NumPy SIMD | **7.28 ms** | **143.95 M insn/s** | 754 pairs detected (314 synthetic + 440 random matches) |
| **ARM64 Function Seeder** | 4.0 MB ARM64 block (1,048,576 insns) | NumPy SIMD | **8.31 ms** | **126.19 M insn/s** | 16,382 candidate hits (277 deduplicated seeds) |
| **Large-scale GPU ADRP Sweep** | 20.0 MB ARM64 block (5,242,880 insns) | WGPU DirectX 12 | **41.20 ms** | **127.25 M insn/s** | Bit-exact match with CPU |
| **Buffer File Compression (LZ4)** | 1,000 synthetic 16 KB pages (16.0 MB) | LZ4 `block` | **36.12 ms** | **442.9 MB/s** (4.84x ratio) | 79.32% disk savings |
| **Buffer File Compression (Zstd)** | 1,000 synthetic 16 KB pages (16.0 MB) | Zstd Level 3 | **77.48 ms** | **206.5 MB/s** (7.39x ratio) | 86.47% disk savings |
| **Decompilation Query Cache** | Live Ghidra Daemon RPC | SQLite L2 Cache | **< 0.01 ms** | **> 100,000 req/s** | In-memory overlay match |
| **SHM Channel IPC Roundtrip** | 64 KB memory-mapped ring buffer | Windows SHM IPC | **< 50 µs** | **> 20,000 msg/s** | Zero-copy shared memory |

**Benchmark Caveats:**
- **CPU SIMD vs. WGPU Crossover:** Below ~5–10 MB, NumPy CPU SIMD (`143.95 M insn/s` on 4 MB blocks) outperforms WGPU DirectX 12 (`127.25 M insn/s` on 20 MB blocks) because PCIe host-to-device transfer overhead exceeds shader execution time. `gpu_adrp_scanner` automatically routes `< 5 MB` inputs to the CPU SIMD path.
- **Synthetic Storage Pages:** The 16 KB `BufferFile` compression figures (`442.9 MB/s` LZ4, `206.5 MB/s` Zstd) are measured on 1,000 synthetic pages generated by `GhidraPageSimulator`, not on live `.rep` `.gbf` databases (Ghidra hardcodes `LocalManagedBufferFile` without an SPI hook).

### Out-of-Distribution Systems Matrix (Uncontaminated Decompilation Verification)

Addresses the dataset contamination problem in neural decompiler benchmarks (such as HumanEval-Decompile) where models recall memorized pretraining code. Evaluated under MSVC 14.44 `cl.exe` / MinGW GCC 16.2.0 via differential co-execution:

| Workload ID | Systems Role & Target Kernel | Raw Ghidra Semantics | LLM Raw Syntax ($R_{syn}$) | LLM Semantic Pass ($R_{sem}$) | Gate 2 Hallucination Catch | SuperGhidra Verified Pass |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| `SHA256_ROUND` | Crypto compression quarter-step (Ch, Maj, 32-bit rotations) | PASS | 100% | **0% (FAIL)** | **REJECTED (100%)** | **PASS (100%)** |
| `CHACHA20_QR` | ChaCha20 quarter-round permutation (rotation invariants) | PASS | 100% | **0% (FAIL)** | **REJECTED (100%)** | **PASS (100%)** |
| `RFC1071_CHECKSUM` | 16-bit 1's complement folded Internet checksum | PASS | 100% | **0% (FAIL)** | **REJECTED (100%)** | **PASS (100%)** |
| `LEB128_DECODE` | DWARF/WASM unsigned LEB128 variable-length integer parsing | PASS | 100% | **0% (FAIL)** | **REJECTED (100%)** | **PASS (100%)** |
| `SPSC_RING_BUFFER` | Lock-free SPSC ring buffer (64-bit pointer alignment padding) | PASS | 100% | **0% (FAIL)** | **REJECTED (100%)** | **PASS (100%)** |
| `SLAB_ALLOC_HEADER` | Slab chunk header bitflag extraction (`size & ~0x7`) | PASS | 100% | **0% (FAIL)** | **REJECTED (100%)** | **PASS (100%)** |

- **Finding:** Raw LLM predictions achieved a 100% compilation rate but a 0.0% semantic pass rate due to subtle binary logic hallucinations. SuperGhidra's D-LiFT / CoExec gate rejected 100% of hallucinated candidates prior to commit.

### HumanEval-Decompile Caveat

The HumanEval-Decompile table itself lives in the main README (between the `humaneval` markers, kept in sync by `scripts/render_humaneval_table.py`).

> **HumanEval-Decompile Caveat (Deterministic C Rewriter, Not Neural Inference):** The `22.62%` (`294/1,300` full corpus, plus `25.26%` on the 30% function-disjoint held-out test split) score measures syntactic recompilability and unit-test execution pass rate produced by [`CompilableDecompilerFilter`](../src/superghidra/core/compilable_filter.py) — a deterministic post-processing rewriter that strips stack-canary boilerplate, normalizes Ghidra pseudo-types (`undefined8`, `CONCAT44`, `SUB84`), and injects symmetric Hex-Rays `defs.h` compatibility macros (`__int64`, `LODWORD`, `HIDWORD`, `BYTEn`) for IDA Pro baselines. No neural model weights or LLM calls are invoked in this benchmark.

### Dual-OS Test Matrix (GitHub Actions CI)

Full 6-job matrix evaluated with `pytest tests -v -rs -rx --strict-markers` (all integration tests run; skipped reasons reported):

| Operating System | Python 3.10 | Python 3.11 | Python 3.12 | Pytest Test Count | Pass Rate (passed / active) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Ubuntu Linux** (`ubuntu-latest`) | 42s | 30s | 27s | 736 collected (715 passed, 21 skipped) | 100% |
| **Windows Server** (`windows-latest`) | 1m 24s | 1m 12s | 1m 14s | 736 collected (715 passed, 21 skipped) | 100% |

Detailed logs and measurement methodology are documented in [`docs/benchmarks/EMPIRICAL_TEST_BENCHMARK_MATRIX.md`](benchmarks/EMPIRICAL_TEST_BENCHMARK_MATRIX.md).

## Installation, CLI & Configuration

**From PyPI:**

```bash
# Core package (ELF/PE/Mach-O loaders, RTTI/MFC recovery, Rust/Go audit, IL2CPP)
pip install superghidra

# Recommended: Core + Z3 formal verification (required for bounds-proven jump tables)
pip install "superghidra[smt]"

# Full installation with all optional backends
pip install "superghidra[all]"
```

> [!IMPORTANT]
> **Bounds-Proven Jump Tables Require `[smt]`**: To formally prove ARM64 switch jump tables and case counts, install `superghidra[smt]` (or `superghidra[all]`), which installs `z3-solver`. A plain `pip install superghidra` detects candidate dispatch structures but cannot prove case bounds without the solver, emitting a warning.

### Optional Dependency Extras

| Extra | Command | What It Enables |
| :--- | :--- | :--- |
| `[smt]` | `pip install "superghidra[smt]"` | Z3 solver backend (`z3-solver`). Required for `ARM64JumpTableProver` switch bounds proofs and `SMTPcodeVerifier` semantic equivalence checks. Plain `pip install superghidra` emits a warning and returns unproven targets when solving switch bounds. |
| `[gpu]` | `pip install "superghidra[gpu]"` | WGPU compute shaders (`wgpu`). Accelerates large ARM64 `ADRP` and function prologue sweeps (≥ 5 MB). |
| `[storage]` | `pip install "superghidra[storage]"` | LZ4 & Zstandard 16 KB page compression (`lz4`, `zstandard`). |
| `[ghidra]` | `pip install "superghidra[ghidra]"` | PyGhidra bridge & JVM headless bindings (`pyghidra`). |
| `[frida]` | `pip install "superghidra[frida]"` | Live Android emulator runtime memory inspection (`frida`). |
| `[rea]` | `pip install "superghidra[rea]"` | REA ecosystem adapter and MCP protocol bridge (`mcp`, `pydantic`). |
| `[all]` | `pip install "superghidra[all]"` | All optional backends listed above. |

**From source (development):**

```bash
git clone https://github.com/yuatemycat/SuperGhidra
cd SuperGhidra
pip install -e ".[all]"
python -m pytest -q
```

**Unified CLI:**

SuperGhidra ships with an integrated standalone command-line executable `superghidra`:

```bash
# Display version and hardware acceleration telemetry
superghidra version

# Prototype standalone P-code decompiler (covers 11/154 exports on test DLLs; handles function prologues, direct calls, and ARM64 lowering; complex branches/floats exit non-zero)
superghidra decompile target.dll --va 0x140001000 --arch x86_64 -o decompiled.c

# Import IDA Pro .til type library and dump schema catalog
superghidra til-import mssdk64.til -o catalog.json

# Match binary bytes against IDA FLIRT signature database
superghidra flirt-match vc32rtf.sig target.exe --rva 0x1000

# Recover MSVC / MFC C++ class hierarchies, RTTI structures, and virtual call tables
superghidra rtti-recover app.dll -o classes.json

# Filter raw decompiler output into clean, compilable C
superghidra filter raw_decompile.c -o clean.c

# Sync JSON write overlays and delta logs into an atomic Ghidra GUI Python script (add --watch for live polling)
superghidra overlay-sync --overlay ghidra_overlay.json --watch --out sync_script.py
```

**Inspect a Windows binary (no Ghidra needed):**

```bash
python -m superghidra.formats.binary_loader app.dll          # sections, imports, exports
python -m superghidra.formats.msvc_class_recovery app.dll    # RTTI + MFC classes
python -m superghidra.formats.serialize_trace app.dll CMyDoc # Serialize() field layout
```

**From Python:**

```python
from superghidra.formats.binary_loader import load_binary
from superghidra.formats.msvc_class_recovery import recover_classes
import superghidra as sg

img = load_binary("app.dll")
print(img.format, img.arch, len(img.sections))

report = recover_classes("app.dll")
print(len(report.mfc_classes), "MFC classes")

# Lift one ARM64 instruction and check it against itself with Z3
ops = sg.ARM64PcodeLifter().lift_instruction(0x1000, 0x91008041)  # add x1, x2, #0x20
print(sg.SMTPcodeVerifier().verify_equivalence(ops, ops).equivalent)
```

**Configuration** is read from environment variables, and nothing is tied to a particular machine:

| Variable | Used for |
| :--- | :--- |
| `GHIDRA_INSTALL_DIR`, `JAVA_HOME` | Ghidra and JDK locations (daemon, headless runs, Java codec build) |
| `SUPERGHIDRA_PROJECTS` | Default projects for the daemon: `dir,name[,program]` entries joined by `;` |
| `SUPERGHIDRA_MSVC_ROOT` | Portable MSVC folder, used when gcc/clang aren't on `PATH` |
| `SUPERGHIDRA_TEST_ARM64_ELF`, `SUPERGHIDRA_TEST_SW_ROOT` | Optional real binaries / a SOLIDWORKS install for the integration tests. Those tests skip when unset. |

## Troubleshooting & Common Gotchas

* **`superghidra decompile` fails or outputs empty blocks on my function:**
  You ran the standalone experimental zero-JVM integer lifter. Switch to `python -m superghidra.core.ghidra_oracle decompile <addr>`.
* **`LockException: Project is locked by another process`:**
  Your `.rep` project is currently open in the Ghidra GUI. The daemon reads from the project without acquiring exclusive locks; if Ghidra holds an exclusive lock or you encounter lock contention, ensure the daemon uses a read-only session or private session fork, and sync changes back via `superghidra overlay-sync --overlay ghidra_overlay.json --out ghidra_gui_overlay_sync.py`.
* **My renamed functions in the daemon don't show up in the Ghidra GUI:**
  Daemon writes go to the JSON overlay (`ghidra_overlay.json`) to prevent `.rep` corruption. Run `superghidra overlay-sync --overlay ghidra_overlay.json --out ghidra_gui_overlay_sync.py` (or pass `--watch` for continuous background polling) and execute that script inside Ghidra's Script Manager, or close the GUI and run `merge_fork`.
* **Z3 Equivalence Checker returns `UNKNOWN`:**
  This is expected behavior, not a crash. The prover returns `UNKNOWN` whenever a block contains floating-point instructions, unmodeled system instructions, or long loops so an agent never commits a false-positive equivalence rewrite.
* **WGPU scanner says `Using CPU SIMD path` even with `[gpu]` installed:**
  For ARM64 `.text` blocks under 5 MB, PCIe transfer overhead exceeds shader execution time, so SuperGhidra automatically routes blocks `< 5 MB` to the NumPy SIMD path (`143.95 M insn/s`).
* **Proposed struct or symbol from the LLM naming pipeline was rejected:**
  The naming pipeline enforces structural invariants before writing to the overlay. Check the daemon log for `VtableSlotMismatch`, `FieldOffsetOutOfBounds`, or `AllocationSizeConflict`.

## Repository Layout

```
src/superghidra/             canonical package, split into 7 domain subsystems
src/superghidra/compat/      backward-compatibility namespace shims
tests/                       domain-isolated pytest suites (1,000+ tests)
benchmarks/                  reproducible benchmark harnesses and measurement scripts
docs/                        benchmark specifications, walkthroughs, and architecture docs
ghidra_extension_skeleton/   Java BufferFile compression extension
templates/                   scaffolds for modules, MCP tools, and test suites
```

If you're an AI agent, start with [AGENTS.md](../AGENTS.md).
