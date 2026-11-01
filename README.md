# SuperGhidra

[![License: AGPL-3.0-or-later](https://img.shields.io/badge/License-AGPL_3.0--or--later-blue.svg)](LICENSE)
[![PyPI version](https://img.shields.io/pypi/v/superghidra.svg)](https://pypi.org/project/superghidra/)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-3776AB.svg)](https://www.python.org/)
[![CI](https://github.com/yuatemycat/SuperGhidra/actions/workflows/ci.yml/badge.svg)](https://github.com/yuatemycat/SuperGhidra/actions/workflows/ci.yml)
[![Featured on Made with REA](https://madewithrea.com/badges/featured.svg)](https://madewithrea.com/builds/superghidra-warm-ghidra-daemon-mcp-server-and-c-recovery-tools-for-age)

**SuperGhidra: Compilable C Rewriter & Guardrailed Agent MCP Suite.**

Python tools that make Ghidra faster to script against, rewrite raw decompiler output into compilable C, and run static binary analyses Ghidra does not include out of the box: MSVC RTTI and MFC `CRuntimeClass` recovery, `Serialize()` archive layout tracing, cross-version function and struct-shift matching, and a Z3 equivalence checker for P-code.

Instead of paying 5–15 seconds of JVM startup per headless run or fighting `.rep` project lock contention while the Ghidra GUI is open, SuperGhidra keeps a single read-only Ghidra instance warm in a background daemon (`127.0.0.1:5073`) backed by an L2 SQLite cache and a non-destructive JSON write overlay. Heavy binary sweeps and class-layout recovery run in pure Python, NumPy SIMD, or WGPU compute shaders without touching the JVM.

![SuperGhidra recovering 755 RTTI classes and 391 MFC classes from mfc140u.dll, then tracing CDWordArray::Serialize, with no Ghidra or JVM](docs/assets/demo.gif)

## Install

```bash
pip install "superghidra[smt]"   # [smt] adds Z3; needed to prove ARM64 jump tables
```

No Ghidra or JVM is needed for the commands below. Python 3.10+. Other extras (GPU, MCP adapters, dev) and source installs are listed in [docs/DETAILS.md](docs/DETAILS.md#installation-cli--configuration).

## What It Does

| Capability | Command |
| :--- | :--- |
| MSVC RTTI and MFC `CRuntimeClass` class recovery from PE files | `superghidra rtti-recover target.dll -o classes.json` |
| Mach-O dyld fixups (chained and legacy), ARM64e PAC, Swift / Objective-C metadata | `superghidra apple-dispatch App --arch arm64 -o dispatch.json` |
| Objective-C class recovery | `superghidra objc-recover` |
| Rust crate / Go module audit of compiled binaries | `superghidra crate-audit target.bin -o deps.json` |
| Unity IL2CPP types, methods and string pools | `superghidra il2cpp-recover global-metadata.dat -o unity.json` |
| Z3 equivalence checking of P-code | `superghidra smt-verify` |
| Rewrite raw decompiler output into compilable C | `superghidra filter raw.c -o clean.c` |
| Cross-version binary CFG and function matching | `superghidra diff` |
| IDA `.til` type import and FLIRT `.sig` matching | `superghidra til-import` / `superghidra flirt-match` |
| Cross-reference APK Dalvik bytecode with native ELF libraries | `superghidra apk-xref` |
| Cross-call def-use value graph | `superghidra trace-values` |
| Warm read-only Ghidra daemon (`127.0.0.1:5073`) with SQLite cache | `superghidra oracle` |
| Non-destructive JSON rename overlay, synced live into the Ghidra GUI | `superghidra overlay-sync --overlay o.json --watch` / `superghidra gui-sync` |
| Experimental zero-JVM decompiler (prototype, see limitations) | `superghidra decompile` / `superghidra decompile-all` |

Run `superghidra <command> --help` for the options. Workflows, architecture, the Python API and configuration are in [docs/DETAILS.md](docs/DETAILS.md).

## Tested on Real macOS & iOS Binaries (v1.0.7 / 1.0.8)

Fixup decoding, Z3-proven ARM64 jump tables and Rust/Go auditing were checked against independent reference tools on shipping macOS and iOS binaries. The runs used the PyPI wheel `superghidra[smt]==1.0.7` on Linux x86_64, with no Ghidra installed. 1.0.8 changes no analysis logic: it only adds a warning when Z3 is missing and an error message for `smt-verify`.

**Key numbers:** fixups matched [LIEF](https://github.com/lief-project/LIEF) 1.0.0 exactly on every slice that parsed. Every proven jump table had the correct destinations, with 0 false proofs.

**Public set** (15 files, 18 slices; `dispatch s` = `apple-dispatch` wall time, `JT s` = jump-table pass):

| Sample | Platform / Arch | Fixup Format | Fixups Matched / Total (LIEF) | Proven JTs (Destinations Verified) | Go / Rust Audit | dispatch s / JT s |
| :--- | :--- | :---: | :---: | :---: | :--- | :---: |
| [Electron Framework](https://github.com/electron/electron/releases/tag/v45.2.1) v45.2.1 | macOS arm64 | chained 2 | 671,510 / 671,510 | 1,427 / 1,427 | — | 2.20 / 185.7 |
| chrome_crashpad_handler (same Electron zip) | macOS arm64 | chained 2 | 3,755 / 3,755 | 2 / 2 | — | 0.05 / 0.32 |
| libvk_swiftshader.dylib (same Electron zip) | macOS arm64 | chained 2 | 46,729 / 46,729 | 226 / 226 | — | 0.17 / 1.30 |
| [AltStore](https://github.com/altstoreio/AltStore/releases) 2.3 Classic | iOS arm64 | chained 6 | 22,720 / 22,720 | 80 / 80 | — | 0.16 / 0.55 |
| AltStoreCore.framework (same IPA) | iOS arm64 | chained 6 | 9,014 / 9,014 | 8 / 8 | — | 0.08 / 0.40 |
| [SideStore](https://github.com/SideStore/SideStore/releases) 0.7.0-alpha | iOS arm64 | chained 6 | 65,902 / 65,902 | 166 / 166 | — | 0.30 / 1.28 |
| OpenSSL.framework (same SideStore IPA) | iOS arm64 | legacy dyld_info | 28,446 / 28,446 | 36 / 36 | — | 0.11 / 0.60 |
| [Dopamine](https://github.com/opa334/Dopamine/releases) 3.0.12 libjailbreak.dylib | iOS arm64 / arm64e | chained 6 / chained 12 | 646 / 646 · 654 / 654 | 0 found | — | 0.04 |
| Dopamine 3.0.12 libchoma.dylib | iOS arm64 / arm64e | dyld_info / chained 1 | 144 / 144 · 143 / 143 | 0 found | — | 0.04 |
| [gh](https://github.com/cli/cli/releases/tag/v2.103.3) 2.103.3 | macOS arm64 | legacy dyld_info | 179,057 / 179,057 | 189 / 189 | Go go1.27.3, 159 deps | 0.62 / 7.93 |
| [fzf](https://github.com/junegunn/fzf/releases/tag/v0.74.5) 0.74.5 | macOS arm64 | legacy dyld_info | 21,387 / 21,387 | 48 / 48 | Go go1.27.2, 6 deps | 0.10 / 0.46 |
| [hugo](https://github.com/gohugoio/hugo/releases/tag/v0.169.0) 0.169.0 universal | macOS arm64 | legacy dyld_info | 347,356 / 347,356 | 408 / 408 | Go go1.27.3, 101 deps | 1.29 / 18.40 |
| hugo 0.169.0 universal | macOS x86_64 | legacy dyld_info | **⚠ known gap: parser error** | — | — | — |
| [ripgrep](https://github.com/BurntSushi/ripgrep/releases/tag/15.2.0) 15.2.0 | macOS arm64 | legacy dyld_info | 12,576 / 12,576 | 36 / 36 | Rust, 16 crates | 0.09 / 0.48 |
| [fd](https://github.com/sharkdp/fd/releases/tag/v10.5.0) 10.5.0 | macOS arm64 | legacy dyld_info | 10,083 / 10,083 | 20 / 20 | Rust, 23 crates | 0.06 / 0.42 |
| [bat](https://github.com/sharkdp/bat/releases/tag/v0.26.1) 0.26.1 | macOS arm64 | legacy dyld_info | 11,841 / 11,841 | 35 / 35 | Rust, 53 crates | 0.07 / 0.49 |

**Held-out set** (never used during development): 30 slices from 22 binaries. Fixups exact vs. LIEF on **30 / 30 slices**, **5,238 / 5,238** proven jump tables with correct destinations, **0** false proofs. The held-out names are withheld on purpose, so the set stays unseen by future tuning.

"100%" means every table SuperGhidra *proves* is right. It does not mean it finds every switch (for example, Electron: 1,427 proven vs. ~2,392 likely switches). Methodology and the coverage table: [docs/DETAILS.md](docs/DETAILS.md#real-world-benchmark-methodology). Synthetic benchmarks (hardware throughput, GPU, compression, OOD) and the CI matrix are there too.

### Reference Puzzle Baseline: HumanEval-Decompile (1,300 Evaluated Functions)

<!-- humaneval:begin -->
| Metric | IDA raw | IDA + filter | Ghidra raw | Ghidra + filter |
| :--- | :---: | :---: | :---: | :---: |
| **Pass Rate (Full Corpus)** | 243/1300 (18.69%) | 247/1300 (19.0%) | 107/1300 (8.23%) | 294/1300 (22.62%) |
| **70% Train Split (230 funcs)** | 197/912 (21.6%) | 201/912 (22.04%) | 64/912 (7.02%) | 196/912 (21.49%) |
| **30% Held-Out Test Split (Function-Disjoint, 98 funcs)** | 46/388 (11.86%) | 46/388 (11.86%) | 43/388 (11.08%) | 98/388 (25.26%) |
| **Held-Out Test (`O2`/`O3` High-Opt)** | 20/194 (10.31%) | 20/194 (10.31%) | 18/194 (9.28%) | 48/194 (24.74%) |
| **Filter Gains** | — | +4 | — | +187 (+55 held-out) |
| **Filter Regressions** | — | -0 | — | -0 |

- **Dataset:** `LLM4Binary/decompile-eval@b9271fae3c556e46948559f4176ffa6f8b4f9491` (1300 evaluable functions from binaries compiled at `O0`–`O3`).
- **Compiler & Host:** Evaluated on `Windows AMD64` by recompiling recovered C/C++ with `gcc.EXE (MinGW-W64 x86_64-ucrt-posix-seh, built by Brecht Sanders, r3) 16.2.0` under `gcc -O0 -lm`.
- **Host ABI Note:** Single-host evaluation. Linux ELF binaries recompiled on Windows (LLP64) experience 32-bit `long` truncation on raw Ghidra emissions (8.23%). On Linux (LP64), raw Ghidra achieves 21.46% (279/1300), exceeding raw IDA.
- **Methodology & Scope Caveat:** Measures syntactic recompilability (`gcc -O0 -lm`) + unit test pass rate via deterministic AST/token rewriting (`CompilableDecompilerFilter` + `defs.h` compatibility macros), not neural LLM weight generation.
- **70/30 Held-Out Split:** Splitting by unique function body (seed `42`, all `O0`–`O3` variants of a function kept together) confirms out-of-sample generalization on the held-out 30% test split (43/388 -> 98/388, +55 gains) with zero regressions.
<!-- humaneval:end -->


The filter is a deterministic rewriter, not a neural model. See the [caveat](docs/DETAILS.md#humaneval-decompile-caveat).

**vs. stock headless Ghidra and other MCP bridges:** one warm JVM instead of 5–15 s startup per run, no `.rep` lock contention with the open GUI, and renames go to a non-destructive overlay with conflict detection instead of the `.rep` database. Full table: [docs/DETAILS.md](docs/DETAILS.md#how-superghidra-compares-to-stock-headless--existing-ghidra-mcp-bridges).

## Known Limitations

- **Jump tables need Z3.** Without `[smt]`, candidates are found but stay `proven=False`, and a warning says `z3-solver` is missing.
- **No x86_64 jump-table prover.** Intel slices get fixup checks only.
- **arm64e hardened switches** (`csel` index clamp) are not detected.
- **Slow on big binaries.** The Electron jump-table pass takes ~3 minutes and ~2.2 GB of RAM. The prover has occasionally stalled for minutes; this could not be reproduced on demand. The static library dependency check takes ~7 s on a binary of hugo's size.
- **hugo's Intel slice fails to parse** (`'MachOSection' object has no attribute 'reserved2'`).
- **`il2cpp-recover`** runs out of memory on Unity metadata v31 (~14 GB on a 9 MB file) because the v31 header layout is wrong. Versions 24–39 are tested on synthetic fixtures and Android samples, not on public Unity iOS builds (no legal public samples exist).
- **`crate-audit`** reports 0 crates ("observed absence") for Rust apps built with `cargo vendor`.
- **C++ RTTI** covers MSVC and MFC only. GNU Itanium ABI RTTI is planned for 1.x. MFC precision is tested in CI on synthetic PE fixtures (100% precision, 0 false positives on non-MFC binaries such as `libcrypto-3.dll`). Real apps such as WinMerge (713 RTTI, 160 MFC classes) are checked by hand.
- **`superghidra decompile` is an experimental prototype**: basic integer ops, prologues, direct calls and early ARM64 lowering (11 of 154 exports decompiled, 7 compiling, across four test DLLs). For real work, use the Ghidra-backed oracle (`python -m superghidra.core.ghidra_oracle decompile <addr>`).
- **PDB export is experimental.** It has no MSVC hash, symbol-record or TPI streams. DWARF 5 is the supported export.
- **SMT checking is sound but incomplete.** Floats, calls, unhandled ops and long loops return `UNKNOWN` by design.
- **The ARM64 lifter** lacks advanced crypto and complex floating-point vector ops.
- **The Java codec** needs external `.sgdb` files or a patched Ghidra jar, because Ghidra hardcodes `LocalManagedBufferFile`.

More detail is in [PLAN.md](PLAN.md) and [Troubleshooting](docs/DETAILS.md#troubleshooting--common-gotchas).

## Agents & MCP

SuperGhidra exposes 56 registered reverse-engineering tools (61 defined) over the Model Context Protocol through [SuperghidraMCP](https://github.com/yuatemycat/SuperGhidraMCP), for example `recover_cpp_classes`, `trace_serialize`, `diff_binaries`, `verify_smt_equivalence` and `gpu_adrp_scan`. It needs `GHIDRA_INSTALL_DIR` and `JAVA_HOME` (Ghidra 11/12 + OpenJDK 21):

```bash
pip install superghidra-mcp
claude mcp add superghidra -- superghidra-mcp -t stdio --project-path <path_to_gpr_or_binary>
```

Config blocks for Claude Desktop, Cursor and Antigravity: [docs/DETAILS.md](docs/DETAILS.md#agent--mcp-configuration-claude-desktop-cursor-antigravity). For native REA adapters in Python apps, install `superghidra[rea]`. If you're an AI agent, start with [AGENTS.md](AGENTS.md).

## Donate

If you find SuperGhidra useful, crypto donations (fast & permissionless) are welcome:

**USDT (BEP20 / BNB Smart Chain):**

```
0xd08d47bde441888166b801616754c667672cd502
```

## Contributing

Issues and PRs are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for the test workflow and the safety rules: read-only projects, verified symbol commits and the emulator allow-list. Report security issues as described in [SECURITY.md](SECURITY.md).

## License

SuperGhidra is licensed under the [GNU AGPL-3.0-or-later](LICENSE). If you modify it and let other people use it over a network, for example as a hosted MCP server, you have to offer them your modified source.

If the AGPL doesn't fit your use, a commercial license is available. See [COMMERCIAL-LICENSE.md](COMMERCIAL-LICENSE.md).

Releases up to and including 0.2.0, and commits before the license change, were published under Apache-2.0. Those versions stay under Apache-2.0 and the text is kept in [`LICENSES/Apache-2.0.txt`](LICENSES/Apache-2.0.txt).

© 2026 yuatemycat and contributors.
