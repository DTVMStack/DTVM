# DTVM Paper Reproduction Package

This directory archives the test cases, benchmark scripts, baseline-runtime build notes, and reference results needed to reproduce every experiment in the Evaluation section of the DTVM paper (`resources/DTVM_paper.pdf`). The material was curated from an experiment archive; the interior layout matches the original package, and every script under `scripts/` treats this directory as its `ROOT`.

Mainline comparison: **DTVM (multipass / lazy)** vs **Wasmtime 45.0.0** vs **Wasmer 7.1.0 (cranelift / singlepass / llvm)**; the EVM-side baseline is **evmone**.

## Layout

```
benchmarks/paper/
├── VERSIONS.md          # runtime version pins (paper baseline + current mainline)
├── ENVIRONMENT.md       # experiment environment and toolchain inventory
├── REPRODUCE.md         # reproduction overview (links to per-topic guides)
├── SOURCES.md           # provenance and license notes
├── docs/                # per-topic reproduction guides
│   ├── POLYBENCH_REPRODUCE.md         # PolyBench wall-clock
│   ├── POLYBENCH_TTFI_REPRODUCE.md    # PolyBench TTFI
│   └── WAPM_TTFI_REPRODUCTION.md      # WAPM TTFI (wasmtime 45 / wasmer 7.1 backends)
├── runtimes/            # per-runtime BUILD.md / build.sh / version.txt (no binaries)
├── benchmarks/          # paper workloads
│   ├── contracts/       # contract microbenchmark: sol sources + evm/wasm hex (runner source not included)
│   ├── polybenchc/      # PolyBench/C 4.2.1, all 30 cases as wasm + WASI rebuild script
│   ├── wapm/            # 21 WAPM wasm files (paper's 20 cases + fortune) + confs + SHA256SUMS
│   ├── overflow/        # integer-overflow (swap-style) + fib(30) 5-way: C++ source + wasm + scripts
│   └── fib/             # standalone fib / md5 (C/Solidity sources + wasm)
└── scripts/             # benchmark drivers and table generators (incl. testsuite runner)

`raw_data/` is created by the scripts at run time and is gitignored; this package ships cases and methodology only, no result data.
```

## Paper Results → Directory Map

| Paper result | Experiment | Workloads | Entry point |
|---|---|---|---|
| Fig. "Ethereum Ecosystem" (Fig. 5) | DTVM vs evmone contract latency | `benchmarks/contracts/` (Merkle-MiMC, GenerativeNFT, ERC1155, Counter, ERC20/721, UniswapV2, fib) | `benchmarks/contracts/REPRODUCE.md` |
| Fig. "JIT improvement over Interp" (Fig. 6) | DTVM JIT vs interpreter | `benchmarks/contracts/` + `benchmarks/fib/` | same + `benchmarks/fib/` |
| Fig. "general-purpose Wasm VMs" (Fig. 7) | fib(30) / integer-overflow latency | `benchmarks/overflow/`, `benchmarks/fib/` | `benchmarks/overflow/REPRODUCE_fib_overflow_5way.md` |
| Fig. 8(a) + Appendix PolyBench table | PolyBench 30-case latency | `benchmarks/polybenchc/` | `docs/POLYBENCH_REPRODUCE.md` |
| Fig. 8(b) + Appendix PolyBench TTFI | PolyBench time-to-first-invocation | `benchmarks/polybenchc/` | `docs/POLYBENCH_TTFI_REPRODUCE.md` |
| Fig. 8(b) + Appendix WAPM table | WAPM 20-case TTFI | `benchmarks/wapm/` | `docs/WAPM_TTFI_REPRODUCTION.md`, `benchmarks/wapm/WAPM_REPRODUCE.md` |
| Deterministic-execution table | cross-arch stack-overflow determinism | `tests/wast/dwasm/call_stack_exceed.wast` (already in this repo) | `docs/testing/` |
| Machine-code-size table | compiled-code size comparison | `benchmarks/polybenchc/` + `benchmarks/fib/` | per-topic docs |


## Quick Start

```bash
cd benchmarks/paper
export ROOT=$(pwd)
# 1. Build DTVM at the repo root:
#    cmake -B build -DZEN_ENABLE_MULTIPASS_JIT=ON -DLLVM_DIR=<llvm15>/lib/cmake/llvm && cmake --build build
#    Scripts default to <repo>/build/dtvm; override via the DTVM env var.
# 2. Install baseline runtimes (see docs/<TOPIC>_REPRODUCE.md and runtimes/<rt>/BUILD.md).
# 3. PolyBench wall-clock
./scripts/setup_polybench_case.sh
./scripts/run_polybench.sh dtvm
./scripts/bench_polybench_timing.sh dtvm multipass
# 4. PolyBench TTFI
WASMTIME_CACHE=0 ./scripts/run_polybench_ttfi_round.sh 1
# 5. WAPM TTFI
WASMTIME_CACHE=0 ./scripts/run_wapm_v45_v71_round.sh 3
# 6. overflow / fib(30)
cd benchmarks/overflow && bash run_dtvm.sh && bash run_wasmtime45.sh
```

## Large Files and Provenance

- `*.wasm`, `*.expected`, and `*.png` are managed by **Git LFS** (see the root `.gitattributes`).
- Per-suite provenance and integrity: `benchmarks/*/MANIFEST.md`, `benchmarks/*/SHA256SUMS`, `SOURCES.md`.
- Runtime binaries are not committed: `runtimes/<rt>/` keeps only `BUILD.md` + `build.sh` + `version.txt` (`out/` and `build/` are gitignored).

## Not Migrated / Archive Gaps

- Full intermediate data (multi-round timestamped runs, per-runtime CSVs, SVG comparisons) and the raw per-iteration contract timing samples (`.time`) are not included.
- The 9 non-paper WAPM cases and the libsodium (72) / wabench (22) suites were not migrated (see `benchmarks/README.md`).
- The contract microbenchmark runner (`test_vmbench`) builds only inside the contract-testbed repository; the sol→wasm / sol→evm compile commands were not recorded in the archive (see `benchmarks/contracts/README.md`, `SOURCES.md`).
- Other gaps are listed in `SOURCES.md` and `benchmarks/wapm/WAPM_REPRODUCE.md` §2.
