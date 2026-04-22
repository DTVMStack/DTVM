---
name: dtvm-perf-profile
description: Profile DTVM execution using Linux perf and generate categorized analysis reports. Use when the user wants to profile a DTVM command, find performance hotspots, break down JIT-compiled EVM basic block execution time, analyze host function overhead, or mentions "perf", "profile", "hotspot", "breakdown", or "bottleneck" in the context of DTVM execution. The user provides a dtvm command line (including bytecode path, calldata, execution mode, etc.).
---

# DTVM Perf Profiling

Profile DTVM execution and produce a categorized performance report.

## Prerequisites

1. **perf binary**: Either system `perf` or a self-built one (check repo root for `./perf`).
2. **Build with `ZEN_ENABLE_LINUX_PERF=ON`**: Required for per-basic-block JIT symbols.

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release \
  -DZEN_ENABLE_MULTIPASS_JIT=ON \
  -DZEN_ENABLE_LINUX_PERF=ON \
  -DLLVM_DIR=/opt/llvm15/lib/cmake/llvm
cmake --build build -j$(nproc)
```

For singlepass JIT, replace `-DZEN_ENABLE_MULTIPASS_JIT=ON` with `-DZEN_ENABLE_SINGLEPASS_JIT=ON` (no LLVM needed).

## Workflow

### 1. Verify build flags

Check `CMakeCache.txt` for `ZEN_ENABLE_LINUX_PERF:BOOL=ON`. If OFF, reconfigure and rebuild.

### 2. Run the profiling script

```bash
.agents/skills/dtvm-perf-profile/scripts/perf_profile.sh \
  --perf ./perf --output-dir perf_results -- \
  ./build/dtvm -m multipass --format evm --gas-limit 0xFFFFFFFFFFFF \
  <bytecode.hex> \
  --calldata <hex> \
  --load-state <state.json> \
  --contract-address <addr> \
  --num-extra-compilations=0 --num-extra-executions=99999
```

The script lives under the skill SSOT at
`<repo>/.agents/skills/dtvm-perf-profile/scripts/perf_profile.sh` — not
under the `.claude/skills/` mirror.

Key flags for the dtvm command:
- `--num-extra-executions=N`: More iterations = better sampling of execution (vs compilation). Use 99999+ for meaningful data.
- `--enable-statistics`: Optional. Adds timer-based breakdown but introduces ~10% overhead from `clock_gettime`. Omit for cleaner perf samples.
- `--num-extra-compilations=0`: Avoid repeated compilations unless profiling compilation itself.

### 3. Interpret the summary

The script generates `perf_summary.txt` with these categories:

| Category | What it measures |
|----------|-----------------|
| EVM Basic Block Hotspots | Time in JIT-compiled EVM code, per BB (e.g. `EVMBB0_JUMPDEST_1405`) |
| EVM Host Functions | Time in host calls (`evmEmitLog3`, `evmGetSLoad`, etc.) |
| Keccak / Hashing | Time in `keccakf1600_bmi` / `ethash_keccak256` |
| JIT Compilation | Register allocator, ISel, MC lowering (only for first compilation) |
| Profiling Overhead | `clock_gettime` overhead from `--enable-statistics` |
| Memory Allocation | `malloc`/`free` from instantiation and host calls |
| Instantiation | `EVMInstance` creation/destruction per execution |
| By DSO | High-level split: dtvm binary vs libc vs jitted SOs vs vdso |

### 4. Drill into hotspots

For any hot symbol, annotate its assembly:

```bash
./perf annotate -i perf_results/perf_dtvm_jit.data -s EVMBB0_JUMPDEST_1405
```

### 5. Present findings

Structure the report as:

1. **Setup**: Command, build flags, iteration count
2. **Top-level split**: Compilation vs Execution vs Instantiation (from `--enable-statistics` if used, or from DSO breakdown)
3. **Execution breakdown**: Table of BB hotspots + host functions + keccak, sorted by overhead
4. **Observations**: Notable findings (e.g. profiling overhead, dominant BBs, hash cost)
5. **Recommendations**: Actionable next steps

## BB Symbol Naming

EVM basic block symbols follow the pattern `EVMBB<funcIdx>_<type>_<evmPC>`:

- `EVMBB0_MAIN_ENTRY_1` -- contract entry point
- `EVMBB0_JUMPDEST_<pc>` -- basic block at EVM PC (JUMPDEST opcode)
- `EVMBB0_SWITCH<n>_<pc>` -- jump dispatch table

The EVM PC can be cross-referenced with the contract's disassembly to identify which Solidity function or logic the BB belongs to.

## Tips

- **Reduce noise**: Omit `--enable-statistics` for cleaner perf data (avoids ~10% `clock_gettime` overhead).
- **Increase signal**: Use high `--num-extra-executions` (100K+) so execution dominates over one-time compilation.
- **Compare modes**: Profile same contract with `-m singlepass` vs `-m multipass` to compare JIT backends.
- **Interpreter baseline**: Profile with `-m interpreter` (no `ZEN_ENABLE_LINUX_PERF` needed) for comparison.
