# EVM bytecode compile optimization summary

Date: 2026-07-03

## Scope

This branch contains the focused opcode compile-time optimizations that were
validated in the opcode benchmark corpus:

- `ADDMOD`: inline a dynamic `u64 + u64 mod u64` fast path in frontend dMIR
  lowering.
- `EXP`: reduce frontend lowering size by specializing small constant
  exponents, avoiding unused exponent variables in the 64-bit path, and
  replacing the generic 256-bit `SHR 1` lowering in the EXP loop with a direct
  four-limb right shift.

The changes intentionally do not introduce a runtime helper for `EXP`.

## Current benchmark snapshot

Cold compile measurements use `depth=32,iters=1`, fresh process per run, median
of repeated runs.

| opcode | DTVM current | revmc current | DTVM/revmc |
| --- | ---: | ---: | ---: |
| ADDMOD | 9.386 ms | 22.916 ms | 0.41x |
| EXP | 95.410 ms | 20.617 ms | 4.63x |

Against the local pre-optimization DTVM build:

| opcode | before | after | delta |
| --- | ---: | ---: | ---: |
| ADDMOD d32 | 162.465 ms | 9.271 ms | -94.3% |
| EXP d32 | 142.739 ms | 92.427 ms | -35.2% |

## Remaining issue

`EXP` is meaningfully reduced but still much slower than revmc. The remaining
cost is not primarily a single `MUL` lowering problem: DTVM already has an
`evm_u256_mul` pseudo-op with x86 lowering. The remaining compile-time cost
comes from expanding the whole `EXP` loop as frontend CFG with variables,
branches, shifts, and repeated U256 operations.

The next high-value step is a real high-level `evm_u256_exp` pseudo-op lowered
in the backend, reusing the existing U256 multiply lowering at the register
level.

## Raw benchmark artifacts

The latest local raw results are outside the repository under:

- `/tmp/dtvm_opcode_benchmark_repro/out/exp_addmod_v3_cold_compile_raw.csv`
- `/tmp/dtvm_opcode_benchmark_repro/out/exp_addmod_v3_vs_revmc_summary.csv`
- `/tmp/dtvm_opcode_benchmark_repro/out/current_dtvm_vs_revmc_d32_compile_summary.csv`
