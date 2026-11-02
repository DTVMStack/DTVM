# Change: Wrap-safe x86 LEA for integer add/sub immediates + MIR add-imm reassoc

- **Status**: Implemented
- **Date**: 2026-11-01
- **Tier**: Light

## Overview

Two trap-safe integer addressing cleanups that do **not** fold `add(dyn,imm)`
into load/store displacement (rejected in DTVMStack #626 / zoowii/DTVM#14):

1. Lower i32 `add`/`sub` with a signed-disp32 immediate to three-address
   `LEA64_32r` so the result is `trunc32(zext32(x)+disp) == wrap32(x+disp)`.
   i64 stays ADD/SUB so EFLAGS.CF remains available for EVM ADC chains.
2. MIR: i32 `add(add(x,C1),C2) → add(x,C1+C2)` and
   `sub(x,C) → add(x,-C)`; integer `mul(x, 1<<k) → shl(x,k)`.
   Do not apply these new add/sub rewrites to i64: value equivalence alone
   does not preserve the carry/borrow consumed by EVM ADC/SBB chains.

Jacobi stencil still addresses with `[base + wrap32(index+C)]`.

## Motivation

jacobi-2d `function_2` emits `mov %r12d,%ecx; add $0x28a8,%ecx; movsd
(%rax,%rcx,1),%xmm0` for each stencil neighbor. The extra `mov` is
two-address ADD while the loop index stays live. `lea 0x28a8(%r12),%ecx`
is one instruction, does not clobber flags, and keeps wrap32.

## Impact

- [compiler](../../modules/compiler/spec.md): `X86CgLowering::tryLowerAddSubImmAsLEA`
- tests: CgIR litmus, `add_imm_lea_wrap.wast` (wrap value + wrap address)

No public API change. Wasm trap / gas / wraparound unchanged.

## Review and validation limits

- Preserve i64 SUB instead of converting it to ADD of a negative constant:
  for `0-1`, SUB sets CF while ADD of `-1` does not. EVM wide subtraction
  uses that CF in the following SBB instructions. Added interpreter/JIT
  result and gas comparisons for a dynamic operand minus `2^64+1`.
- Keep the new add-constant reassociation i32-only as well: the final
  i64 ADD carry-out is not preserved when intermediate additions wrap.
- The original PR reports jacobi-2d execution 3494 → 3219 ms (5 paired
  runs, about 7.9%). This is one workload/configuration, not a general
  throughput claim; remeasure against current main (including #629), and
  retain broad performance validation before merging.
- This review environment lacks CMake and LLVM 15 development tools.
  New MIR/CgIR/EVM tests are added for CI; the full JIT suite and the
  reported benchmark were not rerun here. Native x86 checks cover borrow
  counterexamples and randomized LEA wrap semantics.

## Checklist

- [x] Implementation complete
- [x] Tests added/updated
- [x] Module specs in `docs/modules/` updated (if affected)
- [ ] Updated full build and JIT tests pass in CI
