# Change: Extend x86 CG peephole rules

- **Status**: Implemented
- **Date**: 2026-03-29
- **Tier**: Light

## Overview

Extend the x86 CG peephole pass beyond the original cmp/setcc/test/jcc fold. Add test/setcc simplification, zero-add elimination, adc-zero canonicalization, imm-zero no-op removal, and broader branch folding patterns seen in JIT output.

## Motivation

JIT output analysis revealed additional redundant x86 instruction patterns not covered by the initial peephole rules. These patterns are mechanical artifacts of U256 decomposition and lowering.

## Impact

- Module: `docs/modules/compiler/` (x86 CG peephole only)
- 2 files changed: `src/compiler/target/x86/x86_cg_peephole.cpp` and `.h`
- Benchmark geomean: +6.9%, largest wins in synth/GAS (~2.4x), memory_grow_mstore/by32 (~1.8x)
- Known regressions in small set of memory_grow/nogrow/by1 micro cases (within noise)

## Checklist

- [x] Implementation complete
- [x] Tests added/updated
- [ ] Module specs in `docs/modules/` updated (if affected)
- [x] Build and tests pass
