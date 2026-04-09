# Change: Optimize x86 U256 MUL with BMI2/ADX

- **Status**: Implemented
- **Date**: 2026-03-23
- **Tier**: Light

## Overview

Detect `adx` and `bmi2` CPU features in the x86 compiler target and lower EVM U256 MUL to a BMI2+ADX row-wise MULX + ADCX/ADOX schedule on supported x86_64 hosts. Falls back to existing generic lowering on unsupported CPUs.

## Motivation

U256 multiplication is one of the most expensive EVM operations in the JIT (~100 x86 instructions). BMI2 provides MULX (widening multiply without flags clobber) and ADX provides ADCX/ADOX (dual carry chains), enabling a more efficient multiplication schedule with better instruction-level parallelism.

## Impact

- Module: `docs/modules/compiler/` (x86 lowering for U256 MUL)
- 5 files changed, +165/-28 lines
- Performance: single-shot +0.55% (noise), hot MUL loop +7.5-10.5%
- Hardware requirement: BMI2+ADX (Intel Haswell+, AMD Zen+); graceful fallback on older CPUs
- No functional behavior change; gas and output match in all cases

## Checklist

- [x] Implementation complete
- [x] Tests added/updated (evmc run --bench, gas/output verification)
- [ ] Module specs in `docs/modules/` updated (if affected)
- [x] Build and tests pass
