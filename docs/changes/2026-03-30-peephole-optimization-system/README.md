# Change: Peephole Optimization System for dMIR and x86 CgIR

- **Status**: Implemented
- **Date**: 2026-03-30
- **Tier**: Full

## Overview

A two-level peephole optimization system targeting both dMIR (mid-level IR) and x86 CgIR (code generation IR). The dMIR level has 67 accepted rewrite rules covering identity elimination, boolean algebra, shift-zero, and carry-dead rewrites. The x86 CgIR level has 13 declarative JSON rules for self-moves, zero-shifts, redundant CMP/TEST, fallthrough branches, and setcc+test+jne chain folding. Includes Z3-verified synthesized rules and a CI validation gate.

## Motivation

The JIT compiler generated redundant instructions from mechanical U256 decomposition and lowering. Peephole optimization is a standard compiler technique to clean up such patterns without restructuring the pipeline. The two-level approach catches patterns at both the IR and machine code level.

## Impact

### Affected Modules

- `docs/modules/compiler/` — new dMIR rewrite pass, carry-dead analysis, rule table infrastructure
- `docs/modules/singlepass/` — x86 CgIR peephole pass
- CI pipeline — new `peephole_validation_and_timing_budget` job

### Affected Contracts

No API or interface changes.

### Compatibility

- No breaking changes
- +4.6% geomean improvement on evmone-bench (27 benchmarks)
- Notable wins: snailtracer +3.9%, structarray_alloc +4.1%, swap_math +5.0-5.8%, memory_grow_mstore +11-13%
- ~0.005ms p95 compile overhead from dMIR rewrite pass

## Implementation Plan

### Phase 1: dMIR Rewrite Infrastructure

- [x] Pattern matching framework
- [x] Rule table
- [x] Validation tests

### Phase 2: Carry-Dead Analysis

- [x] `isCarryDead()` for adc→add and sbb→sub rewrites on dead-carry limbs

### Phase 3: Z3-Synthesized Rules

- [x] `add(x,x)→shl(x,1)`, negation folding, boolean identities
- [x] Verified via `tools/synthesize_dmir_rules.py`

### Phase 4: x86 CgIR Peephole

- [x] 13 declarative JSON rules
- [x] Pattern matching on machine instructions

### Phase 5: CI Gate

- [x] `.inc` freshness check
- [x] Structural/execution/semantics validation
- [x] Compile-time budget enforcement

## Compatibility Notes

No backwards-incompatible changes. The optimization passes are additive and do not alter any external APIs or module interfaces.

## Risks

- Rewrite rules must preserve U256 semantics exactly; all rules are Z3-verified but edge cases in carry chain analysis could theoretically miss a case
- Compile-time budget (0.005ms p95) may need adjustment as more rules are added
- JSON rule format for x86 CgIR is a new abstraction layer that adds maintenance surface
