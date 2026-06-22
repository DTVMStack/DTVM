# Change: Peephole Optimization System for dMIR and x86 CgIR

- **Status**: Implemented
- **Date**: 2026-03-30
- **Tier**: Full

## Overview

A two-level peephole optimization system targeting both dMIR (mid-level IR) and x86 CgIR (code generation IR). The dMIR level has 65 accepted rewrite rules, plus 5 hand-written starter rules, covering identity elimination, boolean algebra, shift-zero, and carry-dead rewrites. The x86 CgIR level has 13 declarative JSON rules for self-moves, zero-shifts, redundant CMP/TEST, fallthrough branches, and setcc+test+jne chain folding. The Z3-synthesized subset of the dMIR rules carries a formal proof, and a CI validation gate enforces rule freshness, semantics, and a compile-time budget.

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
- Notable wins: snailtracer +3.9%, structarray_alloc +4.1%, swap_math +5.0% to +5.8% across runs, memory_grow_mstore +11% to +13% across runs
- ~0.005ms p95 compile overhead from dMIR rewrite pass

## What Changed

### dMIR rewrite infrastructure

A pattern-matching framework, rule table, and validation tests for the dMIR
rewrite pass.

### Carry-dead analysis

`isCarryDead()` rewrites adc→add and sbb→sub on dead-carry limbs.

### Z3-synthesized rules

`add(x,x)→shl(x,1)`, negation folding, and boolean identities, generated and
formally verified via `tools/synthesize_dmir_rules.py`.

### x86 CgIR peephole pass

13 declarative JSON rules with pattern matching on machine instructions.

### CI validation gate

`.inc` freshness check, structural/execution/semantics validation, and
compile-time budget enforcement.

## Compatibility Notes

No backwards-incompatible changes. The optimization passes are additive and do not alter any external APIs or module interfaces.

## Risks

- Rewrite rules must preserve U256 semantics exactly; the Z3-synthesized rules carry a formal proof, but the carry-dead rewrites rely on the carry-chain liveness analysis, where an edge case could be missed
- Compile-time budget (0.005ms p95) may need adjustment as more rules are added
- JSON rule format for x86 CgIR is a new abstraction layer that adds maintenance surface
