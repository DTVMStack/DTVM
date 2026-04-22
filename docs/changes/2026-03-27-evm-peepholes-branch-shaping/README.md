# Change: EVM peepholes and branch shaping

- **Status**: Implemented
- **Date**: 2026-03-27
- **Tier**: Light

## Overview

Add EVM frontend peepholes for zero/one/all-ones identities in ADD, SUB, MUL, AND, OR, XOR. Defer NOT and zero-test materialization so ISZERO chains can collapse without building redundant 256-bit MIR values. Improve x86 lowering and CG peepholes for compare chains and short-diamond branches.

## Motivation

The EVM frontend mechanically expands all operations to full 256-bit MIR regardless of operand values. Identity operations (add 0, mul 1, and all-ones, etc.) generate unnecessary instructions that are trivially eliminable at the frontend level.

## Impact

- Modules: `docs/modules/compiler/` (EVM frontend + x86 lowering)
- 5 files changed in `src/compiler/evm_frontend/` and `src/compiler/target/x86/`
- Benchmark geomean: +11.4%, total time reduction ~3.8%
- Notable: jump_around/empty ~48% faster
- 1798/1798 state tests pass

## Checklist

- [x] Implementation complete
- [x] Tests added/updated
- [ ] Module specs in `docs/modules/` updated (if affected)
- [x] Build and tests pass
