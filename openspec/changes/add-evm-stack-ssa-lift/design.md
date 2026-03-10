# EVM Stack SSA Lift Design

## Overview
The implementation lifts EVM stack values into frontend-managed virtual values for conservative block regions. Each lifted block has block-entry variables representing the stack state at block entry. Safe predecessors copy outgoing values into those entry variables. Unsafe or unsupported edges still spill to runtime stack.

## Key Decisions
- Keep implementation in the existing EVM frontend (`EVMAnalyzer`, `EVMByteCodeVisitor`, `EVMMirBuilder`).
- Use per-block entry variables as a Phase-1 phi substitute.
- Only keep edges lifted when analysis proves them safe enough for one-pass construction.
- Preserve existing runtime stack path as fallback.

## Safety Rules
- Materialize on unsupported or unsafe dynamic jumps.
- Materialize blocks with conflicting entry depths.
- Spill before fallback/exception/return boundaries.

## Current Status
- The current implementation is a conservative Phase-1 path that keeps the existing materialized runtime-stack behavior as fallback.
- Validation for this change is currently centered on focused frontend regression tests that exercise lifted edges, fallbacks, and non-lifted stack access behavior.

