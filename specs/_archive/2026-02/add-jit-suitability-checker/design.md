## Context

DTVM's multipass JIT compiles EVM bytecode via an MIR pipeline that expands certain opcodes into long SelectInstruction chains (e.g., SHL produces ~92 Selects per call). When hundreds of such opcodes appear in a single basic block, the greedy register allocator's cost becomes superlinear, causing compilation times to explode from milliseconds to minutes.

Two distinct pathological patterns have been identified:
- **b0 (DUP feedback)**: `DUP1 SHL DUP1 SHL ...` -- the shift result feeds back as both operands, creating exponentially overlapping live ranges
- **b1 (full stack)**: `DUP1 x1000 SHL x1000` -- massive fan-out of a single value across the entire function

A DUP detection fix (`Shift == Value` in `handleShift`) already mitigates b0 at the MIR level. This proposal addresses the remaining cases by detecting pathological patterns before compilation begins, avoiding the expensive JIT path entirely.

## Goals / Non-Goals

- Goals:
  - Detect bytecodes that would cause RA explosion before JIT compilation starts
  - Zero overhead on normal contracts (analysis is O(n) in bytecode length, piggybacks on existing scan)
  - Configurable thresholds to tune false-positive/negative tradeoff
  - Replace the existing flat `MIR_OPCODE_WEIGHT` estimate with a structured, pattern-aware analysis
- Non-Goals:
  - Fixing the register allocator itself (separate effort)
  - Detecting runtime-only pathologies (e.g., infinite loops)
  - Handling singlepass JIT (only multipass is affected)

## Decisions

- **Integration into EVMAnalyzer::analyze()**: The analyzer already scans all opcodes with block boundary detection. Adding ~5 comparisons per opcode is negligible. This avoids a second pass and keeps the analysis colocated with related bytecode metadata.
- **Not integrated into evm_cache.cpp**: The cache focuses on gas metering (SPP) with a different block model (gas chunks vs compilation blocks). Mixing JIT analysis here would conflate concerns.
- **Struct-based result**: `JITSuitabilityResult` provides fine-grained metrics (not just a boolean), enabling callers to log diagnostics, tune thresholds, or implement graduated responses.

## RA-Expensive Opcode Set

Based on empirical analysis of MIR expansion and Select chain density:

| Opcode | Selects/call | Total MIR/call | Justification |
|--------|-------------|----------------|---------------|
| SHL (0x1b) | 92 | ~150-180 | Nested J,K loops over 4 U256 components |
| SHR (0x1c) | 96 | ~160-190 | Same structure as SHL |
| SAR (0x1d) | 52 | ~100-130 | Similar but with sign extension |
| MUL (0x02) | 0 | ~50-60 | Heavy inline U256 mul (no Selects but huge VR fan-out) |
| SIGNEXTEND (0x0b) | 21 | ~80-100 | Two dependency chain loops |

## Detection Heuristics

1. **Per-block density**: Count RA-expensive opcodes per basic block (JUMPDEST to JUMP/STOP/RETURN). Normal contracts have <20 per block; pathological cases have 500+.
2. **Consecutive run length**: Track the longest unbroken sequence of RA-expensive opcodes (DUPs/SWAPs are transparent since they don't generate heavy MIR). Detects both b0 and b1 patterns.
3. **DUP feedback count**: Count `DUPn immediately followed by RA-expensive op` pairs. This specifically targets the b0 pattern where DUP creates the feedback loop.

## Thresholds (initial, tunable)

- `MAX_CONSECUTIVE_RA_EXPENSIVE = 128` -- safe margin above any real contract
- `MAX_BLOCK_RA_EXPENSIVE = 256` -- per-block cap
- `MAX_DUP_FEEDBACK_PATTERN = 64` -- DUP+expensive pairs in whole bytecode
- Existing: `MAX_JIT_BYTECODE_SIZE = 0x6000`, `MAX_JIT_MIR_ESTIMATE = 50000`

## Risks / Trade-offs

- **False positives**: A contract with 129 consecutive MULs would trigger fallback even if compilation would succeed. Mitigation: thresholds are set conservatively high (real contracts have <20 per block).
- **False negatives**: Novel pathological patterns not involving the listed opcodes could still cause RA explosion. Mitigation: the existing `MAX_JIT_MIR_ESTIMATE` serves as a backstop.
- **Maintenance cost**: New RA-expensive opcodes added in the future must be added to the set. Mitigation: the set is small and well-documented.

## Open Questions

- Should the thresholds be runtime-configurable (e.g., via `set_option`) or compile-time only?
- Should the analysis result be cached in `EVMBytecodeCache` for reuse between interpreter and JIT paths?
