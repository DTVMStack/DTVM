# Change: Relax JIT fallback thresholds for benchmark corpus

- **Status**: Implemented
- **Date**: 2026-03-24
- **Tier**: Light

## Overview

Relax EVM JIT precompile fallback MIR/RA thresholds to keep the current evmone benchmark corpus (including micro/signextend) on the JIT path. Bytecode-size cap is unchanged.

## Motivation

Some benchmark contracts were falling back to the interpreter due to conservative MIR/RA thresholds, preventing accurate JIT performance measurement. The thresholds were overly conservative for contracts that the JIT can handle efficiently.

## Impact

- Module: `docs/modules/evm/` (JIT fallback thresholds only)
- 1 file changed, +8/-6 lines
- Benchmark geomean: +0.28%, sum ratio: +0.69%
- Former fallback-heavy cases (memory_grow_mstore) improve; signextend/snailtracer regress slightly
- No functional behavior change; only affects which contracts use JIT vs interpreter

## Checklist

- [x] Implementation complete
- [x] Tests added/updated (static analyzer sweep: fallback_contracts=0)
- [ ] Module specs in `docs/modules/` updated (if affected)
- [x] Build and tests pass
