# Change: U256 composite peephole evidence for xor-self-zero

- **Status**: Implemented
- **Date**: 2026-04-26
- **Tier**: Light

## Overview

Promote `u256-xor-self-zero` from a production-only branch extension to a fully
validated U256 composite rewrite. The rule rewrites each limb result of
`u256_xor(x, x)` to zero after checking that the corresponding left/right limbs
are structurally equal.

## Evidence

- Metadata checker accepts `synthesized-u256` and `smt_256`.
- `dmirValidationTests` covers the positive rewrite and negative non-matches.
- `tools/verify_dmir_u256_soundness.py` replays the 256-bit Z3 proof.
- `tools/test_synth_u256_pattern_coverage.py` verifies synthesis rediscovery.
- CTest and the peephole GitHub Actions job run the same local evidence gate.

## Paper Impact

The paper may report 71 dMIR rules only if it uses the scalar/U256 split: 70
scalar-limb rules plus one composite U256 rule. Performance claims still need a
rerun before the U256 rule is included in the performance headline.
