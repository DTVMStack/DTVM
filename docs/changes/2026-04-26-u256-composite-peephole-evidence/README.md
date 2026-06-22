# Change: U256 composite peephole evidence for xor-self-zero

- **Status**: Implemented
- **Date**: 2026-04-26
- **Tier**: Light

## Overview

`u256-xor-self-zero` rewrites each limb result of `u256_xor(x, x)` to zero
after checking that the corresponding left/right limbs are structurally equal.
This change moves the rule from a branch-only extension into the main rule set,
covered by unit tests and a 256-bit SMT proof. The rule lets the compiler fold
a self-XOR to a constant zero without a runtime computation.

## Evidence

- Metadata checker accepts `synthesized-u256` and `smt_256`.
- `dmirValidationTests` covers the positive rewrite and negative non-matches.
- `tools/verify_dmir_u256_soundness.py` runs a Z3 proof that the rewrite equals
  zero for all 256-bit inputs.
- `tools/test_synth_u256_pattern_coverage.py` verifies synthesis rediscovery.
- The change adds one composite U256 rule to the dMIR rule set, bringing the
  total to 71: 70 scalar-limb rules plus one composite U256 rule.
- Both CTest and the peephole GitHub Actions job run the checks listed above.
