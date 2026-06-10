# EVM context-size opcodes carry a U64 result range at the producer

## What

`convertSingleInstrToU256Operand` (the helper that lifts a single i64
instruction result into a 4-limb u256 operand) now tags its result
`ValueRange::U64` instead of leaving the default `U256`.

This affects the EVM opcodes whose value is structurally a 64-bit quantity and
that flow through this helper: `CALLDATASIZE`, `CODESIZE`, `MSIZE`, `PC`,
`GAS`, `RETURNDATASIZE`.

The only code change is one line in
`src/compiler/evm_frontend/evm_mir_compiler.cpp`; this change-doc is the rest.

## Why

The range analyzer already classifies these opcodes as U64, but the MIR builder
discarded that fact: the helper zero-fills limbs[1..3] and zero-extends limb[0],
then returned an operand with the default `U256` range. So a value that is
provably ≤ 2^64-1 by construction arrived at its **first in-block consumer**
tagged `U256`, and same-block size / bounds arithmetic
(`ADD(CALLDATASIZE, …)`, `LT(GAS, …)`) missed the u64 fast path. The U64 tag
only reappeared after a CFG join via the analyzer's `EntryStackRanges`, never at
first use.

This closes a named builder/analyzer asymmetry. It is distinct from the
in-flight value-range PRs: #524 tags arithmetic **results**, #499 narrows the
compare **consumers**; neither tags these context-size **producers**.

## Soundness

The tag is correct by construction, independent of caller intent: limb[0] is
`zeroExtendToI64(SingleInstr)` and limbs[1..3] are literal zero constants, so the
constructed 256-bit value lies in `[0, 2^64-1]`. If some caller were to feed a
semantically-wider value as a single i64, that value was already truncated
before this helper; the U64 tag faithfully reports that the high limbs are zero
and introduces no new miscompile.

## Evidence

Dual-tap Stream B (`ZEN_EVM_RANGE_PROFILE`) on a probe contract
`CALLDATASIZE DUP1 ADD` (two dynamic, non-constant U64 operands feeding ADD),
same code hash and site (pc=2, ADD) before and after:

| build | lhs_range | rhs_range | lowering path |
|---|---|---|---|
| baseline (no tag) | U256 | U256 | **FULL** |
| this change | U64 | U64 | **NARROW_U128** |

The ADD moves off the full 4-limb path onto the u64 fast path — the range_u64
hit count for this site rises from 0. Reproduce: build the lib, run
`evmone-statetest` over the probe with `ZEN_EVM_RANGE_PROFILE=<csv>` set, and
read the ADD row.

## Testing

CI-faithful flags (`ZEN_ENABLE_JIT_PRECOMPILE_FALLBACK=ON`, matching
`.ci/run_test_suite.sh`):

- multipass `evmone-unittests` (curated run list): 223 / 223 pass.
- multipass `evmone-statetest -k fork_Cancun`: 2723 / 2723 pass, zero new
  failures.
- `tools/format.sh check`: pass.

The lowering change is metadata-only; the emitted limbs are byte-identical to
the prior path, so correctness is unaffected — confirmed by the suites above.

## Scope and limits

The realized benefit is bounded by how often these context-size opcodes feed
**same-block** arithmetic with another u64 operand. Cross-block propagation of
the tag is a separate, larger problem (the analyzer's `EntryStackRanges` are not
imported into the builder in the default build), tracked independently.
