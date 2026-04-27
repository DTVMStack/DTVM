# Change: Inline u256 arithmetic optimizations

- **Status**: Implemented
- **Date**: 2026-04-10
- **Tier**: Light

## Overview

Five MIR-level optimizations to u256 arithmetic lowering in the EVM frontend,
plus a register-allocator workaround uncovered by the new inline DIV/MOD path.
All changes are contained in `src/compiler/evm_frontend/evm_mir_compiler.{cpp,h}`.

- **Shift strength reduction** — In dynamic-shift lowering for `SHL`/`SHR`/`SAR`,
  replace `OP_udiv`/`OP_urem` by 64 with `OP_ushr 6` / `OP_and 63`. Avoids the
  ~30-cycle x86 `DIV` on the dynamic shift path.
- **ADDMOD inline fast path** — For non-constant `ADDMOD` with `mod[3] != 0`
  (modulus ≥ 2^192), inline `intx::addmod` at MIR level: normalize augend/addend
  against `mod`, add with overflow detection, subtract `mod` with borrow
  detection, select. Small moduli (`mod[3] == 0`) and `mod == 0` continue to
  call the runtime helper.
- **Dead-carry barrier elimination** — Drop `protectUnsafeValue` barriers in
  `handleAddU64Const` / `handleSubU64Const` where x86 `CF` is provably dead
  (RHS-immediate MOVs and terminal ADC; SUB/ICMP_ULT/zeroExtend borrow chain in
  SUB never lives `CF`). Generic u256 ADD/SUB chains in the header are
  intentionally unchanged.
- **Value-range narrowing** — Add `ValueRange{U64,U128,U256}` on `Operand`,
  auto-derived from constants and propagated through AND masks, `BYTE`, and
  comparisons. When both operands of `ADD`/`MUL`/`DIV`/`MOD` are provably U64,
  emit a single-instruction fast path instead of the 4-limb chain.
- **Inline u256 DIV/MOD** — Replace the runtime fallback in `handleDiv` /
  `handleMod` with a runtime divisor-size check. Single-limb divisors (upper
  three limbs zero) use the existing cascading 128/64 division pattern inline;
  multi-limb divisors still call the runtime.

A 5-block CFG variant of inline DIV/MOD (with a dedicated `ZeroDivisorBB`)
tripped a `CgLiveRangeCalc` assertion (`TheVNI != nullptr`) during register
allocation. The committed form uses a 3-block CFG matching `handleDiv`: a
branchless guard `SafeB0 = select(B[0] == 0, 1, B[0])` feeds the hardware
`DIV`, then `select(B[0] == 0, 0, result)` zeros the output. This path is
distinct from the `findReachingDefs` fix in PR #456.

## Motivation

U256 arithmetic lowering currently calls into runtime helpers for several
operations that have closed-form MIR sequences. Inlining them removes a call,
exposes the operation to the existing peephole / register-allocation passes,
and on operands that are provably narrow lets the JIT collapse a 4-limb chain
to a single-instruction fast path. The carry-barrier removals are a peephole
cleanup: `protectUnsafeValue` barriers force stack spills for live `CF`, and
several call sites do not actually have a downstream `CF` consumer, so the
barrier is structural noise that survived earlier passes.

A Barrett-reduction MULMOD variant was prototyped in the same line of work
but abandoned — both inline and C-helper forms crashed the register coalescer
on contracts with thousands of `MULMOD` call sites in one function and showed
no measurable win.

## Impact

- Module: `docs/modules/compiler/` (EVM frontend MIR lowering)
- 8 files changed, +547/-34
  - `src/compiler/evm_frontend/evm_mir_compiler.{cpp,h}` — all five
    optimizations + range tracking + reg-alloc workaround
  - `tests/evm_asm/addmod_fastpath_*.{easm,expected}` — 3 boundary fixtures
- Performance (evmone-bench, multipass, 10 reps, suite of 27
  `external/total/{main,micro}` benches, CPU-pinned, single session, baseline
  `upstream/main@ec3c9f9`):
  - Suite-level geomean speedup: **1.0069 (+0.69%)**, 95% bootstrap CI
    `[-1.80%, +3.44%]` — within per-bench noise; not statistically distinguishable
    from parity at suite level
  - Targeted wins on u256-arithmetic-heavy benches: weierstrudel/15 +18.3%,
    weierstrudel/1 +13.5%, swap_math/received +9.7%, snailtracer/benchmark
    +7.9%, swap_math/spent +6.7%, swap_math/insufficient_liquidity +6.6%,
    structarray_alloc/nfts_rank +3.9%
  - Suite-level geomean is in the noise band because integer-arithmetic wins
    on JIT-bound micro benches have largely been absorbed by recent upstream
    work (#428 BMI2 lowering, #435 peephole, #395 SSA)
  - No regressions outside per-bench noise on the bottom benches (CV > 7%)
- Correctness: gas and output match in all paths
- No host or ABI changes; multipass-only — interpreter path is unaffected

## Checklist

- [x] Implementation complete
- [x] Tests added/updated — `tests/evm_asm/addmod_fastpath_*` (3 new boundary
      fixtures, multipass + interpreter both 6/6); `evmone-unittests` multipass
      223/223, interpreter 215/215; `evmone-statetest` `fork_Cancun` 2723/2723
- [ ] Module specs in `docs/modules/` updated (if affected)
- [x] Build and tests pass — CI 17/17 green on PR #458 HEAD `66235af`
