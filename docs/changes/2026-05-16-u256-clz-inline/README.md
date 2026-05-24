# Change: Inline handleClz with 4-limb chain-select and VR::U64 tag

- **Status**: Proposed
- **Date**: 2026-05-16
- **Tier**: Light

## Overview

Replace the pure runtime fallback in `EVMMirBuilder::handleClz`
(`src/compiler/evm_frontend/evm_mir_compiler.cpp:3092-3096`) with an inline
4-limb chain-select that computes EIP-7939 CLZ entirely in MIR and tags the
result with `ValueRange::U64`.

## Motivation

`handleClz` currently delegates to a runtime helper via `callRuntimeFor` →
`RuntimeFunctions.GetClz` → `evmGetClz` (intx::clz). Each invocation pays:

- 8x32B copy through `HostArgScratch` + `Uint256ReturnBuffer`,
- one indirect call out of JIT code,
- ~30-70 cycles of spill/restore + call overhead.

The result is also returned as an opaque `EVMType::UINT256` value, which
defeats `EVMRangeAnalyzer` (PR #493) from propagating the static fact that
`CLZ(v) <= 256` fits in a u64. Downstream narrow consumers in subsequent
basic blocks therefore cannot widen-elide.

Inlining is a known-safe pattern: `handleExp`
(`evm_mir_compiler.cpp:2511-2562`) already uses the same chain-select
template for `computeExpByteSize`. The 4 evmone CLZ unittests
(`evm.clz_gas`, `evm.clz_osaka`, `evm.clz_pre_osaka`, `evm.clz_stack_underflow`
in `tests/evmone_unittests/EVMOneMultipassUnitTestsRunList.txt:49-52`) lock
correctness, including `CLZ(0)=256` per EIP-7939.

Expected perf at the 27-bench suite level: < 0.5% (CLZ is rare). Microbench
runs with a CLZ-heavy contract could plausibly show >= 1%, but no
representative bench is staged.

## Impact

Two commits in this PR:

1. `src/compiler/evm_frontend/evm_mir_compiler.cpp::handleClz` — replace the
   `callRuntimeFor` body with the inline 4-limb chain-select MIR pattern. The
   C++ signature is unchanged.
2. `src/compiler/evm_frontend/evm_imported.{h,cpp}` — drop the now-unused
   `RuntimeFunctions.GetClz` typedef field, `evmGetClz` declaration,
   dispatch-table entry, and function body. After step 1 the helper has no
   remaining callers; whole-tree `grep` and `nm -D libdtvmapi.so` confirm
   internal linkage with no external consumers.

`RuntimeFunctions` is accessed only via designated initializer and named
field, so removing one field does not shift offsets for any consumer.

## Implementation

1. Strip `callRuntimeFor` from `handleClz` and rewrite it as MIR construction
   modeled on `computeExpByteSize` (`evm_mir_compiler.cpp:2511-2562`):

   - Extract the 4 limbs via `extractU256Operand`. Limb index `i` holds bits
     `[64*i, 64*(i+1))`, so the highest limb is index 3.
   - Build three `OP_or`'d "limb-non-zero" predicates: `Has3, Has2, Has1`.
   - Build a value-zero predicate `IsZero = (Limb0 | Limb1 | Limb2 | Limb3) == 0`.
   - Chain-select the highest non-zero limb:
     - `Limb12 = Has1 ? Limb[1] : Limb[0]`,
     - `Limb23 = Has2 ? Limb[2] : Limb12`,
     - `Limb = Has3 ? Limb[3] : Limb23`.
   - Chain-select the matching base offset (limb index 3 -> 0, index 2 -> 64,
     index 1 -> 128, index 0 -> 192):
     - `Off12 = Has1 ? 128 : 192`,
     - `Off23 = Has2 ?  64 : Off12`,
     - `Offset = Has3 ?   0 : Off23`.
   - **Defense-in-depth against `OP_clz(0)`** — follow `handleExp:2547-2548`
     and OR the picked limb with `1` before the unary CLZ. This is dMIR-level
     guarding against any backend (target lowering, fallback path) treating
     `clz(0)` as undefined. The outer Select still produces the correct
     spec value (256) so it does not matter what the underlying CTLZ yields
     on zero, but we keep both guards for parity with `handleExp` and to
     keep the MIR self-contained.
   - `PartialClz = OP_clz(SafeLimb)`,
   - `Partial = Offset + PartialClz`,
   - `Result0 = IsZero ? 256 : Partial` (outer Select for `CLZ(0) = 256`
     per EIP-7939, verified against
     `~/evmone/test/unittests/evm_eip7939_clz_test.cpp:33`).

2. Pack the result into a `U256Inst`:
   - `Result[0] = protectUnsafeValue(Result0, MirI64Type)`,
   - `Result[1..3] = Zero`.

   Then return
   `Operand(Result, EVMType::UINT256, ValueRange::U64)` so downstream
   narrow-consumer analysis (PR #493 `EVMRangeAnalyzer`) sees the tight
   range across basic blocks.

3. Delete the now-dead runtime surface as a second commit:
   `RuntimeFunctions.GetClz` field (`evm_imported.h`), `evmGetClz`
   declaration (`evm_imported.h`), dispatch-table entry
   (`evm_imported.cpp`), and the function body (`evm_imported.cpp`). With
   `handleClz` inlined in step 1, no caller remains.

## Checklist

- [ ] Implementation complete (handleClz inlined)
- [ ] `tools/format.sh check` passes
- [ ] `cmake --build build --target dtvmapi` succeeds
- [ ] Multipass `evmone-unittests` 223/223 (including all 4 `evm.clz_*`)
- [ ] Multipass `evmone-statetest -k fork_Cancun` 2723/2723
- [ ] Module specs in `docs/modules/` updated (n/a — single-function change)
- [ ] Parallel impl review: opus + codex on the diff (Phase 4)
