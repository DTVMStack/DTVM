# Round 1 — Codex Review of G4-safe Implementation

## Verdict
PASS

## Verified
- Check 1: ✅ `handleBitwiseOp` returns `Operand(Result, EVMType::UINT256, OtherOp.getRange())` inside the `BO_OR || BO_XOR` `if constexpr`; function return type is `Operand`. `src/compiler/evm_frontend/evm_mir_compiler.h:575`, `src/compiler/evm_frontend/evm_mir_compiler.h:664-686`
- Check 2: ✅ Phase 5 excludes AND via `if constexpr (BO_OR || BO_XOR)` and uses `Operand::maxRange`; AND still returns earlier for u64-const and U128/NarrowRange, while unconstrained U256 AND falls through to default `Operand(Result, EVMType::UINT256)`. `src/compiler/evm_frontend/evm_mir_compiler.h:615-661`, `src/compiler/evm_frontend/evm_mir_compiler.h:690-707`
- Check 3: ✅ `maxRange` is a static helper on `Operand`; call site correctly uses `Operand::maxRange`. `src/compiler/evm_frontend/evm_mir_compiler.h:266-269`, `src/compiler/evm_frontend/evm_mir_compiler.h:703-705`
- Check 4: ✅ only `BO_SHR_U` returns `ValueOp.getRange()`; SHL and SHR_S share the conservative default return. `src/compiler/evm_frontend/evm_mir_compiler.h:762-776`
- Check 5: ✅ `handleCompareEqU64` uses `FinalResult = LowEq` for `Range == U64`; else branch preserves upper-limb OR-fold, `ICMP_EQ` vs Zero, and AND with `LowEq`; both feed one protected result and zero-fill tail. `src/compiler/evm_frontend/evm_mir_compiler.cpp:2990-3014`
- Check 6: ✅ LT and GT use the same shape: `LowLt`/`LowGt` fast path when range is U64; else branch preserves HasUpper select semantics. `src/compiler/evm_frontend/evm_mir_compiler.cpp:3032-3056`, `src/compiler/evm_frontend/evm_mir_compiler.cpp:3074-3100`
- Check 7: ✅ `git diff --name-only HEAD -- src/` lists only `evm_mir_compiler.cpp` and `evm_mir_compiler.h`; no other `src/` file is modified.
- Check 8: ✅ no fast-path branch returns early; all three compare helpers converge to `Result[0] = protectUnsafeValue(...)` and `Result[1..3] = Zero`. `src/compiler/evm_frontend/evm_mir_compiler.cpp:3009-3014`, `src/compiler/evm_frontend/evm_mir_compiler.cpp:3051-3056`, `src/compiler/evm_frontend/evm_mir_compiler.cpp:3095-3100`

## Refuted / concerns
- Check 9: ⚠️ `tools/format.sh check` was run and failed with exit 123 on unrelated existing files, e.g. `src/singlepass/x64/assembler.h` and `src/host/wasi/sandboxed-system-primitives/src/posix.c`. The two touched files pass `clang-format --dry-run -style=file -Werror`.
- No semantic scope creep found: SUB, SHL, SAR, ADDMOD/MULMOD, EXP, signed compare, and unrelated files are untouched by this diff.

## Suggested commit subject
perf(evm): propagate safe ValueRange through OR/XOR and SHR_U

## Trust-chain analysis
For check #10, the fast paths are intentionally unsound if `Range == U64` lies. EQ would be wrong when upper limbs are nonzero and the low limb equals the constant: it returns `LowEq` true instead of old `LowEq && UpperZero`. LT would be wrong when upper limbs are nonzero and `low < rhs`: it returns true even though the full U256 is greater than any u64. GT would be wrong when upper limbs are nonzero and `low <= rhs`: it returns false even though the full U256 is greater than any u64. This matches the spec trust chain: correctness depends on `ValueRange::U64` implying runtime-zero upper limbs.
