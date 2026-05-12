# PR #493 Soundness Regression Reproducers

End-to-end execution-level evidence that the three soundness fixes in PR #493
are not theoretical: with the fix reverted, DTVM's multipass JIT produces
output that disagrees with the `evmone` reference VM on bytecode that
crosses a CFG join through a lifted JUMPDEST and feeds a `bothFitU64`-gated
fast-path consumer.

## Why this experiment was only possible after commit `2ebfd29`

Earlier drafts of this PR proposed execution-level state-test fixtures to
prove the soundness fixes were observable, but `investigation.md`'s §2b
finding noted the path was architecturally infeasible: the analyzer's
`setRange` refinement was wired only into the non-lifted JUMPDEST consumer,
while lifted blocks (the dominant codegen path under default
`ZEN_ENABLE_EVM_STACK_SSA_LIFT=OFF`) constructed entry operands via
`createStackEntryOperand` / `materializeStackMergeOperand` with the default
`ValueRange::U256`.  No analyzer mis-classification could reach a
fast-path consumer through the dominant codegen path, so no end-to-end
test could surface the bug.

Commit `2ebfd29` (perf: plumb EVMRangeAnalyzer ranges into lifted-block
entry operands) closed that gap.  With it landed, the analyzer's per-slot
range now reaches both codegen paths, and a mis-classified value can fire
the fast path on real bytecode — which makes this reproducer possible.

## SDIV fast-path truncation (`sdiv_sign_mismatch_repro.hex`)

### Bytecode

```
PUSH32 0xFF...FF      ; -1 in signed U256 (analyzer correctly classifies U256)
PUSH1 5               ; dividend = 5 (analyzer correctly classifies U64)
SDIV                  ; signed: 5 / -1 = -5
                      ;   PRE-FIX analyzer rule: result = Dividend.range = U64  (BUG)
                      ;   POST-FIX rule (signedDivModRange): U256 because divisor is U256
PUSH1 1               ; U64
PUSH1 0x2A            ; merge JUMPDEST address
JUMP                  ; cross-CFG-join into lifted block

@0x2A JUMPDEST        ; lifted block; entry stack = [SDIV_result, 1]
                      ;   createStackEntryOperand reads analyzer's range:
                      ;     PRE-FIX: U64  (BUG — fast path admission gate passes)
                      ;     POST-FIX: U256 (fast path declined)
ADD                   ; real: -5 + 1 = -4 = 0xFF...FC
                      ; buggy fast path: u64(0xFF...FB) + 1 = 0xFFFC; upper 3 limbs zeroed
PUSH1 0
MSTORE                ; write 32-byte ADD result to memory[0..32]
PUSH1 32
PUSH1 0
RETURN                ; return memory[0..32] as call output
```

### Observed outputs

| VM | Fix state | Output (32-byte hex, big-endian) | Verdict |
|---|---|---|---|
| `evmone` (spec reference) | n/a | `fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc` | −4, spec-correct |
| DTVM `mode=multipass` | fix applied (HEAD) | `fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc` | matches reference ✓ |
| DTVM `mode=multipass` | fix reverted | `000000000000000000000000000000000000000000000000fffffffffffffffc` | upper 192 bits **truncated to 0** — visible state divergence |

The buggy output preserves only the low 64 bits of the real ADD result
(`0xFFFFFFFFFFFFFFFC` = u64::MAX − 3) and zeroes the upper 3 limbs.
This is exactly the "limbs[2..3] silent truncation" failure mode the
fix commit message described.

### Reproduce

```bash
bash repro_sdiv_fast_path_truncate.sh
```

The script runs the bytecode under (a) `evmone` reference and (b) DTVM
multipass with current code, asserts the outputs match, and prints both.
It does **not** automatically revert the fix and re-test — that requires
a rebuild which the script flags as a manual follow-up.

## Companion: white-box regression net (Option A)

The 42 white-box tests in `src/tests/evm_range_analyzer_tests.cpp` already
catch every soundness mis-classification at the analyzer layer.  Empirical
verification on 2026-05-12 (current HEAD, all three fixes reverted in place,
analyzer rebuilt):

| Test | Pre-fix outcome | Reason |
|---|---|---|
| `SDivByU256IsU256` | FAIL | divisor U256, dividend U64; pre-fix rule says `result = Dividend = U64` (wrong) |
| `SModByU256IsU256` | FAIL | same pattern for SMOD |
| `TimestampIsU256` | FAIL | pre-fix host-context rule put TIMESTAMP in `pushU64` block |
| `NumberIsU256` | FAIL | same — NUMBER |
| `GasLimitIsU256` | FAIL | same — GASLIMIT |
| `ChainIdIsU256` | FAIL | same — CHAINID |
| `CreateAddressIsU256` | FAIL | pre-fix rule classified `CREATE` result as U64; it actually returns a 20-byte address |
| `Create2AddressIsU256` | FAIL | same pattern for `CREATE2` |
| `SDivU256DividendIsU256` | PASS | coincidence — `result = Dividend = U256` happens to match the post-fix answer when dividend is U256 |

Eight tests fail under the pre-fix code, one passes by coincidence.  The
regression net is effective at the analyzer level, but does not by itself
prove that mis-classification has user-visible execution consequences —
that is what the `sdiv_sign_mismatch_repro.hex` experiment supplies.

## Why the host-context bug is harder to surface via this same harness

A symmetric experiment for the `TIMESTAMP`/`NUMBER`/`GASLIMIT`/`CHAINID`
soundness fix would require an EVM `evmc_host_interface` that returns a
context value with bit 64 or higher set (e.g., a non-Ethereum chain ID
larger than 2^32, or a future-dated timestamp).  `evmc run`'s default
host returns small values for all four, so the buggy fast path would
truncate to the same value the real arithmetic produces — no visible
divergence.  Constructing a custom host-overriding harness is doable but
beyond the scope of this experiment; the analyzer-layer regression test
(Option A above, `TimestampIsU256` et al.) is the operative net for that
bug class.
