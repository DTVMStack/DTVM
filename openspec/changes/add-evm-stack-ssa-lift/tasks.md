## 1. Completed in this Change
- ✅ 1.1 Extend `EVMAnalyzer::BlockInfo` with lifted-block metadata (`BodyStartPC`, `BodyEndPC`, CFG edges, resolved entry/exit depths, liftability flags)
- ✅ 1.2 Canonicalize consecutive `JUMPDEST` runs so lifted entry modeling uses stable block PCs
- ✅ 1.3 Propagate entry/exit stack depth across block edges and mark conflicting merge depths conservatively
- ✅ 1.4 Mark unsupported dynamic-control-flow regions and other unsafe block shapes as non-liftable
- ✅ 1.5 Add builder helpers to create per-block lifted entry operands
- ✅ 1.6 Add builder helpers to assign predecessor values into lifted entry operands
- ✅ 1.7 Add builder helpers to spill tracked logical stack values back to `EVMInstance`
- ✅ 1.8 Add builder helpers to synchronize tracked runtime stack depth/top state after spill
- ✅ 1.9 Initialize lifted block state from analyzer output under `ZEN_ENABLE_EVM_STACK_SSA_LIFT`
- ✅ 1.10 Restore logical stack from lifted entry state for liftable blocks and keep the legacy runtime-stack entry path for fallback blocks
- ✅ 1.11 Transfer logical stack state across safe constant-jump and fallthrough edges without immediate runtime materialization
- ✅ 1.12 Materialize conservatively on unsupported edges and before fallback/exception/return boundaries
- ✅ 1.13 Keep `POP` / `DUP` / `SWAP` stack manipulation on the logical stack path where possible instead of opcode-level runtime stack access
- ✅ 1.14 Add analyzer regressions for `JUMPDEST` canonicalization, safe constant-jump edge modeling, hidden entry prefixes, merge-depth conflicts, and dynamic-jump fallback cases
- ✅ 1.15 Add visitor regressions covering non-lifted logical-stack behavior and lifted entry-state restoration

## 2. Validation Completed for this Change
- ✅ 2.1 Build the focused frontend test target for this change
- ✅ 2.2 Validate the focused frontend regression suite used as the acceptance scope for this change
