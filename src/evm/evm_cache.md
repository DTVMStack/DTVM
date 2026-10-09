# EVM Bytecode Cache Design

This document describes the bytecode cache built by `buildBytecodeCache()` in `src/evm/evm_cache.cpp` and used by `BaseInterpreter::interpret()` in `src/evm/interpreter.cpp` as well as the EVM JIT compiler in `src/compiler/evm_compiler.cpp`.

The current SPP design fixes two unsafe gas-shifting boundary classes with 0%
`GasBlock` size growth; the structure remains 32 bytes. Retain both the
unresolved-source guard and the implicit-target predecessor guard because
removing either can make gas placement unsound.

## Layout

- `JumpDestMap[pc]` (`uint8_t`): `1` if `Code[pc]` is `OP_JUMPDEST` and this byte is an opcode byte (not inside PUSH data).
- `PushValueMap[pc]` (`intx::uint256`): decoded immediate for `PUSH1..PUSH32` at `pc`. Unused entries are `0`.
- `GasChunkEnd[pc]` (`uint32_t`): for a chunk start `pc`, the exclusive end PC of the chunk; otherwise `0`.
- `GasChunkCost[pc]` (`uint64_t`): unshifted base gas cost of the block starting at `pc` (sum of EVMC base costs of opcodes in the block); otherwise `0`. Read by the interpreter.
- `GasChunkCostSPP[pc]` (`uint64_t`): SPP-shifted gas cost of the block starting at `pc`. Populated only when the SPP metering pipeline runs (JIT-consumer modules); otherwise the array is empty. Read by the multipass JIT.

## Build Algorithm

### 1) `JumpDestMap` and `PushValueMap`

We scan `Code` linearly and treat `PUSHn` payload bytes as non-opcode bytes:

- If the current opcode byte is `JUMPDEST`, mark `JumpDestMap[pc] = 1`.
- If the opcode is `PUSHn`, decode up to `n` following bytes into `PushValueMap[pc]` and skip over the payload (`pc += n` in the scan).

This matches the EVM rule that jump destinations must be to a `JUMPDEST` opcode byte, never into immediate data.

### 2) Gas chunks (`GasChunkEnd` / `GasChunkCost`)

We still partition the bytecode into straight-line "gas blocks":

- A block always contains at least one opcode.
- A block starts at `pc = 0` and at every opcode-byte `JUMPDEST`.
- A block stops after executing any of these barrier opcodes:
  - `STOP`, `RETURN`, `REVERT`, `SELFDESTRUCT`
  - `INVALID`
  - `JUMP`, `JUMPI`
  - `GAS`
  - `SSTORE`
  - `CREATE`, `CREATE2`
  - `CALL`, `CALLCODE`, `DELEGATECALL`, `STATICCALL`

For each block start `s`, `GasChunkEnd[s]` is the exclusive end PC of that
block.
Critical-edge splitting may insert empty CFG blocks for SPP analysis; these are
internal and do not correspond to bytecode PCs.

#### SPP-based charging

SPP refers to an algorithm that satisfies the three properties: safety,
precision, and polynomial-time complexity. In this context, SPP performs static
analysis on the CFG to reorder where base gas is charged, reducing per-opcode
metering into a smaller set of key charge points while preserving safety on
every execution path.

We build a CFG of gas blocks and compute a *shifted* metering function `m`
using a linear-time SPP pass:

- Edges: fallthrough edges, including `JUMPI` fallthrough, are explicit.
  Resolved jump-target edges (single-target `ResolvedJumpTargets` and
  ConstSet `ResolvedJumpMultiTargets`) are also explicit after validation by
  `JumpDestMap`. Target edges for an unresolved dynamic `JUMP` or `JUMPI` are
  omitted. The source is marked with `HasUnresolvedDynamicSuccessor`, and each
  possible `JUMPDEST` target carries the corresponding
  `ImplicitDynamicPredCount`. The cross-block worklist (`EnableR1`, default
  on) is fail-closed: a reached `Top` dest or a non-converged fixpoint
  commits nothing beyond the block-local pass.
- Critical edges are split before SPP to preserve the local update rules.
- Dominators are computed by the Cooper-Harvey-Kennedy (CHK) algorithm
  (`computeDomInfo` in `evm_cache.cpp`): iterate `IDom[b] = NCA(p, IDom[b])`
  over the reverse-postorder predecessor set until convergence. The reaching
  fixpoint typically settles in 2-3 passes for reducible CFGs and degrades
  gracefully on irreducible cycles. Output is a packed `IDom[]` array plus
  Tarjan DFS Enter/Exit intervals (`DomEnter[]` / `DomExit[]`) so that
  `dominates(a, b)` queries answer in `O(1)` via interval containment. Each
  CHK fixpoint sweep is `O(N + E)`; the number of sweeps `R` is workload-
  dependent (`R = 2` on every measured workload, logged via the
  `chkFixpointRounds` counter), worst-case bounded by the dominator-tree
  depth. Memory is `O(N)`. Both compare favourably with the prior
  iterative-bitset dataflow's `O(N²/64)` time and `O(N²)` memory.
  Natural loops are then computed from `IDom[]` via the standard back-edge
  walk (`buildLoopsUsingDominance`). The pass scans nodes in reverse
  topological order:
  - Non-loop nodes get a single Lemma 6.14 update.
  - Loop nodes are recorded; once all loop members are recorded and all exits
    have been seen, the loop is "fast-forwarded" by applying Lemma 6.14 updates
    to the loop nodes in local reverse-topological order.

#### Optional per-phase wall-clock instrumentation

When the project is configured with `-DZEN_EVM_CACHE_PROFILE=ON`, the build
emits a CSV row per named phase to stderr:

    EVM_CACHE_PROFILE,<phase>,<microseconds>

Named phases: `buildJumpDestMap`, `resolveJumpTargetsCrossBlock`, `buildGasBlocks`, `buildCFGEdges`,
`splitCriticalEdges`, `buildCSR`, `computeReachable`, `computeDomInfo`,
`findBackEdges`, `computeReverseTopo`, `buildLoopsUsingDominance`,
`computeInCycle`, `meteringInit`, `lemma614Schedule`, `writeback`. When `OFF`
(default), the macros expand to `((void)0)` and the release build is
bytecode-identical to the un-instrumented variant — used to drive
`tools/bench_evm_cache.sh` and `tools/analyze_evm_cache_bench.py` for
paired-ratio cluster-bootstrap BCa analysis (see `tests/corpus/evm-cache/`).

This moves common costs earlier, reducing the number of non-zero charge points.
The resulting shifted value `m(s)` is stored in `GasChunkCostSPP[s]` at each
block start; `GasChunkCost[s]` continues to hold the unshifted base cost so
the interpreter fast path is unaffected. The SPP pipeline only runs for
modules that will be JIT-compiled (gated by `EnableSPP` in
`buildBytecodeCache`); for interpreter-only modules `GasChunkCostSPP` is
left empty and the CFG / metering work is skipped.

`UseLinearSPP=true` means only that the detected dominance-based natural loops
passed their body-dominance and nesting checks; it is not a general CFG
reducibility proof. In this path, `InCycle` is the union of the detected loop
masks. If those checks fail, a two-pass Kosaraju-style SCC traversal computes
`InCycle`, and SPP updates only non-cycle nodes in reverse topological order
without loop fast-forward.

## Design Goal

This cache targets the interpreter hot loop: it pre-decodes `PUSHn` immediates
and precomputes straight-line chunks of EVMC base gas so execution avoids
repeated decoding and per-opcode base gas charging. The implementation uses
PC-indexed vectors for deterministic O(n) construction and O(1) lookups.
`JumpDestMap` centralizes `JUMPDEST` validation (skipping PUSH data) to prevent
invalid jumps into immediates.

## Correctness

### Jump destination validation

`JumpDestMap` is built by scanning with correct opcode lengths (`PUSHn`
consumes `1 + n` bytes), so bytes inside PUSH immediates are never treated as
opcodes. This makes `JumpDestMap[pc]` an exact marker of opcode-byte
`JUMPDEST`s, matching the EVM rule that `JUMP`/`JUMPI` destinations must be to a
`JUMPDEST` opcode byte, never into immediate data.

### Correct `PUSHn` immediate decoding

For `PUSHn`, the EVM reads the next `n` bytes as a big-endian immediate; if
fewer than `n` bytes exist, missing bytes are treated as zero. `loadPushValue()`
loads the available bytes and left-shifts by `8 * (n - available)` to append
zero bytes on the right, matching the EVM encoding.

### Correctness of chunk gas charging

`GasChunkCost[s]` is always the unshifted base cost of block `s`, so the
interpreter's fast path enters a chunk only when `gas_left >= GasChunkCost[s]`
and base-cost out-of-gas cannot occur inside a block. The multipass JIT reads
the shifted value `m(s)` from `GasChunkCostSPP[s]`. Lemma 6.14 updates move
cost along represented CFG edges while preserving total base cost on accepted
paths. An unresolved dynamic source has
`HasUnresolvedDynamicSuccessor != 0`, so it cannot receive shifted successor
cost when runtime targets are absent from the explicit CFG.
`effectivePredCount` includes `ImplicitDynamicPredCount`, so a possible dynamic
target cannot receive a shift from only one represented predecessor. `SSTORE`
is also a gas-sensitive boundary because the EIP-2200 sentry depends on the gas
remaining at that instruction. Splitting critical edges and the loop schedule
retain the local update preconditions; the SCC fallback skips cycle nodes and
applies per-node updates without fast-forward. Dynamic and extra gas remain
charged inside opcode handlers as before (memory expansion, cold access,
keccak word cost, and related charges).
