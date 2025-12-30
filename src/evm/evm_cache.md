# EVM Bytecode Cache Design

This document describes the bytecode cache built by `buildBytecodeCache()` in `src/evm/evm_cache.cpp` and used by `BaseInterpreter::interpret()` in `src/evm/interpreter.cpp` as well as the EVM JIT compiler in `src/compiler/evm_compiler.cpp`.

## Layout

- `JumpDestMap[pc]` (`uint8_t`): `1` iff `Code[pc]` is `OP_JUMPDEST` and this byte is an opcode byte (not inside PUSH data).
- `PushValueMap[pc]` (`intx::uint256`): decoded immediate for `PUSH1..PUSH32` at `pc`. Unused entries are `0`.
- `GasChunkEnd[pc]` (`uint32_t`): for a chunk start `pc`, the exclusive end PC of the chunk; otherwise `0`.
- `GasChunkCost[pc]` (`uint64_t`): metering cost charged at block start `pc` (SPP-shifted in optimized mode); otherwise `0`.

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

- Edges: fallthrough edges (including `JUMPI` fallthrough) and constant-jump
  edges (validated by `JumpDestMap`). Dynamic jumps are conservatively
  over-approximated to all `JUMPDEST` blocks.
- Critical edges are split before SPP to preserve the local update rules.
- Dominators and natural loops are computed from the CFG. The pass scans nodes
  in reverse topological order:
  - Non-loop nodes get a single Lemma 6.14 update.
  - Loop nodes are recorded; once all loop members are recorded and all exits
    have been seen, the loop is "fast-forwarded" by applying Lemma 6.14 updates
    to the loop nodes in local reverse-topological order.

This moves common costs earlier, reducing the number of non-zero charge points.
The resulting `m` is stored in `GasChunkCost` at each block start.

If the CFG is not suitable for linear SPP (e.g., dominance-based loop analysis
fails), we still run SPP updates once per node in reverse topological order
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

In SPP mode, `GasChunkCost[s]` is the shifted metering value `m(s)`. Lemma 6.14
updates move cost along CFG edges while preserving total base cost on every
path. Over-approximating dynamic jumps keeps the optimization safe (it may
reduce shifts but never undercharges). Splitting critical edges ensures that
cost is only moved along edges where the local update is valid. When loop
analysis fails, the reverse-topological updates still preserve correctness
without fast-forward.

The fast path is still used only when `gas_left >= GasChunkCost[s]`, so base-cost
out-of-gas cannot occur inside a block. Dynamic/extra gas is charged inside
opcode handlers as before (memory expansion, cold access, keccak word cost, etc).
