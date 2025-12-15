# EVM Interpreter Cache Design

This document describes the interpreter cache built by `buildInterpreterCache()` in `src/evm/evm_cache.cpp` and used by `BaseInterpreter::interpret()` in `src/evm/interpreter.cpp`.

## Layout

- `JumpDestMap[pc]` (`uint8_t`): `1` iff `Code[pc]` is `OP_JUMPDEST` and this byte is an opcode byte (not inside PUSH data).
- `PushValueMap[pc]` (`intx::uint256`): decoded immediate for `PUSH1..PUSH32` at `pc`. Unused entries are `0`.
- `GasChunkEnd[pc]` (`uint32_t`): for a chunk start `pc`, the exclusive end PC of the chunk; otherwise `0`.
- `GasChunkCost[pc]` (`uint64_t`): sum of EVMC base gas costs for opcodes in the chunk starting at `pc`; otherwise `0`.

## Build Algorithm

### 1) `JumpDestMap` and `PushValueMap`

We scan `Code` linearly and treat `PUSHn` payload bytes as non-opcode bytes:

- If the current opcode byte is `JUMPDEST`, mark `JumpDestMap[pc] = 1`.
- If the opcode is `PUSHn`, decode up to `n` following bytes into `PushValueMap[pc]` and skip over the payload (`pc += n` in the scan).

This matches the EVM rule that jump destinations must be to a `JUMPDEST` opcode byte, never into immediate data.

### 2) Gas chunks (`GasChunkEnd` / `GasChunkCost`)

We partition the bytecode into straight-line "chunks" starting at some `ChunkStart` and ending at `ChunkEnd`:

- A chunk always contains at least one opcode.
- A chunk stops *before* a `JUMPDEST` that is not the first opcode of the chunk, so every `JUMPDEST` begins a chunk.
- A chunk stops after executing any of these terminator opcodes:
  - `STOP`, `RETURN`, `REVERT`, `SELFDESTRUCT`
  - `INVALID`
  - `JUMP`, `JUMPI`
  - `GAS`
  - `CREATE`, `CREATE2`
  - `CALL`, `CALLCODE`, `DELEGATECALL`, `STATICCALL`

For each chunk start `s`, we compute:

`GasChunkCost[s] = Σ metrics[opcode_at(pc)].gas_cost` for `pc` in the chunk, where `metrics = evmc_get_instruction_metrics_table(DEFAULT_REVISION)` (and opcode lengths account for `PUSHn`).

The interpreter can then:

If `gas_left >= GasChunkCost[pc]`, charge `GasChunkCost[pc]` once at chunk
entry and execute the opcodes in that range using `doExecute()` / no-gas
helpers. Otherwise, fall back to the normal per-opcode charging path.

Extra/dynamic gas (memory expansion, cold/warm access, etc.) is still charged inside individual opcode handlers, on-demand.

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

For a chunk starting at `s`, `GasChunkCost[s]` is the sum of EVMC base gas costs
for opcodes in that straight-line region. The fast path is used only when
`gas_left >= GasChunkCost[s]`, so base-cost out-of-gas cannot occur inside the
chunk. Charging the sum upfront is equivalent to charging base gas before each
opcode because base costs are non-negative (so the sum implies every prefix) and
the chunk boundaries exclude opcodes that would observe the difference (e.g.,
`GAS` and control-flow/host opcodes terminate the chunk).

When `gas_left < GasChunkCost[s]`, the interpreter falls back to per-opcode
charging, preserving the original exception ordering in low-gas cases (i.e., it
does not return out-of-gas at chunk entry when an earlier non-gas exceptional
condition would be hit while stepping through the chunk).

Dynamic/extra gas is still charged at execution time inside opcode handlers
(e.g., cold access penalties, memory expansion, keccak word cost). If out-of-gas
occurs there, the execution fails at that opcode as required.
