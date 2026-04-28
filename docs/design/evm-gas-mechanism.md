# EVM Gas Mechanism (Interpreter and JIT)

This document describes how DTVM accounts for EVM gas in both the
interpreter and the multipass JIT, and how the SPP (Structured
Precharging Pass) shifts charges along the control-flow graph for the
JIT consumer while keeping the interpreter's per-block totals
unchanged.

## Goals

- Charge each EVM execution path the exact gas the spec requires.
- Detect Out-Of-Gas (OOG) before any state change occurs.
- Amortize the per-opcode "is there enough gas?" check across
  straight-line code so the hot path reduces to one comparison per
  basic block (interpreter) or per chunk start (JIT).

## Shared data: the bytecode cache

Both execution engines read from a single
`zen::evm::EVMBytecodeCache` (`src/evm/evm_cache.h`). The cache is
built lazily on first access via `EVMModule::initBytecodeCache`
(`src/runtime/evm_module.cpp:117-135`) and exposes four parallel
arrays indexed by program counter (PC):

| Field            | Indexed by | Meaning                                                                                 |
| ---------------- | ---------- | --------------------------------------------------------------------------------------- |
| `JumpDestMap`    | PC         | 1 if a `JUMPDEST` opcode begins at this PC, else 0.                                     |
| `PushValueMap`   | PC         | The 256-bit immediate decoded from a `PUSH*` at this PC (otherwise 0).                  |
| `GasChunkEnd`    | chunk-start PC | Exclusive end PC of the gas chunk that starts here. Zero for non-chunk-start PCs.  |
| `GasChunkCost`   | chunk-start PC | **Unshifted** sum of opcode gas costs in the chunk (interpreter consumer).         |
| `GasChunkCostSPP`| chunk-start PC | **SPP-shifted** chunk cost (JIT consumer). Empty when SPP is disabled for this module. |

A "gas chunk" is a maximal straight-line region with no internal
control-flow boundary that can change gas obligations: it ends at
`JUMP`/`JUMPI`/`STOP`/`RETURN`/`REVERT`/`SELFDESTRUCT`/`INVALID`,
just before a `JUMPDEST`, before `SSTORE`/`CALL`/`CREATE`/`GAS`
(opcodes whose actual cost depends on runtime state), or at the end
of the bytecode.

```mermaid
flowchart LR
    Bytecode["EVM bytecode"]
    JD[JumpDestMap]
    PV[PushValueMap]
    CE[GasChunkEnd]
    CC[GasChunkCost\n(unshifted)]
    SPP[GasChunkCostSPP\n(shifted, optional)]

    Bytecode --> Builder["buildBytecodeCache\n(src/evm/evm_cache.cpp)"]
    Builder --> JD
    Builder --> PV
    Builder --> CE
    Builder --> CC
    Builder -. "EnableSPP=true" .-> SPP

    JD --> Interpreter
    PV --> Interpreter
    CE --> Interpreter
    CC --> Interpreter

    JD --> JIT["Multipass JIT\n(EVMMirBuilder)"]
    PV --> JIT
    CE --> JIT
    CC --> JIT
    SPP --> JIT
```

The two consumers read disjoint chunk-cost arrays so neither
perturbs the other. Concretely:

- The interpreter reads only `GasChunkCost` (`src/evm/interpreter.cpp:382`).
- The JIT prefers `GasChunkCostSPP` when non-null and falls back to
  `GasChunkCost` otherwise (`src/compiler/evm_frontend/evm_mir_compiler.cpp:534, 578, 1315`).

## Interpreter mode

The interpreter runs the dispatch loop in
`BaseInterpreter::interpret` (`src/evm/interpreter.cpp:362`). Each
outer iteration starts at `Frame->Pc` and tries the **chunk fast
path** first:

```mermaid
flowchart TD
    Start([outer iter\nPc = ChunkStartPc]) --> Q1{ChunkStartPc\nis a chunk start?\n(GasChunkEnd[Pc] > Pc)}
    Q1 -- "no" --> Slow["Per-opcode dispatch\n(switch/handler call)\nchargeGas(opcode metric)"]
    Slow --> SlowOOG{gas < cost?}
    SlowOOG -- "yes" --> OOG[setStatus(EVMC_OUT_OF_GAS)\nbreak]
    SlowOOG -- "no" --> Pcpp[Frame->Pc++]
    Pcpp --> Start

    Q1 -- "yes" --> Q2{Frame->Msg.gas\n>= GasChunkCost[Pc]?}
    Q2 -- "no" --> OOG
    Q2 -- "yes" --> Pre["Frame->Msg.gas -= GasChunkCost[Pc]\n(pre-charge entire chunk)"]
    Pre --> CG["Computed-goto fast path\nuntil Pc >= ChunkEnd"]
    CG --> Restart{control-flow\nopcode hit?}
    Restart -- "no" --> Start
    Restart -- "yes (JUMP/JUMPI/...)\nupdate Pc, restart" --> Start
```

Key properties:

- Inside a chunk, **no gas check happens per opcode** — the chunk's
  total has already been deducted at the chunk start. The
  computed-goto loop simply executes opcodes, advances `Pc`, and
  checks `Pc >= ChunkEnd` to exit
  (`DISPATCH_NEXT` macro at `src/evm/interpreter.cpp:525`).
- For opcodes whose cost depends on runtime state (`SSTORE`, `CALL*`,
  `CREATE*`, dynamic memory growth), a chunk boundary is forced
  before them so their dynamic gas can be charged separately by the
  per-handler `chargeGas` calls
  (`src/evm/interpreter.cpp:33-50`).
- The interpreter intentionally consumes the **unshifted** cost
  (PR #371). Shifting costs across blocks would charge gas for an
  opcode before that opcode runs, which is observable to users via
  the `GAS` opcode mid-chunk and via `gas_left` reported by callbacks.

## Multipass JIT mode

The JIT lowers EVM bytecode to dMIR via `EVMMirBuilder`
(`src/compiler/evm_frontend/evm_mir_compiler.{h,cpp}`). Gas accounting
is woven into MIR generation by two helpers:

- `meterOpcode(Opcode, PC)` — emit the gas check for one opcode at
  `PC` (`src/compiler/evm_frontend/evm_mir_compiler.cpp:528`).
- `meterOpcodeRange(StartPC, EndPCExclusive)` — emit the gas check
  for a contiguous PC range, used by the JUMPDEST run optimization
  (`src/compiler/evm_frontend/evm_mir_compiler.cpp:548`).

Both ultimately call `meterGas(Cost)` to emit the actual dMIR
sequence (`src/compiler/evm_frontend/evm_mir_compiler.cpp:607`):

```mermaid
flowchart TD
    A["meterOpcode(Op, PC)"] --> B{GasMeteringEnabled?}
    B -- "no" --> X([return])
    B -- "yes" --> C{PC < GasChunkSize\n&& GasChunkEnd[PC] > PC?}
    C -- "no (mid-chunk PC)" --> D["Cost = InstructionMetrics[Op].gas_cost\nmeterGas(Cost)"]
    C -- "yes (chunk start)" --> E["Cost = GasChunkCostSPP[PC]\n  ?? GasChunkCost[PC]\nmeterGas(Cost)"]
    D --> Emit
    E --> Emit

    Emit["meterGas(Cost)\nemit dMIR:\n  CurrentGas = load gas\n  IsOutOfGas = (CurrentGas < Cost)\n  brif IsOutOfGas, OOGBlock, ContinueBlock\n  NewGas = CurrentGas - Cost\n  store NewGas"]
    Emit --> Cont([fall through to opcode lowering])
```

Two consequences:

1. The JIT emits **at most one gas check per chunk** — the call at
   the chunk-start opcode covers every opcode up to (but not
   including) the next chunk start. Calls inside the chunk see
   `GasChunkEnd[PC] == 0` and short-circuit out of `meterOpcode`.
   The `JUMPDEST` run suffix-sum precompute
   (`JumpDestRunLastPC`/`JumpDestRunSkipCost`,
   `evm_mir_compiler.cpp:548-572`) lets the dispatcher skip a whole
   run of consecutive `JUMPDEST`s with one `meterGas` call.
2. The OOG branch is shared across all gas checks in the function
   via `getOrCreateExceptionSetBB(ErrorCode::GasLimitExceeded)`,
   keeping the cold path out of the hot block layout
   (`evm_mir_compiler.cpp:626, 663`).

When the build is configured with `ZEN_ENABLE_EVM_GAS_REGISTER`, the
gas value lives in a virtual register instead of being reloaded from
memory on every check; the synchronization to `EVMInstance` happens
only at `CALL`/`CREATE`/return boundaries
(`evm_mir_compiler.cpp:614-642`).

## SPP cost shifting

The Structured Precharging Pass — implemented as `lemma614Update` in
`src/evm/evm_cache.cpp:919` — moves gas costs **backwards** along the
CFG. For each non-cycle node, it charges the minimum successor cost
upfront, so the consumer only pays the residual at runtime:

```
                 Block A (cost = 3)
                /                \
       Block B (5)            Block C (7)

After SPP (min successor = 5 charged at A):

                 Block A' (cost = 3 + 5 = 8)
                /                \
       Block B' (0)           Block C' (2)
```

Per-path totals are preserved: A→B is `3+5 = 8` before and
`8+0 = 8` after; A→C is `3+7 = 10` before and `8+2 = 10` after. The
benefit is that B's chunk now starts with cost zero, which lets
`meterGas` short-circuit and emit no dMIR at all
(`evm_mir_compiler.cpp:608`), and C's chunk only needs to charge the
residual `2`. The JIT therefore emits fewer non-trivial gas checks
on the hot path and shrinks the OOG fan-out.

Soundness on cycles: the shift never crosses back-edges or
gas-chunk terminators (`SSTORE`/`CALL*`/`CREATE*`/`GAS`), so dynamic
gas is always charged at the correct point
(`evm_cache.cpp:421-427, 919-960`).

### Why a separate `GasChunkCostSPP` array

The interpreter's chunk fast path was specified against the
**unshifted** per-block cost in PR #371 and the cache must continue
to honour that contract. To enable SPP for the JIT without
disturbing the interpreter, the cache exposes two parallel arrays:

- `GasChunkCost` — unshifted, written from `Blocks[Id].Cost`
  (`evm_cache.cpp:1161`), consumed by the interpreter.
- `GasChunkCostSPP` — shifted, written from the metering function
  `Metering[Id]` (`evm_cache.cpp:1165`), consumed by the JIT.

The shifted variant is sound for the JIT because SPP refuses to
shift cost across **gas-sensitive terminators**: `GAS`, `CALL*`,
`CREATE*` (`isGasSensitiveTerminator` and `isGasChunkTerminator`
checks at `evm_cache.cpp:944, 966`). Each of these opcodes ends its
own chunk, so by the time it executes the chunk's cost — shifted or
not — has already been deducted at the chunk-start `meterGas`, and
the value the opcode reads (e.g. `GAS`) reflects the spec-mandated
remaining gas. Cost from the *successor* chunk never leaks back
across the terminator.

### Mixed-precision CFG

The SPP pass needs a sound CFG to compute "minimum successor cost"
correctly:

```mermaid
flowchart LR
    subgraph Static[Static jump]
      P1[PUSH dest_pc] --> J1[JUMP]
      J1 -. resolved .-> D1[JUMPDEST at dest_pc]
    end

    subgraph Dynamic[Dynamic jump]
      X[stack-derived target] --> J2[JUMP]
      J2 -. over-approx .-> D2[every JUMPDEST]
    end
```

- `PUSH n; JUMP` resolves to a single edge to `JUMPDEST` at PC `n`
  (`resolveConstantJumpTarget` in `evm_cache.cpp`).
- Every other dynamic `JUMP` gets edges to **all** `JUMPDEST`
  blocks (`buildCFGEdges`, `evm_cache.cpp:386-429`).

Narrowing dynamic-jump edges using partial call-site information
would under-approximate the CFG and let SPP shift charges along
runtime-impossible edges, which breaks the per-path total invariant.
The over-approximation is intentional and documented inline
(`evm_cache.cpp:419-427`).

## Pipeline gating

The SPP CFG construction and shifting pass is significant compile-
time work and is only useful for the JIT consumer. Interpreter-only
modules skip it via `EVMModule::CacheNeedsSPP`:

```mermaid
sequenceDiagram
    participant Loader as EVMModule::create
    participant Mod as EVMModule
    participant Cache as EVMBytecodeCache
    participant JIT as performEVMJITCompile

    Loader->>Mod: construct (CacheNeedsSPP=false)
    alt RunMode != InterpMode
        Loader->>Mod: EVMAnalyzer.analyze()
        alt JIT-suitable
            Loader->>Mod: CacheNeedsSPP = true
            Loader->>JIT: performEVMJITCompile(Mod)
            JIT->>Cache: getBytecodeCache()
            Cache->>Cache: buildBytecodeCache(EnableSPP=true)
            Note right of Cache: builds CFG, runs SPP,<br/>fills GasChunkCostSPP
            Cache-->>JIT: cache (with SPP)
        end
    end

    Note over Loader,Cache: First call to interpreter only:
    Loader->>Cache: getBytecodeCache()
    Cache->>Cache: buildBytecodeCache(EnableSPP=false)
    Note right of Cache: skips CFG/SPP,<br/>GasChunkCostSPP stays empty
```

`evm_compiler.cpp` passes `nullptr` for the SPP pointer when the
array is empty
(`src/compiler/evm_compiler.cpp:70-74`), so a JIT compilation that
runs without SPP (e.g. JIT bypass paths) cleanly falls back to the
unshifted array and remains correct.

## Failure mode summary

| Trigger                                               | Where                                                              | Result                                       |
| ----------------------------------------------------- | ------------------------------------------------------------------ | -------------------------------------------- |
| Interpreter chunk-start, gas < `GasChunkCost[Pc]`     | `interpreter.cpp:397-398`                                          | Exit outer loop, `setStatus(EVMC_OUT_OF_GAS)` |
| Interpreter slow path, gas < per-opcode cost          | `chargeGas` at `interpreter.cpp:33-50`                             | Same                                         |
| JIT chunk-start `meterGas`, gas < `Cost`              | `meterGas` `IsOutOfGas` branch (`evm_mir_compiler.cpp:622-631`)    | Branch to shared `OutOfGasBB`                 |
| JIT mid-chunk per-opcode `meterGas`, gas < `Cost`     | Same code path, just smaller `Cost`                                 | Same shared `OutOfGasBB`                      |
| Dynamic-cost opcode (SSTORE/CALL*/CREATE*) underpaid  | Forced chunk boundary; charged by handler call                     | Returns OOG status to dispatcher              |

## References

- `src/evm/evm_cache.{h,cpp}` — bytecode cache, CFG construction,
  `buildGasChunksSPP`, `lemma614Update`.
- `src/evm/interpreter.cpp` — chunk fast path (line 395), per-opcode
  `chargeGas` (line 33).
- `src/compiler/evm_frontend/evm_mir_compiler.{h,cpp}` —
  `meterOpcode`, `meterOpcodeRange`, `meterGas`.
- `src/runtime/evm_module.{h,cpp}` — `CacheNeedsSPP` gating before
  `performEVMJITCompile`.
- `src/compiler/evm_compiler.cpp:70-74` — JIT-side `nullptr` fallback
  for empty `GasChunkCostSPP`.
- `docs/changes/2026-04-05-gas-check-placement/README.md` — design
  notes and benchmark results for the mixed-CFG / dual-array split.
- `docs/modules/evm/spec.md` — module spec for the EVM bytecode cache.
