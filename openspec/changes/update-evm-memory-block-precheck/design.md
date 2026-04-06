## Context

The EVM multipass frontend already performs per-op memory expansion checks in `handleMLoad()`, `handleMStore()`, `handleMStore8()`, and `handleMCopy()`. Each path computes a required size, computes or combines an overflow condition, and calls `expandMemoryIR(...)`.

That structure is semantically correct, but it duplicates the same expansion-control CFG when a straight-line basic block contains multiple direct-memory operations whose required sizes can be proven locally at compile time.

Week 1 and Week 2 analysis narrowed the practical first step:

- stay entirely inside one existing analyzer-defined basic block
- avoid helper-sensitive opcodes that may complicate memory-size consistency
- support only direct-memory ops whose required size can be derived from a compile-time constant address
- keep all unsupported patterns on the original path

This design documents the implementation that now exists in the frontend, including the recent correctness fixes around terminators, malformed `PUSHn`, diagnostics gating, and condition typing.

## Goals

- Hoist one shared memory precheck for a narrow, provably safe subset of direct-memory blocks
- Reuse existing analyzer block boundaries rather than creating a new CFG pass
- Preserve overflow behavior, gas charging, aligned growth, and helper semantics
- Keep unsupported or ambiguous cases on the original per-op path
- Keep diagnostics available in logging builds without making them part of the optimization contract

## Non-Goals

- Whole-function or loop-aware memory check hoisting
- Support for dynamic-address recurrence patterns
- Optimization of helper-sensitive blocks
- Coverage for `MCOPY` in the shared precheck path
- Runtime helper redesign
- Backend condition-type refactoring

## Existing Behavior

Before this change, each eligible direct-memory opcode independently emitted:

1. required-size computation
2. overflow detection
3. `expandMemoryIR(...)`
4. `NeedExpand` compare and associated CFG

This remains the fallback behavior for every non-covered case.

## Design Overview

The implementation has two layers:

1. A visitor-side planning phase at basic-block entry
2. A builder-side consumption phase during opcode lowering

### Planning layer

At `handleBeginBlock(...)`, the visitor:

1. opens a block-local memory compile scope with `beginMemoryCompileBlock(PC)`
2. runs `analyzeConstDirectMemoryBlockPrecheck(...)`
3. if the scan succeeds and is eligible, installs the plan via:
   - `setMemoryCompileBlockConstPrecheckPlan(MaxRequiredSize, CoveredDirectOps)`

### Consumption layer

When lowering covered direct-memory ops, the builder calls `tryConsumeConstBlockMemoryPrecheck()`.

If a plan is active and not yet emitted:

1. create `RequiredSize` as an `I64` constant from `MaxRequiredSize`
2. create `NoOverflow` as an `I64` zero constant
3. call `expandMemoryIR(RequiredSize, NoOverflow)`
4. mark the plan as emitted

For each subsequent covered op:

- decrement `CoveredDirectOpsRemaining`
- skip the opcode's original per-op `expandMemoryIR(...)` path

When the remaining count reaches zero, the plan is deactivated.

## Eligibility Model

The implementation is intentionally conservative.

An eligible block must satisfy all of the following:

1. The scan begins at a real analyzer-defined block entry
2. The scan stays within a single basic block
3. The block contains no helper-sensitive opcode
4. Every covered direct-memory address is locally known as a constant `uint64_t`
5. Every required-size addition succeeds without `uint64_t` overflow
6. The block contains at least two covered direct-memory ops

If any condition fails, planning returns an empty plan and the original codegen path is preserved.

## Supported Opcode Set

### Covered direct-memory ops

The precheck planner currently covers:

- `MLOAD`
- `MSTORE`
- `MSTORE8`

### Recognized but not covered

- `MSIZE` is modeled in the local scan as producing an unknown value
- `MCOPY` is tracked by diagnostics but is not part of the block-local shared precheck implementation

### Helper-sensitive barriers

The scan immediately fails if it sees helper-sensitive opcodes, including the families already classified by the visitor for diagnostics:

- `LOG0` to `LOG4`
- `KECCAK256`
- `CALLDATACOPY`
- `CODECOPY`
- `EXTCODECOPY`
- `RETURNDATACOPY`
- `CALL`
- `CALLCODE`
- `DELEGATECALL`
- `STATICCALL`
- `CREATE`
- `CREATE2`

These stay on the original path because they are not part of the first safe optimization envelope.

## Basic-Block Scan Logic

The visitor performs a local abstract stack simulation over bytecode starting from the block entry PC.

### Scan stop conditions

The scan stops or fails under these conditions:

1. A `JUMPDEST` is encountered after the entry instruction
   - this marks the next basic block
2. A helper-sensitive opcode is encountered
   - planning fails immediately
3. A block terminator is encountered
   - the scan exits the block
4. An unsupported opcode or unsupported stack effect is encountered
   - planning fails immediately

### Terminator set

The implemented terminator set is:

- `JUMP`
- `JUMPI`
- `RETURN`
- `STOP`
- `INVALID`
- `REVERT`
- `SELFDESTRUCT`

`JUMPI` is explicitly included so the scan cannot continue incorrectly into the fallthrough region of a new basic block.

## PUSH and Stack Simulation Rules

The planner uses a local `AbstractConstU64` stack with known/unknown lattice values.

### Constant producers

- `PUSH0` produces known zero
- `PUSH1` to `PUSH8` attempt to parse the immediate into a known `uint64_t`
- `ADD` and `SUB` propagate known results only when they remain conservatively safe

### Unknown producers

- `PUSH9` to `PUSH32` produce unknown values
- `MSIZE` produces unknown
- any arithmetic that cannot be proven in the local model produces unknown

### Malformed and truncated bytecode handling

The scan rejects malformed `PUSHn` sequences conservatively:

- `parsePushConstU64(...)` rejects `PUSH1` to `PUSH8` when the immediate would run past `BytecodeSize`
- `PUSH9` to `PUSH32` are also guarded before `ScanPC += NumBytes`
- if the immediate is truncated, the planner returns an empty plan

This is a correctness requirement, not an optimization preference. A malformed or truncated block must never be marked eligible.

## MaxRequiredSize Computation

For each covered direct-memory op, the planner computes a required size:

- `MLOAD(addr)` → `addr + 32`
- `MSTORE(addr, value)` → `addr + 32`
- `MSTORE8(addr, value)` → `addr + 1`

`addConstU64(...)` is used for these additions so the planner can reject any `uint64_t` overflow instead of silently wrapping.

`Plan.MaxRequiredSize` is updated as the maximum required size across all covered ops in the block.

This value is then passed to the builder as one block-level `RequiredSize` constant.

## Code Generation Semantics

### Covered path

For covered direct-memory ops:

1. The first covered op emits one shared `expandMemoryIR(MaxRequiredSize, 0)`
2. Later covered ops reuse the prechecked state by skipping their local pre-expansion path

### Uncovered path

If no plan is active, or if coverage has been exhausted, each opcode retains its original path:

- compute `RequiredSize`
- compute per-op `Overflow`
- call `expandMemoryIR(RequiredSize, Overflow)`

### What is skipped after coverage

For covered `MLOAD`, `MSTORE`, and `MSTORE8`, the optimization skips the redundant opcode-local:

- per-op expansion counter increment path
- per-op `expandMemoryIR(...)` call
- per-op `NeedExpand` CFG generated as part of that call

### What is not skipped

The optimization does not remove:

- the shared block-level `expandMemoryIR(...)`
- actual gas charging inside `expandMemoryIR(...)`
- the final memory access itself
- non-covered opcode logic
- helper-sensitive behavior

## Condition and Overflow Typing

The implementation must match the existing EVM frontend condition model, not an assumed boolean type from another frontend.

### Current frontend reality

- `CompileContext` defines `I8`, `I16`, `I32`, and `I64`, but no `I1`
- EVM-side `CmpInstruction` results in this path are created with `I64Type`
- `expandMemoryIR(...)` combines `Overflow` with `TooLarge` using `OP_or` under `I64Type`
- explicit constant branch conditions in the EVM frontend also use `I64` zero/one values

### Design rule

`NoOverflow` in the block-local precheck path must therefore be represented as:

- `createIntConstInstruction(I64Type, 0)`

This is not merely an implementation detail. It is required for consistency with the existing EVM frontend condition-value representation and for compatibility with `expandMemoryIR(...)`.

## Diagnostics and Instrumentation Boundary

The change includes two classes of state:

### Optimization-critical state

These must remain active regardless of logging mode:

- `CurBlockConstPrecheckPlan`
- plan activation and emission state
- covered-op remaining count
- block-local precheck emission itself

### Diagnostics-only state

These are compile-time instrumentation and may be gated:

- aggregate memory compile counters
- per-block summary counters
- per-block event PCs
- block summary log emission

The implementation gates diagnostics-only bookkeeping with `ZEN_ENABLE_MULTIPASS_JIT_LOGGING`, but does not gate the optimization itself.

## Failure and Fallback Behavior

The design is fail-closed.

If planning cannot prove the block safe, the planner returns no plan and the builder emits the existing per-op path.

Fallback happens on:

- helper-sensitive opcodes
- unsupported opcode shapes
- insufficient simulated stack depth
- unknown direct-memory addresses
- malformed or truncated `PUSHn`
- `uint64_t` overflow while computing required size
- too few covered direct-memory ops

No alternate optimization path is attempted. The original semantics remain the fallback.

## Correctness Guarantees

The implementation preserves the following for covered blocks:

- overflow trapping behavior
- max-required-size validation inside `expandMemoryIR(...)`
- aligned memory growth behavior
- memory expansion gas charging
- original behavior for all unsupported block shapes

This is achieved by hoisting one existing memory-precheck path, not by inventing a separate memory-growth mechanism.

## Risks and Limitations

### Dynamic-address benchmarks remain uncovered

Current target benchmarks such as `memory_grow_mload` and `memory_grow_mstore` still contain dynamic-address straight-line recurrence patterns, so this implementation may not improve those cases yet.

### Conservative analysis rejects many valid blocks

That is intentional. The design prefers a narrow, obviously safe first wave over broader but harder-to-review heuristics.

### Diagnostics can be mistaken for semantics

The design explicitly distinguishes logging-only counters from optimization state to avoid that confusion in future maintenance.

## Validation Strategy

### Build validation

Validate both development and release-style builds that exercise the EVM multipass frontend.

Recent relevant validation includes:

- `cmake --build build --target evmStateTests -j`
- a separate `Release + multipass + evmfallbacksuite` configure/build matching the CI fallback job

### Structural validation

In logging builds, compare:

- block-local precheck hit counts
- `expand_calls`
- `need_expand_cfg`
- direct-memory block summaries

### Behavioral validation

Use covered and uncovered asm samples to confirm:

- covered direct-memory blocks use one shared precheck
- helper-sensitive blocks remain uncovered
- malformed or truncated scan inputs do not become eligible

### Regression expectation

- no change in semantics for unsupported blocks
- no new runtime flag
- no backend dependency changes

## Future Extensions

The next logical expansions, if separately approved, are:

1. dynamic-address straight-line recurrence analysis
2. broader direct-memory opcode support
3. stronger structural validation for target `memory_grow_*` benchmarks

Those are intentionally out of scope for the current documented change.
