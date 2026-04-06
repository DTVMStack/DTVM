## ADDED Requirements

### Requirement: Plan block-local memory precheck only for conservative direct-memory blocks
The EVM multipass JIT frontend SHALL only create a block-local memory precheck plan when a basic block matches the implemented conservative direct-memory pattern.

#### Scenario: Eligible constant-address direct-memory block
- **WHEN** block entry analysis scans one basic block with no helper-sensitive opcode barrier
- **AND** the block contains at least two covered direct-memory operations
- **AND** every covered direct-memory address is locally known as a constant `uint64_t`
- **THEN** the frontend SHALL mark the block eligible for one shared block-local memory precheck

#### Scenario: Dynamic or unsupported block is not eligible
- **WHEN** the local scan encounters an unsupported opcode, unsupported stack effect, or an unknown direct-memory address
- **THEN** the frontend SHALL reject the plan
- **AND** the builder SHALL retain the original per-op memory expansion path

#### Scenario: Helper-sensitive block is not eligible
- **WHEN** the local scan encounters a helper-sensitive opcode family such as `LOG*`, `KECCAK256`, `*COPY`, `CALL*`, or `CREATE*`
- **THEN** the frontend SHALL reject the plan
- **AND** the optimization SHALL not be applied to that block

### Requirement: Respect basic-block boundaries during precheck planning
The EVM multipass JIT frontend SHALL keep block-local memory precheck planning inside one basic block.

#### Scenario: Scan stops at successor block marker
- **WHEN** the planner encounters a `JUMPDEST` after the entry instruction
- **THEN** it SHALL stop scanning before crossing into the next basic block

#### Scenario: Scan stops at block terminator
- **WHEN** the planner encounters `JUMP`, `JUMPI`, `RETURN`, `STOP`, `INVALID`, `REVERT`, or `SELFDESTRUCT`
- **THEN** it SHALL treat that opcode as a block terminator
- **AND** it SHALL not continue scanning into fallthrough or successor code

### Requirement: Reject malformed or truncated PUSH immediates conservatively
The EVM multipass JIT frontend SHALL reject block-local precheck planning when `PUSHn` immediate decoding cannot be proven in-bounds.

#### Scenario: Short immediate parse fails for `PUSH1..PUSH8`
- **WHEN** a `PUSH1..PUSH8` immediate extends past the bytecode size
- **THEN** constant decoding SHALL fail
- **AND** the planner SHALL return no eligible plan

#### Scenario: Long immediate skip fails for `PUSH9..PUSH32`
- **WHEN** a `PUSH9..PUSH32` immediate would advance past the bytecode size
- **THEN** the planner SHALL reject the block
- **AND** it SHALL not mark the block eligible

### Requirement: Derive one block-local maximum required memory size for covered ops
The EVM multipass JIT frontend SHALL compute one `MaxRequiredSize` for each eligible block from the covered direct-memory operations.

#### Scenario: Compute required size for covered operations
- **WHEN** the planner sees a covered `MLOAD(addr)`, `MSTORE(addr, value)`, or `MSTORE8(addr, value)`
- **THEN** it SHALL compute the required size as `addr + 32`, `addr + 32`, or `addr + 1` respectively
- **AND** it SHALL update the block plan with the maximum required size across covered ops

#### Scenario: Required-size overflow invalidates planning
- **WHEN** computing a covered required size would overflow `uint64_t`
- **THEN** the planner SHALL reject the block-local precheck plan

### Requirement: Use one shared precheck for covered direct-memory ops
The EVM multipass JIT frontend SHALL emit one shared memory precheck for the covered operations of an eligible block.

#### Scenario: First covered op emits the shared precheck
- **WHEN** code generation reaches the first covered direct-memory operation in an active eligible block
- **THEN** the builder SHALL emit exactly one `expandMemoryIR(MaxRequiredSize, NoOverflow)` for that block-local plan
- **AND** it SHALL mark the plan as emitted

#### Scenario: Later covered ops skip redundant per-op pre-expansion
- **WHEN** the shared precheck has already been emitted for the active block-local plan
- **THEN** later covered `MLOAD`, `MSTORE`, and `MSTORE8` operations SHALL skip their redundant per-op `expandMemoryIR(...)` path
- **AND** they SHALL continue lowering the actual memory access logic normally

#### Scenario: Uncovered path stays unchanged
- **WHEN** no eligible plan exists, or a plan has been rejected or exhausted
- **THEN** each opcode SHALL retain its original per-op expansion behavior

### Requirement: Preserve existing memory expansion semantics on covered paths
The block-local memory precheck optimization SHALL preserve the existing memory expansion semantics of the EVM frontend.

#### Scenario: Covered precheck preserves overflow, max-size, and gas semantics
- **WHEN** the shared precheck path is used
- **THEN** it SHALL still execute the existing `expandMemoryIR(...)` logic
- **AND** overflow handling SHALL remain enforced
- **AND** max-required-size validation SHALL remain enforced
- **AND** aligned growth and memory-expansion gas charging SHALL remain unchanged

### Requirement: Match the existing EVM frontend condition-value representation
The block-local memory precheck path SHALL construct its no-overflow condition using the same condition-value representation already used by the EVM frontend in this code path.

#### Scenario: No-overflow constant matches existing overflow operand type
- **WHEN** the builder creates the shared precheck for an eligible block
- **THEN** the `NoOverflow` operand SHALL use the existing EVM frontend condition type representation used by other `Overflow` values in `expandMemoryIR(...)`
- **AND** it SHALL not assume a separate `I1` type that is not defined by the current frontend context

### Requirement: Keep diagnostics separate from optimization semantics
The EVM multipass JIT frontend SHALL keep diagnostics-only memory statistics separate from optimization-critical precheck behavior.

#### Scenario: Logging build records block and summary diagnostics
- **WHEN** `ZEN_ENABLE_MULTIPASS_JIT_LOGGING` is enabled
- **THEN** the frontend SHALL record and emit memory compile stats and block summary diagnostics for development analysis

#### Scenario: Non-logging build still keeps the optimization
- **WHEN** `ZEN_ENABLE_MULTIPASS_JIT_LOGGING` is disabled
- **THEN** diagnostics-only counters and block-summary bookkeeping MAY be compiled out
- **AND** the block-local precheck planning and shared precheck optimization SHALL remain active
