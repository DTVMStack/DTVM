# evm-execution Specification

## Purpose
Define DTVM's EVM module loading, execution model, interpreter semantics, and runtime instance behavior (gas, memory, and message handling).

## Requirements
### Requirement: EVM module loading and bytecode storage
The system SHALL load raw EVM bytecode into an `EVMModule` and preserve its length.

#### Scenario: Empty bytecode input
- **WHEN** an EVM module is loaded with bytecode size 0
- **THEN** the module SHALL keep a non-null code pointer
- **AND** the stored code size SHALL be 0

#### Scenario: Invalid raw data
- **WHEN** an EVM module is loaded with a null data pointer and non-zero size
- **THEN** the loader SHALL raise an invalid raw data error

### Requirement: Runtime host binding and execution mode selection
The system SHALL bind the runtime’s EVMC host to each EVM module and select the execution mode based on runtime configuration.

#### Scenario: Host binding
- **WHEN** an EVM module is created
- **THEN** the module SHALL store the runtime’s EVMC host pointer for execution

#### Scenario: JIT selection
- **WHEN** runtime mode is not interpreter mode
- **THEN** the module SHALL trigger EVM JIT compilation during module creation

### Requirement: Bytecode cache construction
The system SHALL lazily build bytecode caches for jump destinations, PUSH immediates, and gas chunks.

#### Scenario: Lazy initialization
- **WHEN** a caller requests the bytecode cache
- **THEN** the cache SHALL be built on first access
- **AND** subsequent accesses SHALL reuse the cached data

#### Scenario: Cache contents
- **WHEN** the cache is built for a bytecode buffer
- **THEN** it SHALL include a jump destination map keyed by PC
- **AND** it SHALL include decoded PUSH values keyed by PC
- **AND** it SHALL include gas-chunk boundaries and base costs

### Requirement: Interpreter execution context and stack safety
The system SHALL enforce stack bounds and execution status when interpreting EVM bytecode.

#### Scenario: Stack overflow
- **WHEN** a stack push would exceed MAXSTACK
- **THEN** the interpreter SHALL set status to stack overflow

#### Scenario: Stack underflow
- **WHEN** a pop/peek is performed on an empty stack
- **THEN** the interpreter SHALL set status to stack underflow

### Requirement: Instance gas accounting and memory expansion
The system SHALL track gas and charge memory expansion costs with bounded memory growth.

#### Scenario: Memory expansion cost
- **WHEN** memory is expanded
- **THEN** the instance SHALL compute the quadratic expansion cost
- **AND** it SHALL deduct gas before resizing memory

#### Scenario: Memory size guard
- **WHEN** a requested memory expansion exceeds the maximum required memory size
- **THEN** the instance SHALL consume remaining gas and fail the operation

### Requirement: Message stack and return data handling
The system SHALL manage per-call message context and return data across nested calls.

#### Scenario: Message push/pop isolation
- **WHEN** a new message is pushed
- **THEN** memory SHALL be cleared or stacked for later restoration
- **AND** current gas SHALL be updated from the message

#### Scenario: Return data propagation
- **WHEN** execution completes or reverts
- **THEN** the instance SHALL store the return data buffer for the caller

### Requirement: Execution runtime and instance lifecycle
The system SHALL define runtime configuration inputs and per-execution instance state for EVM execution.

#### Scenario: Runtime configuration
- **WHEN** a runtime is created for EVM execution
- **THEN** it SHALL record the chain configuration and revision (e.g., Cancun)
- **AND** it SHALL expose execution mode settings (interpreter vs JIT) for module creation

#### Scenario: Instance initialization
- **WHEN** an execution instance is created for a call
- **THEN** it SHALL initialize gas, memory, stack, and message context from the call parameters

### Requirement: Opcode semantics by revision
The system SHALL execute EVM opcodes according to the active protocol revision.

#### Scenario: Revision-specific opcode behavior
- **WHEN** an opcode has revision-dependent behavior
- **THEN** the interpreter SHALL apply the semantics and gas cost defined for the active revision

#### Scenario: Unsupported opcode
- **WHEN** an opcode is not defined in the active revision
- **THEN** the interpreter SHALL fail the execution with an invalid instruction status
