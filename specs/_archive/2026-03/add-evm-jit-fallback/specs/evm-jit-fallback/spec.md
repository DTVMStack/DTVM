# evm-jit-fallback Specification Delta

## ADDED Requirements

### Requirement: JIT fallback interface in EVMMirBuilder
The EVMMirBuilder SHALL provide a fallbackToInterpreter method to transition execution from JIT to interpreter mode.

#### Scenario: Fallback method interface
- **WHEN** EVMMirBuilder detects undefined opcodes, stack overflow/underflow, out of gas, or FALLBACK opcode
- **THEN** it SHALL call fallbackToInterpreter(uint64_t targetPC)
- **AND** the method SHALL generate MIR instructions to save current execution state
- **AND** it SHALL call the runtime fallback function via callRuntimeFor

#### Scenario: State synchronization before fallback
- **WHEN** fallbackToInterpreter is called
- **THEN** the current stack state SHALL be flushed to EVMInstance
- **AND** memory state SHALL be synchronized with EVMInstance
- **AND** the target PC SHALL be validated as a valid instruction boundary

#### Scenario: Runtime function invocation
- **WHEN** state synchronization completes
- **THEN** EVMMirBuilder SHALL call RuntimeFunctions.HandleFallback
- **AND** the call SHALL pass the EVMInstance pointer and target PC
- **AND** the call SHALL use the existing callRuntimeFor template mechanism

### Requirement: Runtime fallback function
The runtime system SHALL provide evmHandleFallback function to manage JIT-to-interpreter transition.

#### Scenario: Fallback function signature
- **WHEN** the runtime fallback function is defined
- **THEN** it SHALL have signature void evmHandleFallback(zen::runtime::EVMInstance *, uint64_t)
- **AND** it SHALL be registered in the RuntimeFunctions structure
- **AND** it SHALL be accessible via the existing function table mechanism

#### Scenario: Interpreter instance creation
- **WHEN** evmHandleFallback is called
- **THEN** it SHALL create a new interpreter instance
- **AND** the interpreter SHALL be initialized with the provided EVMInstance
- **AND** execution SHALL resume from the specified PC

#### Scenario: State validation during transition
- **WHEN** the fallback function processes the transition
- **THEN** it SHALL validate the target PC is within bytecode bounds
- **AND** it SHALL verify stack state consistency
- **AND** it SHALL ensure memory state integrity

### Requirement: Interpreter state restoration
The EVM interpreter SHALL support execution from arbitrary EVM state provided by JIT fallback.

#### Scenario: State-based execution entry point
- **WHEN** interpreter receives fallback execution request
- **THEN** it SHALL provide executeFromState(EVMInstance*, uint64_t) method
- **AND** the method SHALL restore execution context from EVMInstance
- **AND** execution SHALL begin at the specified PC

#### Scenario: Stack state restoration
- **WHEN** executeFromState is called
- **THEN** the interpreter SHALL restore stack contents from EVMInstance
- **AND** it SHALL set the stack pointer to the correct position
- **AND** it SHALL validate stack size constraints

#### Scenario: Memory state consistency
- **WHEN** interpreter resumes execution
- **THEN** it SHALL use the existing memory from EVMInstance
- **AND** memory operations SHALL be consistent with JIT memory semantics
- **AND** memory size and growth behavior SHALL remain unchanged

### Requirement: Execution state preservation
The fallback mechanism SHALL preserve complete EVM execution state across the JIT-interpreter boundary.

#### Scenario: Program counter preservation
- **WHEN** fallback occurs at instruction boundary
- **THEN** the exact PC value SHALL be preserved
- **AND** interpreter SHALL resume at the correct bytecode position
- **AND** no instructions SHALL be skipped or repeated

#### Scenario: Stack state preservation
- **WHEN** JIT execution has modified the stack
- **THEN** all stack values SHALL be preserved in correct order
- **AND** stack size SHALL be maintained accurately
- **AND** stack overflow/underflow conditions SHALL be preserved

#### Scenario: Gas accounting continuity
- **WHEN** execution transitions from JIT to interpreter
- **THEN** remaining gas SHALL be preserved exactly
- **AND** gas costs SHALL continue to be tracked consistently
- **AND** gas exhaustion conditions SHALL be handled identically
