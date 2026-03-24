# evm-jit Spec Delta

## ADDED Requirements

### Requirement: CLZ opcode JIT compilation
The system SHALL compile the CLZ opcode using a runtime call to compute the count of leading zeros in a 256-bit unsigned integer.

#### Scenario: CLZ JIT code generation
- **WHEN** the JIT compiler encounters a CLZ opcode
- **THEN** it SHALL emit a runtime call to the CLZ helper function
- **AND** the helper function SHALL use `intx::clz` for the computation

#### Scenario: CLZ JIT execution result
- **WHEN** JIT-compiled CLZ code is executed
- **THEN** the result SHALL match the interpreter's CLZ behavior exactly
- **AND** gas metering SHALL deduct 5 gas units

## MODIFIED Requirements

### Requirement: Multipass-only EVM JIT support
The system SHALL compile EVM bytecode using the multipass JIT pipeline only.

#### Scenario: CLZ opcode in multipass compilation
- **WHEN** runtime mode is Multipass and bytecode contains CLZ opcode
- **THEN** the system SHALL compile CLZ using the runtime call mechanism
- **AND** the compiled code SHALL be deterministic across compilations
