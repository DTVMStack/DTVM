# evm-execution Spec Delta

## ADDED Requirements

### Requirement: CLZ opcode execution
The system SHALL execute the CLZ (Count Leading Zeros) opcode for Osaka revision and above, returning the count of leading zero bits in a 256-bit unsigned integer.

#### Scenario: CLZ with zero input
- **WHEN** CLZ is executed with input value 0
- **THEN** the result SHALL be 256 (all bits are zero)
- **AND** gas consumption SHALL be 5

#### Scenario: CLZ with non-zero input
- **WHEN** CLZ is executed with a non-zero 256-bit input
- **THEN** the result SHALL be the count of leading zero bits before the most significant set bit
- **AND** gas consumption SHALL be 5

#### Scenario: CLZ with maximum value
- **WHEN** CLZ is executed with input value 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
- **THEN** the result SHALL be 0 (no leading zeros)
- **AND** gas consumption SHALL be 5

#### Scenario: CLZ stack underflow
- **WHEN** CLZ is executed with an empty stack
- **THEN** the interpreter SHALL set status to stack underflow

## MODIFIED Requirements

### Requirement: Opcode semantics by revision
The system SHALL execute EVM opcodes according to the active protocol revision.

#### Scenario: CLZ before Osaka revision
- **WHEN** CLZ opcode (0x1e) is executed on a revision before Osaka
- **THEN** the interpreter SHALL fail the execution with an undefined instruction status
