# evm-tests Specification

## Purpose
Define the EVM test harness, fixture formats, and execution modes used to validate DTVM’s EVM behavior.

## Requirements
### Requirement: EVM assembly sample tests
The system SHALL execute EVM interpreter tests from `tests/evm_asm` using `.hex` bytecode and `.expected` YAML outputs.

#### Scenario: Sample discovery
- **WHEN** interpreter sample tests run
- **THEN** the test harness SHALL scan `tests/evm_asm` for `.hex` files

#### Scenario: Expected output validation
- **WHEN** a `.expected` YAML exists
- **THEN** the test SHALL validate status, error code, stack, memory, storage, transient storage, return value, and events

#### Scenario: Interpreter execution
- **WHEN** sample tests execute
- **THEN** the runtime SHALL run in interpreter mode with EVMC mocked host

### Requirement: Ethereum state test execution
The system SHALL execute Ethereum state tests from `tests/evm_spec_test/state_tests` and validate post-state.

#### Scenario: Revision selection
- **WHEN** `DTVM_TEST_REVISION` is set
- **THEN** the harness SHALL map it to the corresponding EVMC revision
- **AND** default to Cancun if unspecified

#### Scenario: Intrinsic gas validation
- **WHEN** a state test is executed
- **THEN** the harness SHALL compute intrinsic gas and enforce minimum gas requirements
- **AND** it SHALL reject initcode exceeding the configured max size for Shanghai+

#### Scenario: Runtime mode selection
- **WHEN** multipass JIT is unavailable
- **THEN** the harness SHALL fall back to interpreter mode
- **AND** it SHALL enable EVM gas metering when executing state tests

### Requirement: Test utilities and fixtures
The system SHALL provide reusable helpers for fixture parsing and state verification.

#### Scenario: Fixture parsing
- **WHEN** a state test JSON file is parsed
- **THEN** the harness SHALL build pre-state accounts, transaction inputs, and expected post-state metadata

#### Scenario: Host and state verification utilities
- **WHEN** tests validate results
- **THEN** the helpers SHALL support state root and log hash verification
- **AND** they SHALL support temporary hex file creation for bytecode inputs
