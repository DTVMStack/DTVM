# evm-jit Specification

## Purpose
Define DTVM’s multipass JIT compilation pipeline for EVM bytecode, including compilation constraints, code emission, and runtime integration.

## Requirements
### Requirement: Multipass-only EVM JIT support
The system SHALL compile EVM bytecode using the multipass JIT pipeline only.

#### Scenario: Multipass eager compilation
- **WHEN** runtime mode is Multipass
- **THEN** the system SHALL eagerly compile EVM bytecode using the EVM JIT compiler

#### Scenario: Lazy compilation unsupported
- **WHEN** runtime configuration requests lazy JIT for EVM
- **THEN** the system SHALL emit a warning and skip lazy compilation

#### Scenario: Singlepass mode unsupported
- **WHEN** runtime mode is Singlepass
- **THEN** the system SHALL emit an error indicating EVMJIT is unsupported

### Requirement: EVM frontend context setup
The system SHALL initialize the EVM frontend context with bytecode, gas metering flags, and gas chunk metadata.

#### Scenario: Gas metering configuration
- **WHEN** EVM JIT compilation starts
- **THEN** the compiler SHALL enable or disable gas metering based on runtime configuration

#### Scenario: Bytecode and gas chunk provisioning
- **WHEN** the frontend context is initialized
- **THEN** it SHALL receive the bytecode pointer and size
- **AND** it SHALL receive gas chunk end and cost arrays

### Requirement: Machine code emission and module binding
The system SHALL emit machine code to the module’s JIT code memory pool and publish the code pointer and size.

#### Scenario: Code buffer emission
- **WHEN** compilation completes
- **THEN** machine code SHALL be written into the module’s code memory pool

#### Scenario: Entry point selection
- **WHEN** the EVM code is compiled
- **THEN** the JIT SHALL expose the entry-point pointer for function index 0

#### Scenario: Memory protection
- **WHEN** code emission finalizes
- **THEN** the code memory SHALL be protected as read/execute

### Requirement: JIT compilation statistics and perf integration
The system SHALL record compilation timing and optionally emit perf JIT dump symbols.

#### Scenario: Statistics timing
- **WHEN** compilation begins and ends
- **THEN** JITCompilation statistics SHALL be recorded

#### Scenario: Perf JIT dump output
- **WHEN** Linux perf JIT dumping is enabled
- **THEN** the compiler SHALL emit per-block symbols for generated code
