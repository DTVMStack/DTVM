## ADDED Requirements

### Requirement: JIT suitability analysis before compilation
The system SHALL analyze EVM bytecode for patterns that cause register allocation explosion before attempting JIT compilation, and SHALL fall back to interpreter mode when pathological patterns are detected.

#### Scenario: Normal contract passes suitability check
- **WHEN** EVM bytecode contains fewer than 128 consecutive RA-expensive opcodes per run
- **AND** fewer than 256 RA-expensive opcodes per basic block
- **AND** fewer than 64 DUP-feedback patterns
- **AND** the linear MIR estimate is below the configured threshold
- **THEN** the system SHALL proceed with JIT compilation

#### Scenario: High consecutive RA-expensive opcode density triggers fallback
- **WHEN** EVM bytecode contains a run of more than 128 consecutive RA-expensive opcodes (SHL, SHR, SAR, MUL, SIGNEXTEND), with DUP and SWAP opcodes not breaking the run
- **THEN** the system SHALL fall back to interpreter mode for that contract
- **AND** the system SHALL log the fallback reason with the detected pattern metrics

#### Scenario: High per-block RA-expensive opcode density triggers fallback
- **WHEN** a single basic block (JUMPDEST to control-flow terminator) contains more than 256 RA-expensive opcodes
- **THEN** the system SHALL fall back to interpreter mode for that contract

#### Scenario: DUP feedback loop pattern triggers fallback
- **WHEN** EVM bytecode contains more than 64 instances of DUPn immediately followed by an RA-expensive opcode
- **THEN** the system SHALL fall back to interpreter mode for that contract

#### Scenario: Suitability analysis performance
- **WHEN** the suitability analysis runs on any EVM bytecode
- **THEN** the analysis SHALL complete in O(n) time where n is the bytecode length
- **AND** the analysis SHALL not allocate heap memory proportional to bytecode size beyond existing analyzer structures

### Requirement: RA-expensive opcode classification
The system SHALL classify EVM opcodes that expand to complex MIR structures (long Select chains or heavy intermediate value fan-out) as RA-expensive for the purpose of JIT suitability analysis.

#### Scenario: Shift opcodes classified as RA-expensive
- **WHEN** classifying opcodes for JIT suitability
- **THEN** SHL (0x1b), SHR (0x1c), and SAR (0x1d) SHALL be classified as RA-expensive
- **AND** each generates 52-96 SelectInstruction chains per invocation in MIR

#### Scenario: Multiplication classified as RA-expensive
- **WHEN** classifying opcodes for JIT suitability
- **THEN** MUL (0x02) SHALL be classified as RA-expensive
- **AND** it generates ~50-60 MIR instructions with heavy intermediate value fan-out

#### Scenario: Sign extension classified as RA-expensive
- **WHEN** classifying opcodes for JIT suitability
- **THEN** SIGNEXTEND (0x0b) SHALL be classified as RA-expensive
- **AND** it generates ~21 SelectInstruction chains per invocation in MIR

## MODIFIED Requirements

### Requirement: Multipass-only EVM JIT support
The system SHALL compile EVM bytecode using the multipass JIT pipeline only, after verifying bytecode suitability through pattern analysis.

#### Scenario: Multipass eager compilation
- **WHEN** runtime mode is Multipass
- **AND** the bytecode passes JIT suitability analysis
- **THEN** the system SHALL eagerly compile EVM bytecode using the EVM JIT compiler

#### Scenario: Multipass fallback to interpreter
- **WHEN** runtime mode is Multipass
- **AND** the bytecode fails JIT suitability analysis
- **THEN** the system SHALL temporarily switch to interpreter mode for that execution
- **AND** the system SHALL log the fallback with diagnostic metrics

#### Scenario: Lazy compilation unsupported
- **WHEN** runtime configuration requests lazy JIT for EVM
- **THEN** the system SHALL emit a warning and skip lazy compilation

#### Scenario: Singlepass mode unsupported
- **WHEN** runtime mode is Singlepass
- **THEN** the system SHALL emit an error indicating EVMJIT is unsupported
