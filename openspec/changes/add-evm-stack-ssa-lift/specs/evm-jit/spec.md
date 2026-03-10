## MODIFIED Requirements
### Requirement: EVM frontend context setup
The system SHALL allow the EVM multipass frontend to conservatively lift stack values into frontend-managed virtual values before later code generation.

#### Scenario: Safe block edge remains lifted
- **WHEN** a block edge has a statically compatible entry stack depth and supported control-flow shape
- **THEN** the frontend SHALL pass stack values to the successor without immediate runtime stack materialization

#### Scenario: Unsafe edge materializes state
- **WHEN** a block edge cannot be proven safe for lifted stack transfer
- **THEN** the frontend SHALL materialize stack state to `EVMInstance` before continuing execution
