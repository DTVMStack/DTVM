# EVMC VM Interface Specification

## ADDED Requirements

### Requirement: File Organization and Naming Convention
The system SHALL follow consistent naming conventions for EVMC VM interface files and maintain proper file organization.

#### Scenario: EVMC File Naming
- **WHEN** implementing EVMC VM interface files
- **THEN** the system SHALL use `dt_evmc_vm.h` for the header file
- **AND** the system SHALL use `dt_evmc_vm.cpp` for the implementation file
- **AND** the system SHALL maintain `wrapped_host.h` for host interface bridging
- **AND** the system SHALL update build configuration files accordingly

#### Scenario: Build System Integration
- **WHEN** EVMC VM files are renamed or reorganized
- **THEN** the system SHALL update `src/vm/CMakeLists.txt` to reflect new file names
- **AND** the system SHALL ensure proper compilation and linking of EVMC components
- **AND** the system SHALL maintain backward compatibility with existing build processes

#### Scenario: Cross-Environment Compatibility
- **WHEN** building the EVMC library for distribution
- **THEN** the system SHALL statically link libstdc++ into the library
- **AND** the system SHALL ensure the library can run on different Linux environments
- **AND** the system SHALL minimize external runtime dependencies

### Requirement: EVMC ABI Compatibility
The system SHALL provide a complete EVMC (Ethereum Client-VM Connector API) interface implementation that is fully compatible with EVMC ABI version 12.

#### Scenario: VM Instance Creation
- **WHEN** a client calls `evmc_create_dtvmapi()`
- **THEN** the system SHALL return a valid `evmc_vm` instance
- **AND** the instance SHALL have ABI version set to 12
- **AND** the instance SHALL have name set to "dtvm"
- **AND** the instance SHALL have all required function pointers initialized

#### Scenario: VM Instance Destruction
- **WHEN** a client calls the `destroy` method on a VM instance
- **THEN** the system SHALL clean up all allocated resources
- **AND** the system SHALL unload all cached EVM modules
- **AND** the system SHALL delete the managed isolation environment
- **AND** the system SHALL not cause memory leaks

### Requirement: EVM Execution Capability
The system SHALL support EVM bytecode execution through the EVMC execute interface with full EVM1 capability support.

#### Scenario: EVM Bytecode Execution
- **WHEN** a client calls the `execute` method with valid EVM bytecode
- **THEN** the system SHALL load or retrieve the EVM module using CRC32 checksum
- **AND** the system SHALL create an EVM instance in the isolation environment
- **AND** the system SHALL execute the bytecode using DTVM Runtime
- **AND** the system SHALL return a valid `evmc_result` with execution status

#### Scenario: Module Caching Optimization
- **WHEN** the same EVM bytecode is executed multiple times
- **THEN** the system SHALL cache the compiled module using CRC32 checksum as key
- **AND** the system SHALL reuse the cached module for subsequent executions
- **AND** the system SHALL avoid redundant compilation overhead

### Requirement: Runtime Mode Configuration
The system SHALL support dynamic configuration of execution modes through the EVMC set_option interface.

#### Scenario: Interpreter Mode Configuration
- **WHEN** a client calls `set_option` with name "mode" and value "interpreter"
- **THEN** the system SHALL set the runtime configuration to interpreter mode
- **AND** the system SHALL return `EVMC_SET_OPTION_SUCCESS`
- **AND** subsequent executions SHALL use interpreter mode

#### Scenario: Multipass Mode Configuration
- **WHEN** a client calls `set_option` with name "mode" and value "multipass"
- **THEN** the system SHALL set the runtime configuration to multipass JIT mode
- **AND** the system SHALL return `EVMC_SET_OPTION_SUCCESS`
- **AND** subsequent executions SHALL use multipass JIT compilation

#### Scenario: EVM Gas Metering Configuration
- **WHEN** a client calls `set_option` with name "enable_gas_metering" and value "true"
- **THEN** the system SHALL enable MIR-level gas metering in the runtime configuration
- **AND** the system SHALL return `EVMC_SET_OPTION_SUCCESS`
- **AND** subsequent EVM bytecode compilations SHALL include detailed gas metering instrumentation
- **WHEN** a client calls `set_option` with name "enable_gas_metering" and value "false"
- **THEN** the system SHALL disable MIR-level gas metering in the runtime configuration
- **AND** the system SHALL return `EVMC_SET_OPTION_SUCCESS`
- **AND** subsequent EVM bytecode compilations SHALL optimize for performance without detailed gas metering

#### Scenario: Invalid Option Handling
- **WHEN** a client calls `set_option` with an unknown option name
- **THEN** the system SHALL return `EVMC_SET_OPTION_INVALID_NAME`
- **WHEN** a client calls `set_option` with an invalid option value for "mode" (not "interpreter" or "multipass")
- **THEN** the system SHALL return `EVMC_SET_OPTION_INVALID_VALUE`
- **WHEN** a client calls `set_option` with an invalid option value for "enable_gas_metering" (not "true" or "false")
- **THEN** the system SHALL return `EVMC_SET_OPTION_INVALID_VALUE`

### Requirement: Host Interface Integration
The system SHALL provide seamless integration with EVMC host interfaces through the WrappedHost bridge implementation with dynamic reinitialization support.

#### Scenario: Host Interface Initialization
- **WHEN** the execute method is called with host interface and context
- **THEN** the system SHALL reinitialize the WrappedHost with the provided interface
- **AND** the system SHALL store the host context for subsequent operations
- **AND** the system SHALL enable host function calls during execution

#### Scenario: Host Interface Reinitialization
- **WHEN** WrappedHost needs to be reinitialized with different host interface and context
- **THEN** the system SHALL call the `reinitialize` method with new parameters
- **AND** the system SHALL update both HostInterface and HostContext pointers
- **AND** the system SHALL support null interface and context as default parameters

#### Scenario: Host Function Delegation
- **WHEN** EVM execution requires host functions (storage, balance, etc.)
- **THEN** the system SHALL delegate calls through WrappedHost to the client's host implementation
- **AND** the system SHALL properly convert between EVMC C++ and C interfaces
- **AND** the system SHALL maintain type safety and error handling

### Requirement: Resource Management and Safety
The system SHALL implement safe resource management with proper cleanup and error handling, including managed isolation lifecycle.

#### Scenario: Memory Safety
- **WHEN** any operation fails during execution
- **THEN** the system SHALL clean up partially allocated resources
- **AND** the system SHALL not cause memory leaks or dangling pointers
- **AND** the system SHALL return appropriate error codes

#### Scenario: Isolation Management
- **WHEN** multiple executions occur within the same VM instance
- **THEN** the system SHALL reuse the isolation environment when possible
- **AND** the system SHALL create new EVM instances for each execution
- **AND** the system SHALL properly clean up EVM instances after execution

#### Scenario: Managed Isolation Cleanup
- **WHEN** the DTVM destructor is called
- **THEN** the system SHALL properly destroy the managed isolation using `RT->deleteManagedIsolation(Iso)`
- **AND** the system SHALL ensure isolation is only destroyed if it exists (null check)
- **AND** the system SHALL prevent double-deletion of isolation resources

### Requirement: Cross-Platform Deployment
The system SHALL support deployment across different environments with minimal external dependencies through static linking configuration.

#### Scenario: Static Library Dependencies
- **WHEN** building the EVMC library for distribution
- **THEN** the system SHALL statically link libstdc++ using `-static-libstdc++` flag to avoid version conflicts
- **AND** the system SHALL statically link libgcc using `-static-libgcc` flag to ensure runtime compatibility
- **AND** the system SHALL configure CMake with `target_link_options(dtvmapi PRIVATE -static-libstdc++ -static-libgcc)`
- **AND** the system SHALL minimize dynamic library dependencies

#### Scenario: Environment Portability
- **WHEN** deploying the EVMC library to different Linux distributions
- **THEN** the system SHALL run without requiring specific libstdc++ versions
- **AND** the system SHALL work across different glibc versions (within reason)
- **AND** the system SHALL provide clear documentation of minimum system requirements

#### Scenario: Build Configuration Verification
- **WHEN** the CMakeLists.txt is processed during build
- **THEN** the system SHALL apply static linking flags only when ZEN_ENABLE_EVM is enabled
- **AND** the system SHALL configure proper symbol visibility with `-fvisibility=hidden`
- **AND** the system SHALL exclude static libraries from exports using `-Wl,--exclude-libs,ALL`

### Requirement: Error Handling and Reporting
The system SHALL provide comprehensive error handling with appropriate EVMC status codes.

#### Scenario: Module Loading Failure
- **WHEN** EVM module loading fails due to invalid bytecode
- **THEN** the system SHALL return `evmc_result` with status `EVMC_FAILURE`
- **AND** the system SHALL log detailed error information
- **AND** the system SHALL not crash or cause undefined behavior

#### Scenario: Runtime Execution Failure
- **WHEN** EVM execution fails due to runtime errors
- **THEN** the system SHALL return appropriate EVMC status codes
- **AND** the system SHALL preserve gas consumption information when available
- **AND** the system SHALL provide output data when applicable (e.g., REVERT cases)

## Implementation Notes

### CRC32 Checksum Implementation
The system uses a standard CRC32 algorithm with polynomial 0xEDB88320 for module caching. The implementation includes:
- Static lookup table initialization
- Fast computation for bytecode hashing
- Collision handling through map-based storage

### WrappedHost Bridge Architecture
The WrappedHost class provides a complete bridge between EVMC C++ Host interface and C-style host callbacks:
- Inherits from `evmc::Host` for C++ interface compatibility
- Stores raw C interface pointers for delegation
- Implements all required EVMC host methods
- Supports dynamic reinitialization for different host contexts
- Provides default constructor with null parameters for flexible initialization
- Includes `reinitialize(interface, context)` method for runtime host switching

### DTVM Integration Points
The EVMC interface integrates with existing DTVM components:
- `RuntimeConfig`: Configures execution mode and input format (defaults to EVM format and MultipassMode)
- `Runtime`: Manages EVM module loading and execution with managed isolation support
- `Isolation`: Provides execution environment isolation with proper lifecycle management
- `EVMModule` and `EVMInstance`: Core execution units with CRC32-based caching
- File organization: `dt_evmc_vm.h/cpp` for main implementation, `wrapped_host.h` for host bridging

### Performance Characteristics
- Module caching reduces compilation overhead for repeated executions
- WrappedHost delegation adds minimal call overhead
- JIT compilation provides near-native execution performance
- Memory usage scales with number of unique bytecode modules