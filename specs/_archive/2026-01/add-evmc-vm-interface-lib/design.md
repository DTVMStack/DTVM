# Technical Design: EVMC VM Interface Library Implementation

## Context

DTVM currently provides powerful WebAssembly and EVM execution capabilities, but lacks a standardized EVMC (Ethereum Client-VM Connector API) interface. EVMC is a widely adopted standard interface in the Ethereum ecosystem that allows VM implementations to be decoupled from Ethereum clients.

Implementing the EVMC interface will enable DTVM to:
- Seamlessly integrate with existing Ethereum clients (such as Geth, Besu)
- Support standardized VM testing frameworks and tools
- Provide pluggable VM implementation options

## Goals / Non-Goals

### Goals
- Implement complete EVMC ABI version 12 compatibility
- Support dynamic switching between multiple execution modes (interpreter, multipass JIT)
- Provide safe memory and resource management
- Maintain backward compatibility with existing DTVM APIs
- Implement high-performance Host interface bridging

### Non-Goals
- Do not modify existing DTVM core execution engine
- Do not change existing Runtime and Isolation architecture
- Do not implement EVMC optional extension features (such as precompiled contracts)

## Decisions

### Architecture Decision: Wrapper-Based Implementation

**Decision**: Adopt wrapper pattern to implement EVMC interface instead of refactoring existing DTVM architecture.

**Rationale**:
- Minimize impact on existing code
- Maintain clear architectural separation
- Facilitate maintenance and testing
- Support future interface extensions

### Runtime Integration Decision: Module Caching with CRC32

**Decision**: Use CRC32 checksum as the key for EVM module caching.

**Rationale**:
- Fast computation with low performance overhead
- Sufficient collision detection capability for caching scenarios
- Simple implementation and debugging
- Compatible with existing Runtime module management

**Alternatives Considered**:
- SHA256: More secure but computationally expensive, over-engineered for caching scenarios
- Memory address: Unstable, cannot cache across execution sessions

### EVM Gas Metering Configuration Decision: Runtime-Level Control

**Decision**: Expose EVM gas metering control through EVMC set_option interface, mapping to RuntimeConfig.EnableEvmGasMetering.

**Rationale**:
- **Performance Optimization**: Gas metering generates significant MIR code that can interfere with debugging and reduce performance
- **Development Flexibility**: Allows developers to disable gas metering during development/debugging and enable for production
- **Standardized Interface**: Uses standard EVMC set_option mechanism for configuration
- **Runtime Granularity**: Configuration applies to all subsequent module compilations within the VM instance

**Implementation Details**:
- Option name: "enable_gas_metering" with values "true"/"false"
- Maps directly to `RuntimeConfig.EnableEvmGasMetering` boolean field
- Default value: false (disabled for performance)
- Applied during EVM module compilation, affecting MIR-level instrumentation

### EVM Gas Metering Configuration Decision: Runtime-Level Control

**Decision**: Expose EVM gas metering control through EVMC set_option interface, mapping to RuntimeConfig.EnableEvmGasMetering.

**Rationale**:
- **Performance Optimization**: Gas metering generates significant MIR code that can interfere with debugging and reduce performance
- **Development Flexibility**: Allows developers to disable gas metering during development/debugging and enable for production
- **Standardized Interface**: Uses standard EVMC set_option mechanism for configuration
- **Runtime Granularity**: Configuration applies to all subsequent module compilations within the VM instance

**Implementation Details**:
- Option name: "enable_gas_metering" with values "true"/"false"
- Maps directly to `RuntimeConfig.EnableEvmGasMetering` boolean field
- Default value: false (disabled for performance)
- Applied during EVM module compilation, affecting MIR-level instrumentation

### Host Interface Decision: WrappedHost Bridge

**Decision**: Bridge EVMC Host interface and DTVM Runtime through WrappedHost class.

**Rationale**:
- Provide clear interface conversion layer
- Support dynamic reinitialization of Host context
- Facilitate handling of different Host implementations
- Maintain type safety and error handling

### Memory Management Decision: RAII-Based Resource Management

**Decision**: Use RAII pattern to manage lifecycle of VM instances, modules, and Isolation.

**Rationale**:
- Automatic resource cleanup, preventing memory leaks
- Exception-safe resource management
- Follows C++ best practices
- Simplifies error handling logic

### Deployment Decision: Static Linking for Cross-Environment Compatibility

**Decision**: Statically link libstdc++ and libgcc into the EVMC library for distribution.

**Rationale**:
- **Environment Independence**: Eliminates dependency on specific libstdc++ versions across different Linux distributions
- **Deployment Simplicity**: Reduces runtime dependency requirements for end users
- **Version Conflict Avoidance**: Prevents conflicts with system-installed C++ runtime libraries
- **Portability**: Enables the library to run on systems with older or different C++ runtime versions

**Trade-offs**:
- **Library Size**: Increases the final library size by including static runtime components
- **Memory Usage**: May result in multiple copies of runtime libraries if multiple static libraries are loaded
- **Update Isolation**: Security updates to system libstdc++ won't automatically apply to the library

**Implementation Approach**:
- Use `-static-libstdc++` and `-static-libgcc` linker flags in CMakeLists.txt
- Configure CMake with `target_link_options(dtvmapi PRIVATE -static-libstdc++ -static-libgcc)`
- Apply these flags only when ZEN_ENABLE_EVM is enabled for the EVMC library build
- Maintain dynamic linking for development builds to facilitate debugging
- Add symbol visibility controls with `-fvisibility=hidden` and `-Wl,--exclude-libs,ALL`

## Implementation Details

### Core Components

#### DTVM Class Structure
```cpp
struct DTVM : evmc_vm {
    RuntimeConfig Config;           // Runtime configuration (includes EnableEvmGasMetering)
    std::unique_ptr<Runtime> RT;    // DTVM Runtime instance
    std::unique_ptr<WrappedHost> ExecHost;  // Host interface bridge
    std::unordered_map<uint32_t, EVMModule*> LoadedMods;  // Module cache
    Isolation* Iso;                 // Execution isolation environment
};
```

#### EVMC Method Implementations

1. **evmc_create_dtvmapi()**: Factory function to create new DTVM instance
2. **destroy()**: Clean up all resources, including module unloading and Isolation destruction
3. **execute()**: Main execution entry point, handling EVM bytecode execution flow
4. **get_capabilities()**: Return EVMC_CAPABILITY_EVM1
5. **set_option()**: Support "mode" option for setting execution mode and "enable_gas_metering" option for controlling EVM gas metering

#### Execution Flow

1. **Module Loading**: Calculate code CRC32, check cache, load new module if necessary
2. **Instance Creation**: Create EVM instance in Isolation
3. **Execution**: Call DTVM Runtime to execute EVM code
4. **Result Processing**: Convert execution result to EVMC format
5. **Cleanup**: Destroy EVM instance, retain module cache

### Error Handling Strategy

- **Loading Errors**: Return EVMC_FAILURE, log detailed error information
- **Execution Errors**: Pass specific error status through evmc_result
- **Resource Errors**: Use RAII to ensure resource cleanup
- **Configuration Errors**: set_option returns appropriate error codes

### Performance Considerations

- **Module Caching**: Avoid recompiling identical bytecode
- **Isolation Reuse**: Reuse Isolation within the same VM instance
- **Memory Pre-allocation**: Reasonably set initial gas limits
- **Host Interface Optimization**: Minimize Host call overhead

## Risks / Trade-offs

### Risks

1. **Memory Leak Risk**: Module caching may lead to memory accumulation
   - **Mitigation**: Implement LRU cache strategy and explicit cleanup mechanisms

2. **CRC32 Collision Risk**: Different code may produce identical checksums
   - **Mitigation**: Monitor collision rates in production, upgrade to stronger hash algorithms if necessary

3. **Host Interface Compatibility**: Different Host implementations may have subtle differences
   - **Mitigation**: Comprehensive integration testing and error handling

### Trade-offs

1. **Performance vs Standardization**: EVMC interface introduces slight overhead but provides standardization benefits
2. **Memory vs Performance**: Module caching increases memory usage but significantly improves repeated execution performance
3. **Complexity vs Compatibility**: Wrapper adds code complexity but maintains backward compatibility

## Migration Plan

### Phase 1: Core Implementation (Already Complete)
- ✅ Implement basic EVMC interface with proper file naming (dt_evmc_vm.h/cpp)
- ✅ Integrate DTVM Runtime with managed isolation support
- ✅ Basic error handling and resource cleanup
- ✅ Enhanced WrappedHost with reinitialization capability

### Phase 2: Build Integration (Complete)
- ✅ Update CMake configuration
- ✅ Add compilation options and dependencies
- ✅ Configure export symbols and conditional compilation
- ✅ Configure static linking for cross-environment compatibility

### Phase 2.5: OpenSpec Integration (Complete)
- ✅ Add OpenSpec project structure and framework
- ✅ Create AGENTS.md with AI assistant instructions
- ✅ Set up spec-driven development workflow
- ✅ Configure change proposal management system
- ✅ Integrate OpenSpec validation and tooling

### Phase 3: Testing and Validation (Pending)
- Unit test coverage
- Integration testing
- Performance benchmarking
- Compatibility validation

### Phase 4: Documentation and Examples (Pending)
- API documentation updates
- Usage examples
- Integration guides

## Resolved Design Questions

### 1. Module Caching Strategy
**Decision**: Currently use simple unlimited caching based on CRC32 key `std::unordered_map`.
**Rationale**:
- For most use cases, code re-execution scenarios are limited
- Simple implementation reduces complexity and potential errors
- Can add LRU strategy in the future based on actual usage patterns

### 2. Thread Safety
**Decision**: Current implementation does not guarantee thread safety, each thread should use independent DTVM instances.
**Rationale**:
- EVMC specification itself does not require thread safety
- Simplifies implementation, avoids lock overhead
- Aligns with usage patterns of most Ethereum clients

### 3. WrappedHost Complete Implementation
**Implementation Details**: WrappedHost class fully implements all EVMC Host interface methods with enhanced flexibility:
- **Account Operations**: `account_exists`, `get_balance`, `access_account`
- **Storage Operations**: `get_storage`, `set_storage`, `access_storage`
- **Transient Storage**: `get_transient_storage`, `set_transient_storage`
- **Code Operations**: `get_code_size`, `get_code_hash`, `copy_code`
- **Call Operations**: `call`, `selfdestruct`
- **Blockchain State**: `get_tx_context`, `get_block_hash`, `emit_log`
- **Dynamic Reinitialization**: `reinitialize(interface, context)` method for runtime host switching
- **Flexible Construction**: Default constructor with null parameters for deferred initialization

### 4. Performance Considerations
**Benchmark Expectations**:
- Module caching should significantly improve repeated execution performance
- EVMC interface overhead expected < 5% compared to direct calls
- JIT mode performance should approach native DTVM execution