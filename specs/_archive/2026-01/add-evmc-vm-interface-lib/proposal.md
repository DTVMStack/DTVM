# Change: Add EVMC VM Interface Library Implementation

## Why

DTVM needs to provide a standard EVMC (Ethereum Client-VM Connector API) interface implementation to achieve seamless integration with the Ethereum ecosystem. While DTVM currently has powerful WebAssembly and EVM execution capabilities, it lacks a standardized EVMC interface, limiting its use in existing Ethereum clients and toolchains.

By implementing the EVMC interface, DTVM can:
- Be invoked as a standard EVM implementation by Ethereum clients
- Support existing Ethereum development tools and testing frameworks
- Provide pluggable VM implementation options, enhancing ecosystem compatibility

## What Changes

- **Add EVMC VM Interface Implementation**: Add complete EVMC interface implementation in `src/vm/` directory
- **Standard EVMC ABI Compatibility**: Implement complete interface specification for EVMC ABI version 12
- **Multi-Runtime Mode Support**: Support dynamic switching between interpreter and multipass JIT execution modes
- **Memory and Resource Management**: Implement safe VM instance lifecycle management
- **Host Interface Integration**: Enable interaction with Ethereum clients through WrappedHost

### Core Components:
- `evmc_create_dtvmapi()`: VM instance creation function
- `DTVM` class: Main VM implementation inheriting from `evmc_vm`
- Standard EVMC methods: `destroy`, `execute`, `get_capabilities`, `set_option`
- Runtime configuration: Support for EVM format, multiple execution modes, and EVM gas metering control

## Impact

### Affected Specifications:
- **Added**: `evmc-vm-interface` - EVMC standard interface implementation specification

### Affected Code:
- `src/vm/dt_evmc_vm.h` - EVMC VM interface header file (renamed from dt_vm.h)
- `src/vm/dt_evmc_vm.cpp` - EVMC VM interface implementation (renamed from dt_vm.cpp)
- `src/vm/wrapped_host.h` - Host interface wrapper with enhanced reinitialization support
- `src/vm/CMakeLists.txt` - Build system configuration updated for new file names and static linking
- `openspec/AGENTS.md` - **NEW**: OpenSpec framework integration for spec-driven development
- `openspec/` directory structure - **NEW**: Complete OpenSpec project setup

### Compatibility Impact:
- **Backward Compatible**: Does not affect existing DTVM APIs and functionality
- **Ecosystem Integration**: Enhanced compatibility with Ethereum toolchain
- **Performance**: May introduce slight call overhead through EVMC interface, but provides standardization benefits
- **Development Process**: **NEW**: Introduces spec-driven development workflow through OpenSpec

### Dependencies:
- Depends on EVMC library (already included in project)
- Depends on existing DTVM Runtime and EVM execution engine
- Requires WrappedHost implementation to bridge Host interface
- **NEW**: OpenSpec tooling for specification management and validation

### OpenSpec Integration:
- **Specification Management**: Formal specification tracking through `openspec/specs/` directory
- **Change Proposals**: Structured change management through `openspec/changes/` directory
- **Development Workflow**: AI-assisted spec-driven development with validation tools
- **Documentation Standards**: Consistent requirement and scenario documentation format