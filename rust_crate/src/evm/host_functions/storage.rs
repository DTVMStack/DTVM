// Copyright (C) 2021-2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Storage Related Host Functions
//!
//! This module implements EVM storage operations that allow contracts to persist data
//! between function calls and transactions. Storage operations are fundamental to
//! smart contract state management.
//!
//! # EVM Storage Model
//!
//! EVM storage is a key-value store where:
//! - Keys are 32-byte (256-bit) values
//! - Values are 32-byte (256-bit) values  
//! - Storage is persistent across function calls
//! - Each contract has its own isolated storage space
//!
//! # Functions
//!
//! - [`storage_store`] - Store a 32-byte value at a 32-byte key (SSTORE)
//! - [`storage_load`] - Load a 32-byte value from a 32-byte key (SLOAD)
//!
//! # Gas Costs
//!
//! Storage operations have significant gas costs in real EVM:
//! - SSTORE: 5,000-20,000 gas depending on the operation type
//! - SLOAD: 800 gas for warm access, 2,100 gas for cold access
//!
//! # Usage Example
//!
//! ```rust
//! // Store a value (typically called from WASM)
//! storage_store(&instance, key_offset, value_offset)?;
//!
//! // Load a value (typically called from WASM)  
//! storage_load(&instance, key_offset, result_offset)?;
//! ```

use crate::core::instance::ZenInstance;
use crate::evm::error::HostFunctionResult;
use crate::evm::traits::EvmHost;
use crate::evm::utils::MemoryAccessor;

/// Storage store host function implementation
/// Stores a 32-byte value at a 32-byte key in contract storage
///
/// Parameters:
/// - instance: WASM instance pointer
/// - key_bytes_offset: Memory offset of the 32-byte storage key
/// - value_bytes_offset: Memory offset of the 32-byte storage value
pub fn storage_store<T>(
    instance: &ZenInstance<T>,
    key_bytes_offset: i32,
    value_bytes_offset: i32,
) -> HostFunctionResult<()>
where
    T: EvmHost,
{
    // Get the Mockevmhost from the instance
    let evmhost = &instance.extra_ctx;
    let memory = MemoryAccessor::new(instance);

    // Validate and read the storage key (32 bytes)
    let key_bytes = memory.read_bytes32(key_bytes_offset as u32)?;

    // Validate and read the storage value (32 bytes)
    let value_bytes = memory.read_bytes32(value_bytes_offset as u32)?;

    // Store the value in the evmhost using EVMC-compatible method
    evmhost.storage_store(&key_bytes, &value_bytes);

    Ok(())
}

/// Storage load host function implementation
/// Loads a 32-byte value from contract storage at the given 32-byte key
///
/// Parameters:
/// - instance: WASM instance pointer
/// - key_bytes_offset: Memory offset of the 32-byte storage key
/// - result_offset: Memory offset where the 32-byte result should be written
pub fn storage_load<T>(
    instance: &ZenInstance<T>,
    key_bytes_offset: i32,
    result_offset: i32,
) -> HostFunctionResult<()>
where
    T: EvmHost,
{
    // Get the Mockevmhost from the instance
    let evmhost = &instance.extra_ctx;
    let memory = MemoryAccessor::new(instance);

    // Validate and read the storage key (32 bytes)
    let key_bytes = memory.read_bytes32(key_bytes_offset as u32)?;

    // Load the value from storage using EVMC-compatible method
    let value_bytes = evmhost.storage_load(&key_bytes);

    // Write the result to memory
    memory.write_bytes32(result_offset as u32, &value_bytes)?;

    Ok(())
}
