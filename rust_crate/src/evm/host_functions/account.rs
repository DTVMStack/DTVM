// Copyright (C) 2021-2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Account and address related host functions

use crate::core::instance::ZenInstance;
use crate::evm::error::HostFunctionResult;
use crate::evm::traits::EvmHost;
use crate::evm::utils::{validate_address_param, validate_bytes32_param, MemoryAccessor};

/// Get the current contract address
/// Writes the 20-byte contract address to the specified memory location
///
/// Parameters:
/// - instance: WASM instance pointer
/// - result_offset: Memory offset where the 20-byte address should be written
pub fn get_address<T>(instance: &ZenInstance<T>, result_offset: i32) -> HostFunctionResult<()>
where
    T: EvmHost,
{
    let evmhost = &instance.extra_ctx;
    let memory = MemoryAccessor::new(instance);

    // Validate the result offset
    let offset = validate_address_param(instance, result_offset)?;

    // Get the contract address
    let address = evmhost.get_address();

    // Write the address to memory
    memory.write_address(offset, address)?;
    Ok(())
}

/// Get the caller address (msg.sender)
/// Writes the 20-byte caller address to the specified memory location
///
/// Parameters:
/// - instance: WASM instance pointer
/// - result_offset: Memory offset where the 20-byte address should be written
pub fn get_caller<T>(instance: &ZenInstance<T>, result_offset: i32) -> HostFunctionResult<()>
where
    T: EvmHost,
{
    let evmhost = &instance.extra_ctx;
    let memory = MemoryAccessor::new(instance);

    // Validate the result offset
    let offset = validate_address_param(instance, result_offset)?;

    // Get the caller address
    let caller = evmhost.get_caller();

    // Write the address to memory
    memory.write_address(offset, caller)?;

    Ok(())
}

/// Get the transaction origin address (tx.origin)
/// Writes the 20-byte transaction origin address to the specified memory location
///
/// Parameters:
/// - instance: WASM instance pointer
/// - result_offset: Memory offset where the 20-byte address should be written
pub fn get_tx_origin<T>(instance: &ZenInstance<T>, result_offset: i32) -> HostFunctionResult<()>
where
    T: EvmHost,
{
    let evmhost = &instance.extra_ctx;
    let memory = MemoryAccessor::new(instance);

    // Validate the result offset
    let offset = validate_address_param(instance, result_offset)?;

    // Get the transaction origin address
    let origin = evmhost.get_tx_origin();

    // Write the address to memory
    memory.write_address(offset, origin)?;

    Ok(())
}

/// Get the call value (msg.value)
/// Writes the 32-byte call value to the specified memory location
///
/// Parameters:
/// - instance: WASM instance pointer
/// - result_offset: Memory offset where the 32-byte value should be written
pub fn get_call_value<T>(instance: &ZenInstance<T>, result_offset: i32) -> HostFunctionResult<()>
where
    T: EvmHost,
{
    let evmhost = &instance.extra_ctx;
    let memory = MemoryAccessor::new(instance);

    // Validate the result offset
    let offset = validate_bytes32_param(instance, result_offset)?;

    // Get the call value
    let call_value = evmhost.get_call_value();

    // Write the value to memory
    memory.write_bytes32(offset, call_value)?;

    Ok(())
}

/// Get the chain ID
/// Writes the 32-byte chain ID to the specified memory location
///
/// Parameters:
/// - instance: WASM instance pointer
/// - result_offset: Memory offset where the 32-byte chain ID should be written
pub fn get_chain_id<T>(instance: &ZenInstance<T>, result_offset: i32) -> HostFunctionResult<()>
where
    T: EvmHost,
{
    let evmhost = &instance.extra_ctx;
    let memory = MemoryAccessor::new(instance);

    // Validate the result offset
    let offset = validate_bytes32_param(instance, result_offset)?;

    // Get the chain ID
    let chain_id = evmhost.get_chain_id();

    // Write the chain ID to memory
    memory.write_bytes32(offset, chain_id)?;

    Ok(())
}

/// Get the balance of an external account
/// Writes the 32-byte balance to the specified memory location
///
/// This function queries the balance using the AccountBalanceProvider trait,
/// allowing users to implement custom balance lookup logic.
///
/// Parameters:
/// - instance: WASM instance pointer
/// - addr_offset: Memory offset of the 20-byte address to query
/// - result_offset: Memory offset where the 32-byte balance should be written
pub fn get_external_balance<T>(
    instance: &ZenInstance<T>,
    addr_offset: i32,
    result_offset: i32,
) -> HostFunctionResult<()>
where
    T: EvmHost,
{
    let evmhost = &instance.extra_ctx;
    let memory = MemoryAccessor::new(instance);

    // Validate both offsets
    let addr_offset_u32 = validate_address_param(instance, addr_offset)?;
    let result_offset_u32 = validate_bytes32_param(instance, result_offset)?;

    // Read the address to query
    let address = memory.read_address(addr_offset_u32)?;

    // Query the balance using the AccountBalanceProvider trait
    let balance = evmhost.get_external_balance(&address);

    // Write the balance to memory
    memory.write_bytes32(result_offset_u32, &balance)?;
    Ok(())
}
