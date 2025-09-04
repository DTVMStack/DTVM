// Copyright (C) 2021-2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Transaction information related host functions
//!
//! This module provides functions for accessing transaction-specific data
//! such as call data, gas information, and transaction properties.

use crate::core::instance::ZenInstance;
use crate::evm::error::HostFunctionResult;
use crate::evm::traits::EvmHost;
use crate::evm::utils::{validate_bytes32_param, validate_data_param, MemoryAccessor};

/// Get the size of the call data
/// Returns the size of the current call data in bytes
///
/// Parameters:
/// - instance: WASM instance pointer
///
/// Returns:
/// - The size of the call data as i32
pub fn get_call_data_size<T>(instance: &ZenInstance<T>) -> i32
where
    T: EvmHost,
{
    let evmhost = &instance.extra_ctx;
    let call_data_size = evmhost.get_call_data_size();

    call_data_size
}

/// Copy call data to memory
/// Copies a portion of the call data to the specified memory location
///
/// This function follows EVM semantics: if the requested data extends beyond
/// the available call data, the remaining bytes are filled with zeros.
///
/// Parameters:
/// - instance: WASM instance pointer
/// - result_offset: Memory offset where the call data should be copied
/// - data_offset: Offset within the call data to start copying from
/// - length: Number of bytes to copy
pub fn call_data_copy<T>(
    instance: &ZenInstance<T>,
    result_offset: i32,
    data_offset: i32,
    length: i32,
) -> HostFunctionResult<()>
where
    T: EvmHost,
{
    let evmhost = &instance.extra_ctx;
    let memory = MemoryAccessor::new(instance);

    // Validate parameters with buffer size check
    let (result_offset_u32, length_u32) =
        validate_data_param(instance, result_offset, length, Some("call_data_copy"))?;

    if data_offset < 0 {
        return Err(crate::evm::error::out_of_bounds_error(
            data_offset as u32,
            length_u32,
            "negative call data offset",
        ));
    }

    // Create buffer with the exact requested length, initialized with zeros
    let mut buffer = vec![0u8; length_u32 as usize];

    // Copy call data using the evmhost's copy_call_data method
    // This method handles bounds checking and zero-filling automatically
    let call_data = evmhost.call_data_copy();
    let dest_len = buffer.len();

    // Calculate how much we can actually copy
    let available_from_offset = if (data_offset as usize) < call_data.len() {
        call_data.len() - data_offset as usize
    } else {
        0
    };

    let copied_bytes = std::cmp::min(
        std::cmp::min(length_u32 as usize, available_from_offset),
        dest_len,
    );

    if copied_bytes > 0 {
        buffer[..copied_bytes]
            .copy_from_slice(&call_data[data_offset as usize..data_offset as usize + copied_bytes]);
    }

    // Fill remaining buffer with zeros if needed
    if copied_bytes < dest_len && copied_bytes < length_u32 as usize {
        let zero_fill_len =
            std::cmp::min(length_u32 as usize - copied_bytes, dest_len - copied_bytes);
        if zero_fill_len > 0 {
            buffer[copied_bytes..copied_bytes + zero_fill_len].fill(0);
        }
    }
    // Write the entire buffer to memory (including any zero-filled portions)
    // This ensures we always write exactly 'length' bytes as requested
    memory.write_bytes(result_offset_u32, &buffer)?;

    Ok(())
}

/// Get the remaining gas for execution
/// Returns the amount of gas left for the current execution
///
/// Parameters:
/// - instance: WASM instance pointer
///
/// Returns:
/// - The remaining gas as i64
pub fn get_gas_left<T>(instance: &ZenInstance<T>) -> i64
where
    T: EvmHost,
{
    let gas_left = instance.get_gas_left();
    let evmhost = &instance.extra_ctx;
    let gas_left = evmhost.get_gas_left(gas_left as i64);

    gas_left
}

/// Get the transaction gas price
/// Writes the 32-byte gas price to the specified memory location
///
/// Parameters:
/// - instance: WASM instance pointer
/// - result_offset: Memory offset where the 32-byte gas price should be written
pub fn get_tx_gas_price<T>(instance: &ZenInstance<T>, result_offset: i32) -> HostFunctionResult<()>
where
    T: EvmHost,
{
    let evmhost = &instance.extra_ctx;
    let memory = MemoryAccessor::new(instance);

    // Validate the result offset
    let offset = validate_bytes32_param(instance, result_offset)?;

    // Get the gas price from transaction info
    let gas_price = evmhost.get_tx_gas_price();

    // Write the gas price to memory
    memory.write_bytes32(offset, gas_price)?;

    Ok(())
}
