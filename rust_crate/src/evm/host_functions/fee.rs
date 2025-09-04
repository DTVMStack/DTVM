// Copyright (C) 2021-2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Fee related host functions
//!
//! This module provides functions for accessing fee information
//! such as base fee and blob base fee (EIP-4844).

use crate::core::instance::ZenInstance;
use crate::evm::error::HostFunctionResult;
use crate::evm::traits::EvmHost;
use crate::evm::utils::{validate_bytes32_param, MemoryAccessor};

/// Get the current block's base fee
/// Writes the 32-byte base fee to the specified memory location
///
/// Parameters:
/// - instance: WASM instance pointer
/// - result_offset: Memory offset where the 32-byte base fee should be written
pub fn get_base_fee<T>(instance: &ZenInstance<T>, result_offset: i32) -> HostFunctionResult<()>
where
    T: EvmHost,
{
    let evmhost = &instance.extra_ctx;
    let memory = MemoryAccessor::new(instance);

    // Validate the result offset
    let offset = validate_bytes32_param(instance, result_offset)?;

    // Get the base fee from block info
    let base_fee = evmhost.get_base_fee();

    // Write the base fee to memory
    memory.write_bytes32(offset, base_fee)?;

    Ok(())
}

/// Get the current block's blob base fee (EIP-4844)
/// Writes the 32-byte blob base fee to the specified memory location
///
/// Parameters:
/// - instance: WASM instance pointer
/// - result_offset: Memory offset where the 32-byte blob base fee should be written
pub fn get_blob_base_fee<T>(instance: &ZenInstance<T>, result_offset: i32) -> HostFunctionResult<()>
where
    T: EvmHost,
{
    let evmhost = &instance.extra_ctx;
    let memory = MemoryAccessor::new(instance);

    // Validate the result offset
    let offset = validate_bytes32_param(instance, result_offset)?;

    // Get the blob base fee from block info
    let blob_base_fee = evmhost.get_blob_base_fee();

    // Write the blob base fee to memory
    memory.write_bytes32(offset, blob_base_fee)?;

    Ok(())
}
