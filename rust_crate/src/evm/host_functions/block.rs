// Copyright (C) 2021-2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Block Information Host Functions
//!
//! This module provides access to blockchain block information that contracts
//! can use to make decisions based on the current execution environment.
//! Block information is essential for time-based logic, randomness, and
//! blockchain-aware contract behavior.
//!
//! # Available Block Information
//!
//! - [`get_block_number`] - Current block number (BLOCKNUMBER)
//! - [`get_block_timestamp`] - Block timestamp in seconds since Unix epoch (TIMESTAMP)
//! - [`get_block_gas_limit`] - Maximum gas allowed in this block (GASLIMIT)
//! - [`get_block_coinbase`] - Address of the block miner/validator (COINBASE)
//! - [`get_block_prev_randao`] - Previous block's RANDAO value (PREVRANDAO)
//! - [`get_block_hash`] - Hash of a specific block by number (BLOCKHASH)
//!
//! # Block Properties
//!
//! ## Block Number
//! - Monotonically increasing integer
//! - Starts from 0 (genesis block)
//! - Used for time-based logic and historical references
//!
//! ## Block Timestamp
//! - Unix timestamp in seconds
//! - Set by block producer/miner
//! - Should be greater than parent block timestamp
//! - Used for time-based contract logic
//!
//! ## Gas Limit
//! - Maximum gas that can be consumed by all transactions in the block
//! - Adjusts dynamically based on network usage
//! - Used for gas optimization strategies
//!
//! ## Coinbase
//! - Address that receives block rewards and transaction fees
//! - In PoW: miner address
//! - In PoS: validator address
//!
//! ## Previous RANDAO
//! - Source of on-chain randomness
//! - Replaces DIFFICULTY in post-merge Ethereum
//! - Should not be used alone for critical randomness
//!
//! # Security Considerations
//!
//! - Block timestamp can be manipulated by miners within limits (~15 seconds)
//! - Block hash is only available for recent blocks (last 256 blocks)
//! - RANDAO provides weak randomness, combine with other sources for security
//!
//! # Usage Example
//!
//! ```rust
//! // Get current block information
//! let block_number = get_block_number(&instance);
//! let timestamp = get_block_timestamp(&instance);
//! let gas_limit = get_block_gas_limit(&instance);
//!
//! // Get block hash for specific block
//! get_block_hash(&instance, block_number - 1, hash_result_offset)?;
//! ```

use crate::core::instance::ZenInstance;
use crate::evm::error::HostFunctionResult;
use crate::evm::traits::EvmHost;
use crate::evm::utils::{validate_address_param, validate_bytes32_param, MemoryAccessor};

/// Get the current block number
/// Returns the block number as i64
pub fn get_block_number<T>(instance: &ZenInstance<T>) -> i64
where
    T: EvmHost,
{
    let evmhost = &instance.extra_ctx;
    let block_number = evmhost.get_block_number();

    block_number
}

/// Get the current block timestamp
/// Returns the block timestamp as i64
pub fn get_block_timestamp<T>(instance: &ZenInstance<T>) -> i64
where
    T: EvmHost,
{
    let evmhost = &instance.extra_ctx;
    let timestamp = evmhost.get_block_timestamp();

    timestamp
}

/// Get the current block gas limit
/// Returns the block gas limit as i64
pub fn get_block_gas_limit<T>(instance: &ZenInstance<T>) -> i64
where
    T: EvmHost,
{
    let evmhost = &instance.extra_ctx;
    let gas_limit = evmhost.get_block_gas_limit();

    gas_limit
}

/// Get the current block coinbase address
/// Writes the 20-byte coinbase address to the specified memory location
///
/// Parameters:
/// - instance: WASM instance pointer
/// - result_offset: Memory offset where the 20-byte address should be written
pub fn get_block_coinbase<T>(
    instance: &ZenInstance<T>,
    result_offset: i32,
) -> HostFunctionResult<()>
where
    T: EvmHost,
{
    let evmhost = &instance.extra_ctx;
    let memory = MemoryAccessor::new(instance);

    // Validate the result offset
    let offset = validate_address_param(instance, result_offset)?;

    // Get the coinbase address from block info
    let coinbase = evmhost.get_block_coinbase();

    // Write the address to memory
    memory.write_address(offset, coinbase)?;

    Ok(())
}

/// Get the current block's previous randao (difficulty)
/// Writes the 32-byte previous randao to the specified memory location
///
/// Parameters:
/// - instance: WASM instance pointer
/// - result_offset: Memory offset where the 32-byte value should be written
pub fn get_block_prev_randao<T>(
    instance: &ZenInstance<T>,
    result_offset: i32,
) -> HostFunctionResult<()>
where
    T: EvmHost,
{
    let evmhost = &instance.extra_ctx;
    let memory = MemoryAccessor::new(instance);

    // Validate the result offset
    let offset = validate_bytes32_param(instance, result_offset)?;

    // Get the previous randao from block info
    let prev_randao = evmhost.get_block_prev_randao();

    // Write the value to memory
    memory.write_bytes32(offset, prev_randao)?;

    Ok(())
}

/// Get a block hash for a specific block number
/// Writes the 32-byte block hash to the specified memory location
///
/// This function queries the block hash using the BlockHashProvider trait,
/// allowing users to implement custom block hash lookup logic.
///
/// Parameters:
/// - instance: WASM instance pointer
/// - block_num: The block number to get the hash for
/// - result_offset: Memory offset where the 32-byte hash should be written
///
/// Returns:
/// - 1 if successful (hash found)
/// - 0 if block number is invalid or too old
pub fn get_block_hash<T>(
    instance: &ZenInstance<T>,
    block_num: i64,
    result_offset: i32,
) -> HostFunctionResult<i32>
where
    T: EvmHost,
{
    let evmhost = &instance.extra_ctx;
    let memory = MemoryAccessor::new(instance);

    // Validate the result offset
    let offset = validate_bytes32_param(instance, result_offset)?;

    let current_block = evmhost.get_block_number();

    // Basic validation: block number should be non-negative and less than current block
    if block_num < 0 || block_num >= current_block {
        // Write zero hash for invalid block numbers
        let zero_hash = [0u8; 32];
        memory.write_bytes32(offset, &zero_hash)?;

        return Ok(0); // Block not found
    }

    // Query the block hash using the BlockHashProvider trait
    match evmhost.get_block_hash(block_num) {
        Some(hash) => {
            // Write the hash to memory
            memory.write_bytes32(offset, &hash)?;

            Ok(1) // Success
        }
        None => {
            // Write zero hash when block is not found or too old
            let zero_hash = [0u8; 32];
            memory.write_bytes32(offset, &zero_hash)?;

            Ok(0) // Block not found
        }
    }
}
