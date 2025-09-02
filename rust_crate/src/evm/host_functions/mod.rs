// Copyright (C) 2021-2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! EVM Host Functions Implementation
//!
//! This module contains all the EVM host functions organized by functional categories.
//! Each category corresponds to a specific aspect of EVM execution:
//!
//! - **Account**: Address and balance related operations
//! - **Block**: Block information and properties
//! - **Transaction**: Transaction data and gas operations  
//! - **Storage**: Contract storage operations
//! - **Code**: Contract code access and manipulation
//! - **Crypto**: Cryptographic operations (hashing)
//! - **Math**: Mathematical operations (modular arithmetic)
//! - **Contract**: Contract interaction (calls, creation)
//! - **Control**: Execution control (finish, revert, etc.)
//! - **Log**: Event logging and emission
//! - **Fee**: Fee-related operations
//!
//! # Usage
//!
//! ```rust
//! use dtvmcore_rust::evm::host_functions::*;
//!
//! // All host functions are available through their respective modules
//! // or can be imported directly from the root
//! ```

// Core modules - organized by EVM functionality
pub mod account;
pub mod block;
pub mod code;
pub mod contract;
pub mod control;
pub mod crypto;
pub mod fee;
pub mod log;
pub mod math;
pub mod storage;
pub mod transaction;

// Re-export commonly used functions for convenience
// Account operations
pub use account::{
    get_address, get_call_value, get_caller, get_chain_id, get_external_balance, get_tx_origin,
};

// Block operations
pub use block::{
    get_block_coinbase, get_block_gas_limit, get_block_hash, get_block_number,
    get_block_prev_randao, get_block_timestamp,
};

// Transaction operations
pub use transaction::{call_data_copy, get_call_data_size, get_gas_left, get_tx_gas_price};

// Storage operations
pub use storage::{storage_load, storage_store};

// Code operations
pub use code::{
    code_copy, external_code_copy, get_code_size, get_external_code_hash, get_external_code_size,
};

// Crypto operations
pub use crypto::{keccak256, sha256};

// Math operations
pub use math::{addmod, expmod, mulmod};

// Contract operations
pub use contract::{call_code, call_contract, call_delegate, call_static, create_contract};

// Control operations
pub use control::{finish, get_return_data_size, invalid, return_data_copy, revert, self_destruct};

// Log operations
pub use log::{emit_log0, emit_log1, emit_log2, emit_log3, emit_log4, emit_log_event};

// Fee operations
pub use fee::{get_base_fee, get_blob_base_fee};
