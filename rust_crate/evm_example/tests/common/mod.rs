// Copyright (C) 2021-2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Test the public module
//! Contains all the functions and tools shared by all tests.

#![allow(unused_imports)]
#![allow(dead_code)]

pub mod calldata;
pub mod decode;

pub use evm_example::contract_executor::ContractExecutor;
pub use evm_example::mock_context::{BlockInfo, ContractInfo, MockContext};

pub use calldata::*;
pub use decode::*;

use std::fs;

pub fn load_wasm_file(path: &str) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|e| format!("Failed to load WASM file {}: {}", path, e))
}

pub fn calculate_selector(signature: &str) -> [u8; 4] {
    use sha3::{Digest, Keccak256};
    let hash = Keccak256::digest(signature.as_bytes());
    [hash[0], hash[1], hash[2], hash[3]]
}

/// Helper function to create a test address
pub fn random_test_address(byte: u8) -> [u8; 20] {
    let mut addr = [0u8; 20];
    addr[19] = byte; // Set the last byte to distinguish addresses
    addr
}
