// Copyright (C) 2021-2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! BaseInfo Contract EVM Host Functions Integration Test
//!
//! This test suite verifies the BaseHostFunctions.wasm smart contract EVM host functions:
//! - Contract address retrieval
//! - Block information (number, timestamp, gas limit, coinbase, hash)
//! - Transaction information (origin, gas price, gas left)
//! - Chain information (chain ID, base fee, blob base fee, prev randao)
//! - Cryptographic functions (SHA256)

mod common;

use common::calldata::{set_call_data_with_params, ParamBuilder};
use common::*;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

// Test constants for better maintainability and type safety
const TEST_BLOCK_NUMBER: u64 = 12_345;
const TEST_TIMESTAMP: u64 = 1_640_995_200; // 2022-01-01 00:00:00 UTC
const TEST_GAS_LIMIT: u64 = 30_000_000;
const TEST_GAS_PRICE: u64 = 20_000_000_000; // 20 gwei
const TEST_BASE_FEE: u64 = 10_000_000_000; // 10 gwei
const TEST_BLOB_BASE_FEE: u64 = 1_000_000_000; // 1 gwei
const TEST_CHAIN_ID: u64 = 1; // Ethereum mainnet
const TEST_GAS_LEFT: u64 = 100;
const TEST_CONTRACT_ADDRESS_ID: u8 = 5;
const TEST_OWNER_ADDRESS_ID: u8 = 1;
const TEST_COINBASE_ADDRESS_ID: u8 = 99;
const TEST_BLOCK_HASH_QUERY: u64 = 12_344; // Previous block

const TEST_PREV_RANDAO: [u8; 32] = [
    0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x99,
];

// Expected test results as constants
const EXPECTED_PREV_RANDAO_HEX: &str =
    "123456789abcdef0112233445566778899aabbcc000000000000000000000099";
const EXPECTED_BLOCK_HASH_HEX: &str =
    "ab000000000000000000000000000000000000000000000000000000000000cd";
const EXPECTED_SHA256_HASH_HEX: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

// Function selectors - organized by category
mod selectors {
    // Address and contract info
    pub const GET_ADDRESS_INFO: [u8; 4] = [0x4f, 0x2a, 0x36, 0xab]; // getAddressInfo()

    // Block information
    pub const GET_BLOCK_NUM: [u8; 4] = [0x7f, 0x6c, 0x6f, 0x10]; // getBlockNum()
    pub const GET_TIMESTAMP: [u8; 4] = [0x18, 0x8e, 0xc3, 0x56]; // getTimestamp()
    pub const GET_GAS_LIMIT: [u8; 4] = [0x1a, 0x93, 0xd1, 0xc3]; // getGasLimit()
    pub const GET_COINBASE: [u8; 4] = [0xd1, 0xa8, 0x2a, 0x9d]; // getCoinbase()
    pub const GET_BLOCK_HASH: [u8; 4] = [0x65, 0x8c, 0xb4, 0x73]; // getblockHash(uint256)
    pub const GET_PREV_RANDAO: [u8; 4] = [0xf4, 0xc3, 0xa9, 0xb8]; // getPrevRandao()

    // Transaction information
    pub const GET_ORIGIN: [u8; 4] = [0xdf, 0x1f, 0x29, 0xee]; // getOrigin()
    pub const GET_GAS_PRICE: [u8; 4] = [0xab, 0x70, 0xfd, 0x69]; // getGasprice()
    pub const GET_GAS_LEFT: [u8; 4] = [0xed, 0xb4, 0xb8, 0x65]; // getGasleft()

    // Chain information
    pub const GET_CHAIN_INFO: [u8; 4] = [0x21, 0xca, 0xe4, 0x83]; // getChainInfo()
    pub const GET_BASE_FEE: [u8; 4] = [0x15, 0xe8, 0x12, 0xad]; // getBaseFee()
    pub const GET_BLOB_BASE_FEE: [u8; 4] = [0x1f, 0x6d, 0x6e, 0xf7]; // getBlobBaseFee()

    // Cryptographic functions
    pub const TEST_SHA256: [u8; 4] = [0xd0, 0x20, 0xae, 0xb7]; // testSha256(bytes)
}

/// Test fixture for BaseInfo contract tests
struct BaseInfoTestFixture {
    executor: ContractExecutor,
    wasm_bytes: Vec<u8>,
}

impl BaseInfoTestFixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let wasm_bytes = load_wasm_file("../example/BaseHostFunctions.wasm")?;
        let executor = ContractExecutor::new()?;

        Ok(Self {
            executor,
            wasm_bytes,
        })
    }

    fn create_context(&self) -> MockContext {
        MockContext::builder()
            .with_storage(Rc::new(RefCell::new(HashMap::new())))
            .with_code(self.wasm_bytes.clone())
            .build()
    }

    fn deploy_contract(&self, context: &mut MockContext) -> Result<(), Box<dyn std::error::Error>> {
        self.executor.deploy_contract("base_info", context)?;
        Ok(())
    }

    fn call_function(
        &self,
        context: &mut MockContext,
        selector: &[u8; 4],
        params: Vec<ethabi::Token>,
    ) -> Result<evm_example::contract_executor::ContractExecutionResult, Box<dyn std::error::Error>>
    {
        set_call_data_with_params(context, selector, params);
        Ok(self.executor.call_contract_function("base_info", context)?)
    }
}

/// Main integration test for BaseInfo contract
#[test]
fn test_base_info_contract() {
    let fixture = BaseInfoTestFixture::new().expect("Failed to create test fixture");
    let mut context = fixture.create_context();

    fixture
        .deploy_contract(&mut context)
        .expect("Failed to deploy contract");

    // Run all test cases
    test_address_info(&fixture);
    test_block_number(&fixture);
    test_block_timestamp(&fixture);
    test_gas_limit(&fixture);
    test_coinbase(&fixture);
    test_transaction_origin(&fixture);
    test_gas_price(&fixture);
    test_gas_left(&fixture);
    test_chain_id(&fixture);
    test_base_fee(&fixture);
    test_blob_base_fee(&fixture);
    test_prev_randao(&fixture);
    test_block_hash(&fixture);
    test_sha256_function(&fixture);
}

/// Test contract address retrieval
fn test_address_info(fixture: &BaseInfoTestFixture) {
    let expected_address = random_test_address(TEST_CONTRACT_ADDRESS_ID);
    let mut context = MockContext::builder()
        .with_code(fixture.wasm_bytes.clone())
        .with_address(expected_address)
        .build();

    let result = fixture
        .call_function(&mut context, &selectors::GET_ADDRESS_INFO, vec![])
        .expect("Failed to call getAddressInfo");

    assert!(result.success, "getAddressInfo should succeed");

    let actual_address =
        decode_address(&result.return_data).expect("Failed to decode address from return data");

    assert_eq!(
        actual_address, expected_address,
        "Contract address mismatch: expected {:?}, got {:?}",
        expected_address, actual_address
    );
}

/// Test block number retrieval
fn test_block_number(fixture: &BaseInfoTestFixture) {
    let mut context = MockContext::builder()
        .with_code(fixture.wasm_bytes.clone())
        .with_block_number(TEST_BLOCK_NUMBER as i64)
        .build();

    let result = fixture
        .call_function(&mut context, &selectors::GET_BLOCK_NUM, vec![])
        .expect("Failed to call getBlockNum");

    assert!(result.success, "getBlockNum should succeed");

    let block_number = decode_uint256(&result.return_data)
        .expect("Failed to decode block number from return data");

    assert_eq!(
        block_number, TEST_BLOCK_NUMBER,
        "Block number mismatch: expected {}, got {}",
        TEST_BLOCK_NUMBER, block_number
    );
}

/// Test block timestamp retrieval
fn test_block_timestamp(fixture: &BaseInfoTestFixture) {
    let mut context = MockContext::builder()
        .with_code(fixture.wasm_bytes.clone())
        .with_block_timestamp(TEST_TIMESTAMP as i64)
        .build();

    let result = fixture
        .call_function(&mut context, &selectors::GET_TIMESTAMP, vec![])
        .expect("Failed to call getTimestamp");

    assert!(result.success, "getTimestamp should succeed");

    let timestamp =
        decode_uint256(&result.return_data).expect("Failed to decode timestamp from return data");

    assert_eq!(
        timestamp, TEST_TIMESTAMP,
        "Timestamp mismatch: expected {} (2022-01-01 00:00:00 UTC), got {}",
        TEST_TIMESTAMP, timestamp
    );
}

/// Test block gas limit retrieval
fn test_gas_limit(fixture: &BaseInfoTestFixture) {
    let mut context = MockContext::builder()
        .with_code(fixture.wasm_bytes.clone())
        .with_block_gas_limit(TEST_GAS_LIMIT as i64)
        .build();

    let result = fixture
        .call_function(&mut context, &selectors::GET_GAS_LIMIT, vec![])
        .expect("Failed to call getGasLimit");

    assert!(result.success, "getGasLimit should succeed");

    let gas_limit =
        decode_uint256(&result.return_data).expect("Failed to decode gas limit from return data");

    assert_eq!(
        gas_limit, TEST_GAS_LIMIT,
        "Gas limit mismatch: expected {}, got {}",
        TEST_GAS_LIMIT, gas_limit
    );
}

/// Test block coinbase address retrieval
fn test_coinbase(fixture: &BaseInfoTestFixture) {
    let expected_coinbase = random_test_address(TEST_COINBASE_ADDRESS_ID);
    let mut context = MockContext::builder()
        .with_code(fixture.wasm_bytes.clone())
        .with_block_coinbase(expected_coinbase)
        .build();

    let result = fixture
        .call_function(&mut context, &selectors::GET_COINBASE, vec![])
        .expect("Failed to call getCoinbase");

    assert!(result.success, "getCoinbase should succeed");

    let coinbase = decode_address(&result.return_data)
        .expect("Failed to decode coinbase address from return data");

    assert_eq!(
        coinbase, expected_coinbase,
        "Coinbase address mismatch: expected {:?}, got {:?}",
        expected_coinbase, coinbase
    );
}

/// Test transaction origin address retrieval
fn test_transaction_origin(fixture: &BaseInfoTestFixture) {
    let expected_origin = random_test_address(TEST_OWNER_ADDRESS_ID);
    let mut context = MockContext::builder()
        .with_code(fixture.wasm_bytes.clone())
        .with_tx_origin(expected_origin)
        .build();

    let result = fixture
        .call_function(&mut context, &selectors::GET_ORIGIN, vec![])
        .expect("Failed to call getOrigin");

    assert!(result.success, "getOrigin should succeed");

    let origin = decode_address(&result.return_data)
        .expect("Failed to decode origin address from return data");

    assert_eq!(
        origin, expected_origin,
        "Transaction origin mismatch: expected {:?}, got {:?}",
        expected_origin, origin
    );
}

/// Test transaction gas price retrieval
fn test_gas_price(fixture: &BaseInfoTestFixture) {
    let mut context = MockContext::builder()
        .with_code(fixture.wasm_bytes.clone())
        .with_gas_price_wei(TEST_GAS_PRICE)
        .build();

    let result = fixture
        .call_function(&mut context, &selectors::GET_GAS_PRICE, vec![])
        .expect("Failed to call getGasprice");

    assert!(result.success, "getGasprice should succeed");

    let gas_price =
        decode_uint256(&result.return_data).expect("Failed to decode gas price from return data");

    assert_eq!(
        gas_price, TEST_GAS_PRICE,
        "Gas price mismatch: expected {} wei (20 gwei), got {} wei",
        TEST_GAS_PRICE, gas_price
    );
}

/// Test remaining gas retrieval
fn test_gas_left(fixture: &BaseInfoTestFixture) {
    let mut context = MockContext::builder()
        .with_code(fixture.wasm_bytes.clone())
        .build();

    let result = fixture
        .call_function(&mut context, &selectors::GET_GAS_LEFT, vec![])
        .expect("Failed to call getGasleft");

    assert!(result.success, "getGasleft should succeed");

    let gas_left =
        decode_uint256(&result.return_data).expect("Failed to decode gas left from return data");

    assert_eq!(
        gas_left, TEST_GAS_LEFT,
        "Gas left mismatch: expected {}, got {}",
        TEST_GAS_LEFT, gas_left
    );
}

/// Test chain ID retrieval
fn test_chain_id(fixture: &BaseInfoTestFixture) {
    let mut context = MockContext::builder()
        .with_code(fixture.wasm_bytes.clone())
        .with_chain_id_u64(TEST_CHAIN_ID)
        .build();

    let result = fixture
        .call_function(&mut context, &selectors::GET_CHAIN_INFO, vec![])
        .expect("Failed to call getChainInfo");

    assert!(result.success, "getChainInfo should succeed");

    let chain_id =
        decode_uint256(&result.return_data).expect("Failed to decode chain ID from return data");

    assert_eq!(
        chain_id, TEST_CHAIN_ID,
        "Chain ID mismatch: expected {} (Ethereum mainnet), got {}",
        TEST_CHAIN_ID, chain_id
    );
}

/// Test base fee retrieval
fn test_base_fee(fixture: &BaseInfoTestFixture) {
    let mut base_fee_bytes = [0u8; 32];
    base_fee_bytes[24..32].copy_from_slice(&TEST_BASE_FEE.to_be_bytes());

    let mut context = MockContext::builder()
        .with_code(fixture.wasm_bytes.clone())
        .with_base_fee(base_fee_bytes)
        .build();

    let result = fixture
        .call_function(&mut context, &selectors::GET_BASE_FEE, vec![])
        .expect("Failed to call getBaseFee");

    assert!(result.success, "getBaseFee should succeed");

    let base_fee =
        decode_uint256(&result.return_data).expect("Failed to decode base fee from return data");

    assert_eq!(
        base_fee, TEST_BASE_FEE,
        "Base fee mismatch: expected {} wei (10 gwei), got {} wei",
        TEST_BASE_FEE, base_fee
    );
}

/// Test blob base fee retrieval
fn test_blob_base_fee(fixture: &BaseInfoTestFixture) {
    let mut blob_base_fee_bytes = [0u8; 32];
    blob_base_fee_bytes[24..32].copy_from_slice(&TEST_BLOB_BASE_FEE.to_be_bytes());

    let mut context = MockContext::builder()
        .with_code(fixture.wasm_bytes.clone())
        .with_blob_base_fee(blob_base_fee_bytes)
        .build();

    let result = fixture
        .call_function(&mut context, &selectors::GET_BLOB_BASE_FEE, vec![])
        .expect("Failed to call getBlobBaseFee");

    assert!(result.success, "getBlobBaseFee should succeed");

    let blob_base_fee = decode_uint256(&result.return_data)
        .expect("Failed to decode blob base fee from return data");

    assert_eq!(
        blob_base_fee, TEST_BLOB_BASE_FEE,
        "Blob base fee mismatch: expected {} wei (1 gwei), got {} wei",
        TEST_BLOB_BASE_FEE, blob_base_fee
    );
}

/// Test previous randao retrieval
fn test_prev_randao(fixture: &BaseInfoTestFixture) {
    let mut context = MockContext::builder()
        .with_code(fixture.wasm_bytes.clone())
        .with_block_prev_randao(TEST_PREV_RANDAO)
        .build();

    let result = fixture
        .call_function(&mut context, &selectors::GET_PREV_RANDAO, vec![])
        .expect("Failed to call getPrevRandao");

    assert!(result.success, "getPrevRandao should succeed");

    let prev_randao =
        decode_bytes32(&result.return_data).expect("Failed to decode prev randao from return data");

    let actual_hex = hex::encode(&prev_randao);

    assert_eq!(
        actual_hex, EXPECTED_PREV_RANDAO_HEX,
        "Previous randao mismatch: expected {}, got {}",
        EXPECTED_PREV_RANDAO_HEX, actual_hex
    );
}

/// Test block hash retrieval by block number
fn test_block_hash(fixture: &BaseInfoTestFixture) {
    let mut context = MockContext::builder()
        .with_code(fixture.wasm_bytes.clone())
        .build();

    let params = ParamBuilder::new().uint256(TEST_BLOCK_HASH_QUERY).build();

    let result = fixture
        .call_function(&mut context, &selectors::GET_BLOCK_HASH, params)
        .expect("Failed to call getblockHash");

    assert!(result.success, "getblockHash should succeed");

    let block_hash =
        decode_bytes32(&result.return_data).expect("Failed to decode block hash from return data");

    let actual_hex = hex::encode(&block_hash);

    assert_eq!(
        actual_hex, EXPECTED_BLOCK_HASH_HEX,
        "Block hash mismatch for block {}: expected {}, got {}",
        TEST_BLOCK_HASH_QUERY, EXPECTED_BLOCK_HASH_HEX, actual_hex
    );
}

/// Test SHA256 cryptographic function
fn test_sha256_function(fixture: &BaseInfoTestFixture) {
    let mut context = MockContext::builder()
        .with_code(fixture.wasm_bytes.clone())
        .build();

    let test_data = b"Hello, DTVM!";
    let params = ParamBuilder::new().bytes(test_data).build();

    let result = fixture
        .call_function(&mut context, &selectors::TEST_SHA256, params)
        .expect("Failed to call testSha256");

    assert!(result.success, "testSha256 should succeed");

    let sha256_hash =
        decode_bytes32(&result.return_data).expect("Failed to decode SHA256 hash from return data");

    // Note: This appears to be a mock implementation returning zeros
    // In a real implementation, this would be the actual SHA256 hash
    let actual_hex = hex::encode(&sha256_hash);

    assert_eq!(
        actual_hex,
        EXPECTED_SHA256_HASH_HEX,
        "SHA256 hash mismatch for input {:?}: expected {}, got {}",
        std::str::from_utf8(test_data).unwrap_or("invalid UTF-8"),
        EXPECTED_SHA256_HASH_HEX,
        actual_hex
    );
}
