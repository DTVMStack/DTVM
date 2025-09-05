// Copyright (C) 2021-2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Contract Calls Integration Test
//!
//! This test suite verifies contract-to-contract calls functionality:
//! - Regular calls between contracts
//! - Static calls (read-only operations)
//! - Delegate calls (execution in caller's context)
//! - Contract creation (CREATE and CREATE2)

mod common;

use common::calldata::{set_call_data_with_params, ParamBuilder};
use common::*;
use ethabi::encode;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

// Test constants for better maintainability
const TEST_SET_VALUE: u64 = 100;
const TEST_CREATE_VALUE: u64 = 123;
const TEST_CREATE2_VALUE: u64 = 456;
const TEST_OWNER_ADDRESS_ID: u8 = 1;
const TEST_CALLS_CONTRACT_ADDRESS_ID: u8 = 10;
const TEST_TARGET_CONTRACT_ADDRESS_ID: u8 = 20;
const TEST_CREATE_RESULT_ADDRESS_ID: u8 = 9;
const TEST_CREATE2_RESULT_ADDRESS_ID: u8 = 99;

const TEST_CREATE2_SALT: [u8; 32] = [
    0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
];

// Expected test results as constants
const EXPECTED_CALL_RETURN_DATA: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    100,
];

// Function selectors - organized by category
mod selectors {
    use crate::calculate_selector;

    // Contract call operations
    pub fn test_call() -> [u8; 4] {
        calculate_selector("testCall(address,bytes)")
    }

    pub fn test_static_call() -> [u8; 4] {
        calculate_selector("testStaticCall(address,bytes)")
    }

    pub fn test_delegate_call() -> [u8; 4] {
        calculate_selector("testDelegateCall(address,bytes)")
    }

    // Contract creation operations
    pub fn test_create() -> [u8; 4] {
        calculate_selector("testCreate(uint256)")
    }

    pub fn test_create2() -> [u8; 4] {
        calculate_selector("testCreate2(uint256,bytes32)")
    }

    // Target contract operations
    pub fn set_value() -> [u8; 4] {
        calculate_selector("setValue(uint256)")
    }

    pub fn get_value() -> [u8; 4] {
        calculate_selector("getValue()")
    }
}

/// Test fixture for ContractCalls integration tests
struct ContractCallsTestFixture {
    executor: ContractExecutor,
    contract_calls_wasm: Vec<u8>,
    simple_target_wasm: Vec<u8>,
}

impl ContractCallsTestFixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let contract_calls_wasm = load_wasm_file("../example/ContractCalls.wasm")?;
        let simple_target_wasm = load_wasm_file("../example/SimpleTarget.wasm")?;
        let executor = ContractExecutor::new()?;

        Ok(Self {
            executor,
            contract_calls_wasm,
            simple_target_wasm,
        })
    }

    /// Create a fresh context for each test to ensure isolation
    fn create_fresh_context(&self) -> Result<MockContext, Box<dyn std::error::Error>> {
        // Create fresh storage and registry for each test
        let fresh_storage = Rc::new(RefCell::new(HashMap::new()));
        let fresh_registry = Rc::new(RefCell::new(HashMap::new()));

        let owner_address = random_test_address(TEST_OWNER_ADDRESS_ID);
        let calls_contract_address = random_test_address(TEST_CALLS_CONTRACT_ADDRESS_ID);
        let target_contract_address = random_test_address(TEST_TARGET_CONTRACT_ADDRESS_ID);

        // Pre-register both contracts in the fresh registry
        {
            let mut registry = fresh_registry.borrow_mut();
            registry.insert(
                target_contract_address,
                ContractInfo::new(
                    "SimpleTarget.wasm".to_string(),
                    self.simple_target_wasm.clone(),
                ),
            );
            registry.insert(
                calls_contract_address,
                ContractInfo::new(
                    "ContractCalls.wasm".to_string(),
                    self.contract_calls_wasm.clone(),
                ),
            );
        }

        // Deploy target contract first
        let mut target_context = MockContext::builder()
            .with_storage(fresh_storage.clone())
            .with_contract_registry(fresh_registry.clone())
            .with_code(self.simple_target_wasm.clone())
            .with_caller(owner_address)
            .with_address(target_contract_address)
            .build();

        self.executor
            .deploy_contract("simple_target", &mut target_context)?;

        // Create and deploy caller contract context
        let mut caller_context = MockContext::builder()
            .with_storage(fresh_storage.clone())
            .with_contract_registry(fresh_registry.clone())
            .with_code(self.contract_calls_wasm.clone())
            .with_caller(owner_address)
            .with_address(calls_contract_address)
            .build();

        self.executor
            .deploy_contract("contract_calls", &mut caller_context)?;

        Ok(caller_context)
    }

    fn call_function(
        &self,
        context: &mut MockContext,
        selector: &[u8; 4],
        params: Vec<ethabi::Token>,
    ) -> Result<evm_example::contract_executor::ContractExecutionResult, Box<dyn std::error::Error>>
    {
        set_call_data_with_params(context, selector, params);
        Ok(self
            .executor
            .call_contract_function("ContractCalls.wasm", context)?)
    }
}

/// Main integration test for contract calls functionality
#[test]
fn test_contract_calls() {
    let fixture = ContractCallsTestFixture::new().expect("Failed to create test fixture");

    // Run all test cases with fresh contexts for each test
    test_call(&fixture);
    test_static_call(&fixture);
    test_delegate_call(&fixture);
    test_create(&fixture);
    test_create2(&fixture);
}

/// Test regular contract call functionality
fn test_call(fixture: &ContractCallsTestFixture) {
    let mut context = fixture
        .create_fresh_context()
        .expect("Failed to create fresh context");

    // Prepare call data for setValue(100) on the target contract
    let target_call_data = {
        let mut data = selectors::set_value().to_vec();
        data.extend_from_slice(&encode(
            &ParamBuilder::new().uint256(TEST_SET_VALUE).build(),
        ));
        data
    };

    let target_address = random_test_address(TEST_TARGET_CONTRACT_ADDRESS_ID);
    let params = ParamBuilder::new()
        .address(&target_address)
        .bytes(&target_call_data)
        .build();

    let result = fixture
        .call_function(&mut context, &selectors::test_call(), params)
        .expect("Failed to call testCall()");

    assert!(result.success, "testCall() should succeed");

    let (call_success, return_data) =
        decode_call_result(&result.return_data).expect("Failed to decode call result");

    assert!(call_success, "Contract call should succeed");
    assert_eq!(
        return_data, EXPECTED_CALL_RETURN_DATA,
        "Call return data mismatch: expected {:?}, got {:?}",
        EXPECTED_CALL_RETURN_DATA, return_data
    );
}
/// Test static call functionality (read-only operations)
fn test_static_call(fixture: &ContractCallsTestFixture) {
    let mut context = fixture
        .create_fresh_context()
        .expect("Failed to create fresh context");

    // First, set a value using regular call so we have something to read
    let set_call_data = {
        let mut data = selectors::set_value().to_vec();
        data.extend_from_slice(&encode(
            &ParamBuilder::new().uint256(TEST_SET_VALUE).build(),
        ));
        data
    };

    let target_address = random_test_address(TEST_TARGET_CONTRACT_ADDRESS_ID);
    let set_params = ParamBuilder::new()
        .address(&target_address)
        .bytes(&set_call_data)
        .build();

    // Set the value first
    let set_result = fixture
        .call_function(&mut context, &selectors::test_call(), set_params)
        .expect("Failed to call testCall() for setup");

    assert!(set_result.success, "Setup call should succeed");

    // Now test static call to read the value
    let get_call_data = selectors::get_value().to_vec();
    let get_params = ParamBuilder::new()
        .address(&target_address)
        .bytes(&get_call_data)
        .build();

    let result = fixture
        .call_function(&mut context, &selectors::test_static_call(), get_params)
        .expect("Failed to call testStaticCall()");

    assert!(result.success, "testStaticCall() should succeed");

    let (call_success, return_data) =
        decode_call_result(&result.return_data).expect("Failed to decode static call result");

    assert!(call_success, "Static call should succeed");
    assert_eq!(
        return_data, EXPECTED_CALL_RETURN_DATA,
        "Static call return data mismatch: expected {:?}, got {:?}",
        EXPECTED_CALL_RETURN_DATA, return_data
    );
}
/// Test delegate call functionality (execution in caller's context)
fn test_delegate_call(fixture: &ContractCallsTestFixture) {
    let mut context = fixture
        .create_fresh_context()
        .expect("Failed to create fresh context");

    // Prepare call data for setValue(100) on the target contract
    let target_call_data = {
        let mut data = selectors::set_value().to_vec();
        data.extend_from_slice(&encode(
            &ParamBuilder::new().uint256(TEST_SET_VALUE).build(),
        ));
        data
    };

    let target_address = random_test_address(TEST_TARGET_CONTRACT_ADDRESS_ID);
    let params = ParamBuilder::new()
        .address(&target_address)
        .bytes(&target_call_data)
        .build();

    let result = fixture
        .call_function(&mut context, &selectors::test_delegate_call(), params)
        .expect("Failed to call testDelegateCall()");

    assert!(result.success, "testDelegateCall() should succeed");

    let (call_success, return_data) =
        decode_call_result(&result.return_data).expect("Failed to decode delegate call result");

    assert!(call_success, "Delegate call should succeed");
    assert_eq!(
        return_data, EXPECTED_CALL_RETURN_DATA,
        "Delegate call return data mismatch: expected {:?}, got {:?}",
        EXPECTED_CALL_RETURN_DATA, return_data
    );
}
/// Test contract creation using CREATE opcode
fn test_create(fixture: &ContractCallsTestFixture) {
    let mut context = fixture
        .create_fresh_context()
        .expect("Failed to create fresh context");

    let params = ParamBuilder::new().uint256(TEST_CREATE_VALUE).build();

    let result = fixture
        .call_function(&mut context, &selectors::test_create(), params)
        .expect("Failed to call testCreate()");

    assert!(result.success, "testCreate() should succeed");

    let created_address =
        decode_address(&result.return_data).expect("Failed to decode created contract address");

    let expected_address = random_test_address(TEST_CREATE_RESULT_ADDRESS_ID);
    assert_eq!(
        created_address, expected_address,
        "Created contract address mismatch: expected {:?}, got {:?}",
        expected_address, created_address
    );
}

/// Test contract creation using CREATE2 opcode (deterministic address)
fn test_create2(fixture: &ContractCallsTestFixture) {
    let mut context = fixture
        .create_fresh_context()
        .expect("Failed to create fresh context");

    let params = ParamBuilder::new()
        .uint256(TEST_CREATE2_VALUE)
        .fixed_bytes(&TEST_CREATE2_SALT)
        .build();

    let result = fixture
        .call_function(&mut context, &selectors::test_create2(), params)
        .expect("Failed to call testCreate2()");

    assert!(result.success, "testCreate2() should succeed");

    let created_address =
        decode_address(&result.return_data).expect("Failed to decode CREATE2 contract address");

    let expected_address = random_test_address(TEST_CREATE2_RESULT_ADDRESS_ID);
    assert_eq!(
        created_address, expected_address,
        "CREATE2 contract address mismatch: expected {:?}, got {:?}",
        expected_address, created_address
    );
}
