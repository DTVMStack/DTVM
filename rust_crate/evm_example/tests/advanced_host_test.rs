// Copyright (C) 2021-2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Advanced Host Functions Integration Test
//!
//! This test suite verifies advanced EVM host functions using AdvancedHostFunctions.wasm:
//! - Code operations (copy, size, hash)
//! - External contract interactions
//! - Mathematical operations (addmod, mulmod)
//! - Contract lifecycle (self-destruct)
//! - Error handling (invalid operations)

mod common;

use common::calldata::{set_call_data_with_params, ParamBuilder};
use common::*;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

// Test constants for better maintainability
const TEST_EXTERNAL_BALANCE: u64 = 1000;
const TEST_EXTERNAL_CODE_SIZE: u64 = 100;
const TEST_SELF_CODE_SIZE: u64 = 30_334;
const TEST_ADDMOD_A: u64 = 123;
const TEST_ADDMOD_B: u64 = 456;
const TEST_ADDMOD_M: u64 = 789;
const TEST_ADDMOD_RESULT: u64 = 579; // (123 + 456) % 789
const TEST_MULMOD_A: u64 = 123;
const TEST_MULMOD_B: u64 = 456;
const TEST_MULMOD_M: u64 = 789;
const TEST_MULMOD_RESULT: u64 = 69; // (123 * 456) % 789
const TEST_TARGET_ADDRESS_ID: u8 = 20;
const TEST_CONTRACT_ADDRESS_ID: u8 = 10;
const TEST_OWNER_ADDRESS_ID: u8 = 1;

// Expected test results as constants
const EXPECTED_CODE_COPY_HEX: &str = "000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000640061736d010000000176106000017f60037f7f7f0060017f0060027f7f0060077f7f7f7f7f7f7f0060057e7f7f7f7f017f6000006000017e60017f017f60047f7f7f7f0060037f7f7f017f60077e7f7f7f7f7f7f017f600d7f7e7e7e7e7e7e7e7e7e7e7e00000000000000000000000000000000000000000000000000000000";
const EXPECTED_EXTERNAL_CODE_HASH_HEX: &str =
    "de000000000000000000000000000000000000000000000000000000000000ad";
const EXPECTED_EXTERNAL_CODE_COPY_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000006460006000f3000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

// Function selectors - organized by category
mod selectors {
    // Code operations
    pub const TEST_CODE_COPY: [u8; 4] = [0x59, 0x2, 0xd1, 0xea]; // testCodeCopy()
    pub const GET_SELF_CODE_SIZE: [u8; 4] = [0xf7, 0x5, 0xc3, 0x68]; // getSelfCodeSize()

    // External contract operations
    pub const TEST_EXTERNAL_BALANCE: [u8; 4] = [0x59, 0x79, 0x3, 0x47]; // testExternalBalance(address)
    pub const TEST_EXTERNAL_CODE_SIZE: [u8; 4] = [0x68, 0x4f, 0x3b, 0xd5]; // testExternalCodeSize(address)
    pub const TEST_EXTERNAL_CODE_HASH: [u8; 4] = [0x27, 0x83, 0xc4, 0xbd]; // testExternalCodeHash(address)

    // Mathematical operations
    pub const TEST_ADD_MOD: [u8; 4] = [0x1e, 0xbf, 0xbc, 0xed]; // testAddMod(uint256,uint256,uint256)
    pub const TEST_MUL_MOD: [u8; 4] = [0x1, 0x40, 0x66, 0xf3]; // testMulMod(uint256,uint256,uint256)

    // Contract lifecycle
    pub const TEST_SELF_DESTRUCT: [u8; 4] = [0xbc, 0xfb, 0x19, 0x59]; // testSelfDestruct(address)

    // Error handling
    pub const TEST_INVALID: [u8; 4] = [0xd9, 0x0, 0xe, 0xf3]; // testInvalid()
}

/// Test fixture for AdvancedHostFunctions contract tests
struct AdvancedHostTestFixture {
    executor: ContractExecutor,
    wasm_bytes: Vec<u8>,
}

impl AdvancedHostTestFixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let wasm_bytes = load_wasm_file("../example/AdvancedHostFunctions.wasm")?;
        let executor = ContractExecutor::new()?;

        Ok(Self {
            executor,
            wasm_bytes,
        })
    }

    fn create_context(&self) -> MockContext {
        let owner_address = random_test_address(TEST_OWNER_ADDRESS_ID);
        let contract_address = random_test_address(TEST_CONTRACT_ADDRESS_ID);

        MockContext::builder()
            .with_storage(Rc::new(RefCell::new(HashMap::new())))
            .with_code(self.wasm_bytes.clone())
            .with_caller(owner_address)
            .with_address(contract_address)
            .build()
    }

    fn deploy_contract(&self, context: &mut MockContext) -> Result<(), Box<dyn std::error::Error>> {
        self.executor.deploy_contract("advanced_host", context)?;
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
        Ok(self
            .executor
            .call_contract_function("advanced_host", context)?)
    }
}

/// Main integration test for AdvancedHostFunctions contract
#[test]
fn test_advanced_host_functions() {
    let fixture = AdvancedHostTestFixture::new().expect("Failed to create test fixture");
    let mut context = fixture.create_context();

    fixture
        .deploy_contract(&mut context)
        .expect("Failed to deploy contract");

    // Run all test cases
    test_code_copy(&fixture);
    test_external_balance(&fixture);
    test_external_code_size(&fixture);
    test_external_code_hash(&fixture);
    test_external_code_copy(&fixture);
    test_add_mod(&fixture);
    test_mul_mod(&fixture);
    test_self_code_size(&fixture);
    test_self_destruct(&fixture);
    test_invalid(&fixture);
}

/// Test code copy operation
fn test_code_copy(fixture: &AdvancedHostTestFixture) {
    let mut context = fixture.create_context();

    let result = fixture
        .call_function(&mut context, &selectors::TEST_CODE_COPY, vec![])
        .expect("Failed to call testCodeCopy()");

    assert!(result.success, "testCodeCopy() should succeed");

    let actual_hex = hex::encode(&result.return_data);
    assert_eq!(
        actual_hex, EXPECTED_CODE_COPY_HEX,
        "Code copy result mismatch: expected {}, got {}",
        EXPECTED_CODE_COPY_HEX, actual_hex
    );
}

/// Test external balance retrieval
fn test_external_balance(fixture: &AdvancedHostTestFixture) {
    let mut context = fixture.create_context();
    let target_address = random_test_address(TEST_TARGET_ADDRESS_ID);
    let params = ParamBuilder::new().address(&target_address).build();

    let result = fixture
        .call_function(&mut context, &selectors::TEST_EXTERNAL_BALANCE, params)
        .expect("Failed to call testExternalBalance()");

    assert!(result.success, "testExternalBalance() should succeed");

    let balance =
        decode_uint256(&result.return_data).expect("Failed to decode balance from return data");

    assert_eq!(
        balance, TEST_EXTERNAL_BALANCE,
        "External balance mismatch: expected {}, got {}",
        TEST_EXTERNAL_BALANCE, balance
    );
}
/// Test external code size retrieval
fn test_external_code_size(fixture: &AdvancedHostTestFixture) {
    let mut context = fixture.create_context();
    let target_address = random_test_address(TEST_TARGET_ADDRESS_ID);
    let params = ParamBuilder::new().address(&target_address).build();

    let result = fixture
        .call_function(&mut context, &selectors::TEST_EXTERNAL_CODE_SIZE, params)
        .expect("Failed to call testExternalCodeSize()");

    assert!(result.success, "testExternalCodeSize() should succeed");

    let code_size =
        decode_uint256(&result.return_data).expect("Failed to decode code size from return data");

    assert_eq!(
        code_size, TEST_EXTERNAL_CODE_SIZE,
        "External code size mismatch: expected {}, got {}",
        TEST_EXTERNAL_CODE_SIZE, code_size
    );
}
/// Test external code hash retrieval
fn test_external_code_hash(fixture: &AdvancedHostTestFixture) {
    let mut context = fixture.create_context();
    let target_address = random_test_address(TEST_TARGET_ADDRESS_ID);
    let params = ParamBuilder::new().address(&target_address).build();

    let result = fixture
        .call_function(&mut context, &selectors::TEST_EXTERNAL_CODE_HASH, params)
        .expect("Failed to call testExternalCodeHash()");

    assert!(result.success, "testExternalCodeHash() should succeed");

    let code_hash =
        decode_bytes32(&result.return_data).expect("Failed to decode code hash from return data");

    let actual_hex = hex::encode(&code_hash);
    assert_eq!(
        actual_hex, EXPECTED_EXTERNAL_CODE_HASH_HEX,
        "External code hash mismatch: expected {}, got {}",
        EXPECTED_EXTERNAL_CODE_HASH_HEX, actual_hex
    );
}

/// Test external code copy operation
fn test_external_code_copy(fixture: &AdvancedHostTestFixture) {
    let mut context = fixture.create_context();
    let target_address = random_test_address(TEST_TARGET_ADDRESS_ID);
    let params = ParamBuilder::new()
        .address(&target_address)
        .uint256(0)
        .uint256(100)
        .build();

    let selector = calculate_selector("testExternalCodeCopy(address,uint256,uint256)");
    let result = fixture
        .call_function(&mut context, &selector, params)
        .expect("Failed to call testExternalCodeCopy()");

    assert!(result.success, "testExternalCodeCopy() should succeed");

    let actual_hex = hex::encode(&result.return_data);
    assert_eq!(
        actual_hex, EXPECTED_EXTERNAL_CODE_COPY_HEX,
        "External code copy result mismatch: expected {}, got {}",
        EXPECTED_EXTERNAL_CODE_COPY_HEX, actual_hex
    );
}

/// Test addmod mathematical operation
fn test_add_mod(fixture: &AdvancedHostTestFixture) {
    let mut context = fixture.create_context();
    let params = ParamBuilder::new()
        .uint256(TEST_ADDMOD_A)
        .uint256(TEST_ADDMOD_B)
        .uint256(TEST_ADDMOD_M)
        .build();

    let result = fixture
        .call_function(&mut context, &selectors::TEST_ADD_MOD, params)
        .expect("Failed to call testAddMod()");

    assert!(result.success, "testAddMod() should succeed");

    let addmod_result = decode_uint256(&result.return_data)
        .expect("Failed to decode addmod result from return data");

    assert_eq!(
        addmod_result, TEST_ADDMOD_RESULT,
        "AddMod result mismatch: ({} + {}) % {} should be {}, got {}",
        TEST_ADDMOD_A, TEST_ADDMOD_B, TEST_ADDMOD_M, TEST_ADDMOD_RESULT, addmod_result
    );
}

/// Test mulmod mathematical operation
fn test_mul_mod(fixture: &AdvancedHostTestFixture) {
    let mut context = fixture.create_context();
    let params = ParamBuilder::new()
        .uint256(TEST_MULMOD_A)
        .uint256(TEST_MULMOD_B)
        .uint256(TEST_MULMOD_M)
        .build();

    let result = fixture
        .call_function(&mut context, &selectors::TEST_MUL_MOD, params)
        .expect("Failed to call testMulMod()");

    assert!(result.success, "testMulMod() should succeed");

    let mulmod_result = decode_uint256(&result.return_data)
        .expect("Failed to decode mulmod result from return data");

    assert_eq!(
        mulmod_result, TEST_MULMOD_RESULT,
        "MulMod result mismatch: ({} * {}) % {} should be {}, got {}",
        TEST_MULMOD_A, TEST_MULMOD_B, TEST_MULMOD_M, TEST_MULMOD_RESULT, mulmod_result
    );
}
/// Test self code size retrieval
fn test_self_code_size(fixture: &AdvancedHostTestFixture) {
    let mut context = fixture.create_context();

    let result = fixture
        .call_function(&mut context, &selectors::GET_SELF_CODE_SIZE, vec![])
        .expect("Failed to call getSelfCodeSize()");

    assert!(result.success, "getSelfCodeSize() should succeed");

    let code_size = decode_uint256(&result.return_data)
        .expect("Failed to decode self code size from return data");

    assert_eq!(
        code_size, TEST_SELF_CODE_SIZE,
        "Self code size mismatch: expected {}, got {}",
        TEST_SELF_CODE_SIZE, code_size
    );
}

/// Test self destruct operation
fn test_self_destruct(fixture: &AdvancedHostTestFixture) {
    let mut context = fixture.create_context();
    let target_address = random_test_address(TEST_TARGET_ADDRESS_ID);
    let params = ParamBuilder::new().address(&target_address).build();

    let result = fixture
        .call_function(&mut context, &selectors::TEST_SELF_DESTRUCT, params.clone())
        .expect("Failed to call testSelfDestruct()");

    assert!(result.success, "testSelfDestruct() should succeed");

    // Verify that the balance was transferred to the target address
    let balance_result = fixture
        .call_function(&mut context, &selectors::TEST_EXTERNAL_BALANCE, params)
        .expect("Failed to call testExternalBalance() after self destruct");

    assert!(
        balance_result.success,
        "testExternalBalance() after self destruct should succeed"
    );

    let balance = decode_uint256(&balance_result.return_data)
        .expect("Failed to decode balance after self destruct");

    assert_eq!(
        balance, TEST_EXTERNAL_BALANCE,
        "Balance after self destruct should be {}, got {}",
        TEST_EXTERNAL_BALANCE, balance
    );
}

/// Test invalid operation error handling
fn test_invalid(fixture: &AdvancedHostTestFixture) {
    let mut context = fixture.create_context();

    let result = fixture
        .call_function(&mut context, &selectors::TEST_INVALID, vec![])
        .expect("Failed to call testInvalid()");

    // Invalid operations should fail
    assert!(!result.success, "testInvalid() should fail as expected");
}
