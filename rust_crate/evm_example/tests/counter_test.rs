// Copyright (C) 2021-2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Counter Contract EVM Integration Test
//!
//! This test verifies the counter.wasm smart contract with EVM host functions.
//! The counter contract provides:
//! - uint public count: A public counter variable
//! - function increase(): Increments the counter
//! - function decrease(): Decrements the counter
#![allow(dead_code)]

mod common;

use common::calldata::set_call_data_with_params;
use common::*;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

// Counter contract function selectors
const COUNT_SELECTOR: [u8; 4] = [0x06, 0x66, 0x1a, 0xbd]; // count()
const INCREASE_SELECTOR: [u8; 4] = [0xe8, 0x92, 0x7f, 0xbc]; // increase()
const DECREASE_SELECTOR: [u8; 4] = [0xd7, 0x32, 0xd9, 0x55]; // decrease()

#[test]
fn test_counter_contract() {
    // Load counter WASM module
    let counter_wasm_bytes =
        load_wasm_file("../example/counter.wasm").expect("Failed to load counter.wasm");

    // Create shared storage for the test
    let shared_storage = Rc::new(RefCell::new(HashMap::new()));

    // Create contract executor
    let executor = ContractExecutor::new().expect("Failed to create contract executor");

    let mut context = MockContext::builder()
        .with_code(counter_wasm_bytes.clone())
        .with_storage(shared_storage.clone())
        .with_address([0x42; 20])
        .build();

    // Deploy contract
    executor
        .deploy_contract("counter", &mut context)
        .expect("Failed to deploy contract");

    // Test counter operations
    test_initial_count(&executor, &mut context);
    test_increase_counter(&executor, &mut context);
    test_decrease_counter(&executor, &mut context);
}

fn test_initial_count(executor: &ContractExecutor, context: &mut MockContext) {
    // Use new simplified API with no parameters
    set_call_data_with_params(context, &COUNT_SELECTOR, vec![]);

    let result = executor
        .call_contract_function("counter", context)
        .expect("Failed to call count()");

    assert!(result.success, "count() should succeed");

    // Verify initial count is 0
    let count_value = decode_uint256(&result.return_data).unwrap();
    assert_eq!(
        count_value, 0,
        "Initial count should be 0, got {}",
        count_value
    );
}

fn test_increase_counter(executor: &ContractExecutor, context: &mut MockContext) {
    // Use new simplified API with no parameters
    set_call_data_with_params(context, &INCREASE_SELECTOR, vec![]);

    let result = executor
        .call_contract_function("counter", context)
        .expect("Failed to call increase()");

    assert!(result.success, "increase() should succeed");

    // Verify the count increased to 1
    set_call_data_with_params(context, &COUNT_SELECTOR, vec![]);
    let count_result = executor
        .call_contract_function("counter", context)
        .expect("Failed to call count() after increase");

    assert!(
        count_result.success,
        "count() after increase should succeed"
    );

    let count_value = decode_uint256(&count_result.return_data).unwrap();
    assert_eq!(
        count_value, 1,
        "Count should be 1 after increase, got {}",
        count_value
    );
}

fn test_decrease_counter(executor: &ContractExecutor, context: &mut MockContext) {
    // Use new simplified API with no parameters
    set_call_data_with_params(context, &DECREASE_SELECTOR, vec![]);

    let result = executor
        .call_contract_function("counter", context)
        .expect("Failed to call decrease()");

    assert!(result.success, "decrease() should succeed");

    // Verify the count decreased back to 0
    set_call_data_with_params(context, &COUNT_SELECTOR, vec![]);
    let count_result = executor
        .call_contract_function("counter", context)
        .expect("Failed to call count() after decrease");

    assert!(
        count_result.success,
        "count() after decrease should succeed"
    );

    let count_value = decode_uint256(&count_result.return_data).unwrap();
    assert_eq!(
        count_value, 0,
        "Count should be 0 after decrease, got {}",
        count_value
    );
}
