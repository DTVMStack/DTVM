// Copyright (C) 2021-2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! SimpleToken Contract EVM Integration Test
//!
//! This test verifies the SimpleToken.wasm smart contract with EVM host functions.
//! The SimpleToken contract provides basic ERC20-like functionality:
//! - balanceOf(address): Get balance of an address
//! - transfer(address, uint256): Transfer tokens
//! - totalSupply(): Get total token supply
#![allow(dead_code)]

mod common;

use common::*;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

// SimpleToken contract function selectors (first 4 bytes of keccak256(function_signature))
const NAME_SELECTOR: [u8; 4] = [0x06, 0xfd, 0xde, 0x03]; // name()
const SYMBOL_SELECTOR: [u8; 4] = [0x95, 0xd8, 0x9b, 0x41]; // symbol()
const DECIMALS_SELECTOR: [u8; 4] = [0x31, 0x3c, 0xe5, 0x67]; // decimals()
const TOTAL_SUPPLY_SELECTOR: [u8; 4] = [0x18, 0x16, 0x0d, 0xdd]; // totalSupply()
const BALANCE_OF_SELECTOR: [u8; 4] = [0x70, 0xa0, 0x82, 0x31]; // balanceOf(address)
const MINT_SELECTOR: [u8; 4] = [0x40, 0xc1, 0x0f, 0x19]; // mint(address,uint256)
const TRANSFER_SELECTOR: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb]; // transfer(address,uint256)
const APPROVE_SELECTOR: [u8; 4] = [0x09, 0x5e, 0xa7, 0xb3]; // approve(address,uint256)
const TRANSFER_FROM_SELECTOR: [u8; 4] = [0x23, 0xb8, 0x72, 0xdd]; // transferFrom(address,address,uint256)
const ALLOWANCE_SELECTOR: [u8; 4] = [0xdd, 0x62, 0xed, 0x3e]; // allowance(address,address)

#[test]
fn test_simple_token_contract() {
    // Load SimpleToken WASM module
    let token_wasm_bytes =
        load_wasm_file("../example/SimpleToken.wasm").expect("Failed to load SimpleToken.wasm");

    // Create shared storage for the test
    let shared_storage = Rc::new(RefCell::new(HashMap::new()));

    // Create contract executor
    let executor = ContractExecutor::new().expect("Failed to create contract executor");

    let mut context = MockContext::builder()
        .with_code(token_wasm_bytes.clone())
        .with_storage(shared_storage.clone())
        .with_address([0x55; 20])
        .build();

    // Create test addresses
    let owner_address = random_test_address(1);

    // Deploy contract
    // Set constructor parameter: initial supply = 1000000 tokens (1M * 10^18 wei)
    let initial_supply = 1000000u64;
    let mut constructor_data = [0u8; 32];
    constructor_data[24..32].copy_from_slice(&initial_supply.to_be_bytes());
    context.set_call_data(constructor_data.to_vec());

    // Set the caller as the owner (this will be the token owner)
    context.set_caller(owner_address);

    executor
        .deploy_contract("simple_token", &mut context)
        .expect("Failed to deploy contract");

    // Test token operations
    test_total_supply(&executor, &mut context);
    test_token_name(&executor, &mut context);
    test_balance_of(&executor, &mut context);
    test_mint(&executor, &mut context);
    test_transfer(&executor, &mut context);
}

fn test_total_supply(executor: &ContractExecutor, context: &mut MockContext) {
    // Use new simplified API with no parameters
    set_call_data_with_params(context, &TOTAL_SUPPLY_SELECTOR, vec![]);

    let result = executor
        .call_contract_function("simple_token", context)
        .expect("Failed to call totalSupply()");

    assert!(result.success, "totalSupply() should succeed");

    let count_value = decode_uint256(&result.return_data).unwrap();
    assert_eq!(
        count_value, 1000000,
        "Total supply should be 1000000, got {}",
        count_value
    );
}

fn test_token_name(executor: &ContractExecutor, context: &mut MockContext) {
    set_call_data_with_params(context, &NAME_SELECTOR, vec![]);

    let result = executor
        .call_contract_function("simple_token", context)
        .expect("Failed to call name()");

    assert!(result.success, "name() should succeed");

    let count_value = decode_abi_string(&result.return_data).unwrap();
    assert_eq!(
        count_value,
        "SimpleToken".to_string(),
        "Token name should be SimpleToken, got {}",
        count_value
    );
}

fn test_balance_of(executor: &ContractExecutor, context: &mut MockContext) {
    let owner_address = random_test_address(1);
    let params = ParamBuilder::new().address(&owner_address).build();
    set_call_data_with_params(context, &BALANCE_OF_SELECTOR, params);

    let result = executor
        .call_contract_function("simple_token", context)
        .expect("Failed to call balanceOf()");

    assert!(result.success, "balanceOf() should succeed");

    let count_value = decode_uint256(&result.return_data).unwrap();
    assert_eq!(
        count_value, 1000000,
        "Balance  of owner should be 1000000, got {}",
        count_value
    );
}

fn test_mint(executor: &ContractExecutor, context: &mut MockContext) {
    let recipient_address = random_test_address(2);
    let params = ParamBuilder::new()
        .address(&recipient_address)
        .uint256(5000u64)
        .build();
    set_call_data_with_params(context, &MINT_SELECTOR, params);

    let result = executor
        .call_contract_function("simple_token", context)
        .expect("Failed to call mint()");

    assert!(result.success, "mint() should succeed");
    let params = ParamBuilder::new().address(&recipient_address).build();
    set_call_data_with_params(context, &BALANCE_OF_SELECTOR, params);

    let result = executor
        .call_contract_function("simple_token", context)
        .expect("Failed to call balanceOf()");

    assert!(result.success, "balanceOf() should succeed");

    let count_value = decode_uint256(&result.return_data).unwrap();
    assert_eq!(
        count_value, 5000,
        "Balance of recipient should be 5000, got {}",
        count_value
    );
}

fn test_transfer(executor: &ContractExecutor, context: &mut MockContext) {
    let spender_address = random_test_address(3);
    let params = ParamBuilder::new()
        .address(&spender_address)
        .uint256(1000u64)
        .build();
    set_call_data_with_params(context, &TRANSFER_SELECTOR, params);

    let result = executor
        .call_contract_function("simple_token", context)
        .expect("Failed to call transfer()");
    assert!(result.success, "transfer() should succeed");
    let params = ParamBuilder::new().address(&spender_address).build();
    set_call_data_with_params(context, &BALANCE_OF_SELECTOR, params);

    let result = executor
        .call_contract_function("simple_token", context)
        .expect("Failed to call balanceOf()");

    assert!(result.success, "balanceOf() should succeed");

    let count_value = decode_uint256(&result.return_data).unwrap();
    assert_eq!(
        count_value, 1000,
        "Balance of spender should be 1000, got {}",
        count_value
    );
}
