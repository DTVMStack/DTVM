// Copyright (C) 2021-2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![allow(dead_code)]

use crate::calculate_selector;
use crate::create_test_address;

#[allow(dead_code)]
pub fn set_function_call_data(context: &mut super::MockContext, selector: &[u8; 4]) {
    context.set_call_data(selector.to_vec());
    println!(
        "   📋 Set call data with function selector: 0x{}",
        hex::encode(selector)
    );
}

/// Helper function to set call data with address and uint256 parameters
pub fn set_function_call_data_with_address_and_amount(
    context: &mut super::MockContext,
    selector: &[u8; 4],
    address: &[u8; 20],
    amount: u64,
) {
    let mut call_data = selector.to_vec();
    // Add address parameter (padded to 32 bytes)
    call_data.extend_from_slice(&[0u8; 12]);
    call_data.extend_from_slice(address);
    // Add amount parameter (32 bytes, big-endian)
    let mut amount_bytes = [0u8; 32];
    amount_bytes[24..32].copy_from_slice(&amount.to_be_bytes());
    call_data.extend_from_slice(&amount_bytes);
    context.set_call_data(call_data);
    println!(
        "   📋 Set call data with function selector: 0x{}, address: 0x{}, amount: {}",
        hex::encode(selector),
        hex::encode(address),
        amount
    );
}
/// Helper function to set call data with address parameter
pub fn set_function_call_data_with_address(
    context: &mut super::MockContext,
    selector: &[u8; 4],
    address: &[u8; 20],
) {
    let mut call_data = selector.to_vec();
    // Add padding zeros (12 bytes) + address (20 bytes) = 32 bytes total
    call_data.extend_from_slice(&[0u8; 12]);
    call_data.extend_from_slice(address);
    context.set_call_data(call_data);
    println!(
        "   📋 Set call data with function selector: 0x{} and address: 0x{}",
        hex::encode(selector),
        hex::encode(address)
    );
}
/// Helper function to set call data with address and two uint256 parameters
pub fn set_function_call_data_with_address_and_two_uint256(
    context: &mut super::MockContext,
    selector: &[u8; 4],
    address: &[u8; 20],
    a: u64,
    b: u64,
) {
    let mut call_data = selector.to_vec();

    // Add address parameter (padded to 32 bytes)
    call_data.extend_from_slice(&[0u8; 12]);
    call_data.extend_from_slice(address);

    // Add first uint256 parameter
    let mut value_a = [0u8; 32];
    value_a[24..32].copy_from_slice(&a.to_be_bytes());
    call_data.extend_from_slice(&value_a);

    // Add second uint256 parameter
    let mut value_b = [0u8; 32];
    value_b[24..32].copy_from_slice(&b.to_be_bytes());
    call_data.extend_from_slice(&value_b);

    context.set_call_data(call_data);
    println!(
        "   📋 Set call data with function selector: 0x{}, address: 0x{}, and values: {}, {}",
        hex::encode(selector),
        hex::encode(address),
        a,
        b
    );
}
/// Helper function to set call data with three uint256 parameters
pub fn set_function_call_data_with_three_uint256(
    context: &mut super::MockContext,
    selector: &[u8; 4],
    a: u64,
    b: u64,
    c: u64,
) {
    let mut call_data = selector.to_vec();

    // Add first uint256 parameter
    let mut value_a = [0u8; 32];
    value_a[24..32].copy_from_slice(&a.to_be_bytes());
    call_data.extend_from_slice(&value_a);

    // Add second uint256 parameter
    let mut value_b = [0u8; 32];
    value_b[24..32].copy_from_slice(&b.to_be_bytes());
    call_data.extend_from_slice(&value_b);

    // Add third uint256 parameter
    let mut value_c = [0u8; 32];
    value_c[24..32].copy_from_slice(&c.to_be_bytes());
    call_data.extend_from_slice(&value_c);

    context.set_call_data(call_data);
    println!(
        "   📋 Set call data with function selector: 0x{} and values: {}, {}, {}",
        hex::encode(selector),
        a,
        b,
        c
    );
}
/// Helper function to set call data with uint256 parameter
pub fn set_function_call_data_with_uint256(
    context: &mut super::MockContext,
    selector: &[u8; 4],
    value: u64,
) {
    let mut call_data = selector.to_vec();
    // Add uint256 parameter (32 bytes, big-endian)
    let mut value_bytes = [0u8; 32];
    value_bytes[24..32].copy_from_slice(&value.to_be_bytes());
    call_data.extend_from_slice(&value_bytes);
    context.set_call_data(call_data);
    println!(
        "   📋 Set call data with function selector: 0x{} and value: {}",
        hex::encode(selector),
        value
    );
}
/// Helper function to set call data with bytes parameter
pub fn set_function_call_data_with_bytes(
    context: &mut super::MockContext,
    selector: &[u8; 4],
    data: &[u8],
) {
    let mut call_data = selector.to_vec();

    // ABI encode bytes parameter
    // Offset to data (32 bytes)
    call_data.extend_from_slice(&[0u8; 31]);
    call_data.push(0x20); // offset = 32

    // Length of data (32 bytes)
    let mut length_bytes = [0u8; 32];
    length_bytes[24..32].copy_from_slice(&(data.len() as u64).to_be_bytes());
    call_data.extend_from_slice(&length_bytes);

    // Data itself (padded to multiple of 32 bytes)
    call_data.extend_from_slice(data);
    let padding = (32 - (data.len() % 32)) % 32;
    call_data.extend_from_slice(&vec![0u8; padding]);

    context.set_call_data(call_data);
    println!(
        "   📋 Set call data with function selector: 0x{} and {} bytes of data",
        hex::encode(selector),
        data.len()
    );
}
/// Helper function to set call data with uint256 parameter
pub fn set_function_call_data_with_call(context: &mut super::MockContext) {
    // Prepare call data for testCall(address target, bytes data)
    // We want to call setValue(100) on the target contract
    let target_call_data = {
        let mut data = calculate_selector("setValue(uint256)").to_vec();
        let mut value_bytes = [0u8; 32];
        value_bytes[24..32].copy_from_slice(&100u64.to_be_bytes());
        data.extend_from_slice(&value_bytes);
        data
    };

    // Encode the full call: testCall(target_address, target_call_data)
    let mut full_call_data = calculate_selector("testCall(address,bytes)").to_vec();

    // Add target address (32 bytes)
    full_call_data.extend_from_slice(&[0u8; 12]);
    full_call_data.extend_from_slice(&create_test_address(20));

    // Add offset to bytes data (32 bytes) - points to where bytes data starts
    let mut offset_bytes = [0u8; 32];
    offset_bytes[24..32].copy_from_slice(&64u64.to_be_bytes()); // 64 = 32 + 32
    full_call_data.extend_from_slice(&offset_bytes);

    // Add bytes length (32 bytes)
    let mut length_bytes = [0u8; 32];
    length_bytes[24..32].copy_from_slice(&(target_call_data.len() as u64).to_be_bytes());
    full_call_data.extend_from_slice(&length_bytes);

    // Add bytes data (padded to multiple of 32)
    full_call_data.extend_from_slice(&target_call_data);
    let padding = (32 - (target_call_data.len() % 32)) % 32;
    full_call_data.extend_from_slice(&vec![0u8; padding]);

    context.set_call_data(full_call_data);
    println!("   📋 Set call data for testCall operation");
}

/// Helper function to set call data with uint256 parameter
pub fn set_function_call_data_with_static_call(context: &mut super::MockContext) {
    // Prepare call data for testStaticCall to getValue()
    let target_call_data = calculate_selector("getValue()").to_vec();

    // Encode the full call: testStaticCall(target_address, target_call_data)
    let mut full_call_data = calculate_selector("testStaticCall(address,bytes)").to_vec();

    // Add target address (32 bytes)
    full_call_data.extend_from_slice(&[0u8; 12]);
    full_call_data.extend_from_slice(&create_test_address(20));

    // Add offset to bytes data (32 bytes)
    let mut offset_bytes = [0u8; 32];
    offset_bytes[24..32].copy_from_slice(&64u64.to_be_bytes());
    full_call_data.extend_from_slice(&offset_bytes);

    // Add bytes length (32 bytes)
    let mut length_bytes = [0u8; 32];
    length_bytes[24..32].copy_from_slice(&(target_call_data.len() as u64).to_be_bytes());
    full_call_data.extend_from_slice(&length_bytes);

    // Add bytes data (padded to multiple of 32)
    full_call_data.extend_from_slice(&target_call_data);
    let padding = (32 - (target_call_data.len() % 32)) % 32;
    full_call_data.extend_from_slice(&vec![0u8; padding]);

    context.set_call_data(full_call_data);
    println!("   📋 Set call data for testStaticCall operation");
}

/// Helper function to set call data with uint256 parameter
pub fn set_function_call_data_with_create2(context: &mut super::MockContext) {
    // Prepare call data for testCreate2(uint256 _value, bytes32 salt)
    let mut full_call_data = calculate_selector("testCreate2(uint256,bytes32)").to_vec();

    // Add _value parameter (32 bytes)
    let mut value_bytes = [0u8; 32];
    value_bytes[24..32].copy_from_slice(&456u64.to_be_bytes());
    full_call_data.extend_from_slice(&value_bytes);

    // Add salt parameter (32 bytes)
    let salt = [
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        0x07, 0x08,
    ];
    full_call_data.extend_from_slice(&salt);

    context.set_call_data(full_call_data);
    println!(
        "   📋 Set call data for testCreate2 operation with value: 456 and salt: 0x{}",
        hex::encode(&salt)
    );
}
