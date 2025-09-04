// Copyright (C) 2021-2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![allow(dead_code)]

/// Helper function to decode bytes32 from return data
pub fn decode_bytes32(data: &[u8]) -> Result<[u8; 32], String> {
    if data.len() < 32 {
        return Err("Data too short for bytes32".to_string());
    }

    let mut result = [0u8; 32];
    result.copy_from_slice(&data[0..32]);
    Ok(result)
}

/// Helper function to decode uint256 from return data
pub fn decode_uint256(data: &[u8]) -> Result<u64, String> {
    if data.len() < 32 {
        return Err("Data too short for uint256".to_string());
    }

    // Take last 8 bytes for u64 (assuming the value fits in u64)
    let bytes: [u8; 8] = data[24..32].try_into().map_err(|_| "Invalid uint256")?;
    Ok(u64::from_be_bytes(bytes))
}

/// Helper function to decode ABI-encoded string from return data
pub fn decode_abi_string(data: &[u8]) -> Result<String, String> {
    if data.len() < 64 {
        return Err("Data too short for ABI string".to_string());
    }

    // Skip offset (first 32 bytes) and get length (next 32 bytes)
    let length = u32::from_be_bytes(data[60..64].try_into().map_err(|_| "Invalid length")?);
    let start = 64;
    let end = start + length as usize;

    if end > data.len() {
        return Err("String length exceeds data".to_string());
    }

    String::from_utf8(data[start..end].to_vec()).map_err(|_| "Invalid UTF-8".to_string())
}
/// Helper function to decode uint8 from return data
pub fn decode_uint8(data: &[u8]) -> Result<u8, String> {
    if data.len() < 32 {
        return Err("Data too short for uint8".to_string());
    }

    Ok(data[31]) // Last byte
}
/// Helper function to decode address from return data
pub fn decode_address(data: &[u8]) -> Result<[u8; 20], String> {
    if data.len() < 32 {
        return Err("Data too short for address".to_string());
    }

    // Take last 20 bytes for address
    let bytes: [u8; 20] = data[12..32].try_into().map_err(|_| "Invalid address")?;
    Ok(bytes)
}
/// Helper function to decode boolean from return data
pub fn decode_bool(data: &[u8]) -> Result<bool, String> {
    if data.len() < 32 {
        return Err("Data too short for bool".to_string());
    }

    Ok(data[31] != 0)
}
/// Helper function to decode (bool, bytes) return data from contract calls
pub fn decode_call_result(data: &[u8]) -> Result<(bool, Vec<u8>), String> {
    if data.len() < 64 {
        return Err("Data too short for (bool, bytes) tuple".to_string());
    }

    // First 32 bytes: bool success
    let success = decode_bool(&data[0..32])?;

    // Second 32 bytes: offset to bytes data (should be 0x40 = 64)
    let bytes_offset = decode_uint256(&data[32..64])? as usize;

    if data.len() < bytes_offset + 32 {
        return Err("Data too short for bytes length".to_string());
    }

    // At offset: bytes length (32 bytes)
    let bytes_length = decode_uint256(&data[bytes_offset..bytes_offset + 32])? as usize;

    // if data.len() < bytes_offset + 32 + bytes_length {
    //     return Err("Data too short for bytes content".to_string());
    // }
    if data.len() < bytes_offset + 32 + bytes_length {
        return Err(format!(
            "Data too short for bytes content: data.len()={}, expected at least {}+{}+{}",
            data.len(),
            bytes_offset,
            32,
            bytes_length
        ));
    }

    // Extract the actual bytes data
    let bytes_data = data[bytes_offset + 32..bytes_offset + 32 + bytes_length].to_vec();

    Ok((success, bytes_data))
}
