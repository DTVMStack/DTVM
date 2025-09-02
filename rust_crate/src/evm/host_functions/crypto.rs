// Copyright (C) 2021-2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Cryptographic Host Functions
//!
//! This module implements cryptographic operations available to EVM contracts.
//! These functions provide essential cryptographic primitives for smart contract
//! security, data integrity, and blockchain operations.
//!
//! # Supported Hash Functions
//!
//! - [`sha256`] - SHA-256 hash function (used in Bitcoin and other systems)
//! - [`keccak256`] - Keccak-256 hash function (Ethereum's primary hash function)
//!
//! # Hash Function Properties
//!
//! ## SHA-256
//! - Output: 32 bytes (256 bits)
//! - Algorithm: NIST standard SHA-2 family
//! - Usage: Bitcoin addresses, Merkle trees, general cryptographic applications
//! - Gas cost: 60 + 12 per word of input
//!
//! ## Keccak-256  
//! - Output: 32 bytes (256 bits)
//! - Algorithm: Keccak family (different from NIST SHA-3)
//! - Usage: Ethereum addresses, transaction hashes, storage keys
//! - Gas cost: 30 + 6 per word of input
//!
//! # Security Considerations
//!
//! - Both hash functions are cryptographically secure
//! - Collision resistance: computationally infeasible to find two inputs with same hash
//! - Pre-image resistance: computationally infeasible to find input for given hash
//! - Second pre-image resistance: computationally infeasible to find different input with same hash
//!
//! # Usage Example
//!
//! ```rust
//! // Hash some data with SHA-256
//! sha256(&instance, data_offset, data_length, result_offset)?;
//!
//! // Hash some data with Keccak-256
//! keccak256(&instance, data_offset, data_length, result_offset)?;
//! ```

use crate::core::instance::ZenInstance;
use crate::evm::error::HostFunctionResult;
use crate::evm::traits::EvmHost;
use crate::evm::utils::{validate_bytes32_param, validate_data_param, MemoryAccessor};

/// SHA256 hash function implementation
/// Computes the SHA256 hash of the input data and writes it to the result location
///
/// This implements the NIST SHA-256 standard hash function, which produces a 256-bit (32-byte) hash.
/// SHA-256 is widely used in Bitcoin and other blockchain systems.
///
/// Parameters:
/// - instance: WASM instance pointer
/// - input_offset: Memory offset of the input data
/// - input_length: Length of the input data
/// - result_offset: Memory offset where the 32-byte hash should be written
pub fn sha256<T>(
    instance: &ZenInstance<T>,
    input_offset: i32,
    input_length: i32,
    result_offset: i32,
) -> HostFunctionResult<()>
where
    T: EvmHost,
{
    let memory = MemoryAccessor::new(instance);

    // Validate parameters
    let (input_offset_u32, input_length_u32) =
        validate_data_param(instance, input_offset, input_length, Some("sha256"))?;
    let result_offset_u32 = validate_bytes32_param(instance, result_offset)?;

    // Read input data
    let input_data = memory.read_bytes_vec(input_offset_u32, input_length_u32)?;

    let evmhost = &instance.extra_ctx;
    let hash_bytes: [u8; 32] = evmhost.sha256(input_data);

    // Write the hash to memory
    memory.write_bytes32(result_offset_u32, &hash_bytes)?;

    Ok(())
}

/// Keccak256 hash function implementation
/// Computes the Keccak256 hash of the input data and writes it to the result location
///
/// This implements the Keccak-256 hash function used by Ethereum. Note that this is different
/// from NIST SHA-3, although they are both based on the Keccak algorithm.
/// Keccak-256 is used for Ethereum addresses, transaction hashes, and storage keys.
///
/// Parameters:
/// - instance: WASM instance pointer
/// - input_offset: Memory offset of the input data
/// - input_length: Length of the input data
/// - result_offset: Memory offset where the 32-byte hash should be written
pub fn keccak256<T>(
    instance: &ZenInstance<T>,
    input_offset: i32,
    input_length: i32,
    result_offset: i32,
) -> HostFunctionResult<()>
where
    T: EvmHost,
{
    let memory = MemoryAccessor::new(instance);

    // Validate parameters
    let (input_offset_u32, input_length_u32) =
        validate_data_param(instance, input_offset, input_length, Some("keccak256"))?;
    let result_offset_u32 = validate_bytes32_param(instance, result_offset)?;

    // Read input data
    let input_data = memory.read_bytes_vec(input_offset_u32, input_length_u32)?;

    // Compute Keccak256 hash using the sha3 crate
    let evmhost = &instance.extra_ctx;
    let hash_bytes: [u8; 32] = evmhost.keccak256(input_data);

    // Write the hash to memory
    memory.write_bytes32(result_offset_u32, &hash_bytes)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_sha256_known_vectors() {
        // Test SHA256 with known test vectors
        use sha2::{Digest, Sha256};

        // Test empty input
        let mut hasher = Sha256::new();
        hasher.update(b"");
        let result = hasher.finalize();
        let expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_eq!(hex::encode(result), expected);

        // Test "abc"
        let mut hasher = Sha256::new();
        hasher.update(b"abc");
        let result = hasher.finalize();
        let expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert_eq!(hex::encode(result), expected);

        // Test longer input
        let mut hasher = Sha256::new();
        hasher.update(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        let result = hasher.finalize();
        let expected = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1";
        assert_eq!(hex::encode(result), expected);
    }

    #[test]
    fn test_keccak256_known_vectors() {
        // Test Keccak256 with known test vectors
        use sha3::{Digest, Keccak256};

        // Test empty input
        let mut hasher = Keccak256::new();
        hasher.update(b"");
        let result = hasher.finalize();
        let expected = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470";
        assert_eq!(hex::encode(result), expected);

        // Test "abc"
        let mut hasher = Keccak256::new();
        hasher.update(b"abc");
        let result = hasher.finalize();
        let expected = "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45";
        assert_eq!(hex::encode(result), expected);

        // Test Ethereum function signature "transfer(address,uint256)"
        let mut hasher = Keccak256::new();
        hasher.update(b"transfer(address,uint256)");
        let result = hasher.finalize();
        let expected = "a9059cbb2ab09eb219583f4a59a5d0623ade346d962bcd4e46b11da047c9049b";
        assert_eq!(hex::encode(result), expected);
    }

    #[test]
    fn test_hash_function_differences() {
        // Test that SHA256 and Keccak256 produce different results for same input
        use sha2::Digest as Sha2Digest;
        use sha2::Sha256;
        use sha3::Keccak256;

        let input = b"Hello, World!";

        let mut sha256_hasher = Sha256::new();
        sha256_hasher.update(input);
        let sha256_result = sha256_hasher.finalize();

        let mut keccak256_hasher = Keccak256::new();
        keccak256_hasher.update(input);
        let keccak256_result = keccak256_hasher.finalize();

        // Results should be different
        assert_ne!(sha256_result.as_slice(), keccak256_result.as_slice());

        // Both should be 32 bytes
        assert_eq!(sha256_result.len(), 32);
        assert_eq!(keccak256_result.len(), 32);
    }

    #[test]
    fn test_hash_deterministic() {
        // Test that hash functions are deterministic (same input -> same output)
        use sha2::{Digest, Sha256};

        let input = b"deterministic test";

        let mut hasher1 = Sha256::new();
        hasher1.update(input);
        let result1 = hasher1.finalize();

        let mut hasher2 = Sha256::new();
        hasher2.update(input);
        let result2 = hasher2.finalize();

        assert_eq!(result1, result2);
    }

    #[test]
    fn test_hash_edge_cases() {
        // Test with zero-length input
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(b"");
        let result = hasher.finalize();
        assert_eq!(result.len(), 32);

        // Test with single byte
        let mut hasher = Sha256::new();
        hasher.update(b"a");
        let result = hasher.finalize();
        assert_eq!(result.len(), 32);

        // Test with large input (1MB)
        let large_input = vec![0x42u8; 1024 * 1024];
        let mut hasher = Sha256::new();
        hasher.update(&large_input);
        let result = hasher.finalize();
        assert_eq!(result.len(), 32);
    }
}
