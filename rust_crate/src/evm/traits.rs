// Copyright (C) 2021-2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! EVM Host Function Traits
//!
//! This module defines the core traits that users must implement to provide
//! EVM host function functionality. These traits abstract away the data sources
//! and allow users to integrate with their own blockchain nodes, databases,
//! or testing environments.

use num_bigint::BigUint;
use num_traits::{One, Zero};
use sha2::{Digest, Sha256};
use sha3::Keccak256;

/// Log event emitted by a contract
/// Represents an EVM log entry with contract address, data, and topics
#[derive(Clone, Debug, PartialEq)]
pub struct LogEvent {
    /// Address of the contract that emitted the event
    pub contract_address: [u8; 20],
    /// Event data (arbitrary bytes)
    pub data: Vec<u8>,
    /// Event topics (up to 4 topics, each 32 bytes)
    pub topics: Vec<[u8; 32]>,
}

/// Result of a contract call operation
#[derive(Clone, Debug, PartialEq)]
pub struct ContractCallResult {
    /// Whether the call succeeded (true) or failed (false)
    pub success: bool,
    /// Return data from the call
    pub return_data: Vec<u8>,
    /// Gas used by the call
    pub gas_used: i64,
}

impl ContractCallResult {
    /// Create a successful call result
    pub fn success(return_data: Vec<u8>, gas_used: i64) -> Self {
        Self {
            success: true,
            return_data,
            gas_used,
        }
    }

    /// Create a failed call result
    pub fn failure(return_data: Vec<u8>, gas_used: i64) -> Self {
        Self {
            success: false,
            return_data,
            gas_used,
        }
    }

    /// Create a simple success result with no return data
    pub fn simple_success() -> Self {
        Self::success(vec![], 0)
    }

    /// Create a simple failure result with no return data
    pub fn simple_failure() -> Self {
        Self::failure(vec![], 0)
    }
}

/// Result of a contract creation operation
#[derive(Clone, Debug, PartialEq)]
pub struct ContractCreateResult {
    /// Whether the creation succeeded (true) or failed (false)
    pub success: bool,
    /// Address of the created contract (if successful)
    pub contract_address: Option<[u8; 20]>,
    /// Return data from the constructor
    pub return_data: Vec<u8>,
    /// Gas used by the creation
    pub gas_used: i64,
}

impl ContractCreateResult {
    /// Create a successful creation result
    pub fn success(contract_address: [u8; 20], return_data: Vec<u8>, gas_used: i64) -> Self {
        Self {
            success: true,
            contract_address: Some(contract_address),
            return_data,
            gas_used,
        }
    }

    /// Create a failed creation result
    pub fn failure(return_data: Vec<u8>, gas_used: i64) -> Self {
        Self {
            success: false,
            contract_address: None,
            return_data,
            gas_used,
        }
    }

    /// Create a simple failure result
    pub fn simple_failure() -> Self {
        Self::failure(vec![], 0)
    }
}

/// Convert a BigUint to a 32-byte array (big-endian, zero-padded)
/// This ensures the result fits in exactly 32 bytes as required by EVM
pub fn bigint_to_bytes32(value: &BigUint) -> [u8; 32] {
    let mut result = [0u8; 32];
    let bytes = value.to_bytes_be();

    // If the value is larger than 256 bits, we need to truncate it
    // This shouldn't happen in normal EVM operations, but we handle it for safety
    if bytes.len() > 32 {
        // Take the least significant 32 bytes (rightmost)
        result.copy_from_slice(&bytes[bytes.len() - 32..]);
    } else {
        // Zero-pad on the left (big-endian)
        let start_pos = 32 - bytes.len();
        result[start_pos..].copy_from_slice(&bytes);
    }

    result
}

/// Unified EVM Host Interface (EVMC-compatible)
///
/// This trait consolidates all EVM host functions into a single interface,
/// providing a standardized way to interact with the blockchain environment.
/// It integrates all 42 host function interfaces that were previously scattered
/// across multiple traits, ensuring compatibility with EVMC standards.
///
/// The trait is organized into logical groups:
/// - Account Operations: Address and balance related functions
/// - Block Operations: Block information and properties  
/// - Transaction Operations: Transaction data and gas operations
/// - Storage Operations: Contract storage read/write operations (EVMC-compatible)
/// - Code Operations: Contract code access and manipulation
/// - Contract Operations: Contract calls and creation
/// - Control Operations: Execution control (finish, revert, etc.)
/// - Log Operations: Event logging and emission
/// - Execution State: Runtime state checking
///
/// Users should implement this trait to provide their own execution environment.
pub trait EvmHost {
    /// Get the current contract address
    fn get_address(&self) -> &[u8; 20];

    /// Get the hash for a specific block number
    fn get_block_hash(&self, block_number: i64) -> Option<[u8; 32]>;

    /// Get the call data
    fn call_data_copy(&self) -> &[u8];

    /// Get the call data size
    fn get_call_data_size(&self) -> i32 {
        self.call_data_copy().len() as i32
    }

    /// Get the caller address (msg.sender)
    fn get_caller(&self) -> &[u8; 20];

    /// Get the call value (msg.value)
    fn get_call_value(&self) -> &[u8; 32];

    /// Get the chain ID
    fn get_chain_id(&self) -> &[u8; 32];

    /// Get the remaining gas for execution
    fn get_gas_left(&self, gas_left: i64) -> i64;

    /// Get the current block gas limit
    fn get_block_gas_limit(&self) -> i64;

    /// Get the current block number
    fn get_block_number(&self) -> i64;

    /// Get the transaction origin (tx.origin)
    fn get_tx_origin(&self) -> &[u8; 20];

    /// Get the current block timestamp
    fn get_block_timestamp(&self) -> i64;

    /// Store a 32-byte value at a 32-byte key in contract storage (SSTORE)
    fn storage_store(&self, key: &[u8; 32], value: &[u8; 32]);

    /// Load a 32-byte value from contract storage at the given 32-byte key (SLOAD)
    fn storage_load(&self, key: &[u8; 32]) -> [u8; 32];

    /// Add an event to the event log
    fn emit_log_event(&self, event: LogEvent);

    /// Get the contract code
    fn code_copy(&self) -> &[u8];

    /// Get the contract code size
    fn get_code_size(&self) -> i32 {
        self.code_copy().len() as i32
    }

    /// Get the current block's base fee
    fn get_base_fee(&self) -> &[u8; 32];

    /// Get the current block's blob base fee
    fn get_blob_base_fee(&self) -> &[u8; 32];

    /// Get the current block coinbase address
    fn get_block_coinbase(&self) -> &[u8; 20];

    /// Get the transaction gas price
    fn get_tx_gas_price(&self) -> &[u8; 32];

    /// Get the balance for an account address
    fn get_external_balance(&self, address: &[u8; 20]) -> [u8; 32];

    /// Get the size of an external contract's code
    fn get_external_code_size(&self, address: &[u8; 20]) -> Option<i32>;

    /// Get the hash of an external contract's code
    fn get_external_code_hash(&self, address: &[u8; 20]) -> Option<[u8; 32]>;

    /// Get the bytecode of an external contract
    fn external_code_copy(&self, address: &[u8; 20]) -> Option<Vec<u8>>;

    /// Get the current block's previous randao
    fn get_block_prev_randao(&self) -> &[u8; 32];

    /// Self-destruct the current contract and transfer balance to recipient
    fn self_destruct(&self, recipient: &[u8; 20]) -> [u8; 32];

    /// Execute a regular contract call (CALL opcode)
    fn call_contract(
        &self,
        target: &[u8; 20],
        caller: &[u8; 20],
        value: &[u8; 32],
        data: &[u8],
        gas: i64,
    ) -> ContractCallResult;

    /// Execute a call code operation (CALLCODE opcode)
    fn call_code(
        &self,
        target: &[u8; 20],
        caller: &[u8; 20],
        value: &[u8; 32],
        data: &[u8],
        gas: i64,
    ) -> ContractCallResult;

    /// Execute a delegate call (DELEGATECALL opcode)
    fn call_delegate(
        &self,
        target: &[u8; 20],
        caller: &[u8; 20],
        data: &[u8],
        gas: i64,
    ) -> ContractCallResult;

    /// Execute a static call (STATICCALL opcode)
    fn call_static(
        &self,
        target: &[u8; 20],
        caller: &[u8; 20],
        data: &[u8],
        gas: i64,
    ) -> ContractCallResult;

    /// Create a new contract (CREATE or CREATE2 opcode)
    fn create_contract(
        &self,
        creator: &[u8; 20],
        value: &[u8; 32],
        code: &[u8],
        data: &[u8],
        gas: i64,
        salt: Option<[u8; 32]>,
        is_create2: bool,
    ) -> ContractCreateResult;

    /// Get the return data size
    fn get_return_data_size(&self) -> usize {
        self.return_data_copy().len()
    }

    fn finish(&self, data: Vec<u8>);
    /// Get the return data
    fn return_data_copy(&self) -> Vec<u8>;

    /// Set execution status to reverted
    fn revert(&self, revert_data: Vec<u8>);

    /// Set execution status to invalid
    fn invalid(&self);

    fn sha256(&self, input_data: Vec<u8>) -> [u8; 32] {
        // Compute SHA256 hash using the sha2 crate
        let mut hasher = Sha256::new();
        hasher.update(&input_data);
        hasher.finalize().into()
    }

    fn keccak256(&self, input_data: Vec<u8>) -> [u8; 32] {
        // Compute Keccak256 hash using the sha3 crate
        let mut hasher = Keccak256::new();
        hasher.update(&input_data);
        hasher.finalize().into()
    }
    fn addmod(&self, a_bytes: [u8; 32], b_bytes: [u8; 32], n_bytes: [u8; 32]) -> [u8; 32] {
        // Convert bytes to BigUint (big-endian)
        let a = BigUint::from_bytes_be(&a_bytes);
        let b = BigUint::from_bytes_be(&b_bytes);
        let n = BigUint::from_bytes_be(&n_bytes);

        // Handle special case: if n is zero, return zero (EVM behavior)
        let result = if n.is_zero() {
            BigUint::zero()
        } else {
            (&a + &b) % &n
        };

        // Convert result back to 32-byte array (big-endian, zero-padded)
        bigint_to_bytes32(&result)
    }

    fn mulmod(&self, a_bytes: [u8; 32], b_bytes: [u8; 32], n_bytes: [u8; 32]) -> [u8; 32] {
        // Convert bytes to BigUint (big-endian)
        let a = BigUint::from_bytes_be(&a_bytes);
        let b = BigUint::from_bytes_be(&b_bytes);
        let n = BigUint::from_bytes_be(&n_bytes);

        // Handle special case: if n is zero, return zero (EVM behavior)
        let result = if n.is_zero() {
            BigUint::zero()
        } else {
            (&a * &b) % &n
        };

        // Convert result back to 32-byte array (big-endian, zero-padded)
        bigint_to_bytes32(&result)
    }

    fn expmod(&self, base_bytes: [u8; 32], exp_bytes: [u8; 32], mod_bytes: [u8; 32]) -> [u8; 32] {
        // Convert bytes to BigUint (big-endian)
        let base = BigUint::from_bytes_be(&base_bytes);
        let exponent = BigUint::from_bytes_be(&exp_bytes);
        let modulus = BigUint::from_bytes_be(&mod_bytes);

        // Handle special cases according to EVM specification
        let result = if modulus.is_zero() {
            // If modulus is 0, return 0 (EVM behavior)
            BigUint::zero()
        } else if modulus.is_one() {
            // If modulus is 1, result is always 0
            BigUint::zero()
        } else if exponent.is_zero() {
            // If exponent is 0, result is always 1 (including 0^0 = 1)
            BigUint::one()
        } else if base.is_zero() {
            // If base is 0 and exponent > 0, result is 0
            BigUint::zero()
        } else {
            // Perform modular exponentiation using the built-in efficient algorithm
            base.modpow(&exponent, &modulus)
        };
        // Convert result back to 32-byte array (big-endian, zero-padded)
        bigint_to_bytes32(&result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Mock implementation for testing default methods
    struct MockEvmHost;

    impl EvmHost for MockEvmHost {
        fn get_address(&self) -> &[u8; 20] {
            &[0u8; 20]
        }
        fn get_block_hash(&self, _block_number: i64) -> Option<[u8; 32]> {
            None
        }
        fn call_data_copy(&self) -> &[u8] {
            &[]
        }
        fn get_caller(&self) -> &[u8; 20] {
            &[0u8; 20]
        }
        fn get_call_value(&self) -> &[u8; 32] {
            &[0u8; 32]
        }
        fn get_chain_id(&self) -> &[u8; 32] {
            &[0u8; 32]
        }
        fn get_gas_left(&self, gas_left: i64) -> i64 {
            gas_left
        }
        fn get_block_gas_limit(&self) -> i64 {
            0
        }
        fn get_block_number(&self) -> i64 {
            0
        }
        fn get_tx_origin(&self) -> &[u8; 20] {
            &[0u8; 20]
        }
        fn get_block_timestamp(&self) -> i64 {
            0
        }
        fn storage_store(&self, _key: &[u8; 32], _value: &[u8; 32]) {}
        fn storage_load(&self, _key: &[u8; 32]) -> [u8; 32] {
            [0u8; 32]
        }
        fn emit_log_event(&self, _event: LogEvent) {}
        fn code_copy(&self) -> &[u8] {
            &[]
        }
        fn get_base_fee(&self) -> &[u8; 32] {
            &[0u8; 32]
        }
        fn get_blob_base_fee(&self) -> &[u8; 32] {
            &[0u8; 32]
        }
        fn get_block_coinbase(&self) -> &[u8; 20] {
            &[0u8; 20]
        }
        fn get_tx_gas_price(&self) -> &[u8; 32] {
            &[0u8; 32]
        }
        fn get_external_balance(&self, _address: &[u8; 20]) -> [u8; 32] {
            [0u8; 32]
        }
        fn get_external_code_size(&self, _address: &[u8; 20]) -> Option<i32> {
            None
        }
        fn get_external_code_hash(&self, _address: &[u8; 20]) -> Option<[u8; 32]> {
            None
        }
        fn external_code_copy(&self, _address: &[u8; 20]) -> Option<Vec<u8>> {
            None
        }
        fn get_block_prev_randao(&self) -> &[u8; 32] {
            &[0u8; 32]
        }
        fn self_destruct(&self, _recipient: &[u8; 20]) -> [u8; 32] {
            [0u8; 32]
        }
        fn call_contract(
            &self,
            _target: &[u8; 20],
            _caller: &[u8; 20],
            _value: &[u8; 32],
            _data: &[u8],
            _gas: i64,
        ) -> ContractCallResult {
            ContractCallResult::simple_success()
        }
        fn call_code(
            &self,
            _target: &[u8; 20],
            _caller: &[u8; 20],
            _value: &[u8; 32],
            _data: &[u8],
            _gas: i64,
        ) -> ContractCallResult {
            ContractCallResult::simple_success()
        }
        fn call_delegate(
            &self,
            _target: &[u8; 20],
            _caller: &[u8; 20],
            _data: &[u8],
            _gas: i64,
        ) -> ContractCallResult {
            ContractCallResult::simple_success()
        }
        fn call_static(
            &self,
            _target: &[u8; 20],
            _caller: &[u8; 20],
            _data: &[u8],
            _gas: i64,
        ) -> ContractCallResult {
            ContractCallResult::simple_success()
        }
        fn create_contract(
            &self,
            _creator: &[u8; 20],
            _value: &[u8; 32],
            _code: &[u8],
            _data: &[u8],
            _gas: i64,
            _salt: Option<[u8; 32]>,
            _is_create2: bool,
        ) -> ContractCreateResult {
            ContractCreateResult::simple_failure()
        }
        fn finish(&self, _data: Vec<u8>) {}
        fn return_data_copy(&self) -> Vec<u8> {
            vec![]
        }
        fn revert(&self, _revert_data: Vec<u8>) {}
        fn invalid(&self) {}
    }

    #[test]
    fn test_bigint_to_bytes32() {
        // Test zero
        let zero = BigUint::zero();
        let zero_bytes = bigint_to_bytes32(&zero);
        assert_eq!(zero_bytes, [0u8; 32]);

        // Test one
        let one = BigUint::one();
        let one_bytes = bigint_to_bytes32(&one);
        let mut expected = [0u8; 32];
        expected[31] = 1;
        assert_eq!(one_bytes, expected);

        // Test maximum 32-byte value
        let max_bytes = [0xFFu8; 32];
        let max_value = BigUint::from_bytes_be(&max_bytes);
        let result_bytes = bigint_to_bytes32(&max_value);
        assert_eq!(result_bytes, max_bytes);

        // Test small value
        let small_value = BigUint::from(0x1234u32);
        let small_bytes = bigint_to_bytes32(&small_value);
        let mut expected_small = [0u8; 32];
        expected_small[30] = 0x12;
        expected_small[31] = 0x34;
        assert_eq!(small_bytes, expected_small);
    }

    #[test]
    fn test_sha256_default_implementation() {
        let host = MockEvmHost;

        // Test empty input
        let empty_result = host.sha256(vec![]);
        let expected_empty = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(empty_result, expected_empty);

        // Test "abc"
        let abc_result = host.sha256(b"abc".to_vec());
        let expected_abc = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(abc_result, expected_abc);

        // Test longer input
        let long_result =
            host.sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".to_vec());
        let expected_long = [
            0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e,
            0x60, 0x39, 0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67, 0xf6, 0xec, 0xed, 0xd4,
            0x19, 0xdb, 0x06, 0xc1,
        ];
        assert_eq!(long_result, expected_long);
    }

    #[test]
    fn test_keccak256_default_implementation() {
        let host = MockEvmHost;

        // Test empty input
        let empty_result = host.keccak256(vec![]);
        let expected_empty = [
            0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7,
            0x03, 0xc0, 0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04,
            0x5d, 0x85, 0xa4, 0x70,
        ];
        assert_eq!(empty_result, expected_empty);

        // Test "abc"
        let abc_result = host.keccak256(b"abc".to_vec());
        let expected_abc = [
            0x4e, 0x03, 0x65, 0x7a, 0xea, 0x45, 0xa9, 0x4f, 0xc7, 0xd4, 0x7b, 0xa8, 0x26, 0xc8,
            0xd6, 0x67, 0xc0, 0xd1, 0xe6, 0xe3, 0x3a, 0x64, 0xa0, 0x36, 0xec, 0x44, 0xf5, 0x8f,
            0xa1, 0x2d, 0x6c, 0x45,
        ];
        assert_eq!(abc_result, expected_abc);

        // Test Ethereum function signature "transfer(address,uint256)"
        let transfer_result = host.keccak256(b"transfer(address,uint256)".to_vec());
        let expected_transfer = [
            0xa9, 0x05, 0x9c, 0xbb, 0x2a, 0xb0, 0x9e, 0xb2, 0x19, 0x58, 0x3f, 0x4a, 0x59, 0xa5,
            0xd0, 0x62, 0x3a, 0xde, 0x34, 0x6d, 0x96, 0x2b, 0xcd, 0x4e, 0x46, 0xb1, 0x1d, 0xa0,
            0x47, 0xc9, 0x04, 0x9b,
        ];
        assert_eq!(transfer_result, expected_transfer);
    }

    fn u256_from_u8(value: u8) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[31] = value;
        bytes
    }

    #[test]
    fn test_addmod_default_implementation() {
        let host = MockEvmHost;

        // Test basic addition: (5 + 3) % 7 = 1
        let a = u256_from_u8(5);
        let b = u256_from_u8(3);
        let n = u256_from_u8(7);
        let result = host.addmod(a, b, n);
        let expected = u256_from_u8(1);
        assert_eq!(result, expected);

        // Test with zero modulus (should return zero)
        let zero_mod = [0u8; 32];
        let zero_result = host.addmod(a, b, zero_mod);
        assert_eq!(zero_result, [0u8; 32]);

        // Test overflow case: (MAX + 1) % 2 = 0
        let max_val = [0xFFu8; 32];
        let one = u256_from_u8(1);
        let two = u256_from_u8(2);
        let overflow_result = host.addmod(max_val, one, two);
        assert_eq!(overflow_result, [0u8; 32]);

        // More rigorous test: (MAX + MAX/2) % 1 = 0
        let max_half = {
            let mut bytes = [0x7Fu8; 32];
            bytes[0] = 0x7F; // MAX/2 approximately
            bytes
        };
        let one_mod = u256_from_u8(1);
        let rigorous_result1 = host.addmod(max_val, max_half, one_mod);
        assert_eq!(rigorous_result1, [0u8; 32]);

        // More rigorous test: (MAX + 100) % 7 = specific non-zero result
        let hundred = u256_from_u8(100);
        let seven = u256_from_u8(7);
        let rigorous_result2 = host.addmod(max_val, hundred, seven);
        // (2^256 - 1 + 100) % 7 = (2^256 + 99) % 7
        // Since 2^256 % 7 = (2^3)^85 * 2^1 % 7 = 1^85 * 2 % 7 = 2
        // and 99 % 7 = 1
        // The result should be (2 + 1) % 7 = 3.
        let expected_rigorous = u256_from_u8(3);
        assert_eq!(rigorous_result2, expected_rigorous);
    }

    #[test]
    fn test_mulmod_default_implementation() {
        let host = MockEvmHost;

        // Test basic multiplication: (5 * 3) % 7 = 1
        let a = u256_from_u8(5);
        let b = u256_from_u8(3);
        let n = u256_from_u8(7);
        let result = host.mulmod(a, b, n);
        let expected = u256_from_u8(1);
        assert_eq!(result, expected);

        // Test with zero modulus (should return zero)
        let zero_mod = [0u8; 32];
        let zero_result = host.mulmod(a, b, zero_mod);
        assert_eq!(zero_result, [0u8; 32]);

        // Test with zero operand
        let zero = [0u8; 32];
        let zero_mul_result = host.mulmod(zero, b, n);
        assert_eq!(zero_mul_result, [0u8; 32]);

        // More rigorous test: (MAX * 2) % 7 = specific result
        let max_val = [0xFFu8; 32];
        let two = u256_from_u8(2);
        let seven = u256_from_u8(7);
        let rigorous_mul_result = host.mulmod(max_val, two, seven);
        // MAX = 2^256 - 1 ≡ 1 (mod 7), so (MAX * 2) ≡ 2 (mod 7)
        let expected_mul_rigorous = u256_from_u8(2);
        assert_eq!(rigorous_mul_result, expected_mul_rigorous);

        // Test large multiplication: (MAX * MAX) % 13
        let thirteen = u256_from_u8(13);
        let large_mul_result = host.mulmod(max_val, max_val, thirteen);
        // So 2^256 ≡ 3 (mod 13), and MAX = 2^256 - 1 ≡ 2 (mod 13)
        // Therefore (MAX * MAX) ≡ 2 * 2 ≡ 4 (mod 13)
        let expected_large_mul = u256_from_u8(4);
        assert_eq!(large_mul_result, expected_large_mul);
    }

    #[test]
    fn test_expmod_default_implementation() {
        let host = MockEvmHost;

        // Test basic exponentiation: 2^3 % 5 = 3
        let base = u256_from_u8(2);
        let exp = u256_from_u8(3);
        let modulus = u256_from_u8(5);
        let result = host.expmod(base, exp, modulus);
        let expected = u256_from_u8(3);
        assert_eq!(result, expected);

        // Test with zero modulus (should return zero)
        let zero_mod = [0u8; 32];
        let zero_result = host.expmod(base, exp, zero_mod);
        assert_eq!(zero_result, [0u8; 32]);

        // Test with modulus = 1 (should return zero)
        let one_mod = u256_from_u8(1);
        let one_mod_result = host.expmod(base, exp, one_mod);
        assert_eq!(one_mod_result, [0u8; 32]);

        // Test with zero exponent (should return 1, unless base is 0)
        let zero_exp = [0u8; 32];
        let zero_exp_result = host.expmod(base, zero_exp, modulus);
        let expected_one = u256_from_u8(1);
        assert_eq!(zero_exp_result, expected_one);

        // Test with zero base and positive exponent (should return 0)
        let zero_base = [0u8; 32];
        let zero_base_result = host.expmod(zero_base, exp, modulus);
        assert_eq!(zero_base_result, [0u8; 32]);

        // Test edge case: 0^0 % n (where n > 1) should return 1 (mathematical convention)
        let zero_zero_result = host.expmod(zero_base, zero_exp, modulus);
        let expected_one = u256_from_u8(1);
        assert_eq!(zero_zero_result, expected_one);

        // Additional test: any_number^0 % n should return 1 (except when n = 1)
        let any_base = u256_from_u8(42);
        let any_zero_exp_result = host.expmod(any_base, zero_exp, modulus);
        assert_eq!(any_zero_exp_result, expected_one);

        // Test large numbers to ensure no overflow issues
        let large_base = [0xFFu8; 32];
        let small_exp = u256_from_u8(2);
        let large_mod = {
            let mut bytes = [0u8; 32];
            bytes[30] = 0x01; // 256
            bytes
        };
        let large_result = host.expmod(large_base, small_exp, large_mod);
        // MAX^2 % 256 should be 1 (since MAX = 255 mod 256 = -1, and (-1)^2 = 1)
        let expected_large = u256_from_u8(1);
        assert_eq!(large_result, expected_large);
    }
}
