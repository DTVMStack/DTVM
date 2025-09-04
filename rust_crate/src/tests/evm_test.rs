//! Comprehensive Unit Tests for EVM Host Functions
//!
//! This module contains extensive unit tests to verify the correctness of EVM host function implementations.
//! Tests are organized by functionality and include:
//! - Basic functionality tests
//! - Edge case and boundary condition tests  
//! - Error handling tests
//! - Integration tests
//! - Performance regression tests

#[cfg(test)]
mod tests {
    use crate::evm::error::*;
    use crate::evm::traits::*;
    use std::collections::HashMap;

    /// Enhanced Mock context for comprehensive testing of EVM host functions
    #[derive(Clone, Debug)]
    #[allow(dead_code)]
    struct TestEvmHost {
        // Basic context
        address: [u8; 20],
        caller: [u8; 20],
        tx_origin: [u8; 20],
        call_value: [u8; 32],
        chain_id: [u8; 32],
        call_data: Vec<u8>,
        contract_code: Vec<u8>,

        // Block context
        block_number: i64,
        block_timestamp: i64,
        block_gas_limit: i64,
        block_coinbase: [u8; 20],
        block_prev_randao: [u8; 32],
        base_fee: [u8; 32],
        blob_base_fee: [u8; 32],

        // Gas and transaction
        gas_left: i64,
        tx_gas_price: [u8; 32],

        // Storage and state
        storage: HashMap<[u8; 32], [u8; 32]>,
        logs: Vec<LogEvent>,
        return_data: Vec<u8>,

        // External contracts
        external_balances: HashMap<[u8; 20], [u8; 32]>,
        external_codes: HashMap<[u8; 20], Vec<u8>>,

        // Execution state
        is_finished: bool,
        is_reverted: bool,
        is_invalid: bool,
        revert_data: Vec<u8>,
    }

    impl Default for TestEvmHost {
        fn default() -> Self {
            let mut external_balances = HashMap::new();
            external_balances.insert([3u8; 20], {
                let mut balance = [0u8; 32];
                balance[31] = 100; // 100 wei
                balance
            });

            let mut external_codes = HashMap::new();
            external_codes.insert(
                [4u8; 20],
                vec![0x60, 0x01, 0x60, 0x00, 0x52, 0x60, 0x01, 0x60, 0x1f, 0xf3],
            );

            Self {
                address: [1u8; 20],
                caller: [2u8; 20],
                tx_origin: [2u8; 20],
                call_value: [0u8; 32],
                chain_id: {
                    let mut chain_id = [0u8; 32];
                    chain_id[31] = 1; // Ethereum mainnet
                    chain_id
                },
                call_data: vec![0x42, 0x43, 0x44, 0x45],
                contract_code: vec![0x60, 0x80, 0x60, 0x40, 0x52],

                block_number: 12345,
                block_timestamp: 1234567890,
                block_gas_limit: 1000000,
                block_coinbase: [5u8; 20],
                block_prev_randao: [6u8; 32],
                base_fee: {
                    let mut fee = [0u8; 32];
                    fee[31] = 20; // 20 gwei
                    fee
                },
                blob_base_fee: {
                    let mut fee = [0u8; 32];
                    fee[31] = 1; // 1 gwei
                    fee
                },

                gas_left: 500000,
                tx_gas_price: {
                    let mut price = [0u8; 32];
                    price[31] = 25; // 25 gwei
                    price
                },

                storage: HashMap::new(),
                logs: Vec::new(),
                return_data: Vec::new(),

                external_balances,
                external_codes,

                is_finished: false,
                is_reverted: false,
                is_invalid: false,
                revert_data: Vec::new(),
            }
        }
    }

    impl TestEvmHost {
        /// Create a new test host with custom parameters
        fn new() -> Self {
            Self::default()
        }

        /// Set custom call data
        fn with_call_data(mut self, data: Vec<u8>) -> Self {
            self.call_data = data;
            self
        }

        /// Set custom gas left
        fn with_gas_left(mut self, gas: i64) -> Self {
            self.gas_left = gas;
            self
        }

        /// Set custom storage value
        fn with_storage(mut self, key: [u8; 32], value: [u8; 32]) -> Self {
            self.storage.insert(key, value);
            self
        }

        /// Add external contract balance
        fn with_external_balance(mut self, address: [u8; 20], balance: [u8; 32]) -> Self {
            self.external_balances.insert(address, balance);
            self
        }

        /// Add external contract code
        fn with_external_code(mut self, address: [u8; 20], code: Vec<u8>) -> Self {
            self.external_codes.insert(address, code);
            self
        }

        /// Set return data
        fn set_return_data(&mut self, data: Vec<u8>) {
            self.return_data = data;
        }
    }

    impl EvmHost for TestEvmHost {
        fn get_address(&self) -> &[u8; 20] {
            &self.address
        }

        fn get_block_hash(&self, _block_number: i64) -> Option<[u8; 32]> {
            Some([0x12u8; 32])
        }

        fn call_data_copy(&self) -> &[u8] {
            &self.call_data
        }

        fn get_caller(&self) -> &[u8; 20] {
            &self.caller
        }

        fn get_call_value(&self) -> &[u8; 32] {
            &self.call_value
        }

        fn get_chain_id(&self) -> &[u8; 32] {
            &self.chain_id
        }

        fn get_gas_left(&self, gas_left: i64) -> i64 {
            gas_left
        }

        fn get_block_gas_limit(&self) -> i64 {
            self.block_gas_limit
        }

        fn get_block_number(&self) -> i64 {
            self.block_number
        }

        fn get_tx_origin(&self) -> &[u8; 20] {
            &self.tx_origin
        }

        fn get_block_timestamp(&self) -> i64 {
            self.block_timestamp
        }

        fn storage_store(&self, _key: &[u8; 32], _value: &[u8; 32]) {
            // For testing purposes, we'll just ignore the store operation
            // In a real implementation, this would need interior mutability
        }

        fn storage_load(&self, key: &[u8; 32]) -> [u8; 32] {
            self.storage.get(key).copied().unwrap_or([0u8; 32])
        }

        fn emit_log_event(&self, _event: LogEvent) {
            // For testing purposes, we'll just ignore the log event
            // In a real implementation, this would need interior mutability
        }

        fn code_copy(&self) -> &[u8] {
            &self.contract_code
        }

        fn get_base_fee(&self) -> &[u8; 32] {
            &self.base_fee
        }

        fn get_blob_base_fee(&self) -> &[u8; 32] {
            &self.blob_base_fee
        }

        fn get_block_coinbase(&self) -> &[u8; 20] {
            &self.block_coinbase
        }

        fn get_tx_gas_price(&self) -> &[u8; 32] {
            &self.tx_gas_price
        }

        fn get_external_balance(&self, address: &[u8; 20]) -> [u8; 32] {
            self.external_balances
                .get(address)
                .copied()
                .unwrap_or([0u8; 32])
        }

        fn get_external_code_size(&self, address: &[u8; 20]) -> Option<i32> {
            self.external_codes
                .get(address)
                .map(|code| code.len() as i32)
        }

        fn get_external_code_hash(&self, address: &[u8; 20]) -> Option<[u8; 32]> {
            self.external_codes
                .get(address)
                .map(|code| self.keccak256(code.clone()))
        }

        fn external_code_copy(&self, address: &[u8; 20]) -> Option<Vec<u8>> {
            self.external_codes.get(address).cloned()
        }

        fn get_block_prev_randao(&self) -> &[u8; 32] {
            &self.block_prev_randao
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
            ContractCreateResult::success([1u8; 20], vec![], 0)
        }

        fn finish(&self, _data: Vec<u8>) {
            // For testing purposes, we'll just ignore the finish operation
            // In a real implementation, this would need interior mutability
        }

        fn return_data_copy(&self) -> Vec<u8> {
            self.return_data.clone()
        }

        fn revert(&self, _revert_data: Vec<u8>) {
            // For testing purposes, we'll just ignore the revert operation
            // In a real implementation, this would need interior mutability
        }

        fn invalid(&self) {
            // For testing purposes, we'll just ignore the invalid operation
            // In a real implementation, this would need interior mutability
        }
    }

    #[test]
    fn test_evm_host_basic_functionality() {
        let host = TestEvmHost::default();

        // Test address functions
        assert_eq!(host.get_address(), &[1u8; 20]);
        assert_eq!(host.get_caller(), &[2u8; 20]);
        let mut expected_chain_id = [0u8; 32];
        expected_chain_id[31] = 1;
        assert_eq!(host.get_chain_id(), &expected_chain_id);

        // Test block functions
        assert_eq!(host.get_block_number(), 12345);
        assert_eq!(host.get_block_timestamp(), 1234567890);
        assert_eq!(host.get_block_gas_limit(), 1000000);
        assert_eq!(host.get_gas_left(500000), 500000);

        // Test call data
        assert_eq!(host.call_data_copy(), &[0x42, 0x43, 0x44, 0x45]);

        // Test code functions
        assert_eq!(host.code_copy(), &[0x60, 0x80, 0x60, 0x40, 0x52]);
    }

    #[test]
    fn test_crypto_functions() {
        let host = TestEvmHost::default();

        // Test SHA256
        let input = vec![0x61, 0x62, 0x63]; // "abc"
        let sha256_result = host.sha256(input.clone());
        // Expected SHA256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        let expected_sha256 = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(sha256_result, expected_sha256);

        // Test Keccak256
        let keccak256_result = host.keccak256(input);
        // Expected Keccak256("abc") = 4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45
        let expected_keccak256 = [
            0x4e, 0x03, 0x65, 0x7a, 0xea, 0x45, 0xa9, 0x4f, 0xc7, 0xd4, 0x7b, 0xa8, 0x26, 0xc8,
            0xd6, 0x67, 0xc0, 0xd1, 0xe6, 0xe3, 0x3a, 0x64, 0xa0, 0x36, 0xec, 0x44, 0xf5, 0x8f,
            0xa1, 0x2d, 0x6c, 0x45,
        ];
        assert_eq!(keccak256_result, expected_keccak256);
    }

    #[test]
    fn test_math_operations() {
        let host = TestEvmHost::default();

        // Test addmod: (5 + 3) % 7 = 1
        let a = {
            let mut bytes = [0u8; 32];
            bytes[31] = 5;
            bytes
        };
        let b = {
            let mut bytes = [0u8; 32];
            bytes[31] = 3;
            bytes
        };
        let n = {
            let mut bytes = [0u8; 32];
            bytes[31] = 7;
            bytes
        };

        let result = host.addmod(a, b, n);
        let mut expected = [0u8; 32];
        expected[31] = 1;
        assert_eq!(result, expected);

        // Test mulmod: (5 * 3) % 7 = 1
        let result = host.mulmod(a, b, n);
        assert_eq!(result, expected);

        // Test expmod: 5^3 % 7 = 6
        let result = host.expmod(a, b, n);
        expected[31] = 6;
        assert_eq!(result, expected);
    }

    #[test]
    fn test_contract_operations() {
        let host = TestEvmHost::default();

        let target = [1u8; 20];
        let caller = [2u8; 20];
        let value = [0u8; 32];
        let data = vec![0x42];

        // Test contract call
        let result = host.call_contract(&target, &caller, &value, &data, 1000);
        assert!(result.success);

        // Test contract creation
        let result = host.create_contract(&caller, &value, &data, &data, 1000, None, false);
        assert!(result.success);
        assert!(result.contract_address.is_some());
    }

    // ============================================================================
    // Comprehensive Test Suite
    // ============================================================================

    #[test]
    fn test_address_operations() {
        let host = TestEvmHost::default();

        // Test basic address functions
        assert_eq!(host.get_address(), &[1u8; 20]);
        assert_eq!(host.get_caller(), &[2u8; 20]);
        assert_eq!(host.get_tx_origin(), &[2u8; 20]);

        // Test external balance lookup
        let balance = host.get_external_balance(&[3u8; 20]);
        assert_eq!(balance[31], 100); // Should have 100 wei

        // Test non-existent address
        let zero_balance = host.get_external_balance(&[99u8; 20]);
        assert_eq!(zero_balance, [0u8; 32]);
    }

    #[test]
    fn test_block_operations() {
        let host = TestEvmHost::default();

        // Test block properties
        assert_eq!(host.get_block_number(), 12345);
        assert_eq!(host.get_block_timestamp(), 1234567890);
        assert_eq!(host.get_block_gas_limit(), 1000000);
        assert_eq!(host.get_block_coinbase(), &[5u8; 20]);
        assert_eq!(host.get_block_prev_randao(), &[6u8; 32]);

        // Test block hash (should return some value)
        let block_hash = host.get_block_hash(12344);
        assert!(block_hash.is_some());
        assert_eq!(block_hash.unwrap(), [0x12u8; 32]);

        // Test fee operations
        assert_eq!(host.get_base_fee()[31], 20);
        assert_eq!(host.get_blob_base_fee()[31], 1);
    }

    #[test]
    fn test_transaction_operations() {
        let host = TestEvmHost::default();

        // Test call data
        assert_eq!(host.call_data_copy(), &[0x42, 0x43, 0x44, 0x45]);

        // Test gas operations
        assert_eq!(host.get_gas_left(500000), 500000);
        assert_eq!(host.get_tx_gas_price()[31], 25);

        // Test call value
        assert_eq!(host.get_call_value(), &[0u8; 32]);

        // Test chain ID
        assert_eq!(host.get_chain_id()[31], 1);
    }

    #[test]
    fn test_storage_operations() {
        let key = [1u8; 32];
        let value = [2u8; 32];
        let host = TestEvmHost::new().with_storage(key, value);

        // Test storage load
        let loaded_value = host.storage_load(&key);
        assert_eq!(loaded_value, value);

        // Test non-existent key
        let zero_key = [99u8; 32];
        let zero_value = host.storage_load(&zero_key);
        assert_eq!(zero_value, [0u8; 32]);
    }

    #[test]
    fn test_code_operations() {
        let host = TestEvmHost::default();

        // Test contract code
        assert_eq!(host.code_copy(), &[0x60, 0x80, 0x60, 0x40, 0x52]);

        // Test external code
        let external_addr = [4u8; 20];
        let code_size = host.get_external_code_size(&external_addr);
        assert!(code_size.is_some());
        assert_eq!(code_size.unwrap(), 10);

        let code = host.external_code_copy(&external_addr);
        assert!(code.is_some());
        assert_eq!(code.unwrap().len(), 10);

        // Test code hash
        let code_hash = host.get_external_code_hash(&external_addr);
        assert!(code_hash.is_some());
    }

    #[test]
    fn test_crypto_edge_cases() {
        let host = TestEvmHost::default();

        // Test empty input
        let empty_sha256 = host.sha256(vec![]);
        let expected_empty_sha256 = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(empty_sha256, expected_empty_sha256);

        let empty_keccak256 = host.keccak256(vec![]);
        let expected_empty_keccak256 = [
            0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7,
            0x03, 0xc0, 0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04,
            0x5d, 0x85, 0xa4, 0x70,
        ];
        assert_eq!(empty_keccak256, expected_empty_keccak256);

        // Test large input
        let large_input = vec![0x42; 1000];
        let large_sha256 = host.sha256(large_input.clone());
        let large_keccak256 = host.keccak256(large_input);

        // Results should be different
        assert_ne!(large_sha256, large_keccak256);

        // Results should be deterministic
        let large_input2 = vec![0x42; 1000];
        assert_eq!(host.sha256(large_input2.clone()), large_sha256);
        assert_eq!(host.keccak256(large_input2), large_keccak256);
    }

    #[test]
    fn test_math_edge_cases() {
        let host = TestEvmHost::default();

        // Test division by zero (modulus = 0)
        let a = [0u8; 32];
        let b = [0u8; 32];
        let zero_mod = [0u8; 32];

        let addmod_result = host.addmod(a, b, zero_mod);
        assert_eq!(addmod_result, [0u8; 32]);

        let mulmod_result = host.mulmod(a, b, zero_mod);
        assert_eq!(mulmod_result, [0u8; 32]);

        let expmod_result = host.expmod(a, b, zero_mod);
        assert_eq!(expmod_result, [0u8; 32]);

        // Test modulus = 1
        let mut one_mod = [0u8; 32];
        one_mod[31] = 1;

        let addmod_one = host.addmod(a, b, one_mod);
        assert_eq!(addmod_one, [0u8; 32]);

        // Test large numbers
        let max_val = [0xFFu8; 32];
        let mut two = [0u8; 32];
        two[31] = 2;

        let addmod_large = host.addmod(max_val, max_val, two);
        assert_eq!(addmod_large, [0u8; 32]); // (2^256-1 + 2^256-1) % 2 = 0
    }

    #[test]
    fn test_contract_call_variations() {
        let host = TestEvmHost::default();

        let target = [10u8; 20];
        let caller = [11u8; 20];
        let value = [0u8; 32];
        let data = vec![0x12, 0x34, 0x56, 0x78];

        // Test different call types
        let call_result = host.call_contract(&target, &caller, &value, &data, 100000);
        assert!(call_result.success);
        assert_eq!(call_result.gas_used, 0);

        let callcode_result = host.call_code(&target, &caller, &value, &data, 100000);
        assert!(callcode_result.success);

        let delegatecall_result = host.call_delegate(&target, &caller, &data, 100000);
        assert!(delegatecall_result.success);

        let staticcall_result = host.call_static(&target, &caller, &data, 100000);
        assert!(staticcall_result.success);

        // Test contract creation
        let create_result =
            host.create_contract(&caller, &value, &data, &data, 100000, None, false);
        assert!(create_result.success);
        assert!(create_result.contract_address.is_some());

        // Test CREATE2
        let salt = [0x42u8; 32];
        let create2_result =
            host.create_contract(&caller, &value, &data, &data, 100000, Some(salt), true);
        assert!(create2_result.success);
        assert!(create2_result.contract_address.is_some());
    }

    #[test]
    fn test_return_data_operations() {
        let mut host = TestEvmHost::default();

        // Initially no return data
        assert_eq!(host.get_return_data_size(), 0);
        assert_eq!(host.return_data_copy(), Vec::<u8>::new());

        // Set some return data
        let test_data = vec![0x11, 0x22, 0x33, 0x44];
        host.set_return_data(test_data.clone());

        assert_eq!(host.get_return_data_size(), 4);
        assert_eq!(host.return_data_copy(), test_data);
    }

    #[test]
    fn test_builder_pattern() {
        let host = TestEvmHost::new()
            .with_call_data(vec![0x99, 0x88, 0x77])
            .with_gas_left(123456)
            .with_storage([1u8; 32], [2u8; 32])
            .with_external_balance([99u8; 20], {
                let mut balance = [0u8; 32];
                balance[31] = 200;
                balance
            })
            .with_external_code([88u8; 20], vec![0x60, 0x01]);

        // Verify builder pattern worked
        assert_eq!(host.call_data_copy(), &[0x99, 0x88, 0x77]);
        assert_eq!(host.get_gas_left(123456), 123456);
        assert_eq!(host.storage_load(&[1u8; 32]), [2u8; 32]);
        assert_eq!(host.get_external_balance(&[99u8; 20])[31], 200);
        assert_eq!(
            host.external_code_copy(&[88u8; 20]).unwrap(),
            vec![0x60, 0x01]
        );
    }

    // ============================================================================
    // Error Handling Tests
    // ============================================================================

    #[test]
    fn test_error_types() {
        // Test error creation and properties
        let memory_error = out_of_bounds_error(100, 50, "test context");
        assert_eq!(memory_error.category(), "memory");

        let gas_error = gas_error("insufficient gas", "test_function", Some(1000), Some(500));
        assert_eq!(gas_error.function(), "test_function");
        assert_eq!(gas_error.message(), "insufficient gas");
        assert_eq!(gas_error.category(), "gas");

        let storage_error = storage_error("key not found", "storage_load", Some("0x1234"));
        assert_eq!(storage_error.category(), "storage");

        // Test error display
        let display_str = format!("{}", gas_error);
        assert!(display_str.contains("test_function"));
        assert!(display_str.contains("insufficient gas"));
        assert!(display_str.contains("1000"));
        assert!(display_str.contains("500"));
    }

    #[test]
    fn test_error_equality() {
        let error1 = invalid_parameter_error("param1", "value1", "test");
        let error2 = invalid_parameter_error("param1", "value1", "test");
        let error3 = invalid_parameter_error("param2", "value1", "test");

        assert_eq!(error1, error2);
        assert_ne!(error1, error3);
    }

    // ============================================================================
    // Integration Tests
    // ============================================================================

    #[test]
    fn test_complete_evm_scenario() {
        // Simulate a complete EVM execution scenario
        let host = TestEvmHost::new()
            .with_call_data(vec![0xa9, 0x05, 0x9c, 0xbb]) // function selector
            .with_gas_left(1000000)
            .with_storage([1u8; 32], {
                let mut value = [0u8; 32];
                value[31] = 42;
                value
            });

        // 1. Check initial state
        assert_eq!(host.get_gas_left(1000000), 1000000);

        // 2. Load from storage
        let stored_value = host.storage_load(&[1u8; 32]);
        assert_eq!(stored_value[31], 42);

        // 3. Perform some crypto operations
        let hash_input = vec![0x48, 0x65, 0x6c, 0x6c, 0x6f]; // "Hello"
        let hash_result = host.keccak256(hash_input);
        assert_ne!(hash_result, [0u8; 32]);

        // 4. Perform math operations
        let mut a = [0u8; 32];
        a[31] = 10;
        let mut b = [0u8; 32];
        b[31] = 5;
        let mut n = [0u8; 32];
        n[31] = 7;

        let math_result = host.addmod(a, b, n);
        assert_eq!(math_result[31], 1); // (10 + 5) % 7 = 1

        // 5. Make a contract call
        let call_result = host.call_contract(&[99u8; 20], &[88u8; 20], &[0u8; 32], &[0x42], 50000);
        assert!(call_result.success);

        // 6. Check external contract
        let external_code = host.external_code_copy(&[4u8; 20]);
        assert!(external_code.is_some());
        assert!(!external_code.unwrap().is_empty());
    }

    // ============================================================================
    // Performance and Regression Tests
    // ============================================================================

    #[test]
    fn test_large_data_handling() {
        let host = TestEvmHost::default();

        // Test with large call data
        let large_data = vec![0x42; 10000];
        let host_with_large_data = TestEvmHost::new().with_call_data(large_data.clone());

        assert_eq!(host_with_large_data.call_data_copy(), &large_data);

        // Test crypto with large input
        let large_hash = host.sha256(large_data.clone());
        assert_ne!(large_hash, [0u8; 32]);

        // Should be deterministic
        let large_hash2 = host.sha256(large_data);
        assert_eq!(large_hash, large_hash2);
    }

    #[test]
    fn test_boundary_values() {
        let host = TestEvmHost::default();

        // Test with maximum values
        let max_bytes = [0xFFu8; 32];
        let zero_bytes = [0u8; 32];
        let one_bytes = {
            let mut bytes = [0u8; 32];
            bytes[31] = 1;
            bytes
        };

        // Math operations with boundary values
        let result = host.addmod(max_bytes, one_bytes, max_bytes);
        assert_eq!(result, one_bytes); // (2^256-1 + 1) % (2^256-1) = 1

        let result = host.mulmod(max_bytes, zero_bytes, max_bytes);
        assert_eq!(result, zero_bytes); // (2^256-1 * 0) % (2^256-1) = 0

        // Test with gas limits
        let host_no_gas = TestEvmHost::new().with_gas_left(0);
        assert_eq!(host_no_gas.get_gas_left(0), 0);

        let host_max_gas = TestEvmHost::new().with_gas_left(i64::MAX);
        assert_eq!(host_max_gas.get_gas_left(i64::MAX), i64::MAX);
    }
}
