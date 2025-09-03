// Copyright (C) 2021-2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Mock EVM Execution Context Implementation
//!
//! This module provides an example implementation of EVM execution context
//! for testing and development purposes. Users should create their own
//! context implementations based on their specific needs.

use crate::contract_executor::{ContractExecutionResult, ContractExecutor};
use dtvmcore_rust::evm::traits::*;
use dtvmcore_rust::LogEvent;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

/// Contract information stored in the registry
#[derive(Clone, Debug)]
pub struct ContractInfo {
    pub name: String,
    pub code: Vec<u8>,
}

impl ContractInfo {
    pub fn new(name: String, code: Vec<u8>) -> Self {
        Self { name, code }
    }
}

/// Block information for EVM context
/// Contains all block-related data needed for EVM execution
#[derive(Clone, Debug, PartialEq)]
pub struct BlockInfo {
    pub number: i64,
    pub timestamp: i64,
    pub gas_limit: i64,
    pub coinbase: [u8; 20],
    pub prev_randao: [u8; 32],
    pub base_fee: [u8; 32],
    pub blob_base_fee: [u8; 32],
    /// Block hash for the current block (mock value)
    pub hash: [u8; 32],
}

impl Default for BlockInfo {
    fn default() -> Self {
        let mut coinbase = [0u8; 20];
        coinbase[0] = 0x02; // Mock coinbase address

        let mut prev_randao = [0u8; 32];
        prev_randao[0] = 0x01; // Mock prev randao

        let mut base_fee = [0u8; 32];
        base_fee[31] = 1; // Mock base fee (1 wei)

        let mut blob_base_fee = [0u8; 32];
        blob_base_fee[31] = 1; // Mock blob base fee (1 wei)

        let mut hash = [0u8; 32];
        hash[0] = 0x06; // Mock block hash

        Self {
            number: 12345,
            timestamp: 1234567890,
            gas_limit: 1000000,
            coinbase,
            prev_randao,
            base_fee,
            blob_base_fee,
            hash,
        }
    }
}

impl BlockInfo {
    /// Create a new BlockInfo with custom values
    pub fn new(
        number: i64,
        timestamp: i64,
        gas_limit: i64,
        coinbase: [u8; 20],
        prev_randao: [u8; 32],
        base_fee: [u8; 32],
        blob_base_fee: [u8; 32],
    ) -> Self {
        let mut hash = [0u8; 32];
        // Generate a simple mock hash based on block number
        let number_bytes = (number as u64).to_be_bytes();
        hash[0..8].copy_from_slice(&number_bytes);
        hash[0] = 0x06; // Ensure it starts with our mock prefix

        Self {
            number,
            timestamp,
            gas_limit,
            coinbase,
            prev_randao,
            base_fee,
            blob_base_fee,
            hash,
        }
    }

    /// Get coinbase address
    pub fn get_coinbase(&self) -> &[u8; 20] {
        &self.coinbase
    }

    /// Get previous randao
    pub fn get_prev_randao(&self) -> &[u8; 32] {
        &self.prev_randao
    }

    /// Get base fee as bytes
    pub fn get_base_fee_bytes(&self) -> &[u8; 32] {
        &self.base_fee
    }

    /// Get blob base fee as bytes
    pub fn get_blob_base_fee_bytes(&self) -> &[u8; 32] {
        &self.blob_base_fee
    }

    /// Get block hash
    pub fn get_hash(&self) -> &[u8; 32] {
        &self.hash
    }
}

/// Transaction information for EVM context
/// Contains all transaction-related data needed for EVM execution
#[derive(Clone, Debug, PartialEq)]
pub struct TransactionInfo {
    pub origin: [u8; 20],
    pub gas_price: [u8; 32],
    /// Gas left for execution
    pub gas_limit: i64,
}

impl Default for TransactionInfo {
    fn default() -> Self {
        let mut origin = [0u8; 20];
        origin[0] = 0x03; // Mock transaction origin

        let mut gas_price = [0u8; 32];
        gas_price[31] = 2; // Mock gas price (2 wei)

        Self {
            origin,
            gas_price,
            gas_limit: 100, // Default gas limit
        }
    }
}

impl TransactionInfo {
    /// Get transaction origin address
    pub fn get_origin(&self) -> &[u8; 20] {
        &self.origin
    }

    /// Get gas price as bytes
    pub fn get_gas_price_bytes(&self) -> &[u8; 32] {
        &self.gas_price
    }

    /// Get gas left
    pub fn get_gas_limit(&self) -> i64 {
        self.gas_limit
    }

    /// Set gas left (for gas consumption tracking)
    pub fn set_gas_limit(&mut self, gas: i64) {
        self.gas_limit = gas;
    }
}

/// Mock EVM execution context
/// This provides a test environment for EVM contract execution
#[derive(Clone)]
pub struct MockContext {
    /// Contract code with 4-byte length prefix (big-endian)
    contract_code: Vec<u8>,
    /// Storage mapping (hex key -> 32-byte value)
    storage: Rc<RefCell<HashMap<String, Vec<u8>>>>,
    /// Call data for the current execution
    call_data: Vec<u8>,
    /// Current contract address
    address: [u8; 20],
    /// Caller address
    caller: [u8; 20],
    /// Call value
    call_value: [u8; 32],
    /// Chain ID
    chain_id: [u8; 32],
    /// Block information
    block_info: BlockInfo,
    /// Transaction information
    tx_info: TransactionInfo,
    /// Return data from contract execution (set by finish function)
    return_data: Rc<RefCell<Vec<u8>>>,
    /// Execution status (None = running, Some(true) = finished successfully, Some(false) = reverted)
    execution_status: Rc<RefCell<Option<bool>>>,
    /// Events emitted during contract execution
    events: Rc<RefCell<Vec<LogEvent>>>,
    /// Contract registry: address -> contract info
    contract_registry: Rc<RefCell<HashMap<[u8; 20], ContractInfo>>>,
}

/// Builder for MockContext with fluent interface
pub struct MockContextBuilder {
    contract_code: Vec<u8>,
    storage: Option<Rc<RefCell<HashMap<String, Vec<u8>>>>>,
    call_data: Vec<u8>,
    address: [u8; 20],
    caller: [u8; 20],
    call_value: [u8; 32],
    chain_id: [u8; 32],
    block_info: BlockInfo,
    tx_info: TransactionInfo,
    contract_registry: Rc<RefCell<HashMap<[u8; 20], ContractInfo>>>,
}

impl MockContextBuilder {
    /// Create a new builder with default values
    pub fn new() -> Self {
        // Initialize default mock addresses
        let mut address = [0u8; 20];
        address[0] = 0x05; // Mock contract address

        let mut caller = [0u8; 20];
        caller[0] = 0x04; // Mock caller address

        let call_value = [0u8; 32]; // Zero call value

        let mut chain_id = [0u8; 32];
        chain_id[0] = 0x07; // Mock chain ID

        // Default call data for test() function
        let call_data = vec![0xf8, 0xa8, 0xfd, 0x6d]; // test() function selector

        Self {
            contract_code: Vec::new(),
            storage: None,
            call_data,
            address,
            caller,
            call_value,
            chain_id,
            block_info: BlockInfo::default(),
            tx_info: TransactionInfo::default(),
            contract_registry: Rc::new(RefCell::new(HashMap::new())),
        }
    }

    /// Set the contract WASM code
    pub fn with_code(mut self, code: Vec<u8>) -> Self {
        self.contract_code = code;
        self
    }

    /// Set the storage (shared or independent)
    pub fn with_storage(mut self, storage: Rc<RefCell<HashMap<String, Vec<u8>>>>) -> Self {
        self.storage = Some(storage);
        self
    }

    /// Set call data
    pub fn with_call_data(mut self, data: Vec<u8>) -> Self {
        self.call_data = data;
        self
    }

    /// Set contract address
    pub fn with_address(mut self, address: [u8; 20]) -> Self {
        self.address = address;
        self
    }

    /// Set caller address
    pub fn with_caller(mut self, caller: [u8; 20]) -> Self {
        self.caller = caller;
        self
    }

    /// Set call value
    pub fn with_call_value(mut self, value: [u8; 32]) -> Self {
        self.call_value = value;
        self
    }

    /// Set chain ID from u64
    pub fn with_chain_id_u64(mut self, chain_id: u64) -> Self {
        let mut id = [0u8; 32];
        id[24..32].copy_from_slice(&chain_id.to_be_bytes());
        self.chain_id = id;
        self
    }

    /// Set block number
    pub fn with_block_number(mut self, number: i64) -> Self {
        self.block_info.number = number;
        self
    }

    /// Set block timestamp
    pub fn with_block_timestamp(mut self, timestamp: i64) -> Self {
        self.block_info.timestamp = timestamp;
        self
    }

    /// Set block gas limit
    pub fn with_block_gas_limit(mut self, gas_limit: i64) -> Self {
        self.block_info.gas_limit = gas_limit;
        self
    }
    /// Set block coinbase address
    pub fn with_block_coinbase(mut self, coinbase: [u8; 20]) -> Self {
        self.block_info.coinbase = coinbase;
        self
    }

    /// Set base fee
    pub fn with_base_fee(mut self, base_fee: [u8; 32]) -> Self {
        self.block_info.base_fee = base_fee;
        self
    }

    /// Set blob base fee
    pub fn with_blob_base_fee(mut self, blob_base_fee: [u8; 32]) -> Self {
        self.block_info.blob_base_fee = blob_base_fee;
        self
    }

    /// Set block previous randao
    pub fn with_block_prev_randao(mut self, prev_randao: [u8; 32]) -> Self {
        self.block_info.prev_randao = prev_randao;
        self
    }

    /// Set transaction origin
    pub fn with_tx_origin(mut self, origin: [u8; 20]) -> Self {
        self.tx_info.origin = origin;
        self
    }

    /// Set gas price from u64 (in wei)
    pub fn with_gas_price_wei(mut self, wei: u64) -> Self {
        let mut price = [0u8; 32];
        price[24..32].copy_from_slice(&wei.to_be_bytes());
        self.tx_info.gas_price = price;
        self
    }

    /// Set gas left
    pub fn with_gas_limit(mut self, gas: i64) -> Self {
        self.tx_info.gas_limit = gas;
        self
    }

    /// Set the contract registry (shared or independent)
    pub fn with_contract_registry(
        mut self,
        registry: Rc<RefCell<HashMap<[u8; 20], ContractInfo>>>,
    ) -> Self {
        self.contract_registry = registry;
        self
    }

    /// Build the MockContext
    pub fn build(self) -> MockContext {
        let storage = self
            .storage
            .unwrap_or_else(|| Rc::new(RefCell::new(HashMap::new())));

        MockContext {
            contract_code: self.contract_code,
            storage,
            call_data: self.call_data,
            address: self.address,
            caller: self.caller,
            call_value: self.call_value,
            chain_id: self.chain_id,
            block_info: self.block_info,
            tx_info: self.tx_info,
            return_data: Rc::new(RefCell::new(Vec::new())),
            execution_status: Rc::new(RefCell::new(None)),
            events: Rc::new(RefCell::new(Vec::new())),
            contract_registry: self.contract_registry,
        }
    }
}

impl Default for MockContextBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl MockContext {
    /// Create a new MockContext builder
    pub fn builder() -> MockContextBuilder {
        MockContextBuilder::new()
    }

    /// Create a new mock context with the given WASM code (legacy method)
    /// The code will be prefixed with a 4-byte big-endian length header
    pub fn new(wasm_code: Vec<u8>, storage: Rc<RefCell<HashMap<String, Vec<u8>>>>) -> Self {
        Self::builder()
            .with_code(wasm_code)
            .with_storage(storage)
            .build()
    }

    /// Set call data dynamically with validation
    pub fn set_call_data(&mut self, data: Vec<u8>) {
        self.call_data = data;
    }

    pub fn get_gas_limit(&self) -> i64 {
        self.tx_info.gas_limit
    }

    /// Set caller address
    pub fn set_caller(&mut self, caller: [u8; 20]) {
        self.caller = caller;
    }

    /// Set contract address
    pub fn set_address(&mut self, address: [u8; 20]) {
        self.address = address;
    }

    /// Set call value
    pub fn set_call_value(&mut self, value: [u8; 32]) {
        self.call_value = value;
    }

    /// Check if there is return data available
    pub fn has_return_data(&self) -> bool {
        !self.return_data.borrow().is_empty()
    }

    /// Clear all emitted events
    pub fn clear_events(&mut self) {
        self.events.borrow_mut().clear();
    }

    /// Register a contract at the given address
    pub fn register_contract(&mut self, address: [u8; 20], name: String, code: Vec<u8>) {
        let contract_info = ContractInfo::new(name.clone(), code);
        self.contract_registry
            .borrow_mut()
            .insert(address, contract_info);
    }

    /// Get contract info by address
    pub fn get_contract_info(&self, address: &[u8; 20]) -> Option<ContractInfo> {
        self.contract_registry.borrow().get(address).cloned()
    }

    /// Generate CREATE address according to Ethereum rules
    /// address = keccak256(rlp([sender, nonce]))[12:]
    fn generate_create_address(&self, _sender: &[u8; 20], _nonce: u64) -> [u8; 20] {
        //address
        let mut addr = [0u8; 20];
        addr[19] = 9; // Set the last byte to distinguish addresses
        addr
    }

    /// Generate CREATE2 address according to Ethereum rules
    /// address = keccak256(0xff ++ sender ++ salt ++ keccak256(init_code))[12:]
    fn generate_create2_address(
        &self,
        _sender: &[u8; 20],
        _salt: &[u8; 32],
        _init_code: &[u8],
    ) -> [u8; 20] {
        //address

        let mut addr = [0u8; 20];
        addr[19] = 99; // Set the last byte to distinguish addresses
        addr
    }

    /// Execute a contract call using ContractExecutor
    fn execute_contract_call(
        &self,
        target_code: Vec<u8>,
        call_data: Vec<u8>,
        caller: [u8; 20],
        target: [u8; 20],
        value: [u8; 32],
        contract_name: &str,
    ) -> Result<ContractExecutionResult, String> {
        // Create a new context for the contract call
        let mut call_context = self.clone();

        // Set up the call context
        call_context.set_caller(caller);
        call_context.set_address(target);
        call_context.set_call_value(value);
        call_context.set_call_data(call_data);
        call_context.contract_code = target_code;

        // Create a contract executor
        let executor = ContractExecutor::new()
            .map_err(|e| format!("Failed to create contract executor: {}", e))?;

        // Execute the contract call
        executor.call_contract_function(contract_name, &mut call_context)
    }

    /// Execute a contract deployment using ContractExecutor
    fn execute_contract_deployment(
        &self,
        code: Vec<u8>,
        data: Vec<u8>,
        creator: [u8; 20],
        new_address: [u8; 20],
        value: [u8; 32],
    ) -> Result<ContractExecutionResult, String> {
        // Create a new context for the contract deployment
        let mut deploy_context = self.clone();

        // Set up the deployment context
        deploy_context.set_caller(creator);
        deploy_context.set_address(new_address);
        deploy_context.set_call_value(value);
        deploy_context.set_call_data(data);
        deploy_context.contract_code = code[4..].to_vec();

        // Create a contract executor
        let executor = ContractExecutor::new()
            .map_err(|e| format!("Failed to create contract executor: {}", e))?;

        // Execute the contract deployment
        match executor.deploy_contract("SimpleContract.wasm", &mut deploy_context) {
            Ok(_) => {
                // Deployment successful
                Ok(ContractExecutionResult {
                    success: true,
                    return_data: deploy_context.return_data_copy(),
                    error_message: None,
                    is_reverted: false,
                })
            }
            Err(e) => {
                // If deployment fails, return a failure result
                Ok(ContractExecutionResult {
                    success: false,
                    return_data: vec![],
                    error_message: Some(e),
                    is_reverted: false,
                })
            }
        }
    }

    fn set_return_data(&self, data: Vec<u8>) {
        *self.return_data.borrow_mut() = data;
        *self.execution_status.borrow_mut() = Some(true); // Mark as finished successfully
    }

    pub fn is_reverted(&self) -> bool {
        matches!(*self.execution_status.borrow(), Some(false))
    }

    fn get_contract_code(&self) -> &[u8] {
        &self.contract_code
    }
}

// Implement the EvmHost trait for MockContext
impl EvmHost for MockContext {
    fn get_address(&self) -> &[u8; 20] {
        &self.address
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

    fn get_tx_origin(&self) -> &[u8; 20] {
        self.tx_info.get_origin()
    }

    fn get_block_number(&self) -> i64 {
        self.block_info.number
    }

    fn get_block_timestamp(&self) -> i64 {
        self.block_info.timestamp
    }

    fn get_block_gas_limit(&self) -> i64 {
        self.block_info.gas_limit
    }

    fn get_block_coinbase(&self) -> &[u8; 20] {
        self.block_info.get_coinbase()
    }

    fn get_block_prev_randao(&self) -> &[u8; 32] {
        self.block_info.get_prev_randao()
    }

    fn get_base_fee(&self) -> &[u8; 32] {
        self.block_info.get_base_fee_bytes()
    }

    fn get_blob_base_fee(&self) -> &[u8; 32] {
        self.block_info.get_blob_base_fee_bytes()
    }

    fn get_tx_gas_price(&self) -> &[u8; 32] {
        self.tx_info.get_gas_price_bytes()
    }

    fn get_gas_left(&self, gas_left: i64) -> i64 {
        gas_left
    }

    fn call_data_copy(&self) -> &[u8] {
        &self.call_data
    }

    fn code_copy(&self) -> &[u8] {
        &self.contract_code
    }

    fn finish(&self, data: Vec<u8>) {
        *self.return_data.borrow_mut() = data;
        *self.execution_status.borrow_mut() = Some(true); // Mark as finished successfully
    }

    fn return_data_copy(&self) -> Vec<u8> {
        self.return_data.borrow().clone()
    }

    fn revert(&self, revert_data: Vec<u8>) {
        *self.return_data.borrow_mut() = revert_data;
        *self.execution_status.borrow_mut() = Some(false); // Mark as reverted
    }

    fn invalid(&self) {
        *self.execution_status.borrow_mut() = Some(false); // Mark as reverted
    }

    fn emit_log_event(&self, event: LogEvent) {
        self.events.borrow_mut().push(event.clone());
    }

    fn storage_store(&self, key: &[u8; 32], value: &[u8; 32]) {
        let key_hex = format!("0x{}", hex::encode(key));

        self.storage.borrow_mut().insert(key_hex, value.to_vec());
    }

    fn storage_load(&self, key: &[u8; 32]) -> [u8; 32] {
        let key_hex = format!("0x{}", hex::encode(key));

        let storage = self.storage.borrow();

        let value = match storage.get(&key_hex) {
            Some(value) => value.clone(),
            None => {
                vec![0u8; 32]
            }
        };

        let mut result = [0u8; 32];
        let copy_len = std::cmp::min(value.len(), 32);
        result[..copy_len].copy_from_slice(&value[..copy_len]);
        result
    }

    /// Self-destruct the current contract and transfer balance to recipient
    fn self_destruct(&self, _recipient: &[u8; 20]) -> [u8; 32] {
        // Get the current contract's balance using AccountBalanceProvider
        let contract_address = self.get_address();
        let contract_balance = self.get_external_balance(contract_address);

        // In a real implementation, this would:
        // 1. Transfer the balance to the recipient
        // 2. Mark the contract as destructed
        // 3. Clear the contract's storage
        // 4. Remove the contract code

        // For now, we just return the transferred amount
        contract_balance
    }
    fn get_external_balance(&self, _address: &[u8; 20]) -> [u8; 32] {
        // Return a mock balance (1000 ETH in wei)
        let mut balance = [0u8; 32];
        balance[24..32].copy_from_slice(&1000u64.to_be_bytes());
        balance
    }

    fn get_block_hash(&self, _block_number: i64) -> Option<[u8; 32]> {
        // Return a mock block hash
        let mut hash = [0u8; 32];
        hash[0] = 0xab;
        hash[31] = 0xcd;
        Some(hash)
    }
    fn get_external_code_size(&self, _address: &[u8; 20]) -> Option<i32> {
        // Return mock code size
        Some(100)
    }

    fn get_external_code_hash(&self, _address: &[u8; 20]) -> Option<[u8; 32]> {
        // Return mock code hash
        let mut hash = [0u8; 32];
        hash[0] = 0xde;
        hash[31] = 0xad;
        Some(hash)
    }

    fn external_code_copy(&self, _address: &[u8; 20]) -> Option<Vec<u8>> {
        // Return mock code
        Some(vec![0x60, 0x00, 0x60, 0x00, 0xf3]) // Simple mock bytecode
    }

    fn call_contract(
        &self,
        target: &[u8; 20],
        caller: &[u8; 20],
        value: &[u8; 32],
        data: &[u8],
        gas: i64,
    ) -> ContractCallResult {
        // Get target contract code from registry
        let (target_code, contract_name) = match self.get_contract_info(target) {
            Some(info) => (info.code, info.name),
            None => {
                let current_code = self.get_contract_code();
                (current_code.to_vec(), "Unknown".to_string())
            }
        };

        // Execute the contract call
        match self.execute_contract_call(
            target_code,
            data.to_vec(),
            *caller,
            *target,
            *value,
            &contract_name,
        ) {
            Ok(result) => {
                let gas_used = gas.min(50000); // Mock gas consumption
                self.set_return_data(result.return_data.clone());
                if result.success && !result.is_reverted {
                    ContractCallResult::success(result.return_data, gas_used)
                } else {
                    ContractCallResult::failure(result.return_data, gas_used)
                }
            }
            Err(_e) => ContractCallResult::failure(vec![], gas.min(21000)),
        }
    }

    fn call_code(
        &self,
        target: &[u8; 20],
        caller: &[u8; 20],
        value: &[u8; 32],
        data: &[u8],
        gas: i64,
    ) -> ContractCallResult {
        // CALLCODE: Execute target's code but in current contract's context
        // Use target's code but keep current address and storage
        let (target_code, contract_name) = match self.get_contract_info(target) {
            Some(info) => (info.code, info.name),
            None => (self.get_contract_code().to_vec(), "Unknown".to_string()),
        };
        let current_address = self.get_address(); // Keep current address

        match self.execute_contract_call(
            target_code,
            data.to_vec(),
            *caller,
            *current_address,
            *value,
            &contract_name,
        ) {
            Ok(result) => {
                let gas_used = gas.min(50000);
                self.set_return_data(result.return_data.clone());
                if result.success && !result.is_reverted {
                    ContractCallResult::success(result.return_data, gas_used)
                } else {
                    ContractCallResult::failure(result.return_data, gas_used)
                }
            }
            Err(_e) => ContractCallResult::failure(vec![], gas.min(21000)),
        }
    }

    fn call_delegate(
        &self,
        target: &[u8; 20],
        caller: &[u8; 20],
        data: &[u8],
        gas: i64,
    ) -> ContractCallResult {
        // DELEGATECALL: Execute target's code in current contract's full context
        // Use target's code but keep current address, caller, and value
        let (target_code, contract_name) = match self.get_contract_info(target) {
            Some(info) => (info.code, info.name),
            None => (self.get_contract_code().to_vec(), "Unknown".to_string()),
        };
        let current_address = self.get_address(); // Keep current address
        let current_value = self.get_call_value(); // Keep current value

        match self.execute_contract_call(
            target_code,
            data.to_vec(),
            *caller,
            *current_address,
            *current_value,
            &contract_name,
        ) {
            Ok(result) => {
                let gas_used = gas.min(50000);
                self.set_return_data(result.return_data.clone());
                if result.success && !result.is_reverted {
                    ContractCallResult::success(result.return_data, gas_used)
                } else {
                    ContractCallResult::failure(result.return_data, gas_used)
                }
            }
            Err(_e) => ContractCallResult::failure(vec![], gas.min(21000)),
        }
    }

    fn call_static(
        &self,
        target: &[u8; 20],
        caller: &[u8; 20],
        data: &[u8],
        gas: i64,
    ) -> ContractCallResult {
        // STATICCALL: Execute target's code but prevent state changes
        let (target_code, contract_name) = match self.get_contract_info(target) {
            Some(info) => (info.code, info.name),
            None => (self.get_contract_code().to_vec(), "Unknown".to_string()),
        };
        let zero_value = [0u8; 32]; // No value transfer in static calls

        match self.execute_contract_call(
            target_code,
            data.to_vec(),
            *caller,
            *target,
            zero_value,
            &contract_name,
        ) {
            Ok(result) => {
                let gas_used = gas.min(50000);
                self.set_return_data(result.return_data.clone());
                if result.success && !result.is_reverted {
                    ContractCallResult::success(result.return_data, gas_used)
                } else {
                    ContractCallResult::failure(result.return_data, gas_used)
                }
            }
            Err(_e) => ContractCallResult::failure(vec![], gas.min(21000)),
        }
    }

    fn create_contract(
        &self,
        creator: &[u8; 20],
        value: &[u8; 32],
        code: &[u8],
        data: &[u8],
        _gas: i64,
        salt: Option<[u8; 32]>,
        is_create2: bool,
    ) -> ContractCreateResult {
        // Generate contract address according to Ethereum rules
        let new_address = if is_create2 {
            // CREATE2 address generation: keccak256(0xff ++ creator ++ salt ++ keccak256(init_code))[12:]
            let salt_bytes = salt.unwrap_or([0u8; 32]);
            self.generate_create2_address(creator, &salt_bytes, code)
        } else {
            // CREATE address generation: keccak256(rlp([sender, nonce]))[12:]
            // For simplicity, we'll use a mock nonce based on current context
            self.generate_create_address(creator, 0)
        };

        // Simulate gas consumption based on code size
        let gas_used = 21000 + (code.len() as i64 * 200) + (data.len() as i64 * 68);

        // Check for simple failure conditions
        if code.is_empty() {
            return ContractCreateResult::failure(vec![], gas_used);
        }

        // Check value transfer (simplified)
        let value_amount = u64::from_be_bytes([
            value[24], value[25], value[26], value[27], value[28], value[29], value[30], value[31],
        ]);

        if value_amount > 0 {
            // In a real implementation, we would check balance and transfer value
        }

        // Execute constructor if data is provided
        let return_data = if !data.is_empty() {
            // Execute the constructor using ContractExecutor
            match self.execute_contract_deployment(
                code.to_vec(),
                data.to_vec(),
                *creator,
                new_address,
                *value,
            ) {
                Ok(result) => {
                    self.set_return_data(result.return_data.clone());
                    if result.success {
                        result.return_data
                    } else {
                        return ContractCreateResult::failure(result.return_data, gas_used);
                    }
                }
                Err(_e) => {
                    return ContractCreateResult::failure(vec![], gas_used);
                }
            }
        } else {
            vec![]
        };

        // Register the newly created contract in the registry
        let contract_name = if is_create2 {
            format!("CREATE2_Contract_0x{}", hex::encode(&new_address[16..20]))
        } else {
            format!("CREATE_Contract_0x{}", hex::encode(&new_address[16..20]))
        };

        // Clone self to get mutable access for registration
        let mut mutable_self = self.clone();
        mutable_self.register_contract(new_address, contract_name, code.to_vec());
        ContractCreateResult::success(new_address, return_data, gas_used)
    }
}

// Implement AsRef<MockContext> for MockContext to support the host functions API
impl AsRef<MockContext> for MockContext {
    fn as_ref(&self) -> &MockContext {
        self
    }
}
