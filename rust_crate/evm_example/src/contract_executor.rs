// Copyright (C) 2021-2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Contract Executor Module
//!
//! Provides reusable contract execution functionality, supporting smart contract deployment and invocation

use crate::evm_bridge::create_complete_evm_host_functions;
use crate::mock_context::MockContext;
use dtvmcore_rust::core::runtime::ZenRuntime;
use dtvmcore_rust::evm::EvmHost;
use std::rc::Rc;

/// Contract execution result
#[derive(Debug)]
pub struct ContractExecutionResult {
    pub success: bool,
    pub return_data: Vec<u8>,
    pub error_message: Option<String>,
    pub is_reverted: bool,
}

/// Contract executor
pub struct ContractExecutor {
    runtime: Rc<ZenRuntime>,
}

impl ContractExecutor {
    /// Create a new contract executor
    pub fn new() -> Result<Self, String> {
        // Create runtime
        let rt = ZenRuntime::new(None);

        // Create EVM host functions
        let host_funcs = create_complete_evm_host_functions();
        // Register host module
        let _host_module = rt
            .create_host_module("env", host_funcs.iter(), true)
            .map_err(|e| format!("Host module creation failed: {}", e))?;

        Ok(ContractExecutor { runtime: rt })
    }

    /// Deploy contract
    pub fn deploy_contract(
        &self,
        contract_name: &str,
        context: &mut MockContext,
    ) -> Result<(), String> {
        // Load WASM file
        let wasm_bytes = context.code_copy();

        let wasm_mod = self
            .runtime
            .load_module_from_bytes(contract_name, &wasm_bytes)
            .map_err(|e| format!("Failed to load WASM module: {}", e))?;

        // Deploy contract
        let isolation = self
            .runtime
            .new_isolation()
            .map_err(|e| format!("Failed to create isolation: {}", e))?;

        let inst = wasm_mod
            .new_instance_with_context(isolation, context.get_gas_limit() as u64, context.clone())
            .map_err(|e| format!("Failed to create instance: {}", e))?;

        inst.call_wasm_func("deploy", &[])
            .map_err(|e| format!("Failed to deploy contract: {}", e))?;

        Ok(())
    }

    /// Call contract function
    pub fn call_contract_function(
        &self,
        contract_name: &str,
        context: &mut MockContext,
    ) -> Result<ContractExecutionResult, String> {
        // Load WASM module
        let wasm_bytes = context.code_copy();

        let wasm_mod = self
            .runtime
            .load_module_from_bytes(contract_name, &wasm_bytes)
            .map_err(|e| format!("Failed to load WASM module: {}", e))?;

        // Create isolation and call
        let isolation = self
            .runtime
            .new_isolation()
            .map_err(|e| format!("Failed to create isolation: {}", e))?;

        let inst = wasm_mod
            .new_instance_with_context(isolation, context.get_gas_limit() as u64, context.clone())
            .map_err(|e| format!("Failed to create instance: {}", e))?;

        // Execute function call
        match inst.call_wasm_func("call", &[]) {
            Ok(_) => {
                let is_reverted = context.is_reverted();

                if is_reverted {
                    let return_data = if context.has_return_data() {
                        context.return_data_copy()
                    } else {
                        vec![]
                    };

                    Ok(ContractExecutionResult {
                        success: false,
                        return_data,
                        error_message: Some("Transaction reverted".to_string()),
                        is_reverted: true,
                    })
                } else {
                    let return_data = if context.has_return_data() {
                        context.return_data_copy()
                    } else {
                        vec![]
                    };

                    Ok(ContractExecutionResult {
                        success: true,
                        return_data,
                        error_message: None,
                        is_reverted: false,
                    })
                }
            }
            Err(err) => Ok(ContractExecutionResult {
                success: false,
                return_data: vec![],
                error_message: Some(err.to_string()),
                is_reverted: context.is_reverted(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock_context::MockContext;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::rc::Rc;

    #[test]
    fn test_deploy_contract_with_counter() {
        // Load counter.wasm file for testing
        let counter_wasm = std::fs::read("../example/counter.wasm")
            .expect("⚠️ Counter WASM file not found, skipping test");

        let executor = ContractExecutor::new().expect("Failed to create executor");
        let shared_storage = Rc::new(RefCell::new(HashMap::new()));

        let mut context = MockContext::builder()
            .with_code(counter_wasm)
            .with_storage(shared_storage)
            .with_address([0x42; 20])
            .with_gas_limit(1000000)
            .build();

        // Test contract deployment
        let result = executor.deploy_contract("counter", &mut context);

        match result {
            Ok(_) => {
                assert!(true);
            }
            Err(_) => {
                panic!("Counter deployment should succeed");
            }
        }
    }

    #[test]
    fn test_call_contract_function_with_counter() {
        // Load counter.wasm file for testing
        let counter_wasm = std::fs::read("../example/counter.wasm")
            .expect("⚠️ Counter WASM file not found, skipping test");

        let executor = ContractExecutor::new().expect("Failed to create executor");
        let shared_storage = Rc::new(RefCell::new(HashMap::new()));

        // Counter contract function selectors
        const COUNT_SELECTOR: [u8; 4] = [0x06, 0x66, 0x1a, 0xbd]; // count()
        const INCREASE_SELECTOR: [u8; 4] = [0xe8, 0x92, 0x7f, 0xbc]; // increase()

        // Test 1: Call count() function (should return 0 initially)
        let mut context = MockContext::builder()
            .with_code(counter_wasm.clone())
            .with_storage(shared_storage.clone())
            .with_address([0x42; 20])
            .with_gas_limit(1000000)
            .build();

        context.set_call_data(COUNT_SELECTOR.to_vec());
        let result = executor.call_contract_function("counter", &mut context);

        match result {
            Ok(execution_result) => {
                assert_eq!(
                    execution_result.return_data,
                    vec![
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0
                    ],
                    "Initial counter should be 0"
                );
                assert!(
                    execution_result.success,
                    "Counter count() call should succeed"
                );
            }
            Err(err) => {
                panic!("Counter count() call failed: {}", err);
            }
        }

        // Test 2: Call increase() function
        context.set_call_data(INCREASE_SELECTOR.to_vec());

        let result2 = executor.call_contract_function("counter", &mut context);

        match result2 {
            Ok(execution_result) => {
                assert!(
                    execution_result.success,
                    "Counter increase() call should succeed"
                );
            }
            Err(err) => {
                panic!("Counter increase() call failed: {}", err);
            }
        }

        // Test 3: Call count() again to verify the increase worked
        context.set_call_data(COUNT_SELECTOR.to_vec());

        let result3 = executor.call_contract_function("counter", &mut context);

        match result3 {
            Ok(execution_result) => {
                assert_eq!(
                    execution_result.return_data,
                    vec![
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 1
                    ],
                    "Counter should be 1 after increase"
                );
                assert!(
                    execution_result.success,
                    "Counter count() call should succeed"
                );
            }
            Err(err) => {
                panic!("Counter count() call after increase failed: {}", err);
            }
        }
    }
}
