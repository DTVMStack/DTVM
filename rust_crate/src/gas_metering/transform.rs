// Copyright (C) 2021-2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::gas_inject::{inject, ConstantCostRules, Rules};
use parity_wasm::{elements, serialize};
use thiserror::Error;

/// Simple gas meter for WASM modules
#[derive(Error, Debug)]
pub enum TransformError {
    #[error("Failed to parse WASM: {0}")]
    Parse(elements::Error),

    #[error("Failed to inject gas metering: {0}")]
    Inject(String),

    #[error("Failed to serialize WASM: {0}")]
    Serialize(elements::Error),
}
pub struct GasMeter;

impl GasMeter {
    /// Transform WASM with default gas configuration
    pub fn transform_default(input_wasm: &[u8]) -> Result<Vec<u8>, TransformError> {
        // Example: ConstantCostRules::new(1, 8192, 1)
        // - instruction_cost = 1 gas per opcode
        // - memory_grow_cost = 8192 gas per 64 KiB memory page
        // - call_per_local_cost = 1 gas per local per call
        //
        // These defaults are conservative and may be tuned based on benchmarks
        // or the specific economic model of the runtime.
        let gas_rules = ConstantCostRules::new(1, 8192, 1);
        Self::transform_with_rules(input_wasm, gas_rules)
    }

    /// Transform WASM with custom gas rules
    pub fn transform_with_rules<T: Rules>(
        input_wasm: &[u8],
        gas_rules: T,
    ) -> Result<Vec<u8>, TransformError> {
        let module = elements::Module::from_bytes(input_wasm).map_err(TransformError::Parse)?;

        let injected_module = inject(module, &gas_rules)
            .map_err(|err| TransformError::Inject(format!("{:?}", err)))?;

        serialize(injected_module).map_err(TransformError::Serialize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{runtime::ZenRuntime, types::ZenValue};
    use parity_wasm::elements;

    const INSTRUMENTED_USE_GAS: &str = "__instrumented_use_gas";

    /// Find exported gas function index and assert that calls to it exist in the code
    fn assert_gas_export_and_calls(wasm_bytes: &[u8]) {
        let module =
            elements::Module::from_bytes(wasm_bytes).expect("Failed to parse transformed WASM");

        // Locate __instrumented_use_gas export and get its internal function index
        let gas_fn_index: Option<u32> = module.export_section().and_then(|export_section| {
            export_section.entries().iter().find_map(|export| {
                if export.field() == INSTRUMENTED_USE_GAS {
                    if let elements::Internal::Function(idx) = export.internal() {
                        return Some(*idx);
                    }
                }
                None
            })
        });
        assert!(
            gas_fn_index.is_some(),
            "Transformed WASM should export __instrumented_use_gas"
        );
        let gas_idx = gas_fn_index.unwrap();

        // Scan for calls to the gas function index
        let found_call = module
            .code_section()
            .map_or(false,|code_section|{
                code_section
                    .bodies()
                    .iter()
                    .flat_map(|body| body.code().elements())
                    .any(|instruction| matches!(instruction, elements::Instruction::Call(idx) if *idx == gas_idx))
            });

        assert!(
            found_call,
            "Transformed WASM should contain calls to the gas function"
        );
    }

    /// Execute a function with given args and allow caller to validate results and gas via callbacks
    fn execute_and_assert<F, G>(
        wasm_bytes: &[u8],
        gas_limit: u64,
        func_name: &str,
        args: &[ZenValue],
        validate_results: F,
        validate_gas: G,
    ) where
        F: Fn(&[ZenValue]),
        G: Fn(u64),
    {
        let rt = ZenRuntime::new(None);

        let wasm_mod = rt
            .load_module_from_bytes("transformed_test.wasm", wasm_bytes)
            .expect("Failed to load transformed WASM module.");

        let isolation = rt.new_isolation().expect("Failed to create isolation.");
        let inst = wasm_mod
            .new_instance(isolation, gas_limit)
            .expect("Failed to create WASM instance.");

        let values = inst
            .call_wasm_func(func_name, args)
            .expect("Failed to call function");

        // Let caller validate return values
        validate_results(&values);

        // Validate gas consumption via callback
        let gas_left = inst.get_gas_left();
        validate_gas(gas_left);
    }

    #[test]
    fn test_transform_default() {
        let wat = r#"
            (module
                (func $add (param $a i32) (param $b i32) (result i32)
                    local.get $a
                    local.get $b
                    i32.add
                )
                (export "add" (func $add))
            )
        "#;

        let wasm_bytes = wat::parse_str(wat).expect("Failed to parse WAT");
        let transformed =
            GasMeter::transform_default(&wasm_bytes).expect("Transform should succeed");

        // 1) Validate gas export and injected calls
        assert_gas_export_and_calls(&transformed);

        // 2) Execute transformed module and validate gas consumption using generic helper
        let args = vec![ZenValue::ZenI32Value(5), ZenValue::ZenI32Value(3)];
        execute_and_assert(
            &transformed,
            1000,
            "add",
            &args,
            |values| {
                assert!(
                    matches!(values[0], ZenValue::ZenI32Value(8)),
                    "Expected return 8, got {}",
                    values[0]
                );
            },
            |left| {
                assert_eq!(left, 997, "Expected gas left 997, got {}", left);
            },
        );
    }

    #[test]
    fn test_transform_with_rules() {
        let wat = r#"
            (module
                (func $test
                    i32.const 1
                    i32.const 2
                    i32.add
                    drop
                )
                (export "test" (func $test))
            )
        "#;

        let wasm_bytes = wat::parse_str(wat).expect("Failed to parse WAT");
        let custom_rules = ConstantCostRules::new(5, 32768, 3);
        let transformed = GasMeter::transform_with_rules(&wasm_bytes, custom_rules)
            .expect("Transform with rules should succeed");

        // 1) Validate gas export and injected calls
        assert_gas_export_and_calls(&transformed);

        // 2) Execute transformed module and validate gas consumption using generic helper
        execute_and_assert(
            &transformed,
            1000,
            "test",
            &[],
            |values| {
                assert!(values.is_empty(), "Function should return empty values");
            },
            |left| {
                assert_eq!(left, 980, "Expected gas left 980, got {}", left);
            },
        );
    }

    #[test]
    fn test_transform_invalid_wasm() {
        let invalid_wasm = b"invalid wasm bytes";
        let result = GasMeter::transform_default(invalid_wasm);

        assert!(result.is_err(), "Transform should fail with invalid WASM");
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Failed to parse WASM"));
    }

    #[test]
    fn test_transform_with_custom_rules() {
        use parity_wasm::elements::Instruction;

        // Define custom gas rules
        struct MyRules;

        impl Rules for MyRules {
            fn instruction_cost(&self, instruction: &Instruction) -> Option<u32> {
                match instruction {
                    Instruction::Nop => Some(1),
                    Instruction::I32Add => Some(3),
                    Instruction::I32Const(_) => Some(2),
                    Instruction::Drop => Some(1),
                    Instruction::If(_) => Some(10),
                    Instruction::Loop(_) => Some(15),
                    Instruction::Call(_) => Some(20),
                    Instruction::CallIndirect(_, _) => Some(25),
                    // Allow most other instructions with default cost
                    _ => Some(5),
                }
            }

            fn memory_grow_cost(&self) -> crate::gas_metering::gas_inject::MemoryGrowCost {
                use std::num::NonZeroU32;
                crate::gas_metering::gas_inject::MemoryGrowCost::Linear(
                    NonZeroU32::new(16384).unwrap(),
                )
            }

            fn call_per_local_cost(&self) -> u32 {
                2
            }
        }

        let wat = r#"
            (module
                (func $custom_test
                    i32.const 10
                    i32.const 20
                    i32.add
                    drop
                    nop
                )
                (export "custom_test" (func $custom_test))
            )
        "#;

        let wasm_bytes = wat::parse_str(wat).expect("Failed to parse WAT");
        let custom_rules = MyRules;
        let transformed = GasMeter::transform_with_rules(&wasm_bytes, custom_rules)
            .expect("Transform with rules should succeed");

        // 1) Validate gas export and injected calls
        assert_gas_export_and_calls(&transformed);

        // 2) Execute transformed module and validate gas consumption using generic helper
        execute_and_assert(
            &transformed,
            1000,
            "custom_test",
            &[],
            |values| {
                assert!(values.is_empty(), "Function should return empty values");
            },
            |left| {
                assert_eq!(left, 991, "Expected gas left 991, got {}", left);
            },
        );
    }
}
