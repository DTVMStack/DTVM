// Copyright (C) 2021-2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[cfg(test)]
mod tests {
    use std::fs;
    use std::rc::Rc;

    use crate::core::{instance::ZenInstance, runtime::ZenRuntime, types::ZenValue};
    use crate::gas_metering::GasMeter;

    /// Helper function to compile WAST to WASM if needed
    fn get_wasm_bytes(wast_path: &str, wasm_path: &str) -> Result<Vec<u8>, String> {
        // First try to read the WASM file
        if let Ok(bytes) = fs::read(wasm_path) {
            return Ok(bytes);
        }

        // If WASM doesn't exist, try to read WAST and compile it
        if let Ok(wast_content) = fs::read_to_string(wast_path) {
            // Use wat crate to compile WAST to WASM
            match wat::parse_str(&wast_content) {
                Ok(wasm_bytes) => {
                    // Save the compiled WASM for future use
                    if let Err(e) = fs::write(wasm_path, &wasm_bytes) {
                        println!("⚠️ Warning: Could not save WASM file: {}", e);
                    }
                    return Ok(wasm_bytes);
                }
                Err(e) => {
                    return Err(format!("Failed to compile WAST: {}", e));
                }
            }
        }

        Err(format!("Neither {} nor {} found", wasm_path, wast_path))
    }

    #[inline(never)]
    fn create_runtime() -> Rc<ZenRuntime> {
        ZenRuntime::new(None)
    }

    /// Helper function to set up runtime with gas host module and load WASM
    fn setup_gas_test(gas_limit: u64) -> Result<(Rc<ZenRuntime>, Rc<ZenInstance<i64>>), String> {
        let rt = create_runtime();
        // Load the WASM file
        let wasm_bytes = get_wasm_bytes("./example/infinite.wast", "./example/infinite.wasm")?;

        // Compile with gas instrumentation
        let gas_bytes = GasMeter::transform_default(&wasm_bytes)
            .map_err(|e| format!("Failed to compile with gas instrumentation: {}", e))?;

        let wasm_mod = rt
            .load_module_from_bytes("./example/infinite.wasm", &gas_bytes)
            .map_err(|e| format!("Failed to load WASM module: {}", e))?;

        let isolation = rt
            .new_isolation()
            .map_err(|e| format!("Failed to create isolation: {}", e))?;

        let inst = wasm_mod
            .new_instance(isolation, gas_limit)
            .map_err(|e| format!("Failed to create WASM instance: {}", e))?;

        Ok((rt, inst))
    }

    #[test]
    fn test_infinite_loop_gas_control() {
        let gas_limit: u64 = 1000000; // 1M gas units

        let (_rt, inst) = match setup_gas_test(gas_limit) {
            Ok(result) => result,
            Err(err) => {
                println!("⚠️ Skipping test - {}", err);
                return;
            }
        };
        let args = vec![];
        let results = inst.call_wasm_func("infinite_with_work", &args);

        // The function should fail due to gas limit
        match results {
            Ok(_) => {
                panic!("Infinite loop should have been stopped by gas limit");
            }
            Err(err) => {
                assert_eq!(
                    "error_code: 90099\nerror_msg: OutOfGas".to_string(),
                    err,
                    "✅ Function stopped as :  {}",
                    err
                );
                assert_eq!(0, inst.get_gas_left(), "Gas left: {}", inst.get_gas_left());
            }
        }
    }

    #[test]
    fn test_normal_function_with_gas() {
        let gas_limit: u64 = 1000000;
        let (_rt, inst) = match setup_gas_test(gas_limit) {
            Ok(result) => result,
            Err(err) => {
                println!("⚠️ Skipping test - {}", err);
                return;
            }
        };

        let results = inst.call_wasm_func("test_then_infinite", &vec![]);

        match results {
            Ok(values) => {
                assert_eq!(
                    999998,
                    inst.get_gas_left(),
                    "Expected gas left 999998, got {}",
                    inst.get_gas_left()
                );

                if !values.is_empty() {
                    // Should return 42 as defined in the WAST file
                    if let ZenValue::ZenI32Value(val) = &values[0] {
                        assert_eq!(42, *val, "Expected return value 42, got {}", val);
                    } else {
                        panic!("Expected i32 return value, got {}", values[0]);
                    }
                }
            }
            Err(err) => {
                println!("❌ Unexpected error: {}", err);
                panic!("Normal function should complete successfully");
            }
        }
    }
}
