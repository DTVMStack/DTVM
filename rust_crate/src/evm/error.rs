// Copyright (C) 2021-2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Error Handling System for EVM Host Functions
//!
//! This module provides a comprehensive error handling system for EVM host function operations.
//! It includes error types and utility functions for creating context-aware error messages.
//!
//! # Error Categories
//!
//! - **Memory Errors** - Out of bounds access, invalid memory operations
//! - **Parameter Errors** - Invalid function parameters, type mismatches
//! - **Context Errors** - Missing or invalid execution context
//! - **Gas Errors** - Insufficient gas, gas limit exceeded
//! - **Storage Errors** - Storage access failures, key not found
//! - **Call Errors** - Contract call failures, invalid addresses
//! - **Crypto Errors** - Cryptographic operation failures
//! - **Arithmetic Errors** - Mathematical operation errors (division by zero, overflow)
//!
//! # Usage
//!
//! ```rust
//! use dtvmcore_rust::evm::error::*;
//!
//! // Create specific error types
//! let gas_error = gas_error("Insufficient gas", "expensive_operation", Some(50000), Some(10000));
//! let storage_error = storage_error("Key not found", "storage_load", Some("0x1234"));
//!
//! // Handle errors
//! match some_operation() {
//!     Ok(result) => println!("Success: {:?}", result),
//!     Err(e) => println!("Error: {}", e),
//! }
//! ```

use std::fmt;

/// Result type for host function operations
pub type HostFunctionResult<T> = Result<T, HostFunctionError>;

/// Errors that can occur during host function execution
#[derive(Debug, Clone, PartialEq)]
pub enum HostFunctionError {
    /// Memory access out of bounds
    OutOfBounds {
        offset: u32,
        length: u32,
        message: String,
        function: String,
    },
    /// Invalid parameter provided to function
    InvalidParameter {
        param: String,
        value: String,
        message: String,
        function: String,
    },
    /// EVM context not found or invalid
    ContextNotFound { message: String, function: String },
    /// Memory access error
    MemoryAccessError { message: String, function: String },
    /// General execution error
    ExecutionError { message: String, function: String },
    /// Gas-related error
    GasError {
        message: String,
        function: String,
        gas_requested: Option<i64>,
        gas_available: Option<i64>,
    },
    /// Storage operation error
    StorageError {
        message: String,
        function: String,
        key: Option<String>,
    },
    /// Contract call error
    CallError {
        message: String,
        function: String,
        target_address: Option<String>,
    },
    /// Cryptographic operation error
    CryptoError {
        message: String,
        function: String,
        operation: String,
    },
    /// Arithmetic operation error
    ArithmeticError {
        message: String,
        function: String,
        operation: String,
    },
}

impl fmt::Display for HostFunctionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HostFunctionError::OutOfBounds {
                offset,
                length,
                message,
                function,
            } => {
                write!(
                    f,
                    "[{}] Memory out of bounds at offset {} length {}: {}",
                    function, offset, length, message
                )
            }
            HostFunctionError::InvalidParameter {
                param,
                value,
                message,
                function,
            } => {
                write!(
                    f,
                    "[{}] Invalid parameter '{}' with value '{}': {}",
                    function, param, value, message
                )
            }
            HostFunctionError::ContextNotFound { message, function } => {
                write!(f, "[{}] EVM context not found: {}", function, message)
            }
            HostFunctionError::MemoryAccessError { message, function } => {
                write!(f, "[{}] Memory access error: {}", function, message)
            }
            HostFunctionError::ExecutionError { message, function } => {
                write!(f, "[{}] Execution error: {}", function, message)
            }
            HostFunctionError::GasError {
                message,
                function,
                gas_requested,
                gas_available,
            } => match (gas_requested, gas_available) {
                (Some(req), Some(avail)) => {
                    write!(
                        f,
                        "[{}] Gas error: {} (requested: {}, available: {})",
                        function, message, req, avail
                    )
                }
                _ => {
                    write!(f, "[{}] Gas error: {}", function, message)
                }
            },
            HostFunctionError::StorageError {
                message,
                function,
                key,
            } => match key {
                Some(k) => write!(
                    f,
                    "[{}] Storage error for key '{}': {}",
                    function, k, message
                ),
                None => write!(f, "[{}] Storage error: {}", function, message),
            },
            HostFunctionError::CallError {
                message,
                function,
                target_address,
            } => match target_address {
                Some(addr) => write!(
                    f,
                    "[{}] Call error to address '{}': {}",
                    function, addr, message
                ),
                None => write!(f, "[{}] Call error: {}", function, message),
            },
            HostFunctionError::CryptoError {
                message,
                function,
                operation,
            } => {
                write!(
                    f,
                    "[{}] Cryptographic error in '{}': {}",
                    function, operation, message
                )
            }
            HostFunctionError::ArithmeticError {
                message,
                function,
                operation,
            } => {
                write!(
                    f,
                    "[{}] Arithmetic error in '{}': {}",
                    function, operation, message
                )
            }
        }
    }
}

impl std::error::Error for HostFunctionError {}

/// Helper function to create out of bounds error
pub fn out_of_bounds_error(offset: u32, length: u32, context: &str) -> HostFunctionError {
    HostFunctionError::OutOfBounds {
        offset,
        length,
        message: format!("Out of bounds in {}", context),
        function: "unknown".to_string(),
    }
}

/// Helper function to create out of bounds error with function name
pub fn out_of_bounds_error_with_function(
    offset: u32,
    length: u32,
    context: &str,
    function: &str,
) -> HostFunctionError {
    HostFunctionError::OutOfBounds {
        offset,
        length,
        message: format!("Out of bounds in {}", context),
        function: function.to_string(),
    }
}

/// Helper function to create invalid parameter error
pub fn invalid_parameter_error(param: &str, value: &str, context: &str) -> HostFunctionError {
    HostFunctionError::InvalidParameter {
        param: param.to_string(),
        value: value.to_string(),
        message: format!("Invalid parameter in {}", context),
        function: "unknown".to_string(),
    }
}

/// Helper function to create invalid parameter error with function name
pub fn invalid_parameter_error_with_function(
    param: &str,
    value: &str,
    context: &str,
    function: &str,
) -> HostFunctionError {
    HostFunctionError::InvalidParameter {
        param: param.to_string(),
        value: value.to_string(),
        message: format!("Invalid parameter in {}", context),
        function: function.to_string(),
    }
}

/// Helper function to create context not found error
pub fn context_not_found_error(context: &str) -> HostFunctionError {
    HostFunctionError::ContextNotFound {
        message: format!("Context not found in {}", context),
        function: "unknown".to_string(),
    }
}

/// Helper function to create memory access error
pub fn memory_access_error(message: &str, function: &str) -> HostFunctionError {
    HostFunctionError::MemoryAccessError {
        message: message.to_string(),
        function: function.to_string(),
    }
}

/// Helper function to create execution error
pub fn execution_error(message: &str, function: &str) -> HostFunctionError {
    HostFunctionError::ExecutionError {
        message: message.to_string(),
        function: function.to_string(),
    }
}

/// Helper function to create gas error
pub fn gas_error(
    message: &str,
    function: &str,
    gas_requested: Option<i64>,
    gas_available: Option<i64>,
) -> HostFunctionError {
    HostFunctionError::GasError {
        message: message.to_string(),
        function: function.to_string(),
        gas_requested,
        gas_available,
    }
}

/// Helper function to create storage error
pub fn storage_error(message: &str, function: &str, key: Option<&str>) -> HostFunctionError {
    HostFunctionError::StorageError {
        message: message.to_string(),
        function: function.to_string(),
        key: key.map(|k| k.to_string()),
    }
}

/// Helper function to create call error
pub fn call_error(
    message: &str,
    function: &str,
    target_address: Option<&str>,
) -> HostFunctionError {
    HostFunctionError::CallError {
        message: message.to_string(),
        function: function.to_string(),
        target_address: target_address.map(|addr| addr.to_string()),
    }
}

/// Helper function to create crypto error
pub fn crypto_error(message: &str, function: &str, operation: &str) -> HostFunctionError {
    HostFunctionError::CryptoError {
        message: message.to_string(),
        function: function.to_string(),
        operation: operation.to_string(),
    }
}

/// Helper function to create arithmetic error
pub fn arithmetic_error(message: &str, function: &str, operation: &str) -> HostFunctionError {
    HostFunctionError::ArithmeticError {
        message: message.to_string(),
        function: function.to_string(),
        operation: operation.to_string(),
    }
}

impl HostFunctionError {
    /// Get the function name where this error occurred
    pub fn function(&self) -> &str {
        match self {
            HostFunctionError::OutOfBounds { function, .. } => function,
            HostFunctionError::InvalidParameter { function, .. } => function,
            HostFunctionError::ContextNotFound { function, .. } => function,
            HostFunctionError::MemoryAccessError { function, .. } => function,
            HostFunctionError::ExecutionError { function, .. } => function,
            HostFunctionError::GasError { function, .. } => function,
            HostFunctionError::StorageError { function, .. } => function,
            HostFunctionError::CallError { function, .. } => function,
            HostFunctionError::CryptoError { function, .. } => function,
            HostFunctionError::ArithmeticError { function, .. } => function,
        }
    }

    /// Get the error message
    pub fn message(&self) -> &str {
        match self {
            HostFunctionError::OutOfBounds { message, .. } => message,
            HostFunctionError::InvalidParameter { message, .. } => message,
            HostFunctionError::ContextNotFound { message, .. } => message,
            HostFunctionError::MemoryAccessError { message, .. } => message,
            HostFunctionError::ExecutionError { message, .. } => message,
            HostFunctionError::GasError { message, .. } => message,
            HostFunctionError::StorageError { message, .. } => message,
            HostFunctionError::CallError { message, .. } => message,
            HostFunctionError::CryptoError { message, .. } => message,
            HostFunctionError::ArithmeticError { message, .. } => message,
        }
    }

    /// Get error category as string
    pub fn category(&self) -> &'static str {
        match self {
            HostFunctionError::OutOfBounds { .. } => "memory",
            HostFunctionError::InvalidParameter { .. } => "parameter",
            HostFunctionError::ContextNotFound { .. } => "context",
            HostFunctionError::MemoryAccessError { .. } => "memory",
            HostFunctionError::ExecutionError { .. } => "execution",
            HostFunctionError::GasError { .. } => "gas",
            HostFunctionError::StorageError { .. } => "storage",
            HostFunctionError::CallError { .. } => "call",
            HostFunctionError::CryptoError { .. } => "crypto",
            HostFunctionError::ArithmeticError { .. } => "arithmetic",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_properties() {
        let out_of_bounds = out_of_bounds_error(0, 10, "test");
        assert_eq!(out_of_bounds.function(), "unknown");
        assert_eq!(out_of_bounds.category(), "memory");

        let gas_error = gas_error("insufficient gas", "test_function", Some(1000), Some(500));
        assert_eq!(gas_error.function(), "test_function");
        assert_eq!(gas_error.message(), "insufficient gas");
        assert_eq!(gas_error.category(), "gas");

        let error = storage_error("key not found", "storage_load", Some("0x1234"));
        assert_eq!(error.function(), "storage_load");
        assert_eq!(error.message(), "key not found");
        assert_eq!(error.category(), "storage");
    }

    #[test]
    fn test_error_display() {
        let error = crypto_error("hash computation failed", "sha256", "SHA256");
        let display_str = format!("{}", error);
        assert!(display_str.contains("sha256"));
        assert!(display_str.contains("SHA256"));
        assert!(display_str.contains("hash computation failed"));
    }

    #[test]
    fn test_error_equality() {
        let error1 = invalid_parameter_error("param1", "value1", "test");
        let error2 = invalid_parameter_error("param1", "value1", "test");
        assert_eq!(error1, error2);

        let error3 = invalid_parameter_error("param2", "value1", "test");
        assert_ne!(error1, error3);
    }
}
