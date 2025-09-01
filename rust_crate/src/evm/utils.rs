// Copyright (C) 2021-2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! EVM Utilities - Memory Access and Debug Tools
//!
//! This module provides essential utilities for EVM host function development,
//! combining memory access operations with debugging and logging capabilities.
//!
//! # Key Features
//!
//! ## Memory Access
//! - **Bounds Checking** - All memory access operations include comprehensive bounds validation
//! - **Type Safety** - Generic implementations with proper type constraints
//! - **Error Handling** - Detailed error reporting for memory access failures
//! - **Performance** - Optimized for frequent memory operations
//!
//!
//! # Usage
//!
//! ```rust
//! use dtvmcore_rust::evm::utils::format_hex;
//!
//! // Debug formatting
//! let data = vec![0x12, 0x34, 0x56, 0x78];
//! println!("Data: 0x{}", format_hex(&data));
//! ```
//!
//! # Safety
//!
//! All memory operations in this module are designed to be safe and prevent:
//! - Buffer overflows and underflows
//! - Out-of-bounds memory access
//! - Invalid pointer dereferences
//! - Memory corruption

use crate::core::instance::ZenInstance;
use crate::evm::error::{out_of_bounds_error, HostFunctionResult};

// ============================================================================
// Memory Access Utilities
// ============================================================================

/// Memory accessor for safe WASM memory operations
pub struct MemoryAccessor<'a, T> {
    instance: &'a ZenInstance<T>,
}

impl<'a, T> MemoryAccessor<'a, T> {
    /// Create a new memory accessor
    pub fn new(instance: &'a ZenInstance<T>) -> Self {
        Self { instance }
    }

    /// Validate that a memory range is accessible
    pub fn validate_range(&self, offset: u32, length: u32) -> bool {
        // Use the existing validation from the instance
        self.instance.validate_wasm_addr(offset, length)
    }

    /// Read bytes from WASM memory with bounds checking
    pub fn read_bytes(&self, offset: u32, length: u32) -> HostFunctionResult<&[u8]> {
        if !self.validate_range(offset, length) {
            return Err(out_of_bounds_error(offset, length, "read_bytes"));
        }

        unsafe {
            let ptr = self.instance.get_host_memory(offset);
            Ok(std::slice::from_raw_parts(ptr, length as usize))
        }
    }

    /// Write bytes to WASM memory with bounds checking
    pub fn write_bytes(&self, offset: u32, data: &[u8]) -> HostFunctionResult<()> {
        let length = data.len() as u32;
        if !self.validate_range(offset, length) {
            return Err(out_of_bounds_error(offset, length, "write_bytes"));
        }

        unsafe {
            let ptr = self.instance.get_host_memory(offset) as *mut u8;
            std::ptr::copy_nonoverlapping(data.as_ptr(), ptr, data.len());
        }
        Ok(())
    }

    /// Read a 32-byte value from memory
    pub fn read_bytes32(&self, offset: u32) -> HostFunctionResult<[u8; 32]> {
        let bytes = self.read_bytes(offset, 32)?;
        let mut result = [0u8; 32];
        result.copy_from_slice(bytes);
        Ok(result)
    }

    /// Write a 32-byte value to memory
    pub fn write_bytes32(&self, offset: u32, data: &[u8; 32]) -> HostFunctionResult<()> {
        self.write_bytes(offset, data)
    }

    /// Read a 20-byte address from memory
    pub fn read_address(&self, offset: u32) -> HostFunctionResult<[u8; 20]> {
        let bytes = self.read_bytes(offset, 20)?;
        let mut result = [0u8; 20];
        result.copy_from_slice(bytes);
        Ok(result)
    }

    /// Write a 20-byte address to memory
    pub fn write_address(&self, offset: u32, data: &[u8; 20]) -> HostFunctionResult<()> {
        self.write_bytes(offset, data)
    }

    /// Read a variable-length byte array from memory
    pub fn read_bytes_vec(&self, offset: u32, length: u32) -> HostFunctionResult<Vec<u8>> {
        let bytes = self.read_bytes(offset, length)?;
        Ok(bytes.to_vec())
    }

    /// Copy data between memory locations
    pub fn copy_memory(
        &self,
        src_offset: u32,
        dst_offset: u32,
        length: u32,
    ) -> HostFunctionResult<()> {
        let src_data = self.read_bytes(src_offset, length)?;
        self.write_bytes(dst_offset, src_data)
    }
}

// ============================================================================
// Memory Validation Utilities
// ============================================================================

/// Helper function for safe memory operations
pub fn safe_memory_access<T, U, F>(
    instance: &ZenInstance<T>,
    offset: u32,
    length: u32,
    operation: F,
) -> HostFunctionResult<U>
where
    F: FnOnce(&[u8]) -> U,
{
    let accessor = MemoryAccessor::new(instance);
    let memory_slice = accessor.read_bytes(offset, length)?;
    Ok(operation(memory_slice))
}

/// Helper function for safe memory writes
pub fn safe_memory_write<T, F>(
    instance: &ZenInstance<T>,
    offset: u32,
    length: u32,
    operation: F,
) -> HostFunctionResult<()>
where
    F: FnOnce(&mut [u8]),
{
    let accessor = MemoryAccessor::new(instance);
    if !accessor.validate_range(offset, length) {
        return Err(out_of_bounds_error(offset, length, "safe_memory_write"));
    }

    unsafe {
        let ptr = instance.get_host_memory(offset) as *mut u8;
        let memory_slice = std::slice::from_raw_parts_mut(ptr, length as usize);
        operation(memory_slice);
    }

    Ok(())
}

/// Validate multiple memory ranges at once
/// Returns the first invalid range if any, or Ok(()) if all are valid
pub fn validate_memory_ranges<T>(
    instance: &ZenInstance<T>,
    ranges: &[(u32, u32)], // (offset, length) pairs
) -> HostFunctionResult<()> {
    let accessor = MemoryAccessor::new(instance);

    for (i, &(offset, length)) in ranges.iter().enumerate() {
        if !accessor.validate_range(offset, length) {
            return Err(out_of_bounds_error(
                offset,
                length,
                &format!("memory range validation failed at index {}", i),
            ));
        }
    }

    Ok(())
}

/// Validate that an offset can hold a specific data type
pub fn validate_offset_for_type<T>(
    instance: &ZenInstance<T>,
    offset: i32,
    type_size: u32,
    type_name: &str,
) -> HostFunctionResult<u32> {
    if offset < 0 {
        return Err(out_of_bounds_error(
            offset as u32,
            type_size,
            &format!("negative offset for {}", type_name),
        ));
    }

    let offset_u32 = offset as u32;
    let accessor = MemoryAccessor::new(instance);

    if !accessor.validate_range(offset_u32, type_size) {
        return Err(out_of_bounds_error(
            offset_u32,
            type_size,
            &format!("invalid memory access for {}", type_name),
        ));
    }

    Ok(offset_u32)
}

/// Validate address parameter (20 bytes)
pub fn validate_address_param<T>(
    instance: &ZenInstance<T>,
    offset: i32,
) -> HostFunctionResult<u32> {
    validate_offset_for_type(instance, offset, 20, "address")
}

/// Validate bytes32 parameter (32 bytes)
pub fn validate_bytes32_param<T>(
    instance: &ZenInstance<T>,
    offset: i32,
) -> HostFunctionResult<u32> {
    validate_offset_for_type(instance, offset, 32, "bytes32")
}

/// Validate variable length data parameter
pub fn validate_data_param<T>(
    instance: &ZenInstance<T>,
    offset: i32,
    length: i32,
) -> HostFunctionResult<(u32, u32)> {
    if offset < 0 {
        return Err(out_of_bounds_error(
            offset as u32,
            length as u32,
            "negative data offset",
        ));
    }

    if length < 0 {
        return Err(out_of_bounds_error(
            offset as u32,
            length as u32,
            "negative data length",
        ));
    }

    let offset_u32 = offset as u32;
    let length_u32 = length as u32;
    let accessor = MemoryAccessor::new(instance);

    if !accessor.validate_range(offset_u32, length_u32) {
        return Err(out_of_bounds_error(
            offset_u32,
            length_u32,
            "invalid memory access for data",
        ));
    }

    Ok((offset_u32, length_u32))
}
