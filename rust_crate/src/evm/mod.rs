// Copyright (C) 2021-2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! EVM ABI Mock Host Functions Implementation
//!
//! This module provides a complete implementation of EVM host functions
//! for testing and development purposes in a WASM environment.

pub mod error;
pub mod host_functions;
pub mod traits;
pub mod utils;

// Re-export main types for convenience
pub use error::{HostFunctionError, HostFunctionResult};
pub use host_functions::*;
pub use traits::*;
pub use utils::MemoryAccessor;
