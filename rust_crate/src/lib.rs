// Copyright (C) 2021-2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod core;
pub mod evm;
pub mod gas_metering;
pub mod tests;

// Re-export main EVM types for convenience
pub use evm::traits::LogEvent;
pub use evm::{HostFunctionError, HostFunctionResult};
