// Copyright (C) 2021-2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Logging and event host functions

use crate::core::instance::ZenInstance;
use crate::evm::error::HostFunctionResult;
use crate::evm::traits::{EvmHost, LogEvent};
use crate::evm::utils::{validate_bytes32_param, validate_data_param, MemoryAccessor};

/// Emit a log event (LOG0, LOG1, LOG2, LOG3, LOG4 opcodes)
/// Creates a log entry with the specified data and topics
///
/// Parameters:
/// - instance: WASM instance pointer
/// - data_offset: Memory offset of the log data
/// - length: Length of the log data
/// - num_topics: Number of topics (0-4)
/// - topic1_offset: Memory offset of the first topic (32 bytes, or 0 if not used)
/// - topic2_offset: Memory offset of the second topic (32 bytes, or 0 if not used)
/// - topic3_offset: Memory offset of the third topic (32 bytes, or 0 if not used)
/// - topic4_offset: Memory offset of the fourth topic (32 bytes, or 0 if not used)
pub fn emit_log_event<T>(
    instance: &ZenInstance<T>,
    data_offset: i32,
    length: i32,
    num_topics: i32,
    topic1_offset: i32,
    topic2_offset: i32,
    topic3_offset: i32,
    topic4_offset: i32,
) -> HostFunctionResult<()>
where
    T: EvmHost,
{
    let memory = MemoryAccessor::new(instance);
    let evmhost = &instance.extra_ctx;

    // Validate number of topics
    if num_topics < 0 || num_topics > 4 {
        return Err(crate::evm::error::invalid_parameter_error(
            "num_topics",
            &num_topics.to_string(),
            "emit_log_event",
        ));
    }

    // Validate data parameters
    let (data_offset_u32, length_u32) = validate_data_param(instance, data_offset, length, Some("emit_log_event"))?;

    // Read the log data
    let log_data = memory.read_bytes_vec(data_offset_u32, length_u32)?;

    // Read topics based on num_topics
    let mut topics = Vec::new();
    let topic_offsets = [topic1_offset, topic2_offset, topic3_offset, topic4_offset];

    for i in 0..(num_topics as usize) {
        let topic_offset = topic_offsets[i];
        if topic_offset != 0 {
            // Validate topic offset
            let topic_offset_u32 = validate_bytes32_param(instance, topic_offset)?;

            // Read the topic
            let topic = memory.read_bytes32(topic_offset_u32)?;

            topics.push(topic);
        } else {
            // Topic offset is 0, use zero topic
            topics.push([0u8; 32]);
        }
    }

    // Get the current contract address for the log
    let contract_address = evmhost.get_address();

    // Create the log event
    let log_event = LogEvent {
        contract_address: *contract_address,
        data: log_data.clone(),
        topics: topics.clone(),
    };

    // Store the event in the evmhost (this is the key addition!)
    evmhost.emit_log_event(log_event);

    Ok(())
}

/// Emit a simple log event with no topics (LOG0)
/// Convenience function for LOG0 opcode
///
/// Parameters:
/// - instance: WASM instance pointer
/// - data_offset: Memory offset of the log data
/// - length: Length of the log data
pub fn emit_log0<T>(
    instance: &ZenInstance<T>,
    data_offset: i32,
    length: i32,
) -> HostFunctionResult<()>
where
    T: EvmHost,
{
    emit_log_event(instance, data_offset, length, 0, 0, 0, 0, 0)
}

/// Emit a log event with one topic (LOG1)
/// Convenience function for LOG1 opcode
///
/// Parameters:
/// - instance: WASM instance pointer
/// - data_offset: Memory offset of the log data
/// - length: Length of the log data
/// - topic1_offset: Memory offset of the first topic
pub fn emit_log1<T>(
    instance: &ZenInstance<T>,
    data_offset: i32,
    length: i32,
    topic1_offset: i32,
) -> HostFunctionResult<()>
where
    T: EvmHost,
{
    emit_log_event(instance, data_offset, length, 1, topic1_offset, 0, 0, 0)
}

/// Emit a log event with two topics (LOG2)
/// Convenience function for LOG2 opcode
///
/// Parameters:
/// - instance: WASM instance pointer
/// - data_offset: Memory offset of the log data
/// - length: Length of the log data
/// - topic1_offset: Memory offset of the first topic
/// - topic2_offset: Memory offset of the second topic
pub fn emit_log2<T>(
    instance: &ZenInstance<T>,
    data_offset: i32,
    length: i32,
    topic1_offset: i32,
    topic2_offset: i32,
) -> HostFunctionResult<()>
where
    T: EvmHost,
{
    emit_log_event(
        instance,
        data_offset,
        length,
        2,
        topic1_offset,
        topic2_offset,
        0,
        0,
    )
}

/// Emit a log event with three topics (LOG3)
/// Convenience function for LOG3 opcode
///
/// Parameters:
/// - instance: WASM instance pointer
/// - data_offset: Memory offset of the log data
/// - length: Length of the log data
/// - topic1_offset: Memory offset of the first topic
/// - topic2_offset: Memory offset of the second topic
/// - topic3_offset: Memory offset of the third topic
pub fn emit_log3<T>(
    instance: &ZenInstance<T>,
    data_offset: i32,
    length: i32,
    topic1_offset: i32,
    topic2_offset: i32,
    topic3_offset: i32,
) -> HostFunctionResult<()>
where
    T: EvmHost,
{
    emit_log_event(
        instance,
        data_offset,
        length,
        3,
        topic1_offset,
        topic2_offset,
        topic3_offset,
        0,
    )
}

/// Emit a log event with four topics (LOG4)
/// Convenience function for LOG4 opcode
///
/// Parameters:
/// - instance: WASM instance pointer
/// - data_offset: Memory offset of the log data
/// - length: Length of the log data
/// - topic1_offset: Memory offset of the first topic
/// - topic2_offset: Memory offset of the second topic
/// - topic3_offset: Memory offset of the third topic
/// - topic4_offset: Memory offset of the fourth topic
pub fn emit_log4<T>(
    instance: &ZenInstance<T>,
    data_offset: i32,
    length: i32,
    topic1_offset: i32,
    topic2_offset: i32,
    topic3_offset: i32,
    topic4_offset: i32,
) -> HostFunctionResult<()>
where
    T: EvmHost,
{
    emit_log_event(
        instance,
        data_offset,
        length,
        4,
        topic1_offset,
        topic2_offset,
        topic3_offset,
        topic4_offset,
    )
}

/// Validate log event parameters
#[allow(dead_code)]
fn validate_log_params(data_offset: i32, length: i32, num_topics: i32) -> HostFunctionResult<()> {
    if data_offset < 0 {
        return Err(crate::evm::error::out_of_bounds_error(
            data_offset as u32,
            length as u32,
            "negative log data offset",
        ));
    }

    if length < 0 {
        return Err(crate::evm::error::out_of_bounds_error(
            data_offset as u32,
            length as u32,
            "negative log data length",
        ));
    }

    if num_topics < 0 || num_topics > 4 {
        return Err(crate::evm::error::invalid_parameter_error(
            "num_topics",
            &num_topics.to_string(),
            "log event validation",
        ));
    }

    Ok(())
}
