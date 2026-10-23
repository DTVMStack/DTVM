// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_EVM_EVM_ABSINTERP_H
#define ZEN_EVM_EVM_ABSINTERP_H

#include <cstddef>
#include <cstdint>
#include <unordered_map>
#include <vector>

#include <evmc/instructions.h>

#include "platform/platform.h"

namespace zen::evm {

// Cross-block Const / ConstSet / Top worklist. Extends Resolved (already
// filled by the block-local pass). On Top or non-convergence, leaves Resolved
// unchanged and writes no multi-targets (fail-closed).
void resolveJumpTargetsCrossBlock(
    const common::Byte *Code, size_t CodeSize,
    const std::vector<uint8_t> &JumpDestMap,
    const evmc_instruction_metrics *Metrics,
    std::unordered_map<uint32_t, uint32_t> &Resolved,
    std::unordered_map<uint32_t, std::vector<uint32_t>> &Multi);

} // namespace zen::evm

#endif
