// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "evm/evm_cache.h"

#include "evm/evm.h"
#include "evmc/instructions.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace zen::evm {

// - Cache entries are indexed by EVM PC (byte offset into `Code`).
// - `JumpDestMap[pc]` marks valid JUMP destinations (JUMPDEST outside PUSH
//   data).
// - `PushValueMap[pc]` stores decoded PUSHn immediates (big-endian,
//   zero-padded).
// - `GasChunkEnd/Cost[pc]` describe straight-line chunks whose EVMC base gas
//   can be charged once, then executed via no-gas handlers until
//   `GasChunkEnd[pc]`.
//   Chunks stop at JUMPDEST boundaries and control/host opcodes; dynamic/extra
//   gas remains charged inside opcode handlers.

namespace {

// Returns the total byte length of an opcode (including PUSH immediate bytes).
static uint8_t opcodeLen(uint8_t OpcodeU8) {
  if (OpcodeU8 >= static_cast<uint8_t>(evmc_opcode::OP_PUSH1) &&
      OpcodeU8 <= static_cast<uint8_t>(evmc_opcode::OP_PUSH32)) {
    return static_cast<uint8_t>(
        OpcodeU8 - static_cast<uint8_t>(evmc_opcode::OP_PUSH1) + 2);
  }
  return 1;
}

static bool isGasChunkTerminator(uint8_t OpcodeU8) {
  switch (static_cast<evmc_opcode>(OpcodeU8)) {
  case evmc_opcode::OP_STOP:
  case evmc_opcode::OP_RETURN:
  case evmc_opcode::OP_REVERT:
  case evmc_opcode::OP_SELFDESTRUCT:
  case evmc_opcode::OP_INVALID:
  case evmc_opcode::OP_JUMP:
  case evmc_opcode::OP_JUMPI:
  case evmc_opcode::OP_GAS:
  case evmc_opcode::OP_CREATE:
  case evmc_opcode::OP_CREATE2:
  case evmc_opcode::OP_CALL:
  case evmc_opcode::OP_CALLCODE:
  case evmc_opcode::OP_DELEGATECALL:
  case evmc_opcode::OP_STATICCALL:
    return true;
  default:
    return false;
  }
}

static uint64_t loadBeUint64(const zen::common::Byte *Src) {
  uint64_t Value = 0;
  std::memcpy(&Value, Src, sizeof(Value));
  return intx::to_big_endian(Value);
}

static uint64_t loadBeUint64Partial(const zen::common::Byte *Src, size_t Len) {
  if (Len == 0) {
    return 0;
  }
  if (Len == 8) {
    return loadBeUint64(Src);
  }
  uint64_t Value = 0;
  std::memcpy(reinterpret_cast<uint8_t *>(&Value) + (sizeof(Value) - Len), Src,
              Len);
  return intx::to_big_endian(Value);
}

static intx::uint256 loadBeUint256(const zen::common::Byte *Src, size_t Len) {
  intx::uint256 Value;
  if (Len <= 8) {
    Value[0] = loadBeUint64Partial(Src, Len);
    return Value;
  }

  Value[0] = loadBeUint64(Src + Len - 8);
  if (Len <= 16) {
    Value[1] = loadBeUint64Partial(Src, Len - 8);
    return Value;
  }

  Value[1] = loadBeUint64(Src + Len - 16);
  if (Len <= 24) {
    Value[2] = loadBeUint64Partial(Src, Len - 16);
    return Value;
  }

  Value[2] = loadBeUint64(Src + Len - 24);
  Value[3] = loadBeUint64Partial(Src, Len - 24);
  return Value;
}

// Decodes the PUSH immediate at `Pc` and zero-pads if the code ends early.
static intx::uint256 loadPushValue(const zen::common::Byte *Code,
                                   size_t CodeSize, size_t Pc,
                                   uint8_t NumBytes) {
  const size_t Offset = Pc + 1;
  if (Offset >= CodeSize) {
    return 0;
  }

  const size_t AvailableBytes = CodeSize - Offset;
  const size_t CopyBytes = std::min<size_t>(NumBytes, AvailableBytes);
  if (CopyBytes == 0) {
    return 0;
  }

  intx::uint256 Value = loadBeUint256(Code + Offset, CopyBytes);
  const size_t MissingBytes = static_cast<size_t>(NumBytes) - CopyBytes;
  if (MissingBytes != 0) {
    Value <<= static_cast<uint64_t>(MissingBytes * 8);
  }
  return Value;
}

static void
buildJumpDestMapAndPushCache(const zen::common::Byte *Code, size_t CodeSize,
                             std::vector<uint8_t> &JumpDestMap,
                             std::vector<intx::uint256> &PushValueMap) {
  for (size_t Pc = 0; Pc < CodeSize; ++Pc) {
    const zen::common::Byte CurOpcode = Code[Pc];
    if (CurOpcode == static_cast<zen::common::Byte>(evmc_opcode::OP_JUMPDEST)) {
      JumpDestMap[Pc] = 1;
      continue;
    }
    const uint8_t CurOpcodeU8 = static_cast<uint8_t>(CurOpcode);
    if (CurOpcodeU8 >= static_cast<uint8_t>(evmc_opcode::OP_PUSH1) &&
        CurOpcodeU8 <= static_cast<uint8_t>(evmc_opcode::OP_PUSH32)) {
      const uint8_t NumBytes =
          CurOpcodeU8 - static_cast<uint8_t>(evmc_opcode::OP_PUSH1) + 1;
      PushValueMap[Pc] = loadPushValue(Code, CodeSize, Pc, NumBytes);
      Pc += NumBytes;
    }
  }
}

// Precomputes straight-line chunks where EVMC base gas can be charged once.
static void buildGasChunks(const zen::common::Byte *Code, size_t CodeSize,
                           const evmc_instruction_metrics *MetricsTable,
                           std::vector<uint32_t> &GasChunkEnd,
                           std::vector<uint64_t> &GasChunkCost) {
  size_t Pc = 0;
  while (Pc < CodeSize) {
    const size_t ChunkStart = Pc;
    uint64_t GasCost = 0;
    while (Pc < CodeSize) {
      const uint8_t CurOpcodeU8 = static_cast<uint8_t>(Code[Pc]);
      if (Pc != ChunkStart &&
          CurOpcodeU8 == static_cast<uint8_t>(evmc_opcode::OP_JUMPDEST)) {
        break;
      }
      GasCost += MetricsTable[CurOpcodeU8].gas_cost;
      Pc += opcodeLen(CurOpcodeU8);
      if (isGasChunkTerminator(CurOpcodeU8)) {
        break;
      }
    }

    GasChunkEnd[ChunkStart] = static_cast<uint32_t>(Pc);
    GasChunkCost[ChunkStart] = GasCost;
  }
}

} // namespace

void buildBytecodeCache(EVMBytecodeCache &Cache, const common::Byte *Code,
                        size_t CodeSize) {
  Cache.JumpDestMap.assign(CodeSize, 0);
  Cache.PushValueMap.resize(CodeSize);
  Cache.GasChunkEnd.assign(CodeSize, 0);
  Cache.GasChunkCost.assign(CodeSize, 0);

  buildJumpDestMapAndPushCache(Code, CodeSize, Cache.JumpDestMap,
                               Cache.PushValueMap);
  static const auto *MetricsTable =
      evmc_get_instruction_metrics_table(DEFAULT_REVISION);
  buildGasChunks(Code, CodeSize, MetricsTable, Cache.GasChunkEnd,
                 Cache.GasChunkCost);
}

} // namespace zen::evm
