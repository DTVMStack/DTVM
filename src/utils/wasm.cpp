// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "utils/wasm.h"

#include "common/enums.h"

namespace zen::utils {

using namespace common;

const uint8_t *skipBlockType(const uint8_t *Ip, const uint8_t *End) {
  using namespace common;
  WASMType Type = getWASMBlockTypeFromOpcode(*Ip);
  // Block type is type index(post-MVP)
  if (Type == WASMType::ERROR_TYPE) {
    Ip--;
    uint32_t TypeIndex;
    readLEBNumber<uint32_t>(Ip, End, TypeIndex);
  } else {
    Ip++;
  }
  return Ip;
}

const uint8_t *skipCurrentBlock(const uint8_t *Ip, const uint8_t *End) {
  uint32_t NestedLevel = 0;
  while (Ip < End) {
    uint8_t Opcode = *Ip++; // skip opcode
    switch (Opcode) {
    case UNREACHABLE:
    case NOP:
      break;

    case BLOCK:
    case LOOP:
    case IF:
      ++NestedLevel;
      ++Ip; // skip value_type
      break;

    case ELSE:
      if (NestedLevel == 0) {
        return Ip - 1;
      }
      break;

    case END:
      if (NestedLevel == 0) {
        return Ip - 1;
      }
      --NestedLevel;
      break;

    case BR:
    case BR_IF:
      Ip = skipLEBNumber<uint32_t>(Ip, End); // skip label
      break;

    case BR_TABLE: {
      uint32_t NumTargets;
      Ip = readLEBNumber(Ip, End, NumTargets); // skip count
      for (uint32_t I = 0; I <= NumTargets; ++I) {
        Ip = skipLEBNumber<uint32_t>(Ip, End); // skip labels
      }
      break;
    }

    case RETURN:
      break;

    case CALL:
      Ip = skipLEBNumber<uint32_t>(Ip, End); // skip func_idx
      break;

    case CALL_INDIRECT:
      Ip = skipLEBNumber<uint32_t>(Ip, End); // skip type_idx
      ++Ip;                                  // skip tbl_idx
      break;

    case DROP:
    case DROP_64:
    case SELECT:
    case SELECT_64:
      break;

    case GET_LOCAL:
    case SET_LOCAL:
    case TEE_LOCAL:
    case GET_GLOBAL:
    case SET_GLOBAL:
    case GET_GLOBAL_64:
    case SET_GLOBAL_64:
      Ip = skipLEBNumber<uint32_t>(Ip, End); // skip idx
      break;

    case I32_LOAD:
    case I32_LOAD8_S:
    case I32_LOAD8_U:
    case I32_LOAD16_S:
    case I32_LOAD16_U:
    case I64_LOAD:
    case I64_LOAD8_S:
    case I64_LOAD8_U:
    case I64_LOAD16_S:
    case I64_LOAD16_U:
    case I64_LOAD32_S:
    case I64_LOAD32_U:
    case F32_LOAD:
    case F64_LOAD:

    case I32_STORE:
    case I32_STORE8:
    case I32_STORE16:
    case I64_STORE:
    case I64_STORE8:
    case I64_STORE16:
    case I64_STORE32:
    case F32_STORE:
    case F64_STORE:
      Ip = skipLEBNumber<uint32_t>(Ip, End); // align
      Ip = skipLEBNumber<uint32_t>(Ip, End); // offset
      break;

    case MEMORY_SIZE:
    case MEMORY_GROW:
      Ip = skipLEBNumber<uint32_t>(Ip, End); // 0x0
      break;

    case I32_CONST:
      Ip = skipLEBNumber<uint32_t>(Ip, End); // i32 val
      break;

    case I64_CONST:
      Ip = skipLEBNumber<uint64_t>(Ip, End); // i64 val
      break;

    case F32_CONST:
      Ip += sizeof(float); // float value
      break;

    case F64_CONST:
      Ip += sizeof(double); // double value
      break;

    case I32_EQZ:
    case I32_EQ:
    case I32_NE:
    case I32_LT_S:
    case I32_LT_U:
    case I32_GT_S:
    case I32_GT_U:
    case I32_LE_S:
    case I32_LE_U:
    case I32_GE_S:
    case I32_GE_U:

    case I64_EQZ:
    case I64_EQ:
    case I64_NE:
    case I64_LT_S:
    case I64_LT_U:
    case I64_GT_S:
    case I64_GT_U:
    case I64_LE_S:
    case I64_LE_U:
    case I64_GE_S:
    case I64_GE_U:

    case F32_EQ:
    case F32_NE:
    case F32_LT:
    case F32_GT:
    case F32_LE:
    case F32_GE:

    case F64_EQ:
    case F64_NE:
    case F64_LT:
    case F64_GT:
    case F64_LE:
    case F64_GE:

    case I32_CLZ:
    case I32_CTZ:
    case I32_POPCNT:

    case I32_ADD:
    case I32_SUB:
    case I32_MUL:
    case I32_DIV_S:
    case I32_DIV_U:
    case I32_REM_S:
    case I32_REM_U:
    case I32_AND:
    case I32_OR:
    case I32_XOR:
    case I32_SHL:
    case I32_SHR_S:
    case I32_SHR_U:
    case I32_ROTL:
    case I32_ROTR:

    case I64_CLZ:
    case I64_CTZ:
    case I64_POPCNT:

    case I64_ADD:
    case I64_SUB:
    case I64_MUL:
    case I64_DIV_S:
    case I64_DIV_U:
    case I64_REM_S:
    case I64_REM_U:
    case I64_AND:
    case I64_OR:
    case I64_XOR:
    case I64_SHL:
    case I64_SHR_S:
    case I64_SHR_U:
    case I64_ROTL:
    case I64_ROTR:

    case F32_ABS:
    case F32_NEG:
    case F32_CEIL:
    case F32_FLOOR:
    case F32_TRUNC:
    case F32_NEAREST:
    case F32_SQRT:

    case F32_ADD:
    case F32_SUB:
    case F32_MUL:
    case F32_DIV:
    case F32_MIN:
    case F32_MAX:
    case F32_COPYSIGN:

    case F64_ABS:
    case F64_NEG:
    case F64_CEIL:
    case F64_FLOOR:
    case F64_TRUNC:
    case F64_NEAREST:
    case F64_SQRT:

    case F64_ADD:
    case F64_SUB:
    case F64_MUL:
    case F64_DIV:
    case F64_MIN:
    case F64_MAX:
    case F64_COPYSIGN:

    case I32_WRAP_I64:
    case I32_TRUNC_S_F32:
    case I32_TRUNC_U_F32:
    case I32_TRUNC_S_F64:
    case I32_TRUNC_U_F64:

    case I64_EXTEND_S_I32:
    case I64_EXTEND_U_I32:
    case I64_TRUNC_S_F32:
    case I64_TRUNC_U_F32:
    case I64_TRUNC_S_F64:
    case I64_TRUNC_U_F64:

    case F32_CONVERT_S_I32:
    case F32_CONVERT_U_I32:
    case F32_CONVERT_S_I64:
    case F32_CONVERT_U_I64:
    case F32_DEMOTE_F64:

    case F64_CONVERT_S_I32:
    case F64_CONVERT_U_I32:
    case F64_CONVERT_S_I64:
    case F64_CONVERT_U_I64:
    case F64_PROMOTE_F32:

    case I32_REINTERPRET_F32:
    case I64_REINTERPRET_F64:
    case F32_REINTERPRET_I32:
    case F64_REINTERPRET_I64:

    case I32_EXTEND8_S:
    case I32_EXTEND16_S:
    case I64_EXTEND8_S:
    case I64_EXTEND16_S:
    case I64_EXTEND32_S:
      break;

    } // switch opcode
  }   // while ip < end
  return nullptr;
}

const char *getWASMTypeString(WASMType Type) {
  switch (Type) {
#define DEFINE_VALUE_TYPE(NAME, OPCODE, TEXT)                                  \
  case WASMType::NAME:                                                         \
    return TEXT;
#define DEFINE_BLOCK_TYPE(NAME, OPCODE, TEXT)                                  \
  DEFINE_VALUE_TYPE(NAME, OPCODE, TEXT)
#include "common/wasm_defs/valtype.def"
#undef DEFINE_BLOCK_TYPE
#undef DEFINE_VALUE_TYPE
  default:
    ZEN_UNREACHABLE();
  }
}

const char *getOpcodeString(uint8_t Opcode) {
  switch (Opcode) {
#define DEFINE_WASM_OPCODE(NAME, OPCODE, TEXT)                                 \
  case NAME:                                                                   \
    return TEXT;
#include "common/wasm_defs/opcode.def"
#undef DEFINE_WASM_OPCODE
  default:
    ZEN_UNREACHABLE();
  }
}

common::SectionOrder getSectionOrder(common::SectionType SecType) {
  switch (SecType) {
#define DEFINE_SECTION_TYPE(NAME, ID, TEXT)                                    \
  case SectionType::SEC_##NAME:                                                \
    return common::SectionOrder::SEC_ORDER_##NAME;
#include "common/wasm_defs/sectype.def"
#undef DEFINE_SECTION_TYPE
  default:
    ZEN_UNREACHABLE();
  }
}

} // namespace zen::utils