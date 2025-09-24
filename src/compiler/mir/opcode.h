// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#ifndef COMPILER_IR_OPCODE_H
#define COMPILER_IR_OPCODE_H

#include "compiler/common/common_defs.h"
#include <string>

namespace COMPILER {

enum Opcode : uint16_t {
  OP_placeholder = 0,
#define OPCODE(STR) OP_##STR,
#include "compiler/mir/opcodes.def"
#undef OPCODE
  OP_unknown,

  /* following may need to be updated after adding a new opcode */
  OP_UNARY_EXPR_START = OP_clz,
  OP_UNARY_EXPR_END = OP_fpround_nearest,

  OP_BIN_EXPR_START = OP_add,
  OP_BIN_EXPR_END = OP_wasm_umul_overflow,

  OP_OVERFLOW_BIN_EXPR_START = OP_wasm_sadd_overflow,
  OP_OVERFLOW_BIN_EXPR_END = OP_BIN_EXPR_END,

  OP_CONV_EXPR_START = OP_inttoptr,
  OP_CONV_EXPR_END = OP_wasm_fptoui,

  OP_OTHER_EXPR_START = OP_dread,
  OP_OTHER_EXPR_END = OP_wasm_usub128_overflow,

  OP_CTRL_STMT_START = OP_br,
  OP_CTRL_STMT_END = OP_return,

  OP_OTHER_STMT_START = OP_dassign,
  OP_OTHER_STMT_END = OP_wasm_check_stack_boundary,

  OP_START = OP_UNARY_EXPR_START,
  OP_END = OP_OTHER_STMT_END,
};

const std::string &getOpcodeString(Opcode opcode);

class OpcodeDesc {
public:
  static constexpr bool isStatement(Opcode opcode) {
    // TODO: use desc information
    switch (opcode) {
    case OP_dassign:
    case OP_return:
    case OP_store:
      return true;
    default:
      return false;
    }
  }
};

} // namespace COMPILER

#endif // COMPILER_IR_OPCODE_H
