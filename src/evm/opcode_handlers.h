// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_EVM_OPCODE_HANDLERS_H
#define ZEN_EVM_OPCODE_HANDLERS_H

#include "evm/interpreter.h"
#include "common/errors.h"

// EVM error checking macro definitions
#define EVM_STACK_CHECK(FramePtr, N)                                           \
  if ((FramePtr)->stackHeight() < (N)) {                                       \
    throw zen::common::getError(zen::common::ErrorCode::UnexpectedNumArgs);    \
  }

// Generic condition check + exception throwing macro
#define EVM_THROW_IF(lhs, op, rhs, error_code)                               \
  if ((lhs) op (rhs)) {                                                       \
    throw zen::common::getError(zen::common::ErrorCode::error_code);          \
  }


// Simple boolean condition check macro
#define EVM_THROW_IF_TRUE(condition, error_code)                             \
  if (condition) {                                                           \
    throw zen::common::getError(zen::common::ErrorCode::error_code);         \
  }


namespace zen::evm {

class InterpreterExecContext;
struct EVMFrame;

// Arithmetic operations
void handleOpADD(EVMFrame *Frame);
void handleOpSUB(EVMFrame *Frame);
void handleOpMUL(EVMFrame *Frame);
void handleOpDIV(EVMFrame *Frame);
void handleOpMOD(EVMFrame *Frame);
void handleOpADDMOD(EVMFrame *Frame);
void handleOpMULMOD(EVMFrame *Frame);
void handleOpEXP(EVMFrame *Frame);
void handleOpSDIV(EVMFrame *Frame);
void handleOpSMOD(EVMFrame *Frame);
void handleOpSIGNEXTEND(EVMFrame *Frame);

// Bitwise operations
void handleOpAND(EVMFrame *Frame);
void handleOpOR(EVMFrame *Frame);
void handleOpXOR(EVMFrame *Frame);
void handleOpNOT(EVMFrame *Frame);
void handleOpBYTE(EVMFrame *Frame);
void handleOpSHL(EVMFrame *Frame);
void handleOpSHR(EVMFrame *Frame);
void handleOpSAR(EVMFrame *Frame);

// Comparison operations
void handleOpEQ(EVMFrame *Frame);
void handleOpISZERO(EVMFrame *Frame);
void handleOpLT(EVMFrame *Frame);
void handleOpGT(EVMFrame *Frame);
void handleOpSLT(EVMFrame *Frame);
void handleOpSGT(EVMFrame *Frame);

// Memory operations
void handleOpMSTORE(EVMFrame *Frame);
void handleOpMSTORE8(EVMFrame *Frame);
void handleOpMLOAD(EVMFrame *Frame);

// Control flow operations
bool handleOpJUMP(EVMFrame *Frame, const uint8_t *Code, size_t CodeSize);
bool handleOpJUMPI(EVMFrame *Frame, const uint8_t *Code, size_t CodeSize);

// Environment operations
void handleOpPC(EVMFrame *Frame);
void handleOpMSize(EVMFrame *Frame);
void handleOpGAS(EVMFrame *Frame);
void handleOpGASLIMIT(EVMFrame *Frame);

// Return operations
void handleOpRETURN(InterpreterExecContext &Context, EVMFrame *Frame);
void handleOpREVERT(InterpreterExecContext &Context, EVMFrame *Frame);

// Stack operations
void handleOpPUSH(EVMFrame *Frame, uint8_t OpcodeByte, const uint8_t *Code, size_t CodeSize);
void handleOpDUP(uint8_t OpcodeByte, EVMFrame *Frame);
void handleOpSWAP(uint8_t OpcodeByte, EVMFrame *Frame);

// Utility functions
uint64_t calculateMemoryExpansionCost(uint64_t CurrentSize, uint64_t NewSize);

} // namespace zen::evm

#endif // ZEN_EVM_OPCODE_HANDLERS_H
