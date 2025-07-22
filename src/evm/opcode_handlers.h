// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_EVM_OPCODE_HANDLERS_H
#define ZEN_EVM_OPCODE_HANDLERS_H

#include "common/errors.h"
#include "evm/interpreter.h"
#include "evmc/instructions.h"

// EVM error checking macro definitions
#define EVM_STACK_CHECK(FramePtr, N)                                           \
  if ((FramePtr)->stackHeight() < (N)) {                                       \
    throw zen::common::getError(zen::common::ErrorCode::UnexpectedNumArgs);    \
  }

// Generic condition check + exception throwing macro
#define EVM_THROW_IF(Lhs, Op, Rhs, errorCode)                                  \
  if ((Lhs)Op(Rhs)) {                                                          \
    throw zen::common::getError(zen::common::ErrorCode::errorCode);            \
  }

// Simple boolean condition check macro
#define EVM_THROW_IF_TRUE(Condition, errorCode)                                \
  if (Condition) {                                                             \
    throw zen::common::getError(zen::common::ErrorCode::errorCode);            \
  }

#define EVM_REGISTRY_GET(OpName)                                               \
  static OpName##Handler get##OpName##Handler() {                              \
    static OpName##Handler OpName;                                             \
    return OpName;                                                             \
  }

namespace zen::evm {
class EVMResource {
public:
  static EVMFrame *CurrentFrame;
  static InterpreterExecContext *CurrentContext;

  static void setExecutionContext(EVMFrame *Frame,
                                  InterpreterExecContext *Context) {
    CurrentFrame = Frame;
    CurrentContext = Context;
  }
  static EVMFrame *getCurFrame() { return CurrentFrame; }
  static InterpreterExecContext *getInterpreterExecContent() {
    return CurrentContext;
  }
};

// CRTP Base class for all opcode handlers
template <typename Derived> class EVMOpcodeHandlerBase {
protected:
  static EVMFrame *getFrame() { return EVMResource::getCurFrame(); }

  static InterpreterExecContext *getContext() {
    return EVMResource::getInterpreterExecContent();
  }

public:
  // Default gas calculation using EVMC table lookup
  static uint64_t calculateGas(evmc_opcode Op,
                               evmc_revision Revision = EVMC_CANCUN) {
    const struct evmc_instruction_metrics *MetricsTable =
        evmc_get_instruction_metrics_table(Revision);
    if (MetricsTable == nullptr) {
      throw zen::common::getError(
          zen::common::ErrorCode::EVMInvalidInstruction);
    }
    return MetricsTable[Op].gas_cost;
  }
  void execute(){};
};

template <typename UnaryOp>
class UnaryOpHandler : public EVMOpcodeHandlerBase<UnaryOpHandler<UnaryOp>> {
public:
  static void execute() {
    using Base = EVMOpcodeHandlerBase<UnaryOpHandler<UnaryOp>>;
    auto *Frame = Base::getFrame();
    EVM_STACK_CHECK(Frame, 1);

    intx::uint256 A = Frame->pop();

    intx::uint256 Result = UnaryOp{}(A);
    Frame->push(Result);
  }
};

template <typename BinaryOp>
class BinaryOpHandler : public EVMOpcodeHandlerBase<BinaryOpHandler<BinaryOp>> {
public:
  static void execute() {
    using Base = EVMOpcodeHandlerBase<BinaryOpHandler<BinaryOp>>;
    auto *Frame = Base::getFrame();
    EVM_STACK_CHECK(Frame, 2);

    intx::uint256 A = Frame->pop();
    intx::uint256 B = Frame->pop();

    intx::uint256 Result = BinaryOp{}(A, B);
    Frame->push(Result);
  }
};

template <typename TernaryOp>
class TernaryOpHandler
    : public EVMOpcodeHandlerBase<TernaryOpHandler<TernaryOp>> {
public:
  static void execute() {
    using Base = EVMOpcodeHandlerBase<TernaryOpHandler<TernaryOp>>;
    auto *Frame = Base::getFrame();
    EVM_STACK_CHECK(Frame, 3);

    intx::uint256 A = Frame->pop();
    intx::uint256 B = Frame->pop();
    intx::uint256 C = Frame->pop();

    intx::uint256 Result = TernaryOp{}(A, B, C);
    Frame->push(Result);
  }
};

#define DEFINE_UNARY_OP(OpName, Calc)                                          \
  struct OpName##OP {                                                          \
    intx::uint256 operator()(const intx::uint256 &A) const { return Calc; }    \
  };                                                                           \
  using OpName##Handler = UnaryOpHandler<OpName##OP>;

#define DEFINE_BINARY_OP(OpName, Calc)                                         \
  struct OpName##OP {                                                          \
    intx::uint256 operator()(const intx::uint256 &A,                           \
                             const intx::uint256 &B) const {                   \
      return Calc;                                                             \
    }                                                                          \
  };                                                                           \
  using OpName##Handler = BinaryOpHandler<OpName##OP>;

#define DEFINE_TERNARY_OP(OpName, Calc)                                        \
  struct OpName##OP {                                                          \
    intx::uint256 operator()(const intx::uint256 &A, const intx::uint256 &B,   \
                             const intx::uint256 &C) const {                   \
      return Calc;                                                             \
    }                                                                          \
  };                                                                           \
  using OpName##Handler = TernaryOpHandler<OpName##OP>;

// Arithmetic operations
DEFINE_BINARY_OP(Add, (A + B));
DEFINE_BINARY_OP(Sub, (A - B));
DEFINE_BINARY_OP(Mul, (A * B));
DEFINE_BINARY_OP(Div, ((B == 0) ? intx::uint256(0) : (A / B)));
DEFINE_BINARY_OP(Mod, ((B == 0) ? intx::uint256(0) : A % B));
DEFINE_BINARY_OP(Exp, intx::exp(A, B));
DEFINE_BINARY_OP(SDiv, intx::sdivrem(A, B).quot);
DEFINE_BINARY_OP(SMod, intx::sdivrem(A, B).rem);

// Modular arithmetic operations
DEFINE_TERNARY_OP(Addmod,
                  ((C == 0) ? intx::uint256(0) : intx::addmod(A, B, C)));
DEFINE_TERNARY_OP(Mulmod,
                  ((C == 0) ? intx::uint256(0) : intx::mulmod(A, B, C)));

// Unary operations
DEFINE_UNARY_OP(Not, (~A));
DEFINE_UNARY_OP(IsZero, (A == 0));

// Bitwise operations
DEFINE_BINARY_OP(And, (A & B));
DEFINE_BINARY_OP(Or, (A | B));
DEFINE_BINARY_OP(Xor, (A ^ B));
// DEFINE_BINARY_OP(Byte, (A & (1 << (8 * B))));
DEFINE_BINARY_OP(Shl, (A << B));
DEFINE_BINARY_OP(Shr, (A >> B));
// DEFINE_BINARY_OP(Sar, (A >> B));
DEFINE_BINARY_OP(Eq, (A == B));
DEFINE_BINARY_OP(Lt, (A < B));
DEFINE_BINARY_OP(Gt, (A > B));
DEFINE_BINARY_OP(Slt, intx::slt(A, B));
DEFINE_BINARY_OP(Sgt, intx::slt(B, A));

// Temporary implementation for GAS opcode
class GasHandler : public EVMOpcodeHandlerBase<GasHandler> {
public:
  static void execute() {
    EVMFrame *Frame = getFrame();
    uint64_t GasCost = calculateGas(evmc_opcode::OP_GAS);
    Frame->push(intx::uint256(Frame->GasLeft - GasCost));
  }
};

// Registry class to manage execution context
class EVMOpcodeHandlerRegistry {
public:
  EVM_REGISTRY_GET(Gas);
  // Arithmetic operations
  EVM_REGISTRY_GET(Add);
  EVM_REGISTRY_GET(Sub);
  EVM_REGISTRY_GET(Mul);
  EVM_REGISTRY_GET(Div);
  EVM_REGISTRY_GET(Mod);
  EVM_REGISTRY_GET(Exp);
  EVM_REGISTRY_GET(SDiv);
  EVM_REGISTRY_GET(SMod);
  // Modular arithmetic operations
  EVM_REGISTRY_GET(Addmod);
  EVM_REGISTRY_GET(Mulmod);
  // Unary operations
  EVM_REGISTRY_GET(Not);
  EVM_REGISTRY_GET(IsZero);
  // Bitwise operations
  EVM_REGISTRY_GET(And);
  EVM_REGISTRY_GET(Or);
  EVM_REGISTRY_GET(Xor);
  EVM_REGISTRY_GET(Shl);
  EVM_REGISTRY_GET(Shr);
  EVM_REGISTRY_GET(Eq);
  EVM_REGISTRY_GET(Lt);
  EVM_REGISTRY_GET(Gt);
  EVM_REGISTRY_GET(Slt);
  EVM_REGISTRY_GET(Sgt);
};

// Arithmetic operations
void handleOpSIGNEXTEND(EVMFrame *Frame);

// Bitwise operations
void handleOpBYTE(EVMFrame *Frame);
void handleOpSAR(EVMFrame *Frame);

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
void handleOpPUSH(EVMFrame *Frame, uint8_t OpcodeByte, const uint8_t *Code,
                  size_t CodeSize);
void handleOpDUP(uint8_t OpcodeByte, EVMFrame *Frame);
void handleOpSWAP(uint8_t OpcodeByte, EVMFrame *Frame);

// Utility functions
uint64_t calculateMemoryExpansionCost(uint64_t CurrentSize, uint64_t NewSize);

} // namespace zen::evm

#endif // ZEN_EVM_OPCODE_HANDLERS_H
