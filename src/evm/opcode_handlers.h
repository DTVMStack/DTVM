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
#define EVM_REQUIRE(Condition, errorCode)                                      \
  if (!Condition) {                                                            \
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
  static InterpreterExecContext *getInterpreterExecContext() {
    return CurrentContext;
  }
};

// CRTP Base class for all opcode handlers
template <typename Derived> class EVMOpcodeHandlerBase {
protected:
  static EVMFrame *getFrame() { return EVMResource::getCurFrame(); }

  static InterpreterExecContext *getContext() {
    return EVMResource::getInterpreterExecContext();
  }

public:
  void execute() {
    uint64_t GasCost = static_cast<Derived *>(this)->calculateGas();
    EVM_THROW_IF(getFrame()->GasLeft, <, GasCost, EVMOutOfGas);
    getFrame()->GasLeft -= GasCost;
    static_cast<Derived *>(this)->doExecute();
  };
};

template <typename UnaryOp>
class UnaryOpHandler : public EVMOpcodeHandlerBase<UnaryOpHandler<UnaryOp>> {
public:
  static void doExecute() {
    using Base = EVMOpcodeHandlerBase<UnaryOpHandler<UnaryOp>>;
    auto *Frame = Base::getFrame();
    EVM_STACK_CHECK(Frame, 1);

    intx::uint256 A = Frame->pop();

    intx::uint256 Result = UnaryOp{}(A);
    Frame->push(Result);
  }
  static uint64_t calculateGas();
};

template <typename BinaryOp>
class BinaryOpHandler : public EVMOpcodeHandlerBase<BinaryOpHandler<BinaryOp>> {
public:
  static void doExecute() {
    using Base = EVMOpcodeHandlerBase<BinaryOpHandler<BinaryOp>>;
    auto *Frame = Base::getFrame();
    EVM_STACK_CHECK(Frame, 2);

    intx::uint256 A = Frame->pop();
    intx::uint256 B = Frame->pop();

    intx::uint256 Result = BinaryOp{}(A, B);
    Frame->push(Result);
  }
  static uint64_t calculateGas();
};

template <typename TernaryOp>
class TernaryOpHandler
    : public EVMOpcodeHandlerBase<TernaryOpHandler<TernaryOp>> {
public:
  static void doExecute() {
    using Base = EVMOpcodeHandlerBase<TernaryOpHandler<TernaryOp>>;
    auto *Frame = Base::getFrame();
    EVM_STACK_CHECK(Frame, 3);

    intx::uint256 A = Frame->pop();
    intx::uint256 B = Frame->pop();
    intx::uint256 C = Frame->pop();

    intx::uint256 Result = TernaryOp{}(A, B, C);
    Frame->push(Result);
  }
  static uint64_t calculateGas();
};

#define DEFINE_UNARY_OP(OpName, Calc)                                          \
  struct OpName##OP {                                                          \
    intx::uint256 operator()(const intx::uint256 &A) const { return (Calc); }  \
  };                                                                           \
  using OpName##Handler = UnaryOpHandler<OpName##OP>;

#define DEFINE_BINARY_OP(OpName, Calc)                                         \
  struct OpName##OP {                                                          \
    intx::uint256 operator()(const intx::uint256 &A,                           \
                             const intx::uint256 &B) const {                   \
      return (Calc);                                                           \
    }                                                                          \
  };                                                                           \
  using OpName##Handler = BinaryOpHandler<OpName##OP>;

#define DEFINE_TERNARY_OP(OpName, Calc)                                        \
  struct OpName##OP {                                                          \
    intx::uint256 operator()(const intx::uint256 &A, const intx::uint256 &B,   \
                             const intx::uint256 &C) const {                   \
      return (Calc);                                                           \
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
DEFINE_BINARY_OP(SDiv,
                 ((B == 0) ? intx::uint256(0) : intx::sdivrem(A, B).quot));
DEFINE_BINARY_OP(SMod, ((B == 0) ? intx::uint256(0) : intx::sdivrem(A, B).rem));

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
DEFINE_BINARY_OP(Shl, (A < 256 ? B << A : intx::uint256(0)));
DEFINE_BINARY_OP(Shr, (A < 256 ? B >> A : intx::uint256(0)));
DEFINE_BINARY_OP(Eq, (A == B));
DEFINE_BINARY_OP(Lt, (A < B));
DEFINE_BINARY_OP(Gt, (A > B));
DEFINE_BINARY_OP(Slt, intx::slt(A, B));
DEFINE_BINARY_OP(Sgt, intx::slt(B, A));

#define DEFINE_UNIMPLEMENT_HANDLER(OpName)                                     \
  class OpName##Handler : public EVMOpcodeHandlerBase<OpName##Handler> {       \
  public:                                                                      \
    static void doExecute();                                                   \
    static uint64_t calculateGas();                                            \
  };

// Arithmetic operations
DEFINE_UNIMPLEMENT_HANDLER(SignExtend);
DEFINE_UNIMPLEMENT_HANDLER(Byte);
DEFINE_UNIMPLEMENT_HANDLER(Sar);

// Memory operations
DEFINE_UNIMPLEMENT_HANDLER(MStore);
DEFINE_UNIMPLEMENT_HANDLER(MStore8);
DEFINE_UNIMPLEMENT_HANDLER(MLoad);

// Control flow operations
DEFINE_UNIMPLEMENT_HANDLER(Jump);
DEFINE_UNIMPLEMENT_HANDLER(JumpI);

// Environment operations
DEFINE_UNIMPLEMENT_HANDLER(PC);
DEFINE_UNIMPLEMENT_HANDLER(MSize);

// Return operations
DEFINE_UNIMPLEMENT_HANDLER(Gas);
DEFINE_UNIMPLEMENT_HANDLER(GasLimit);
DEFINE_UNIMPLEMENT_HANDLER(Return);
DEFINE_UNIMPLEMENT_HANDLER(Revert);

// Stack operations
DEFINE_UNIMPLEMENT_HANDLER(PUSH);
DEFINE_UNIMPLEMENT_HANDLER(DUP);
DEFINE_UNIMPLEMENT_HANDLER(SWAP);

// Registry class to manage execution context
class EVMOpcodeHandlerRegistry {
public:
  // Arithmetic operations
  EVM_REGISTRY_GET(Add);
  EVM_REGISTRY_GET(Sub);
  EVM_REGISTRY_GET(Mul);
  EVM_REGISTRY_GET(Div);
  EVM_REGISTRY_GET(Mod);
  EVM_REGISTRY_GET(Exp);
  EVM_REGISTRY_GET(SDiv);
  EVM_REGISTRY_GET(SMod);
  EVM_REGISTRY_GET(SignExtend);
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
  EVM_REGISTRY_GET(Byte);
  EVM_REGISTRY_GET(Sar);
  // Memory operations
  EVM_REGISTRY_GET(MStore);
  EVM_REGISTRY_GET(MStore8);
  EVM_REGISTRY_GET(MLoad);
  // Control flow operations
  EVM_REGISTRY_GET(Jump);
  EVM_REGISTRY_GET(JumpI);
  // Environment operations
  EVM_REGISTRY_GET(PC);
  EVM_REGISTRY_GET(MSize);
  EVM_REGISTRY_GET(Gas);
  EVM_REGISTRY_GET(GasLimit);
  // Return operations
  EVM_REGISTRY_GET(Return);
  EVM_REGISTRY_GET(Revert);
  // Stack operations
  EVM_REGISTRY_GET(PUSH);
  EVM_REGISTRY_GET(DUP);
  EVM_REGISTRY_GET(SWAP);
};

// Utility functions
uint64_t calculateMemoryExpansionCost(uint64_t CurrentSize, uint64_t NewSize);

} // namespace zen::evm

#endif // ZEN_EVM_OPCODE_HANDLERS_H
