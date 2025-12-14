// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_EVM_OPCODE_HANDLERS_H
#define ZEN_EVM_OPCODE_HANDLERS_H

#include "evm/interpreter.h"
#include "evmc/instructions.h"
#include <cstdint>

// EVM error checking macro definitions
#define EVM_STACK_CHECK(FramePtr, N)                                           \
  if ((FramePtr)->stackHeight() < (N)) {                                       \
    getContext()->setStatus(EVMC_STACK_UNDERFLOW);                             \
    return;                                                                    \
  }
// Overflow: k elements will be pushed in this time (usually k=1), whether it
// exceeds 1024
#define EVM_REQUIRE_STACK_SPACE(FramePtr, k)                                   \
  if ((FramePtr)->stackHeight() + (k) > 1024) {                                \
    getContext()->setStatus(EVMC_STACK_OVERFLOW);                              \
    return;                                                                    \
  }

// EVMFrame check
#define EVM_FRAME_CHECK(FramePtr)                                              \
  if (!(FramePtr)) {                                                           \
    throw zen::common::getError(zen::common::ErrorCode::EVMFrameNotFound);     \
  }

// Simple boolean condition check macro
#define EVM_REQUIRE(Condition, errorCode)                                      \
  if (!(Condition)) {                                                          \
    throw zen::common::getError(zen::common::ErrorCode::errorCode);            \
  }

// Sets the specified error status and returns immediately unless the given
// condition is true.
#define EVM_SET_EXCEPTION_UNLESS(Condition, errorStatus)                       \
  if (!(Condition)) {                                                          \
    getContext()->setStatus(errorStatus);                                      \
    return;                                                                    \
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
  using Byte = common::Byte;
  static void execute() {
    auto *Frame = getFrame();
    auto *Context = getContext();
    uint64_t GasCost = Derived::calculateGas();
    if ((uint64_t)Frame->Msg.gas < GasCost) {
      Context->setStatus(EVMC_OUT_OF_GAS);
      return;
    }
    Frame->Msg.gas -= GasCost;
    Derived::doExecute();
  }
};

template <typename UnaryOp>
class UnaryOpHandler : public EVMOpcodeHandlerBase<UnaryOpHandler<UnaryOp>> {
public:
  static EVMFrame *getFrame() { return EVMResource::getCurFrame(); }
  static InterpreterExecContext *getContext() {
    return EVMResource::getInterpreterExecContext();
  }
  static void doExecute() {
    auto *Frame = getFrame();
    EVM_STACK_CHECK(Frame, 1);

    auto &A = Frame->Stack[Frame->Sp - 1];
    A = UnaryOp{}(A);
  }
  static uint64_t calculateGas();
};

template <typename BinaryOp>
class BinaryOpHandler : public EVMOpcodeHandlerBase<BinaryOpHandler<BinaryOp>> {
public:
  static EVMFrame *getFrame() { return EVMResource::getCurFrame(); }
  static InterpreterExecContext *getContext() {
    return EVMResource::getInterpreterExecContext();
  }
  static void doExecute() {
    auto *Frame = getFrame();
    EVM_STACK_CHECK(Frame, 2);

    auto &A = Frame->Stack[Frame->Sp - 1];
    auto &B = Frame->Stack[Frame->Sp - 2];
    B = BinaryOp{}(A, B);
    --Frame->Sp;
  }
  static uint64_t calculateGas();
};

template <typename TernaryOp>
class TernaryOpHandler
    : public EVMOpcodeHandlerBase<TernaryOpHandler<TernaryOp>> {
public:
  static EVMFrame *getFrame() { return EVMResource::getCurFrame(); }
  static InterpreterExecContext *getContext() {
    return EVMResource::getInterpreterExecContext();
  }
  static void doExecute() {
    auto *Frame = getFrame();
    EVM_STACK_CHECK(Frame, 3);

    auto &A = Frame->Stack[Frame->Sp - 1];
    auto &B = Frame->Stack[Frame->Sp - 2];
    auto &C = Frame->Stack[Frame->Sp - 3];
    C = TernaryOp{}(A, B, C);
    Frame->Sp -= 2;
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
    static EVMFrame *getFrame() { return EVMResource::getCurFrame(); }         \
    static InterpreterExecContext *getContext() {                              \
      return EVMResource::getInterpreterExecContext();                         \
    }                                                                          \
    static void doExecute();                                                   \
    static uint64_t calculateGas();                                            \
  };

#define DEFINE_MULTIOPCODE_UNIMPLEMENT_HANDLER(OpName)                         \
  class OpName##Handler : public EVMOpcodeHandlerBase<OpName##Handler> {       \
  public:                                                                      \
    inline static evmc_opcode OpCode = OP_INVALID;                             \
    static EVMFrame *getFrame() { return EVMResource::getCurFrame(); }         \
    static InterpreterExecContext *getContext() {                              \
      return EVMResource::getInterpreterExecContext();                         \
    }                                                                          \
    static void doExecute();                                                   \
    static uint64_t calculateGas();                                            \
  };

// environmental information
DEFINE_UNIMPLEMENT_HANDLER(Address);
DEFINE_UNIMPLEMENT_HANDLER(Balance);
DEFINE_UNIMPLEMENT_HANDLER(Origin);
DEFINE_UNIMPLEMENT_HANDLER(Caller);
DEFINE_UNIMPLEMENT_HANDLER(CallValue);
DEFINE_UNIMPLEMENT_HANDLER(CallDataLoad);
DEFINE_UNIMPLEMENT_HANDLER(CallDataSize);
DEFINE_UNIMPLEMENT_HANDLER(CodeSize);
DEFINE_UNIMPLEMENT_HANDLER(CallDataCopy);
DEFINE_UNIMPLEMENT_HANDLER(CodeCopy);
DEFINE_UNIMPLEMENT_HANDLER(GasPrice);
DEFINE_UNIMPLEMENT_HANDLER(ExtCodeSize);
DEFINE_UNIMPLEMENT_HANDLER(ExtCodeCopy);
DEFINE_UNIMPLEMENT_HANDLER(ReturnDataSize);
DEFINE_UNIMPLEMENT_HANDLER(ReturnDataCopy);
DEFINE_UNIMPLEMENT_HANDLER(ExtCodeHash);

// block message
DEFINE_UNIMPLEMENT_HANDLER(BlockHash);
DEFINE_UNIMPLEMENT_HANDLER(CoinBase);
DEFINE_UNIMPLEMENT_HANDLER(TimeStamp);
DEFINE_UNIMPLEMENT_HANDLER(Number);
DEFINE_UNIMPLEMENT_HANDLER(PrevRanDao);
DEFINE_UNIMPLEMENT_HANDLER(ChainId);
DEFINE_UNIMPLEMENT_HANDLER(SelfBalance);
DEFINE_UNIMPLEMENT_HANDLER(BaseFee);
DEFINE_UNIMPLEMENT_HANDLER(BlobHash);
DEFINE_UNIMPLEMENT_HANDLER(BlobBaseFee);
// storage operations
DEFINE_UNIMPLEMENT_HANDLER(SLoad);
DEFINE_UNIMPLEMENT_HANDLER(SStore);

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
DEFINE_UNIMPLEMENT_HANDLER(JumpDest);
// Temporary Storage
DEFINE_UNIMPLEMENT_HANDLER(TLoad);
DEFINE_UNIMPLEMENT_HANDLER(TStore);

DEFINE_UNIMPLEMENT_HANDLER(MCopy);

// Environment operations
DEFINE_UNIMPLEMENT_HANDLER(PC);
DEFINE_UNIMPLEMENT_HANDLER(MSize);

// Return operations
DEFINE_UNIMPLEMENT_HANDLER(Gas);
DEFINE_UNIMPLEMENT_HANDLER(GasLimit);
DEFINE_UNIMPLEMENT_HANDLER(Return);
DEFINE_UNIMPLEMENT_HANDLER(Revert);

// Stack operations
DEFINE_UNIMPLEMENT_HANDLER(Pop);
DEFINE_MULTIOPCODE_UNIMPLEMENT_HANDLER(Push);
DEFINE_UNIMPLEMENT_HANDLER(Push0);
DEFINE_MULTIOPCODE_UNIMPLEMENT_HANDLER(Dup);
DEFINE_MULTIOPCODE_UNIMPLEMENT_HANDLER(Swap);

// Call operations
DEFINE_MULTIOPCODE_UNIMPLEMENT_HANDLER(Create);
DEFINE_MULTIOPCODE_UNIMPLEMENT_HANDLER(Call);

// Logging operations
DEFINE_MULTIOPCODE_UNIMPLEMENT_HANDLER(Log);

// Crypto operations
DEFINE_UNIMPLEMENT_HANDLER(Keccak256);

// Self-destruct operation
DEFINE_UNIMPLEMENT_HANDLER(SelfDestruct);

} // namespace zen::evm

#endif // ZEN_EVM_OPCODE_HANDLERS_H
