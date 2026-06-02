// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_EVM_OPCODE_HANDLERS_H
#define ZEN_EVM_OPCODE_HANDLERS_H

#include "evm/arith_profile.h"
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
  static thread_local EVMFrame *CurrentFrame;
  static thread_local InterpreterExecContext *CurrentContext;
  static thread_local const evmc_instruction_metrics *CurrentMetricsTable;
  // Join key for the dual-tap arith profiler (ZEN_EVM_LIMB_PROFILE). FNV-1a
  // hash of the currently-executing contract code; set once per interpret()
  // run, dormant when the profiler is off.
  static thread_local uint64_t CurrentCodeHash;

  static void setExecutionContext(EVMFrame *Frame,
                                  InterpreterExecContext *Context) {
    CurrentFrame = Frame;
    CurrentContext = Context;
  }
  static void setMetricsTable(const evmc_instruction_metrics *Table) {
    CurrentMetricsTable = Table;
  }
  static void setCodeHash(uint64_t Hash) { CurrentCodeHash = Hash; }
  static uint64_t getCodeHash() { return CurrentCodeHash; }
  /// Clear thread-local execution pointers after an interpreter run so reused
  /// InterpreterExecContext cannot leak cross-call state to host or tooling.
  static void clear() {
    CurrentFrame = nullptr;
    CurrentContext = nullptr;
    CurrentMetricsTable = nullptr;
    CurrentCodeHash = 0;
  }
  /// Runs clear() on scope exit (including when interpret() throws).
  struct ClearGuard {
    ~ClearGuard() { clear(); }
  };
  static const evmc_instruction_metrics *getMetricsTable() {
    return CurrentMetricsTable;
  }
  static EVMFrame *getCurFrame() { return CurrentFrame; }
  static InterpreterExecContext *getInterpreterExecContext() {
    return CurrentContext;
  }
};

// Dual-tap Stream A helper: emit one CSV row per arithmetic operand recording
// its dynamic 64-bit limb width. Reads the opcode byte straight from the
// frame's code buffer at the current Pc. Dormant unless ZEN_EVM_LIMB_PROFILE
// is set (the recordLimb gate is checked inside the emitter).
inline void profileArithLimbs(EVMFrame *Frame, const intx::uint256 *const *Ops,
                              uint32_t NumOps) {
  if (!arith_profile::limbProfileEnabled()) {
    return;
  }
  const uint8_t Opcode =
      (Frame->Msg.code != nullptr && Frame->Pc < Frame->Msg.code_size)
          ? Frame->Msg.code[Frame->Pc]
          : 0;
  // Restrict Stream A to the arithmetic opcodes Stream B also reports, so the
  // two CSVs join cleanly. The shared BinaryOpHandler/TernaryOpHandler also
  // back comparison/bitwise ops, which are out of scope here.
  switch (Opcode) {
  case OP_ADD:
  case OP_MUL:
  case OP_SUB:
  case OP_DIV:
  case OP_SDIV:
  case OP_MOD:
  case OP_SMOD:
  case OP_ADDMOD:
  case OP_MULMOD:
    break;
  default:
    return;
  }
  const uint64_t CodeHash = EVMResource::getCodeHash();
  for (uint32_t I = 0; I < NumOps; ++I) {
    arith_profile::recordLimb(CodeHash, Frame->Pc, Opcode, I,
                              arith_profile::limbWidth(*Ops[I]));
  }
}

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
    {
      const intx::uint256 *Ops[2] = {&A, &B};
      profileArithLimbs(Frame, Ops, 2);
    }
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
    {
      const intx::uint256 *Ops[3] = {&A, &B, &C};
      profileArithLimbs(Frame, Ops, 3);
    }
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
DEFINE_UNARY_OP(Clz, (intx::clz(A)));

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
    inline static thread_local evmc_opcode OpCode = OP_INVALID;                \
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
DEFINE_UNIMPLEMENT_HANDLER(Exp);

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
