// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_ACTION_EVM_BYTECODE_VISITOR_H
#define ZEN_ACTION_EVM_BYTECODE_VISITOR_H

#include "compiler/evm_frontend/evm_mir_compiler.h"
#include "evm/evm.h"
#include "evmc/evmc.h"
#include "evmc/instructions.h"
#include "runtime/evm_module.h"

namespace COMPILER {

template <typename IRBuilder> class EVMByteCodeVisitor {
  typedef typename IRBuilder::CompilerContext CompilerContext;
  typedef typename IRBuilder::Operand Operand;
  typedef zen::action::VMEvalStack<Operand> EvalStack;
  using Byte = zen::common::Byte;
  using Bytes = zen::common::Bytes;

public:
  EVMByteCodeVisitor(IRBuilder &Builder, CompilerContext *Ctx)
      : Builder(Builder), Ctx(Ctx) {
    ZEN_ASSERT(Ctx);
  }

  bool compile() {
    Builder.initEVM(Ctx);
    bool Ret = decode();
    Builder.finalizeEVMBase();
    return Ret;
  }

private:
  void push(const Operand &Opnd) { Stack.push(Opnd); }

  Operand pop() {
    ZEN_ASSERT(!Stack.empty());
    Operand Opnd = Stack.pop();
    Builder.releaseOperand(Opnd);
    return Opnd;
  }

  bool decode() {
    const uint8_t *Bytecode =
        reinterpret_cast<const uint8_t *>(Ctx->getBytecode());
    size_t BytecodeSize = Ctx->getBytecodeSize();
    const uint8_t *Ip = Bytecode;
    const uint8_t *IpEnd = Bytecode + BytecodeSize;

    while (Ip < IpEnd) {
      evmc_opcode Opcode = static_cast<evmc_opcode>(*Ip);
      ptrdiff_t Diff = Ip - Bytecode;
      PC = static_cast<uint64_t>(Diff >= 0 ? Diff : 0);
      Ip++;
      PC++;

      switch (Opcode) {
      case OP_STOP:
        handleStop();
        return true;
      case OP_ADD:
        handleBinaryArithmetic<BinaryOperator::BO_ADD>();
        break;
      case OP_SUB:
        handleBinaryArithmetic<BinaryOperator::BO_SUB>();
        break;
      case OP_LT:
        handleCompare<CompareOperator::CO_LT>();
        break;
      case OP_GT:
        handleCompare<CompareOperator::CO_GT>();
        break;
      case OP_SLT:
        handleCompare<CompareOperator::CO_LT_S>();
        break;
      case OP_SGT:
        handleCompare<CompareOperator::CO_GT_S>();
        break;
      case OP_EQ:
        handleCompare<CompareOperator::CO_EQ>();
        break;
      case OP_ISZERO:
        handleCompare<CompareOperator::CO_EQZ>();
        break;
      case OP_AND:
        handleBitwiseOp<BinaryOperator::BO_AND>();
        break;
      case OP_OR:
        handleBitwiseOp<BinaryOperator::BO_OR>();
        break;
      case OP_XOR:
        handleBitwiseOp<BinaryOperator::BO_XOR>();
        break;
      case OP_NOT:
        handleNot();
        break;
      case OP_POP:
        Builder.handlePop();
        break;

      case OP_PUSH0:
      case OP_PUSH1:
      case OP_PUSH2:
      case OP_PUSH3:
      case OP_PUSH4:
      case OP_PUSH5:
      case OP_PUSH6:
      case OP_PUSH7:
      case OP_PUSH8:
      case OP_PUSH9:
      case OP_PUSH10:
      case OP_PUSH11:
      case OP_PUSH12:
      case OP_PUSH13:
      case OP_PUSH14:
      case OP_PUSH15:
      case OP_PUSH16:
      case OP_PUSH17:
      case OP_PUSH18:
      case OP_PUSH19:
      case OP_PUSH20:
      case OP_PUSH21:
      case OP_PUSH22:
      case OP_PUSH23:
      case OP_PUSH24:
      case OP_PUSH25:
      case OP_PUSH26:
      case OP_PUSH27:
      case OP_PUSH28:
      case OP_PUSH29:
      case OP_PUSH30:
      case OP_PUSH31:
      case OP_PUSH32: {
        uint8_t NumBytes = Opcode - OP_PUSH0;
        handlePush(NumBytes);
        Ip += NumBytes;
        break;
      }

      case OP_DUP1:
      case OP_DUP2:
      case OP_DUP3:
      case OP_DUP4:
      case OP_DUP5:
      case OP_DUP6:
      case OP_DUP7:
      case OP_DUP8:
      case OP_DUP9:
      case OP_DUP10:
      case OP_DUP11:
      case OP_DUP12:
      case OP_DUP13:
      case OP_DUP14:
      case OP_DUP15:
      case OP_DUP16: {
        uint8_t DupIndex = Opcode - OP_DUP1 + 1;
        handleDup(DupIndex);
        break;
      }

      case OP_SWAP1:
      case OP_SWAP2:
      case OP_SWAP3:
      case OP_SWAP4:
      case OP_SWAP5:
      case OP_SWAP6:
      case OP_SWAP7:
      case OP_SWAP8:
      case OP_SWAP9:
      case OP_SWAP10:
      case OP_SWAP11:
      case OP_SWAP12:
      case OP_SWAP13:
      case OP_SWAP14:
      case OP_SWAP15:
      case OP_SWAP16: {
        uint8_t SwapIndex = Opcode - OP_SWAP1 + 1;
        handleSwap(SwapIndex);
        break;
      }

      case OP_MUL: {
        ZEN_ASSERT_TODO();
      }

      case OP_DIV: {
        ZEN_ASSERT_TODO();
      }

      case OP_SDIV: {
        ZEN_ASSERT_TODO();
      }

      case OP_MOD: {
        ZEN_ASSERT_TODO();
      }

      case OP_SMOD: {
        ZEN_ASSERT_TODO();
      }

      case OP_ADDMOD: {
        ZEN_ASSERT_TODO();
      }

      case OP_MULMOD: {
        ZEN_ASSERT_TODO();
      }

      case OP_EXP: {
        ZEN_ASSERT_TODO();
      }

      case OP_SIGNEXTEND: {
        ZEN_ASSERT_TODO();
      }

      case OP_BYTE: {
        ZEN_ASSERT_TODO();
      }

      case OP_SHL: {
        ZEN_ASSERT_TODO();
      }

      case OP_SHR: {
        ZEN_ASSERT_TODO();
      }

      case OP_SAR: {
        ZEN_ASSERT_TODO();
      }

      case OP_KECCAK256: {
        ZEN_ASSERT_TODO();
      }

      case OP_ADDRESS: {
        Operand Result = Builder.handleAddress();
        push(Result);
        break;
      }

      case OP_BALANCE: {
        ZEN_ASSERT_TODO();
      }

      case OP_ORIGIN: {
        Operand Result = Builder.handleOrigin();
        push(Result);
        break;
      }

      case OP_CALLER: {
        Operand Result = Builder.handleCaller();
        push(Result);
        break;
      }

      case OP_CALLVALUE: {
        Operand Result = Builder.handleCallValue();
        push(Result);
        break;
      }

      case OP_CALLDATALOAD: {
        ZEN_ASSERT_TODO();
      }

      case OP_CALLDATASIZE: {
        Operand Result = Builder.handleCallDataSize();
        push(Result);
        break;
      }

      case OP_CALLDATACOPY: {
        ZEN_ASSERT_TODO();
      }

      case OP_CODESIZE: {
        Operand Result = Builder.handleCodeSize();
        push(Result);
        break;
      }

      case OP_CODECOPY: {
        ZEN_ASSERT_TODO();
      }

      case OP_GASPRICE: {
        Operand Result = Builder.handleGasPrice();
        push(Result);
        break;
      }

      case OP_EXTCODESIZE: {
        ZEN_ASSERT_TODO();
      }

      case OP_EXTCODECOPY: {
        ZEN_ASSERT_TODO();
      }

      case OP_RETURNDATASIZE: {
        ZEN_ASSERT_TODO();
      }

      case OP_RETURNDATACOPY: {
        ZEN_ASSERT_TODO();
      }

      case OP_EXTCODEHASH: {
        ZEN_ASSERT_TODO();
      }

      case OP_BLOCKHASH: {
        ZEN_ASSERT_TODO();
      }

      case OP_COINBASE: {
        ZEN_ASSERT_TODO();
      }

      case OP_TIMESTAMP: {
        ZEN_ASSERT_TODO();
      }

      case OP_NUMBER: {
        ZEN_ASSERT_TODO();
      }

      case OP_PREVRANDAO: {
        ZEN_ASSERT_TODO();
      }

      case OP_GASLIMIT: {
        ZEN_ASSERT_TODO();
      }

      case OP_CHAINID: {
        ZEN_ASSERT_TODO();
      }

      case OP_SELFBALANCE: {
        ZEN_ASSERT_TODO();
      }

      case OP_BASEFEE: {
        ZEN_ASSERT_TODO();
      }

      case zen::evm::OP_BLOBHASH: {
        ZEN_ASSERT_TODO();
      }

      case zen::evm::OP_BLOBBASEFEE: {
        ZEN_ASSERT_TODO();
      }

      case OP_MLOAD: {
        ZEN_ASSERT_TODO();
      }

      case OP_MSTORE: {
        ZEN_ASSERT_TODO();
      }

      case OP_MSTORE8: {
        ZEN_ASSERT_TODO();
      }

      case OP_SLOAD: {
        ZEN_ASSERT_TODO();
      }

      case OP_SSTORE: {
        ZEN_ASSERT_TODO();
      }

      case OP_MSIZE: {
        ZEN_ASSERT_TODO();
      }

      case zen::evm::OP_TLOAD: {
        ZEN_ASSERT_TODO();
      }

      case zen::evm::OP_TSTORE: {
        ZEN_ASSERT_TODO();
      }

      case zen::evm::OP_MCOPY: {
        ZEN_ASSERT_TODO();
      }

      case OP_LOG0:
      case OP_LOG1:
      case OP_LOG2:
      case OP_LOG3:
      case OP_LOG4: {
        ZEN_ASSERT_TODO();
      }

      case OP_CREATE: {
        ZEN_ASSERT_TODO();
      }

      case OP_CALL: {
        ZEN_ASSERT_TODO();
      }

      case OP_CALLCODE: {
        ZEN_ASSERT_TODO();
      }

      case OP_DELEGATECALL: {
        ZEN_ASSERT_TODO();
      }

      case OP_CREATE2: {
        ZEN_ASSERT_TODO();
      }

      case OP_STATICCALL: {
        ZEN_ASSERT_TODO();
      }

      case OP_SELFDESTRUCT: {
        ZEN_ASSERT_TODO();
      }

      // Control flow operations
      case OP_JUMP: {
        Operand Dest = pop();
        Builder.handleJump(Dest);
        break;
      }

      case OP_JUMPI: {
        Operand Dest = pop();
        Operand Cond = pop();
        Builder.handleJumpI(Dest, Cond);
        break;
      }

      case OP_JUMPDEST: {
        Builder.handleJumpDest();
        break;
      }

      // Environment operations
      case OP_PC: {
        Operand Result = Builder.handlePC();
        push(Result);
        break;
      }

      case OP_GAS: {
        Operand Result = Builder.handleGas();
        push(Result);
        break;
      }

      // Halt operations
      case OP_RETURN: {
        ZEN_ASSERT_TODO();
      }

      case OP_REVERT:
        // End execution
        return true;

      default:
        throw getErrorWithExtraMessage(ErrorCode::UnsupportedOpcode,
                                       std::to_string(Opcode));
      }
    }

    return true;
  }

  void handleStop() { Builder.handleStop(); }

  template <BinaryOperator Opr> void handleBinaryArithmetic() {
    Operand RHS = pop();
    Operand LHS = pop();
    Operand Result = Builder.template handleBinaryArithmetic<Opr>(LHS, RHS);
    push(Result);
  }

  template <CompareOperator Opr> void handleCompare() {
    Operand CmpRHS = (Opr != CompareOperator::CO_EQZ) ? pop() : Operand();
    Operand CmpLHS = pop();
    Operand Result = Builder.template handleCompareOp<Opr>(CmpLHS, CmpRHS);
    push(Result);
  }

  template <BinaryOperator Opr> void handleBitwiseOp() {
    Operand RHS = pop();
    Operand LHS = pop();
    Operand Result = Builder.template handleBitwiseOp<Opr>(LHS, RHS);
    push(Result);
  }

  void handleNot() {
    Operand Opnd = pop();
    Operand Result = Builder.handleNot(Opnd);
    push(Result);
  }

  void handlePush(uint8_t NumBytes) {
    Bytes Data = readBytes(NumBytes);
    Operand Result = Builder.handlePush(Data);
    push(Result);
  }

  Bytes readBytes(uint8_t Count) {
    if (PC + Count > Ctx->getBytecodeSize()) {
      throw getError(common::ErrorCode::UnexpectedEnd);
    }
    const uint8_t *Bytecode =
        reinterpret_cast<const uint8_t *>(Ctx->getBytecode());
    Bytes Result(reinterpret_cast<const std::byte *>(Bytecode + PC), Count);
    PC += Count;
    return Result;
  }

  void handleDup(uint8_t Index) {
    Operand Result = Builder.handleDup(Index);
    push(Result);
  }

  void handleSwap(uint8_t Index) { Builder.handleSwap(Index); }

  IRBuilder &Builder;
  CompilerContext *Ctx;
  EvalStack Stack;
  uint64_t PC = 0;
};

} // namespace COMPILER

#endif // ZEN_ACTION_EVM_BYTECODE_VISITOR_H
