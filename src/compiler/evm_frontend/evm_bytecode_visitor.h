// Copyright (C) 2021-2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "compiler/evm_frontend/evm_mir_compiler.h"
#include "evmc/evmc.h"
#include "evmc/instructions.h"
#include "intx/intx.hpp"

namespace COMPILER {

template <typename IRBuilder> class EVMByteCodeVisitor {
  typedef typename IRBuilder::CompilerContext CompilerContext;
  typedef typename IRBuilder::Operand Operand;
  typedef typename IRBuilder::template EVMEvalStack<Operand> EVMEvalStack;

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
  void push(Operand Opnd) { Stack.push(Opnd); }

  Operand pop() {
    ZEN_ASSERT(!Stack.empty());
    Operand Opnd = Stack.pop();
    Builder.releaseOperand(Opnd);
    return Opnd;
  }

  Operand peek(size_t Index = 0) { return Stack.peek(Index); }

  bool decode() {
    const uint8_t *Bytecode = Ctx->getBytecode();
    size_t BytecodeSize = Ctx->getBytecodeSize();
    const uint8_t *Ip = Bytecode;
    const uint8_t *IpEnd = Bytecode + BytecodeSize;

    while (Ip < IpEnd) {
      evmc_opcode Opcode = static_cast<evmc_opcode>(*Ip);
      ptrdiff_t diff = Ip - Bytecode;
      PC = static_cast<uint64_t>(diff >= 0 ? diff : 0);
      Ip++;

      switch (Opcode) {
      // Stack operations
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
        uint32_t NumBytes = Opcode - OP_PUSH1 + 1;
        Operand Result = Builder.handlePush(Ip, NumBytes);
        push(Result);
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
        uint32_t N = Opcode - OP_DUP1 + 1;
        ZEN_ASSERT(Stack.size() >= N);
        Operand Value = peek(N - 1);
        push(Value);
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
        uint32_t N = Opcode - OP_SWAP1 + 1;
        ZEN_ASSERT(Stack.size() >= N + 1);
        Builder.handleSwap(N);
        break;
      }

      case OP_POP: {
        ZEN_ASSERT(!Stack.empty());
        pop();
        Builder.handlePop();
        break;
      }

      // Arithmetic operations
      case OP_ADD: {
        Operand B = pop();
        Operand A = pop();
        Operand Result = Builder.template handleBinaryArithmetic<OP_ADD>(A, B);
        push(Result);
        break;
      }

      case OP_MUL: {
        ZEN_ASSERT_TODO();
      }

      case OP_SUB: {
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

      case OP_LT: {
        ZEN_ASSERT_TODO();
      }

      case OP_GT: {
        ZEN_ASSERT_TODO();
      }

      case OP_SLT: {
        ZEN_ASSERT_TODO();
      }

      case OP_SGT: {
        ZEN_ASSERT_TODO();
      }

      case OP_EQ: {
        ZEN_ASSERT_TODO();
      }

      case OP_ISZERO: {
        ZEN_ASSERT_TODO();
      }

      case OP_AND: {
        ZEN_ASSERT_TODO();
      }

      case OP_OR: {
        ZEN_ASSERT_TODO();
      }

      case OP_XOR: {
        ZEN_ASSERT_TODO();
      }

      case OP_NOT: {
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
        ZEN_ASSERT_TODO();
      }

      case OP_BALANCE: {
        ZEN_ASSERT_TODO();
      }

      case OP_ORIGIN: {
        ZEN_ASSERT_TODO();
      }

      case OP_CALLER: {
        ZEN_ASSERT_TODO();
      }

      case OP_CALLVALUE: {
        ZEN_ASSERT_TODO();
      }

      case OP_CALLDATALOAD: {
        ZEN_ASSERT_TODO();
      }

      case OP_CALLDATASIZE: {
        ZEN_ASSERT_TODO();
      }

      case OP_CALLDATACOPY: {
        ZEN_ASSERT_TODO();
      }

      case OP_CODESIZE: {
        ZEN_ASSERT_TODO();
      }

      case OP_CODECOPY: {
        ZEN_ASSERT_TODO();
      }

      case OP_GASPRICE: {
        ZEN_ASSERT_TODO();
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

      case OP_BLOBHASH: {
        ZEN_ASSERT_TODO();
      }

      case OP_BLOBBASEFEE: {
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

      case OP_TLOAD: {
        ZEN_ASSERT_TODO();
      }

      case OP_TSTORE: {
        ZEN_ASSERT_TODO();
      }

      case OP_MCOPY: {
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
      case OP_STOP:
      case OP_RETURN:
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

  IRBuilder &Builder;
  CompilerContext *Ctx;
  EVMEvalStack Stack;
  uint64_t PC = 0;
};

} // namespace COMPILER
