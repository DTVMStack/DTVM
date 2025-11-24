// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_ACTION_EVM_BYTECODE_VISITOR_H
#define ZEN_ACTION_EVM_BYTECODE_VISITOR_H

#include "compiler/evm_frontend/evm_mir_compiler.h"
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
  static constexpr size_t EVM_MAX_STACK_SIZE = 1024;

  void push(const Operand &Opnd) {
    CurStackOffset++;
    if (CurStackOffset > MaxStackOffset) {
      MaxStackOffset = CurStackOffset;
      if (MaxStackOffset > EVM_MAX_STACK_SIZE) {
        // Detect stack overflow within a block
        throw getError(common::ErrorCode::EVMStackOverflow);
      }
    }
    Stack.push(Opnd);
  }

  Operand pop() {
    CurStackOffset--;
    if (CurStackOffset < MinStackOffset) {
      MinStackOffset = CurStackOffset;
    }
    Operand Opnd;
    if (Stack.empty()) {
      Opnd = Builder.stackPop();
    } else {
      Opnd = Stack.pop();
    }
    Builder.releaseOperand(Opnd);
    return Opnd;
  }

  bool decode() {
    try {
      const uint8_t *Bytecode =
          reinterpret_cast<const uint8_t *>(Ctx->getBytecode());
      size_t BytecodeSize = Ctx->getBytecodeSize();
      const uint8_t *Ip = Bytecode;
      const uint8_t *IpEnd = Bytecode + BytecodeSize;
      bool LastStop = false;

      while (Ip < IpEnd) {
        evmc_opcode Opcode = static_cast<evmc_opcode>(*Ip);
        ptrdiff_t Diff = Ip - Bytecode;
        PC = static_cast<uint64_t>(Diff >= 0 ? Diff : 0);

        Ip++;

        bool IsDeadInstruction = InDeadCode && Opcode != OP_JUMPDEST;
        if (IsDeadInstruction) {
          if (Opcode >= OP_PUSH0 && Opcode <= OP_PUSH32) {
            uint8_t NumBytes =
                static_cast<uint8_t>(Opcode) - static_cast<uint8_t>(OP_PUSH0);
            Ip += NumBytes;
          }
          continue;
        }
        bool IsJumpDest = (Opcode == OP_JUMPDEST);
        LastStop = (Opcode == OP_STOP);

        if (!IsJumpDest) {
          Builder.meterOpcode(Opcode);
        }

        switch (Opcode) {
        case OP_STOP:
          handleEndBlock();
          handleStop();
          InDeadCode = true;
          break;
        case OP_ADD:
          handleBinaryArithmetic<BinaryOperator::BO_ADD>();
          break;
        case OP_MUL:
          handleMul();
          break;
        case OP_SUB:
          handleBinaryArithmetic<BinaryOperator::BO_SUB>();
          break;
        case OP_DIV:
          handleDiv();
          break;
        case OP_SDIV:
          handleSDiv();
          break;
        case OP_MOD:
          handleMod();
          break;
        case OP_SMOD:
          handleSMod();
          break;
        case OP_ADDMOD:
          handleAddMod();
          break;
        case OP_MULMOD:
          handleMulMod();
          break;
        case OP_EXP:
          handleExp();
          break;
        case OP_SIGNEXTEND:
          handleSignextend();
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
        case OP_BYTE:
          handleByte();
          break;
        case OP_SHL:
          handleShift<BinaryOperator::BO_SHL>();
          break;
        case OP_SHR:
          handleShift<BinaryOperator::BO_SHR_U>();
          break;
        case OP_SAR:
          handleShift<BinaryOperator::BO_SHR_S>();
          break;
        case OP_POP:
          handlePop();
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

        case OP_LOG0:
        case OP_LOG1:
        case OP_LOG2:
        case OP_LOG3:
        case OP_LOG4: {
          uint8_t NumTopics = Opcode - OP_LOG0;
          handleLog(NumTopics);
          break;
        }

        case OP_KECCAK256: {
          Operand Offset = pop();
          Operand Length = pop();
          Operand Result = Builder.handleKeccak256(Offset, Length);
          push(Result);
          break;
        }

        case OP_ADDRESS: {
          Operand Result = Builder.handleAddress();
          push(Result);
          break;
        }

        case OP_BALANCE: {
          Operand Address = pop();
          Operand Result = Builder.handleBalance(Address);
          push(Result);
          break;
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
          Operand Offset = pop();
          Operand Result = Builder.handleCallDataLoad(Offset);
          push(Result);
          break;
        }

        case OP_CALLDATASIZE: {
          Operand Result = Builder.handleCallDataSize();
          push(Result);
          break;
        }

        case OP_CALLDATACOPY: {
          Operand DestOffset = pop();
          Operand Offset = pop();
          Operand Size = pop();
          Builder.handleCallDataCopy(DestOffset, Offset, Size);
          break;
        }

        case OP_CODESIZE: {
          Operand Result = Builder.handleCodeSize();
          push(Result);
          break;
        }

        case OP_CODECOPY: {
          Operand DestOffset = pop();
          Operand Offset = pop();
          Operand Size = pop();
          Builder.handleCodeCopy(DestOffset, Offset, Size);
          break;
        }

        case OP_GASPRICE: {
          Operand Result = Builder.handleGasPrice();
          push(Result);
          break;
        }

        case OP_EXTCODESIZE: {
          Operand Address = pop();
          Operand Result = Builder.handleExtCodeSize(Address);
          push(Result);
          break;
        }

        case OP_EXTCODECOPY: {
          Operand Address = pop();
          Operand DestOffset = pop();
          Operand Offset = pop();
          Operand Size = pop();
          Builder.handleExtCodeCopy(Address, DestOffset, Offset, Size);
          break;
        }

        case OP_RETURNDATASIZE: {
          Operand Result = Builder.handleReturnDataSize();
          push(Result);
          break;
        }

        case OP_RETURNDATACOPY: {
          Operand DestOffset = pop();
          Operand Offset = pop();
          Operand Size = pop();
          Builder.handleReturnDataCopy(DestOffset, Offset, Size);
          break;
        }

        case OP_EXTCODEHASH: {
          Operand Address = pop();
          Operand Result = Builder.handleExtCodeHash(Address);
          push(Result);
          break;
        }

        case OP_BLOCKHASH: {
          Operand BlockNumber = pop();
          Operand Result = Builder.handleBlockHash(BlockNumber);
          push(Result);
          break;
        }

        case OP_COINBASE: {
          Operand Result = Builder.handleCoinBase();
          push(Result);
          break;
        }

        case OP_TIMESTAMP: {
          Operand Result = Builder.handleTimestamp();
          push(Result);
          break;
        }

        case OP_NUMBER: {
          Operand Result = Builder.handleNumber();
          push(Result);
          break;
        }

        case OP_PREVRANDAO: {
          Operand Result = Builder.handlePrevRandao();
          push(Result);
          break;
        }

        case OP_GASLIMIT: {
          Operand Result = Builder.handleGasLimit();
          push(Result);
          break;
        }

        case OP_CHAINID: {
          Operand Result = Builder.handleChainId();
          push(Result);
          break;
        }

        case OP_SELFBALANCE: {
          Operand Result = Builder.handleSelfBalance();
          push(Result);
          break;
        }

        case OP_BASEFEE: {
          Operand Result = Builder.handleBaseFee();
          push(Result);
          break;
        }

        case OP_BLOBHASH: {
          Operand Index = pop();
          Operand Result = Builder.handleBlobHash(Index);
          push(Result);
          break;
        }

        case OP_BLOBBASEFEE: {
          Operand Result = Builder.handleBlobBaseFee();
          push(Result);
          break;
        }

        case OP_MLOAD: {
          Operand Addr = pop();
          Operand Result = Builder.handleMLoad(Addr);
          push(Result);
          break;
        }

        case OP_MSTORE: {
          Operand Addr = pop();
          Operand Value = pop();
          Builder.handleMStore(Addr, Value);
          break;
        }

        case OP_MSTORE8: {
          Operand Addr = pop();
          Operand Value = pop();
          Builder.handleMStore8(Addr, Value);
          break;
        }

        case OP_SLOAD: {
          Operand Key = pop();
          Operand Result = Builder.handleSLoad(Key);
          push(Result);
          break;
        }

        case OP_SSTORE: {
          Operand Key = pop();
          Operand Value = pop();
          Builder.handleSStore(Key, Value);
          break;
        }

        case OP_MSIZE: {
          Operand Result = Builder.handleMSize();
          push(Result);
          break;
        }

        case OP_TLOAD: {
          Operand Index = pop();
          Operand Result = Builder.handleTLoad(Index);
          push(Result);
          break;
        }

        case OP_TSTORE: {
          Operand Index = pop();
          Operand Value = pop();
          Builder.handleTStore(Index, Value);
          break;
        }

        case OP_MCOPY: {
          Operand DestAddr = pop();
          Operand SrcAddr = pop();
          Operand Length = pop();
          Builder.handleMCopy(DestAddr, SrcAddr, Length);
          break;
        }

        case OP_CREATE: {
          handleCreate();
          break;
        }

        case OP_CALL: {
          handleCallImpl(&IRBuilder::handleCall);
          break;
        }

        case OP_CALLCODE: {
          handleCallImpl(&IRBuilder::handleCallCode);
          break;
        }

        case OP_DELEGATECALL: {
          handleCallImplWithoutValue(&IRBuilder::handleDelegateCall);
          break;
        }

        case OP_CREATE2: {
          handleCreate2();
          break;
        }

        case OP_STATICCALL: {
          handleCallImplWithoutValue(&IRBuilder::handleStaticCall);
          break;
        }

        case OP_SELFDESTRUCT: {
          Operand Beneficiary = pop();
          Builder.handleSelfDestruct(Beneficiary);
          break;
        }

        // Control flow operations
        case OP_JUMP: {
          Operand Dest = pop();
          handleEndBlock();
          Builder.handleJump(Dest);
          InDeadCode = true;
          break;
        }

        case OP_JUMPI: {
          Operand Dest = pop();
          Operand Cond = pop();
          handleEndBlock();
          Builder.handleJumpI(Dest, Cond);
          break;
        }

        case OP_JUMPDEST: {
          InDeadCode = false;
          handleEndBlock();
          Builder.handleJumpDest(PC);
          Builder.meterOpcode(Opcode);
          break;
        }

        // Environment operations
        case OP_PC: {
          Operand Result = Builder.handlePC(PC);
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
          Operand MemOffset = pop();
          Operand Length = pop();
          handleEndBlock();
          Builder.handleReturn(MemOffset, Length);
          InDeadCode = true;
          break;
        }

        case OP_REVERT: {
          Operand OffsetOp = pop();
          Operand SizeOp = pop();
          handleEndBlock();
          Builder.handleRevert(OffsetOp, SizeOp);
          InDeadCode = true;
          break;
        }

        case OP_INVALID: {
          handleEndBlock();
          Builder.handleInvalid();
          InDeadCode = true;
          break;
        }

        default:
          throw getErrorWithExtraMessage(ErrorCode::UnsupportedOpcode,
                                         std::to_string(Opcode));
        }
        PC++; // offset 1 byte for opcode
      }
      if (!LastStop) {
        handleStop();
      }
    } catch (const common::Error &E) {
      int32_t ExitCode;
      switch (E.getCode()) {
      case common::ErrorCode::EVMStackOverflow:
        ExitCode = 6; // EVMC_STACK_OVERFLOW;
        break;
      case common::ErrorCode::EVMStackUnderflow:
        ExitCode = 7; // EVMC_STACK_UNDERFLOW;
        break;
      case common::ErrorCode::UnsupportedOpcode:
        ExitCode = 4; // EVMC_INVALID_INSTRUCTION;
        break;
      case common::ErrorCode::UnexpectedEnd:
        ExitCode = 4; // EVMC_INVALID_INSTRUCTION;
        break;
      default:
        ExitCode = 1; // EVMC_FAILURE;
      }
      // TODO: Store the abnormal state in the evmc_status_code type
      // for example, Ctx->setError(ExitCode);
      return false;
    }
    return true;
  }

  void handleBeginBlock() {
    //
  }

  void handleEndBlock() {
    // Save unused stack elements to runtime
    EvalStack ReverseStack;
    while (!Stack.empty()) {
      Operand Opnd = Stack.pop();
      ReverseStack.push(Opnd);
    }
    while (!ReverseStack.empty()) {
      Operand Opnd = ReverseStack.pop();
      Builder.stackPush(Opnd);
    }
    CurStackOffset = 0;
    MinStackOffset = 0;
    MaxStackOffset = 0;
  }

  void handleStop() { Builder.handleStop(); }

  template <BinaryOperator Opr> void handleBinaryArithmetic() {
    Operand LHS = pop();
    Operand RHS = pop();
    Operand Result = Builder.template handleBinaryArithmetic<Opr>(LHS, RHS);
    push(Result);
  }

  void handleMul() {
    Operand MultiplicandOp = pop();
    Operand MultiplierOp = pop();
    Operand Result = Builder.handleMul(MultiplicandOp, MultiplierOp);
    push(Result);
  }

  void handleDiv() {
    Operand DividendOp = pop();
    Operand DivisorOp = pop();
    Operand Result = Builder.handleDiv(DividendOp, DivisorOp);
    push(Result);
  }

  void handleSDiv() {
    Operand DividendOp = pop();
    Operand DivisorOp = pop();
    Operand Result = Builder.handleSDiv(DividendOp, DivisorOp);
    push(Result);
  }

  void handleMod() {
    Operand DividendOp = pop();
    Operand DivisorOp = pop();
    Operand Result = Builder.handleMod(DividendOp, DivisorOp);
    push(Result);
  }

  void handleSMod() {
    Operand DividendOp = pop();
    Operand DivisorOp = pop();
    Operand Result = Builder.handleSMod(DividendOp, DivisorOp);
    push(Result);
  }

  void handleAddMod() {
    Operand AugendOp = pop();
    Operand AddendOp = pop();
    Operand ModulusOp = pop();
    Operand Result = Builder.handleAddMod(AugendOp, AddendOp, ModulusOp);
    push(Result);
  }

  void handleMulMod() {
    Operand MultiplicandOp = pop();
    Operand MultiplierOp = pop();
    Operand ModulusOp = pop();
    Operand Result =
        Builder.handleMulMod(MultiplicandOp, MultiplierOp, ModulusOp);
    push(Result);
  }

  void handleExp() {
    Operand BaseOp = pop();
    Operand ExponentOp = pop();
    Operand Result = Builder.handleExp(BaseOp, ExponentOp);
    push(Result);
  }

  template <CompareOperator Opr> void handleCompare() {
    Operand CmpLHS = pop();
    Operand CmpRHS = (Opr != CompareOperator::CO_EQZ) ? pop() : Operand();
    Operand Result = Builder.template handleCompareOp<Opr>(CmpLHS, CmpRHS);
    push(Result);
  }

  template <BinaryOperator Opr> void handleBitwiseOp() {
    Operand LHS = pop();
    Operand RHS = pop();
    Operand Result = Builder.template handleBitwiseOp<Opr>(LHS, RHS);
    push(Result);
  }

  void handleNot() {
    Operand Opnd = pop();
    Operand Result = Builder.handleNot(Opnd);
    push(Result);
  }

  void handleSignextend() {
    Operand IndexOp = pop();
    Operand ValueOp = pop();
    Operand Result = Builder.handleSignextend(IndexOp, ValueOp);
    push(Result);
  }

  void handleByte() {
    Operand IndexOp = pop();
    Operand ValueOp = pop();
    Operand Result = Builder.handleByte(IndexOp, ValueOp);
    push(Result);
  }

  template <BinaryOperator Opr> void handleShift() {
    Operand ShiftOp = pop();
    Operand ValueOp = pop();
    Operand Result = Builder.template handleShift<Opr>(ShiftOp, ValueOp);
    push(Result);
  }

  void handlePush(uint8_t NumBytes) {
    Bytes Data = readBytes(NumBytes);
    Operand Result = Builder.handlePush(Data);
    push(Result);
  }

  Bytes readBytes(uint8_t Count) {
    // offset 1 byte for opcode
    if (PC + 1 + Count > Ctx->getBytecodeSize()) {
      throw getError(common::ErrorCode::UnexpectedEnd);
    }
    const Byte *Bytecode = Ctx->getBytecode();
    Bytes Result(Bytecode + PC + 1, Count);
    PC += Count;
    return Result;
  }

  // DUP1-DUP16: Duplicate Nth stack item
  void handleDup(uint8_t Index) {
    Operand Result;
    if (Stack.getSize() < static_cast<uint32_t>(Index)) {
      int32_t MemIndex = static_cast<int32_t>(Index) - Stack.getSize() - 1;
      Result = Builder.stackGet(MemIndex);
    } else {
      Result = Stack.peek(Index - 1);
    }
    push(Result);
  }

  // POP: Remove top stack item
  Operand handlePop() {
    Operand Result = pop();
    return Result;
  }

  // SWAP1-SWAP16: Swap top with Nth+1 stack item
  void handleSwap(uint8_t Index) {
    int32_t MemIndex = static_cast<int32_t>(Index) - Stack.getSize();
    if (Stack.empty()) {
      Operand A = Builder.stackGet(0);
      Operand B = Builder.stackGet(MemIndex);
      Builder.stackSet(0, B);
      Builder.stackSet(MemIndex, A);
    } else if (Stack.getSize() < static_cast<uint32_t>(Index) + 1u) {
      Operand &A = Stack.peek(0);
      Operand B = Builder.stackGet(MemIndex);
      Builder.stackSet(MemIndex, A);
      A = B;
    } else {
      std::swap(Stack.peek(0), Stack.peek(Index));
    }
  }

  // ==================== Environment Instruction Handlers ====================

  // LOG0-LOG4: Emit log with 0-4 topics
  void handleLog(uint8_t NumTopics) {
    Operand OffsetOp = pop();
    Operand SizeOp = pop();
    std::array<Operand, 4> Topics{};

    for (int i = 0; i < NumTopics && i < 4; ++i) {
      Topics[i] = pop();
    }

    // TODO: currently, LOG will crash in fibonacci test
    // Builder.handleLog(OffsetOp, SizeOp, Topics[0], Topics[1], Topics[2],
    //                   Topics[3], NumTopics);
  }

  void handleCreate() {
    Operand ValueOp = pop();
    Operand OffsetOp = pop();
    Operand SizeOp = pop();
    Operand RetAddrOp = Builder.handleCreate(ValueOp, OffsetOp, SizeOp);
    push(RetAddrOp);
  }

  void handleCreate2() {
    Operand ValueOp = pop();
    Operand OffsetOp = pop();
    Operand SizeOp = pop();
    Operand SaltOp = pop();
    Operand RetAddrOp =
        Builder.handleCreate2(ValueOp, OffsetOp, SizeOp, SaltOp);
    push(RetAddrOp);
  }

  // template for call/callcode
  template <typename CallHandler> void handleCallImpl(CallHandler handler) {
    Operand GasOp = pop();
    Operand ToAddrOp = pop();
    Operand ValueOp = pop();
    Operand ArgsOffsetOp = pop();
    Operand ArgsSizeOp = pop();
    Operand RetOffsetOp = pop();
    Operand RetSizeOp = pop();
    Operand StatusOp =
        (Builder.*handler)(GasOp, ToAddrOp, ValueOp, ArgsOffsetOp, ArgsSizeOp,
                           RetOffsetOp, RetSizeOp);
    push(StatusOp);
  }

  // template for delegatecall/staticcall
  template <typename CallHandler>
  void handleCallImplWithoutValue(CallHandler handler) {
    Operand GasOp = pop();
    Operand ToAddrOp = pop();
    Operand ArgsOffsetOp = pop();
    Operand ArgsSizeOp = pop();
    Operand RetOffsetOp = pop();
    Operand RetSizeOp = pop();
    Operand StatusOp = (Builder.*handler)(GasOp, ToAddrOp, ArgsOffsetOp,
                                          ArgsSizeOp, RetOffsetOp, RetSizeOp);
    push(StatusOp);
  }

  IRBuilder &Builder;
  CompilerContext *Ctx;
  EvalStack Stack;
  bool InDeadCode = false;
  // Min and max stack offset within a block
  int32_t MinStackOffset = 0;
  int32_t MaxStackOffset = 0;
  int32_t CurStackOffset = 0;
  uint64_t PC = 0;
};

} // namespace COMPILER

#endif // ZEN_ACTION_EVM_BYTECODE_VISITOR_H
