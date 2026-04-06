// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_ACTION_EVM_BYTECODE_VISITOR_H
#define ZEN_ACTION_EVM_BYTECODE_VISITOR_H

#include "compiler/evm_frontend/evm_analyzer.h"
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

  struct BlockConstPrecheckPlan {
    bool Eligible = false;
    uint64_t MaxRequiredSize = 0;
    uint64_t CoveredDirectOps = 0;
  };

  struct BlockLinearPrecheckPlan {
    bool Eligible = false;
    evmc_opcode CoveredOpcode = OP_STOP;
    uint64_t AccessWidth = 0;
    uint64_t CoveredDirectOps = 0;
    uint8_t StrideStackIndex = 0;
  };

  struct AbstractConstU64 {
    bool Known = false;
    uint64_t Value = 0;
  };

  void push(const Operand &Opnd) { Stack.push(Opnd); }

  Operand pop() {
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
      EVMAnalyzer Analyzer(Ctx->getRevision());
      Analyzer.analyze(Bytecode, BytecodeSize);

      const uint8_t *Ip = Bytecode;
      const bool StartsWithJumpDest =
          BytecodeSize > 0 &&
          static_cast<evmc_opcode>(Bytecode[0]) == OP_JUMPDEST;
      if (!StartsWithJumpDest) {
        handleBeginBlock(Analyzer);
      }
      const uint8_t *IpEnd = Bytecode + BytecodeSize;

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
        if (!IsJumpDest) {
          if (!Builder.isOpcodeDefined(Opcode)) {
#ifdef ZEN_ENABLE_JIT_FALLBACK_TEST
            // For testing purposes, we can use 0xEE as a FALLBACK trigger
            // In a real scenario, this would call the runtime's handleUndefined
            // function When testing is enabled, treat 0xEE opcodes as fallback
            // triggers
            if (Opcode == 0xee) {
              handleEndBlock();
              PC++;
              Builder.fallbackToInterpreter(
                  PC); // Continue from next instruction
              continue;
            }
#endif
            handleEndBlock();
            Builder.handleUndefined();
            PC++;
            continue;
          }
          Builder.meterOpcode(Opcode, PC);
        }

        switch (Opcode) {
        case OP_STOP:
          handleEndBlock();
          handleStop();
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
        case OP_CLZ:
          handleClz();
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
          Builder.noteHelperOpcodeInBlock(Opcode, PC);
          uint8_t NumTopics = Opcode - OP_LOG0;
          handleLog(NumTopics);
          break;
        }

        case OP_KECCAK256: {
          Builder.noteHelperOpcodeInBlock(Opcode, PC);
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
          Builder.noteHelperOpcodeInBlock(Opcode, PC);
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
          Builder.noteHelperOpcodeInBlock(Opcode, PC);
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
          Builder.noteHelperOpcodeInBlock(Opcode, PC);
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
          Builder.noteHelperOpcodeInBlock(Opcode, PC);
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
          Builder.noteMemoryOpcodeInBlock(Opcode, PC);
          maybePrepareLinearBlockMemoryPrecheck(Opcode);
          Operand Addr = pop();
          Operand Result = Builder.handleMLoad(Addr);
          push(Result);
          break;
        }

        case OP_MSTORE: {
          Builder.noteMemoryOpcodeInBlock(Opcode, PC);
          maybePrepareLinearBlockMemoryPrecheck(Opcode);
          Operand Addr = pop();
          Operand Value = pop();
          Builder.handleMStore(Addr, Value);
          break;
        }

        case OP_MSTORE8: {
          Builder.noteMemoryOpcodeInBlock(Opcode, PC);
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
          Builder.noteMemoryOpcodeInBlock(Opcode, PC);
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
          Builder.noteMemoryOpcodeInBlock(Opcode, PC);
          Operand DestAddr = pop();
          Operand SrcAddr = pop();
          Operand Length = pop();
          Builder.handleMCopy(DestAddr, SrcAddr, Length);
          break;
        }

        case OP_CREATE: {
          Builder.noteHelperOpcodeInBlock(Opcode, PC);
          handleCreate();
          break;
        }

        case OP_CALL: {
          Builder.noteHelperOpcodeInBlock(Opcode, PC);
          handleCallImpl(&IRBuilder::handleCall);
          break;
        }

        case OP_CALLCODE: {
          Builder.noteHelperOpcodeInBlock(Opcode, PC);
          handleCallImpl(&IRBuilder::handleCallCode);
          break;
        }

        case OP_DELEGATECALL: {
          Builder.noteHelperOpcodeInBlock(Opcode, PC);
          handleCallImplWithoutValue(&IRBuilder::handleDelegateCall);
          break;
        }

        case OP_CREATE2: {
          Builder.noteHelperOpcodeInBlock(Opcode, PC);
          handleCreate2();
          break;
        }

        case OP_STATICCALL: {
          Builder.noteHelperOpcodeInBlock(Opcode, PC);
          handleCallImplWithoutValue(&IRBuilder::handleStaticCall);
          break;
        }

        case OP_SELFDESTRUCT: {
          Operand Beneficiary = pop();
          handleEndBlock();
          Builder.handleSelfDestruct(Beneficiary);
          handleStop();
          InDeadCode = true;
          break;
        }

        // Control flow operations
        case OP_JUMP: {
          Operand Dest = pop();
          handleEndBlock();
          Builder.handleJump(Dest);
          break;
        }

        case OP_JUMPI: {
          Operand Dest = pop();
          Operand Cond = pop();
          handleEndBlock();
          Builder.handleJumpI(Dest, Cond);
          handleBeginBlock(Analyzer);
          break;
        }

        case OP_JUMPDEST: {
          // Consecutive JUMPDEST opcodes share one body BB in multipass.
          // Charge all skipped metering points before jumping to the shared
          // destination at the end of the run.
          uint64_t RunStartPC = PC;
          while (Ip < IpEnd && static_cast<evmc_opcode>(*Ip) == OP_JUMPDEST) {
            Ip++;
            PC++;
          }
          if (PC > RunStartPC && !InDeadCode) {
            Builder.meterOpcodeRange(RunStartPC, PC);
          }
          handleEndBlock();
          Builder.handleJumpDest(PC);
          Builder.meterOpcode(Opcode, PC);
          handleBeginBlock(Analyzer);
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
          break;
        }

        case OP_REVERT: {
          Operand OffsetOp = pop();
          Operand SizeOp = pop();
          handleEndBlock();
          Builder.handleRevert(OffsetOp, SizeOp);
          break;
        }

        case OP_INVALID: {
          handleEndBlock();
          Builder.handleInvalid();
          break;
        }

        default:
          // Treat as undefined
          handleEndBlock();
          Builder.handleUndefined();
        }
        PC++; // offset 1 byte for opcode
      }
      if (!InDeadCode) {
        handleStop();
      }
    } catch (const common::Error &E) {
      ZEN_UNREACHABLE();
      return false;
    }
    return true;
  }

  void handleBeginBlock(EVMAnalyzer &Analyzer) {
    const auto &BlockInfos = Analyzer.getBlockInfos();
    ZEN_ASSERT(BlockInfos.count(PC) > 0 && "Block info not found");
    Builder.beginMemoryCompileBlock(PC);
    CurBlockLinearPrecheckPlan = BlockLinearPrecheckPlan();
    const Byte *Bytecode = Ctx->getBytecode();
    size_t BytecodeSize = Ctx->getBytecodeSize();
    BlockConstPrecheckPlan PrecheckPlan =
        analyzeConstDirectMemoryBlockPrecheck(Bytecode, BytecodeSize, PC);
    if (PrecheckPlan.Eligible) {
      Builder.setMemoryCompileBlockConstPrecheckPlan(
          PrecheckPlan.MaxRequiredSize, PrecheckPlan.CoveredDirectOps);
    } else {
      CurBlockLinearPrecheckPlan =
          analyzeLinearDirectMemoryBlockPrecheck(Bytecode, BytecodeSize, PC);
      if (CurBlockLinearPrecheckPlan.Eligible) {
        Builder.setMemoryCompileBlockLinearPrecheckPlan(
            CurBlockLinearPrecheckPlan.AccessWidth,
            CurBlockLinearPrecheckPlan.CoveredDirectOps,
            CurBlockLinearPrecheckPlan.CoveredOpcode == OP_MSTORE);
      }
    }
    const auto &BlockInfo = BlockInfos.at(PC);
    if (BlockInfo.HasUndefinedInstr) {
      Builder.handleUndefined();
      InDeadCode = true;
      return;
    }
    if (static_cast<size_t>(-BlockInfo.MinStackHeight) > EVM_MAX_STACK_SIZE) {
      Builder.handleTrap(common::ErrorCode::EVMStackUnderflow);
      InDeadCode = true;
      return;
    }
    if (static_cast<size_t>(BlockInfo.MaxStackHeight) > EVM_MAX_STACK_SIZE) {
      Builder.handleTrap(common::ErrorCode::EVMStackOverflow);
      InDeadCode = true;
      return;
    }
    InDeadCode = false;
    Builder.createStackCheckBlock(-BlockInfo.MinStackHeight,
                                  1024 - BlockInfo.MaxStackHeight);
    int32_t TotalPopSize = -BlockInfo.MinPopHeight;
    EvalStack ReverseStack;
    while (TotalPopSize > 0) {
      ReverseStack.push(Builder.stackPop());
      TotalPopSize--;
    }
    while (!ReverseStack.empty()) {
      Operand Opnd = ReverseStack.pop();
      Stack.push(Opnd);
    }
  }

  void handleEndBlock() {
    Builder.endMemoryCompileBlock();
    CurBlockLinearPrecheckPlan = BlockLinearPrecheckPlan();
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
    InDeadCode = true;
  }

  void handleStop() { Builder.handleStop(); }

  static bool isHelperSensitiveOpcode(evmc_opcode Opcode) {
    switch (Opcode) {
    case OP_LOG0:
    case OP_LOG1:
    case OP_LOG2:
    case OP_LOG3:
    case OP_LOG4:
    case OP_KECCAK256:
    case OP_CALLDATACOPY:
    case OP_CODECOPY:
    case OP_EXTCODECOPY:
    case OP_RETURNDATACOPY:
    case OP_CREATE:
    case OP_CALL:
    case OP_CALLCODE:
    case OP_DELEGATECALL:
    case OP_CREATE2:
    case OP_STATICCALL:
      return true;
    default:
      return false;
    }
  }

  static bool isBlockTerminatorOpcode(evmc_opcode Opcode) {
    return Opcode == OP_JUMP || Opcode == OP_JUMPI || Opcode == OP_RETURN ||
           Opcode == OP_STOP || Opcode == OP_INVALID || Opcode == OP_REVERT ||
           Opcode == OP_SELFDESTRUCT;
  }

  static AbstractConstU64 makeUnknownConstU64() { return {}; }

  static AbstractConstU64 makeKnownConstU64(uint64_t Value) {
    return AbstractConstU64{true, Value};
  }

  static bool addConstU64(uint64_t LHS, uint64_t RHS, uint64_t &Result) {
    if (UINT64_MAX - LHS < RHS) {
      return false;
    }
    Result = LHS + RHS;
    return true;
  }

  static bool parsePushConstU64(const Byte *Bytecode, size_t BytecodeSize,
                                uint64_t ImmediatePC, uint8_t NumBytes,
                                uint64_t &Value) {
    Value = 0;
    if (NumBytes > 8) {
      return false;
    }
    if (ImmediatePC + NumBytes > BytecodeSize) {
      return false;
    }
    for (uint8_t I = 0; I < NumBytes; ++I) {
      Value = (Value << 8) | static_cast<uint64_t>(std::to_integer<uint8_t>(
                                 Bytecode[ImmediatePC + I]));
    }
    return true;
  }

  static bool consumeExpectedOpcode(const Byte *Bytecode, size_t BytecodeSize,
                                    uint64_t &ScanPC,
                                    evmc_opcode ExpectedOpcode) {
    if (ScanPC >= BytecodeSize ||
        static_cast<evmc_opcode>(Bytecode[ScanPC]) != ExpectedOpcode) {
      return false;
    }
    ++ScanPC;
    return true;
  }

  static bool consumeZeroPush(const Byte *Bytecode, size_t BytecodeSize,
                              uint64_t &ScanPC) {
    if (ScanPC >= BytecodeSize) {
      return false;
    }

    evmc_opcode Opcode = static_cast<evmc_opcode>(Bytecode[ScanPC]);
    if (Opcode == OP_PUSH0) {
      ++ScanPC;
      return true;
    }

    if (Opcode < OP_PUSH1 || Opcode > OP_PUSH8) {
      return false;
    }

    const uint8_t NumBytes =
        static_cast<uint8_t>(Opcode) - static_cast<uint8_t>(OP_PUSH0);
    uint64_t Value = 0;
    if (!parsePushConstU64(Bytecode, BytecodeSize, ScanPC + 1, NumBytes,
                           Value) ||
        Value != 0) {
      return false;
    }

    ScanPC += static_cast<uint64_t>(1 + NumBytes);
    return true;
  }

  static bool consumeLinearRecurrencePrefix(const Byte *Bytecode,
                                            size_t BytecodeSize,
                                            uint64_t EntryPC,
                                            uint64_t &ScanPC) {
    ScanPC = EntryPC;
    if (ScanPC < BytecodeSize &&
        static_cast<evmc_opcode>(Bytecode[ScanPC]) == OP_JUMPDEST) {
      ++ScanPC;
    }

    return consumeZeroPush(Bytecode, BytecodeSize, ScanPC) &&
           consumeExpectedOpcode(Bytecode, BytecodeSize, ScanPC,
                                 OP_CALLDATALOAD) &&
           consumeZeroPush(Bytecode, BytecodeSize, ScanPC);
  }

  BlockLinearPrecheckPlan analyzeLinearMloadDirectMemoryBlockPrecheck(
      const Byte *Bytecode, size_t BytecodeSize, uint64_t EntryPC) {
    uint64_t ScanPC = 0;
    if (!consumeLinearRecurrencePrefix(Bytecode, BytecodeSize, EntryPC,
                                       ScanPC)) {
      return {};
    }

    uint64_t CoveredDirectOps = 0;
    while (ScanPC < BytecodeSize) {
      evmc_opcode Opcode = static_cast<evmc_opcode>(Bytecode[ScanPC]);
      if (Opcode == OP_JUMPDEST || isBlockTerminatorOpcode(Opcode)) {
        break;
      }

      uint64_t MotifPC = ScanPC;
      if (!consumeExpectedOpcode(Bytecode, BytecodeSize, MotifPC, OP_DUP1) ||
          !consumeExpectedOpcode(Bytecode, BytecodeSize, MotifPC, OP_MLOAD) ||
          !consumeExpectedOpcode(Bytecode, BytecodeSize, MotifPC, OP_POP) ||
          !consumeExpectedOpcode(Bytecode, BytecodeSize, MotifPC, OP_DUP2) ||
          !consumeExpectedOpcode(Bytecode, BytecodeSize, MotifPC, OP_ADD)) {
        return {};
      }

      ++CoveredDirectOps;
      ScanPC = MotifPC;
    }

    if (CoveredDirectOps < 2) {
      return {};
    }

    BlockLinearPrecheckPlan Plan;
    Plan.Eligible = true;
    Plan.CoveredOpcode = OP_MLOAD;
    Plan.AccessWidth = 32;
    Plan.CoveredDirectOps = CoveredDirectOps;
    Plan.StrideStackIndex = 2;
    return Plan;
  }

  BlockLinearPrecheckPlan analyzeLinearMstoreDirectMemoryBlockPrecheck(
      const Byte *Bytecode, size_t BytecodeSize, uint64_t EntryPC) {
    uint64_t ScanPC = 0;
    if (!consumeLinearRecurrencePrefix(Bytecode, BytecodeSize, EntryPC,
                                       ScanPC)) {
      return {};
    }

    uint64_t CoveredDirectOps = 0;
    while (ScanPC < BytecodeSize) {
      evmc_opcode Opcode = static_cast<evmc_opcode>(Bytecode[ScanPC]);
      if (Opcode == OP_JUMPDEST || isBlockTerminatorOpcode(Opcode)) {
        break;
      }

      uint64_t MotifPC = ScanPC;
      if (!consumeExpectedOpcode(Bytecode, BytecodeSize, MotifPC, OP_DUP1) ||
          !consumeExpectedOpcode(Bytecode, BytecodeSize, MotifPC, OP_DUP1) ||
          !consumeExpectedOpcode(Bytecode, BytecodeSize, MotifPC, OP_MSTORE) ||
          !consumeExpectedOpcode(Bytecode, BytecodeSize, MotifPC, OP_DUP2) ||
          !consumeExpectedOpcode(Bytecode, BytecodeSize, MotifPC, OP_ADD)) {
        return {};
      }

      ++CoveredDirectOps;
      ScanPC = MotifPC;
    }

    if (CoveredDirectOps < 2) {
      return {};
    }

    BlockLinearPrecheckPlan Plan;
    Plan.Eligible = true;
    Plan.CoveredOpcode = OP_MSTORE;
    Plan.AccessWidth = 32;
    Plan.CoveredDirectOps = CoveredDirectOps;
    Plan.StrideStackIndex = 3;
    return Plan;
  }

  BlockLinearPrecheckPlan analyzeLinearDirectMemoryBlockPrecheck(
      const Byte *Bytecode, size_t BytecodeSize, uint64_t EntryPC) {
    BlockLinearPrecheckPlan Plan = analyzeLinearMloadDirectMemoryBlockPrecheck(
        Bytecode, BytecodeSize, EntryPC);
    if (Plan.Eligible) {
      return Plan;
    }
    return analyzeLinearMstoreDirectMemoryBlockPrecheck(Bytecode, BytecodeSize,
                                                        EntryPC);
  }

  void maybePrepareLinearBlockMemoryPrecheck(evmc_opcode Opcode) {
    if (!CurBlockLinearPrecheckPlan.Eligible ||
        CurBlockLinearPrecheckPlan.CoveredOpcode != Opcode ||
        Stack.getSize() <= CurBlockLinearPrecheckPlan.StrideStackIndex) {
      return;
    }
    Builder.prepareLinearBlockMemoryPrecheck(
        Stack.peek(CurBlockLinearPrecheckPlan.StrideStackIndex));
  }

  BlockConstPrecheckPlan
  analyzeConstDirectMemoryBlockPrecheck(const Byte *Bytecode,
                                        size_t BytecodeSize, uint64_t EntryPC) {
    BlockConstPrecheckPlan Plan;
    std::vector<AbstractConstU64> SimStack;
    bool SawDirectMemory = false;

    for (uint64_t ScanPC = EntryPC; ScanPC < BytecodeSize; ++ScanPC) {
      evmc_opcode Opcode = static_cast<evmc_opcode>(Bytecode[ScanPC]);
      if (ScanPC != EntryPC && Opcode == OP_JUMPDEST) {
        break;
      }
      if (isHelperSensitiveOpcode(Opcode)) {
        return {};
      }

      switch (Opcode) {
      case OP_JUMPDEST:
        break;
      case OP_PUSH0: {
        SimStack.push_back(makeKnownConstU64(0));
        break;
      }
      case OP_PUSH1:
      case OP_PUSH2:
      case OP_PUSH3:
      case OP_PUSH4:
      case OP_PUSH5:
      case OP_PUSH6:
      case OP_PUSH7:
      case OP_PUSH8: {
        uint8_t NumBytes =
            static_cast<uint8_t>(Opcode) - static_cast<uint8_t>(OP_PUSH0);
        uint64_t Value = 0;
        if (!parsePushConstU64(Bytecode, BytecodeSize, ScanPC + 1, NumBytes,
                               Value)) {
          return {};
        }
        SimStack.push_back(makeKnownConstU64(Value));
        ScanPC += NumBytes;
        break;
      }
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
        uint8_t NumBytes =
            static_cast<uint8_t>(Opcode) - static_cast<uint8_t>(OP_PUSH0);
        if (NumBytes > BytecodeSize - ScanPC) {
          return {};
        }
        ScanPC += NumBytes;
        SimStack.push_back(makeUnknownConstU64());
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
        uint8_t Index =
            static_cast<uint8_t>(Opcode) - static_cast<uint8_t>(OP_DUP1) + 1;
        if (SimStack.size() < Index) {
          return {};
        }
        SimStack.push_back(SimStack[SimStack.size() - Index]);
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
        uint8_t Index =
            static_cast<uint8_t>(Opcode) - static_cast<uint8_t>(OP_SWAP1) + 1;
        if (SimStack.size() <= Index) {
          return {};
        }
        std::swap(SimStack.back(), SimStack[SimStack.size() - Index - 1]);
        break;
      }
      case OP_POP: {
        if (SimStack.empty()) {
          return {};
        }
        SimStack.pop_back();
        break;
      }
      case OP_ADD: {
        if (SimStack.size() < 2) {
          return {};
        }
        AbstractConstU64 LHS = SimStack.back();
        SimStack.pop_back();
        AbstractConstU64 RHS = SimStack.back();
        SimStack.pop_back();
        uint64_t Sum = 0;
        if (LHS.Known && RHS.Known && addConstU64(LHS.Value, RHS.Value, Sum)) {
          SimStack.push_back(makeKnownConstU64(Sum));
        } else {
          SimStack.push_back(makeUnknownConstU64());
        }
        break;
      }
      case OP_SUB: {
        if (SimStack.size() < 2) {
          return {};
        }
        AbstractConstU64 LHS = SimStack.back();
        SimStack.pop_back();
        AbstractConstU64 RHS = SimStack.back();
        SimStack.pop_back();
        if (LHS.Known && RHS.Known && LHS.Value >= RHS.Value) {
          SimStack.push_back(makeKnownConstU64(LHS.Value - RHS.Value));
        } else {
          SimStack.push_back(makeUnknownConstU64());
        }
        break;
      }
      case OP_MLOAD: {
        if (SimStack.empty()) {
          return {};
        }
        AbstractConstU64 Addr = SimStack.back();
        SimStack.pop_back();
        if (!Addr.Known) {
          return {};
        }
        uint64_t RequiredSize = 0;
        if (!addConstU64(Addr.Value, 32, RequiredSize)) {
          return {};
        }
        Plan.MaxRequiredSize = std::max(Plan.MaxRequiredSize, RequiredSize);
        Plan.CoveredDirectOps++;
        SawDirectMemory = true;
        SimStack.push_back(makeUnknownConstU64());
        break;
      }
      case OP_MSTORE: {
        if (SimStack.size() < 2) {
          return {};
        }
        AbstractConstU64 Addr = SimStack.back();
        SimStack.pop_back();
        SimStack.pop_back();
        if (!Addr.Known) {
          return {};
        }
        uint64_t RequiredSize = 0;
        if (!addConstU64(Addr.Value, 32, RequiredSize)) {
          return {};
        }
        Plan.MaxRequiredSize = std::max(Plan.MaxRequiredSize, RequiredSize);
        Plan.CoveredDirectOps++;
        SawDirectMemory = true;
        break;
      }
      case OP_MSTORE8: {
        if (SimStack.size() < 2) {
          return {};
        }
        AbstractConstU64 Addr = SimStack.back();
        SimStack.pop_back();
        SimStack.pop_back();
        if (!Addr.Known) {
          return {};
        }
        uint64_t RequiredSize = 0;
        if (!addConstU64(Addr.Value, 1, RequiredSize)) {
          return {};
        }
        Plan.MaxRequiredSize = std::max(Plan.MaxRequiredSize, RequiredSize);
        Plan.CoveredDirectOps++;
        SawDirectMemory = true;
        break;
      }
      case OP_MSIZE:
        SimStack.push_back(makeUnknownConstU64());
        break;
      default:
        if (isBlockTerminatorOpcode(Opcode)) {
          ScanPC = BytecodeSize;
          break;
        }
        return {};
      }
    }

    Plan.Eligible = SawDirectMemory && Plan.CoveredDirectOps >= 2;
    return Plan;
  }

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

  void handleClz() {
    Operand Opnd = pop();
    Operand Result = Builder.handleClz(Opnd);
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
    const Byte *Bytecode = Ctx->getBytecode();
    uint64_t Start = PC + 1;
    uint64_t BytecodeSize = Ctx->getBytecodeSize();
    uint64_t Available = (Start < BytecodeSize) ? (BytecodeSize - Start) : 0;
    uint64_t ReadCount = (Count < Available) ? Count : Available;

    Bytes Result = ReadCount > 0
                       ? Bytes(Bytecode + Start, static_cast<size_t>(ReadCount))
                       : Bytes();
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

  template <size_t NumTopics> void handleLogImpl() {
    ZEN_STATIC_ASSERT(NumTopics <= 4);
    Operand OffsetOp = pop();
    Operand SizeOp = pop();

    if constexpr (NumTopics == 0) {
      Builder.template handleLogWithTopics<0>(OffsetOp, SizeOp);
    } else {
      std::array<Operand, NumTopics> Topics;
      for (size_t i = 0; i < NumTopics; ++i) {
        Topics[i] = pop();
      }

      if constexpr (NumTopics == 1) {
        Builder.template handleLogWithTopics<1>(OffsetOp, SizeOp, Topics[0]);
      } else if constexpr (NumTopics == 2) {
        Builder.template handleLogWithTopics<2>(OffsetOp, SizeOp, Topics[0],
                                                Topics[1]);
      } else if constexpr (NumTopics == 3) {
        Builder.template handleLogWithTopics<3>(OffsetOp, SizeOp, Topics[0],
                                                Topics[1], Topics[2]);
      } else { // NumTopics == 4
        Builder.template handleLogWithTopics<4>(
            OffsetOp, SizeOp, Topics[0], Topics[1], Topics[2], Topics[3]);
      }
    }
  }

  void handleLog(uint8_t NumTopics) {
    switch (NumTopics) {
    case 0:
      handleLogImpl<0>();
      break;
    case 1:
      handleLogImpl<1>();
      break;
    case 2:
      handleLogImpl<2>();
      break;
    case 3:
      handleLogImpl<3>();
      break;
    case 4:
      handleLogImpl<4>();
      break;
    default:
      ZEN_UNREACHABLE();
    }
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
  BlockLinearPrecheckPlan CurBlockLinearPrecheckPlan;
  bool InDeadCode = false;
  uint64_t PC = 0;
};

} // namespace COMPILER

#endif // ZEN_ACTION_EVM_BYTECODE_VISITOR_H
