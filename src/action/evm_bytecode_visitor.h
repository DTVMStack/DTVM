// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_ACTION_EVM_BYTECODE_VISITOR_H
#define ZEN_ACTION_EVM_BYTECODE_VISITOR_H

#include "compiler/evm_frontend/evm_analyzer.h"
#include "compiler/evm_frontend/evm_lifted_stack_lifter.h"
#include "compiler/evm_frontend/evm_memory_analysis.h"
#include "compiler/evm_frontend/evm_memory_facts.h"
#include "compiler/evm_frontend/evm_mir_compiler.h"
#include "evmc/evmc.h"
#include "evmc/instructions.h"
#include "runtime/evm_module.h"

#include <array>
#include <map>
#include <type_traits>
#include <utility>
#include <vector>

namespace COMPILER {

template <typename IRBuilder> class EVMByteCodeVisitor {
  typedef typename IRBuilder::CompilerContext CompilerContext;
  typedef typename IRBuilder::Operand Operand;
  typedef zen::action::VMEvalStack<Operand> EvalStack;
  using StackLifterType = EVMLiftedStackLifter<IRBuilder>;
  using MergeMaterializationRequest =
      typename StackLifterType::MergeMaterializationRequest;
  using Byte = zen::common::Byte;
  using Bytes = zen::common::Bytes;

public:
  EVMByteCodeVisitor(IRBuilder &Builder, CompilerContext *Ctx)
      : Builder(Builder), Ctx(Ctx), StackLifter(Builder) {
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
  static constexpr size_t EVM_MAX_PUSH_IMMEDIATE_SIZE = 32;

  struct BlockConstPrecheckPlan {
    bool Eligible = false;
    uint64_t MaxRequiredSize = 0;
    uint64_t CoveredDirectOps = 0;
    std::vector<uint64_t> WordStoreOffsets;
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

  struct LargeStaticWorkspaceVerifierResult {
    uint64_t Candidates = 0;
    uint64_t VerifiedSegments = 0;
    uint64_t VerifiedOps = 0;
    uint64_t VerifiedMLoadOps = 0;
    uint64_t VerifiedMStoreOps = 0;
    uint64_t VerifiedMStore8Ops = 0;
    uint64_t MaxRequiredSize = 0;
    uint64_t Rejected = 0;
    uint64_t RejectDynamicOffset = 0;
    uint64_t RejectUnknownBase = 0;
    uint64_t RejectUnboundedInterval = 0;
    uint64_t RejectOverflowRisk = 0;
    uint64_t RejectSideEffect = 0;
    uint64_t RejectHelperByteExactRisk = 0;
    uint64_t RejectTooFewOps = 0;
    bool HasLoweringPlan = false;
    uint64_t LoweringFirstPC = 0;
    uint64_t LoweringLastPC = 0;
    uint64_t LoweringMaxRequiredSize = 0;
    uint64_t LoweringCoveredOps = 0;
    uint64_t LoweringCoveredMLoadOps = 0;
    uint64_t LoweringCoveredMStoreOps = 0;
    uint64_t LoweringCoveredMStore8Ops = 0;
  };

  template <typename T, typename = void>
  struct HasRegisterCurrentBlockPC : std::false_type {};
  template <typename T>
  struct HasRegisterCurrentBlockPC<
      T, std::void_t<decltype(std::declval<T &>().registerCurrentBlockPC(
             uint64_t{}))>> : std::true_type {};

  template <typename T, typename = void>
  struct HasSpillTrackedStackPreservingPrefix : std::false_type {};
  template <typename T>
  struct HasSpillTrackedStackPreservingPrefix<
      T, std::void_t<
             decltype(std::declval<T &>().spillTrackedStackPreservingPrefix(
                 std::declval<const std::vector<Operand> &>(), uint32_t{}))>>
      : std::true_type {};

  template <typename T, typename = void>
  struct HasMaterializeStackMergeOperand : std::false_type {};
  template <typename T>
  struct HasMaterializeStackMergeOperand<
      T,
      std::void_t<decltype(std::declval<T &>().materializeStackMergeOperand(
          std::declval<const std::vector<uint64_t> &>(),
          std::declval<const std::vector<std::pair<uint64_t, Operand>> &>()))>>
      : std::true_type {};

  template <typename T, typename = void>
  struct HasSetMemoryFacts : std::false_type {};
  template <typename T>
  struct HasSetMemoryFacts<
      T, std::void_t<decltype(std::declval<T &>().setMemoryFacts(
             std::declval<const MemoryFacts &>()))>> : std::true_type {};

  template <typename T, typename = void>
  struct HasBeginMemoryCompileBlockWithBodyEnd : std::false_type {};
  template <typename T>
  struct HasBeginMemoryCompileBlockWithBodyEnd<
      T, std::void_t<decltype(std::declval<T &>().beginMemoryCompileBlock(
             uint64_t{}, uint64_t{}))>> : std::true_type {};

  void setMemoryFactsCompat() {
    if constexpr (HasSetMemoryFacts<IRBuilder>::value) {
      Builder.setMemoryFacts(MemoryFacts.getFacts());
    }
  }

  void buildMemoryFacts(const EVMAnalyzer &Analyzer, const uint8_t *Bytecode,
                        size_t BytecodeSize) {
    MemoryFacts.reset();
    MemoryEntryAddressAnalysis EntryAddresses(Analyzer, Bytecode, BytecodeSize);
    const auto &BlockInfos = Analyzer.getBlockInfos();

    for (const auto &[EntryPC, BlockInfo] : BlockInfos) {
      const int32_t EntryDepth = std::max(BlockInfo.ResolvedEntryStackDepth, 0);
      std::vector<MemoryEntryValue> EntryValues = EntryAddresses.getEntryValues(
          EntryPC, static_cast<uint32_t>(EntryDepth));
      MemoryFacts.beginBlock(EntryPC, BlockInfo.BodyStartPC,
                             BlockInfo.BodyEndPC, EntryValues,
                             BlockInfo.Successors, BlockInfo.Predecessors);

      size_t ScanPC = static_cast<size_t>(BlockInfo.BodyStartPC);
      const size_t EndPC = std::min<size_t>(BlockInfo.BodyEndPC, BytecodeSize);
      while (ScanPC < EndPC) {
        evmc_opcode Opcode = static_cast<evmc_opcode>(Bytecode[ScanPC]);
        MemoryFacts.observeOpcode(Opcode, static_cast<uint64_t>(ScanPC),
                                  Bytecode, BytecodeSize);
        ++ScanPC;
        if (Opcode >= OP_PUSH0 && Opcode <= OP_PUSH32) {
          ScanPC +=
              static_cast<uint8_t>(Opcode) - static_cast<uint8_t>(OP_PUSH0);
        }
      }
    }
    MemoryFacts.endBlock();
  }

  void beginMemoryCompileBlockCompat(uint64_t EntryPC, uint64_t BodyEndPC) {
    if constexpr (HasBeginMemoryCompileBlockWithBodyEnd<IRBuilder>::value) {
      Builder.beginMemoryCompileBlock(EntryPC, BodyEndPC);
    } else {
      (void)BodyEndPC;
      Builder.beginMemoryCompileBlock(EntryPC);
    }
  }

  template <typename T, typename = void>
  struct HasHandleJumpWithCandidates : std::false_type {};
  template <typename T>
  struct HasHandleJumpWithCandidates<
      T, std::void_t<decltype(std::declval<T &>().handleJump(
             std::declval<Operand>(),
             std::declval<const std::vector<uint64_t> *>()))>>
      : std::true_type {};

  template <typename T, typename = void>
  struct HasHandleJumpIWithCandidates : std::false_type {};
  template <typename T>
  struct HasHandleJumpIWithCandidates<
      T, std::void_t<decltype(std::declval<T &>().handleJumpI(
             std::declval<Operand>(), std::declval<Operand>(),
             std::declval<const std::vector<uint64_t> *>()))>>
      : std::true_type {};

  void registerCurrentBlockPC(uint64_t BlockPC) {
    if constexpr (HasRegisterCurrentBlockPC<IRBuilder>::value) {
      Builder.registerCurrentBlockPC(BlockPC);
    } else {
      (void)BlockPC;
    }
  }

  void spillTrackedStackPreservingPrefix(const std::vector<Operand> &Values,
                                         uint32_t PrefixDepth) {
    if constexpr (HasSpillTrackedStackPreservingPrefix<IRBuilder>::value) {
      Builder.spillTrackedStackPreservingPrefix(Values, PrefixDepth);
    } else {
      (void)PrefixDepth;
      Builder.spillTrackedStack(Values);
    }
  }

  Operand materializeStackMergeOperandCompat(
      const std::vector<uint64_t> &PredBlockPCs,
      const std::vector<std::pair<uint64_t, Operand>> &IncomingValues) {
    if constexpr (HasMaterializeStackMergeOperand<IRBuilder>::value) {
      return Builder.materializeStackMergeOperand(PredBlockPCs, IncomingValues);
    } else {
      (void)PredBlockPCs;
      Operand Result = Builder.createStackEntryOperand();
      if (!IncomingValues.empty()) {
        Builder.assignStackEntryOperand(Result, IncomingValues.back().second);
      }
      return Result;
    }
  }

  void handleJumpCompat(Operand Dest,
                        const std::vector<uint64_t> *CandidateTargets) {
    if constexpr (HasHandleJumpWithCandidates<IRBuilder>::value) {
      Builder.handleJump(Dest, CandidateTargets);
    } else {
      (void)CandidateTargets;
      Builder.handleJump(Dest);
    }
  }

  void handleJumpICompat(Operand Dest, Operand Cond,
                         const std::vector<uint64_t> *CandidateTargets) {
    if constexpr (HasHandleJumpIWithCandidates<IRBuilder>::value) {
      Builder.handleJumpI(Dest, Cond, CandidateTargets);
    } else {
      (void)CandidateTargets;
      Builder.handleJumpI(Dest, Cond);
    }
  }

  void push(const Operand &Opnd) { Stack.push(Opnd); }

  void requireLogicalStackDepth(uint32_t Depth) {
    ZEN_ASSERT(Stack.getSize() >= Depth &&
               "Logical EVM stack must be preloaded at block entry");
  }

  Operand pop() {
    requireLogicalStackDepth(1);
    Operand Opnd = Stack.pop();
    Builder.releaseOperand(Opnd);
    return Opnd;
  }

  bool decode() {
    try {
      const uint8_t *Bytecode =
          reinterpret_cast<const uint8_t *>(Ctx->getBytecode());
      size_t BytecodeSize = Ctx->getBytecodeSize();
      EVMAnalyzer Analyzer(Ctx->getRevision());
      if (Ctx->getResolvedJumpTargets()) {
        Analyzer.setResolvedJumpTargets(Ctx->getResolvedJumpTargets());
      }
      Analyzer.analyze(Bytecode, BytecodeSize);
      if constexpr (HasSetMemoryFacts<IRBuilder>::value) {
        buildMemoryFacts(Analyzer, Bytecode, BytecodeSize);
        setMemoryFactsCompat();
      }
      initializeLiftedBlocks(Analyzer);

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
          if (tryHandleControlFlowMacroOp(Analyzer, Bytecode, BytecodeSize,
                                          Opcode, Ip)) {
            continue;
          }
          if (tryHandleKeccakMacroOp(Bytecode, BytecodeSize, Opcode, Ip)) {
            continue;
          }
          if (tryHandleAddressMacroOp(Bytecode, BytecodeSize, Opcode, Ip)) {
            continue;
          }
          if (tryHandleMemoryMacroOp(Bytecode, BytecodeSize, Opcode, Ip)) {
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
          maybePrepareLinearBlockMemoryPrecheck(Opcode);
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
          handleJumpOpcode(Analyzer, Dest);
          break;
        }

        case OP_JUMPI: {
          Operand Dest = pop();
          Operand Cond = pop();
          handleJumpIOpcode(Analyzer, Dest, Cond);
          break;
        }

        case OP_JUMPDEST: {
          // Consecutive JUMPDEST opcodes share one body BB in multipass.
          // Charge all skipped metering points before jumping to the shared
          // destination at the end of the run.
          const bool HasDeferredLiftedFallthrough =
              DeferredLiftedJumpDestFallthrough;
          DeferredLiftedJumpDestFallthrough = false;
          bool HasLiveFallthrough = !InDeadCode || HasDeferredLiftedFallthrough;
          uint64_t RunStartPC = PC;
          while (Ip < IpEnd && static_cast<evmc_opcode>(*Ip) == OP_JUMPDEST) {
            Ip++;
            PC++;
          }
          if (PC > RunStartPC && HasLiveFallthrough) {
            Builder.meterOpcodeRange(RunStartPC, PC);
          }
          // A lifted JUMPI fallthrough that starts at this JUMPDEST has already
          // assigned its entry state and finalized the predecessor block, but
          // deliberately deferred handleBeginBlock until handleJumpDest wires
          // the staging fallthrough BB to the canonical body. Materializing a
          // shared-entry phi in that staging BB would give it the analyzer's
          // full predecessor count even though the BB has only the single
          // JUMPI fallthrough predecessor.
          bool AlreadyBegunLiftedEntry = HasLiveFallthrough &&
                                         CurrentBlockLifted &&
                                         RunStartPC == CurrentBlockEntryPC;
          if (HasDeferredLiftedFallthrough) {
            // Entry edge assignment and predecessor finalization are complete.
            // Begin the target once below, after entering its canonical body.
          } else if (AlreadyBegunLiftedEntry) {
            // Entry edge already assigned by the predecessor terminator; do not
            // reassign. The predecessor's handleBeginBlock already restored
            // this block's lifted logical entry state onto the logical stack.
            // The re-begin below (handleBeginBlock after handleJumpDest)
            // restores it again in the canonical JUMPDEST body block, so drain
            // the stale copy first to prevent the logical stack from being
            // doubled.
            drainLogicalStack();
          } else if (HasLiveFallthrough && tryAssignFallthroughEntryState(PC)) {
            // Keep runtime stack materialization elided on lifted fallthrough.
          } else {
            if (HasLiveFallthrough && CurrentBlockLifted && isLiftedBlock(PC)) {
              auto OutgoingStack = drainLogicalStack();
              assignLiftedEntryState(PC, OutgoingStack);
              finalizeBlockExit(std::move(OutgoingStack), false);
            } else {
              handleEndBlock();
              if (HasLiveFallthrough && isLiftedBlock(PC)) {
                assignLiftedEntryStateFromRuntime(Analyzer, PC);
              }
            }
          }
          Builder.handleJumpDest(PC, HasLiveFallthrough);
          handleBeginBlock(Analyzer);
          Builder.meterOpcode(Opcode, PC);
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
        handleEndBlock();
        handleStop();
      }
    } catch (const common::Error &) {
      throw;
    }
    return true;
  }

  void initializeLiftedBlocks(const EVMAnalyzer &Analyzer) {
    StackLifter.initialize(Analyzer);
  }

  bool isLiftedBlock(uint64_t BlockPC) const {
    return StackLifter.isLiftedBlock(BlockPC);
  }

  bool canAssignLiftedEntryStateFromRuntime(const EVMAnalyzer &Analyzer,
                                            uint64_t PredBlockPC,
                                            uint64_t SuccBlockPC) const {
    if (!isLiftedBlock(SuccBlockPC)) {
      return false;
    }

    const auto &BlockInfos = Analyzer.getBlockInfos();
    auto PredIt = BlockInfos.find(PredBlockPC);
    auto SuccIt = BlockInfos.find(SuccBlockPC);
    if (PredIt == BlockInfos.end() || SuccIt == BlockInfos.end()) {
      return false;
    }

    return PredIt->second.ResolvedExitStackDepth >= 0 &&
           SuccIt->second.FullEntryStateDepth >= 0 &&
           PredIt->second.ResolvedExitStackDepth ==
               SuccIt->second.FullEntryStateDepth;
  }

  std::vector<Operand> drainLogicalStack() {
    EvalStack ReverseStack;
    std::vector<Operand> Values;
    while (!Stack.empty()) {
      ReverseStack.push(Stack.pop());
    }
    while (!ReverseStack.empty()) {
      Values.push_back(ReverseStack.pop());
    }
    return Values;
  }

  void restoreLogicalStack(const std::vector<Operand> &Values) {
    for (const Operand &Opnd : Values) {
      Stack.push(Opnd);
    }
  }

  void finalizeBlockExit(std::vector<Operand> Values, bool Materialize) {
    Builder.endMemoryCompileBlock();
    CurBlockLinearPrecheckPlan = BlockLinearPrecheckPlan();
    if (Materialize) {
      if (CurrentBlockLifted) {
        // The lifted logical stack spans the full absolute entry depth
        // (FullEntryStateDepth), including any hidden live-in prefix slots, so
        // the spill base is the stack bottom: prefix 0. Spilling at Hidden*32
        // would write the stack above its bottom and inflate the recorded
        // StackSize by the prefix depth, causing spurious overflow traps and
        // missed underflow traps in later blocks.
        spillTrackedStackPreservingPrefix(Values, /*PrefixDepth=*/0);
      } else {
        for (const Operand &Opnd : Values) {
          Builder.stackPush(Opnd);
        }
      }
    }
    InDeadCode = true;
    CurrentBlockLifted = false;
  }

  bool tryGetConstantJumpSuccessorPC(const EVMAnalyzer &Analyzer,
                                     const Operand &Dest,
                                     uint64_t &SuccPC) const {
    if (!Dest.isConstant()) {
      return false;
    }
    const auto &ConstValue = Dest.getConstValue();
    if ((ConstValue[3] | ConstValue[2] | ConstValue[1]) != 0) {
      return false;
    }
    uint64_t RawDest = ConstValue[0];
    if (!Analyzer.hasCanonicalJumpDest(RawDest)) {
      return false;
    }
    SuccPC = Analyzer.getCanonicalJumpDestPC(RawDest);
    return true;
  }

  void assignLiftedEntryState(uint64_t BlockPC,
                              const std::vector<Operand> &Values) {
    StackLifter.assignEntryState(CurrentBlockEntryPC, BlockPC, Values);
  }

  void assignCompatibleDynamicJumpRegionEntryStates(
      const EVMAnalyzer &Analyzer, const std::vector<Operand> &Values) {
    for (uint64_t TargetBlockPC :
         Analyzer.getCompatibleDynamicJumpTargetBlocksForSourceBlock(
             CurrentBlockEntryPC)) {
      if (!isLiftedBlock(TargetBlockPC)) {
        continue;
      }
      StackLifter.assignEntryState(CurrentBlockEntryPC, TargetBlockPC, Values);
    }
  }

  void assignCompatibleDynamicJumpRegionEntryStatesFromRuntime(
      const EVMAnalyzer &Analyzer) {
    for (uint64_t TargetBlockPC :
         Analyzer.getCompatibleDynamicJumpTargetBlocksForSourceBlock(
             CurrentBlockEntryPC)) {
      if (!canAssignLiftedEntryStateFromRuntime(Analyzer, CurrentBlockEntryPC,
                                                TargetBlockPC)) {
        continue;
      }
      StackLifter.assignEntryState(
          CurrentBlockEntryPC, TargetBlockPC,
          loadLiftedEntryStateFromRuntime(Analyzer, TargetBlockPC));
    }
  }

  void assignLiftedEntryStateFromRuntime(const EVMAnalyzer &Analyzer,
                                         uint64_t BlockPC) {
    if (!canAssignLiftedEntryStateFromRuntime(Analyzer, CurrentBlockEntryPC,
                                              BlockPC)) {
      return;
    }
    StackLifter.assignEntryState(
        CurrentBlockEntryPC, BlockPC,
        loadLiftedEntryStateFromRuntime(Analyzer, BlockPC));
  }

  bool tryAssignConstantJumpEntryState(const EVMAnalyzer &Analyzer,
                                       const Operand &Dest) {
    uint64_t SuccPC = 0;
    if (!CurrentBlockLifted ||
        !tryGetConstantJumpSuccessorPC(Analyzer, Dest, SuccPC) ||
        !isLiftedBlock(SuccPC)) {
      return false;
    }
    auto OutgoingStack = drainLogicalStack();
    assignLiftedEntryState(SuccPC, OutgoingStack);
    finalizeBlockExit(std::move(OutgoingStack), false);
    return true;
  }

  bool tryAssignFallthroughEntryState(uint64_t SuccPC) {
    if (!CurrentBlockLifted || !isLiftedBlock(SuccPC)) {
      return false;
    }
    auto OutgoingStack = drainLogicalStack();
    assignLiftedEntryState(SuccPC, OutgoingStack);
    finalizeBlockExit(std::move(OutgoingStack), false);
    return true;
  }

  std::vector<Operand>
  loadLiftedEntryStateFromRuntime(const EVMAnalyzer &Analyzer,
                                  uint64_t BlockPC) {
    std::vector<Operand> Values;
    const auto &BlockInfos = Analyzer.getBlockInfos();
    auto It = BlockInfos.find(BlockPC);
    if (It == BlockInfos.end() || !isLiftedBlock(BlockPC)) {
      return Values;
    }
    const auto &BlockInfo = It->second;
    ZEN_ASSERT(BlockInfo.ResolvedEntryStackDepth >= 0 &&
               "Lifted block must have resolved entry depth");
    ZEN_ASSERT(BlockInfo.FullEntryStateDepth >= 0 &&
               "Lifted block must have full entry state depth");
    Values.reserve(static_cast<size_t>(BlockInfo.FullEntryStateDepth));
    for (int32_t Index = 0; Index < BlockInfo.FullEntryStateDepth; ++Index) {
      int32_t StackIndex = BlockInfo.ResolvedEntryStackDepth - Index - 1;
      Values.push_back(Builder.stackGet(StackIndex));
    }
    return Values;
  }

  bool validateLiftedBlockStackBounds(const EVMAnalyzer::BlockInfo &BlockInfo) {
    ZEN_ASSERT(BlockInfo.ResolvedEntryStackDepth >= 0 &&
               "Lifted block must have resolved entry depth");

    int64_t EntryDepth =
        static_cast<int64_t>(BlockInfo.ResolvedEntryStackDepth);
    int64_t MinDepth =
        EntryDepth + static_cast<int64_t>(BlockInfo.MinStackHeight);
    if (MinDepth < 0) {
      Builder.handleTrap(common::ErrorCode::EVMStackUnderflow);
      InDeadCode = true;
      CurrentBlockLifted = false;
      return false;
    }

    int64_t MaxDepth =
        EntryDepth + static_cast<int64_t>(BlockInfo.MaxStackHeight);
    if (MaxDepth > static_cast<int64_t>(EVM_MAX_STACK_SIZE)) {
      Builder.handleTrap(common::ErrorCode::EVMStackOverflow);
      InDeadCode = true;
      CurrentBlockLifted = false;
      return false;
    }

    return true;
  }

  void handleBeginBlock(EVMAnalyzer &Analyzer) {
    const auto &BlockInfos = Analyzer.getBlockInfos();
    ZEN_ASSERT(BlockInfos.count(PC) > 0 && "Block info not found");
    const auto &BlockInfo = BlockInfos.at(PC);
    beginMemoryCompileBlockCompat(PC, BlockInfo.BodyEndPC);
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

    LargeStaticWorkspaceVerifierResult LargeStaticWorkspace =
        analyzeLargeStaticWorkspaceVerifier(Bytecode, BytecodeSize, PC);
    if (hasLargeStaticWorkspaceVerifierResult(LargeStaticWorkspace)) {
      Builder.noteLargeStaticWorkspaceVerifierResult(
          LargeStaticWorkspace.Candidates,
          LargeStaticWorkspace.VerifiedSegments,
          LargeStaticWorkspace.VerifiedOps,
          LargeStaticWorkspace.VerifiedMLoadOps,
          LargeStaticWorkspace.VerifiedMStoreOps,
          LargeStaticWorkspace.VerifiedMStore8Ops,
          LargeStaticWorkspace.MaxRequiredSize, LargeStaticWorkspace.Rejected,
          LargeStaticWorkspace.RejectDynamicOffset,
          LargeStaticWorkspace.RejectUnknownBase,
          LargeStaticWorkspace.RejectUnboundedInterval,
          LargeStaticWorkspace.RejectOverflowRisk,
          LargeStaticWorkspace.RejectSideEffect,
          LargeStaticWorkspace.RejectHelperByteExactRisk,
          LargeStaticWorkspace.RejectTooFewOps);
    }
#ifdef ZEN_ENABLE_EVM_MEM_LARGE_STATIC_WORKSPACE_LOWERING
    if (LargeStaticWorkspace.HasLoweringPlan) {
      Builder.setMemoryCompileBlockLargeStaticWorkspacePrecheckPlan(
          LargeStaticWorkspace.LoweringFirstPC,
          LargeStaticWorkspace.LoweringLastPC,
          LargeStaticWorkspace.LoweringMaxRequiredSize,
          LargeStaticWorkspace.LoweringCoveredOps,
          LargeStaticWorkspace.LoweringCoveredMLoadOps,
          LargeStaticWorkspace.LoweringCoveredMStoreOps,
          LargeStaticWorkspace.LoweringCoveredMStore8Ops);
    }
#endif // ZEN_ENABLE_EVM_MEM_LARGE_STATIC_WORKSPACE_LOWERING
    CurrentBlockEntryPC = PC;
    registerCurrentBlockPC(PC);
    bool LiftedBlock = isLiftedBlock(PC);
    if (LiftedBlock && !validateLiftedBlockStackBounds(BlockInfo)) {
      return;
    }

    if (static_cast<size_t>(-BlockInfo.MinStackHeight) > EVM_MAX_STACK_SIZE) {
      Builder.handleTrap(common::ErrorCode::EVMStackUnderflow);
      InDeadCode = true;
      CurrentBlockLifted = false;
      return;
    }
    if (static_cast<size_t>(BlockInfo.MaxStackHeight) > EVM_MAX_STACK_SIZE) {
      Builder.handleTrap(common::ErrorCode::EVMStackOverflow);
      InDeadCode = true;
      CurrentBlockLifted = false;
      return;
    }
    InDeadCode = false;
    if (!LiftedBlock) {
      Builder.createStackCheckBlock(-BlockInfo.MinStackHeight,
                                    1024 - BlockInfo.MaxStackHeight);
    }

    if (LiftedBlock) {
      CurrentBlockLifted = true;
      materializeLiftedBlockMergeRequests(PC, BlockInfo);
      restoreLiftedBlockLogicalEntryState(PC);
#ifndef NDEBUG
      // Debug invariant: a lifted block's logical entry state must be fully
      // materialized before its body is compiled. StackLifter.hasCompleteEntry-
      // State() cannot be a hard assertion here: on a single linear pass a
      // lifted loop header is begun before its back-edge predecessor is
      // visited, and a lifted JUMPDEST reached only from dead code is never
      // assigned, so ExpectedIncomingCount legitimately exceeds the arrived
      // edges. The sound begin-time property is that the entry stack the body
      // consumes has the resolved full depth with every slot defined.
      {
        const std::vector<Operand> LogicalEntry =
            StackLifter.getLogicalEntryState(PC);
        ZEN_ASSERT(static_cast<int32_t>(LogicalEntry.size()) ==
                       std::max(BlockInfo.FullEntryStateDepth, 0) &&
                   "lifted block entry-state depth mismatch at block begin");
        for (const Operand &Slot : LogicalEntry) {
          ZEN_ASSERT(!Slot.isEmpty() && "lifted block entry-state slot is "
                                        "undefined at block begin");
        }
      }
#endif
      return;
    }

    CurrentBlockLifted = false;
    int32_t TotalPopSize = -BlockInfo.MinPopHeight;
    EvalStack ReverseStack;
    // Refine each popped Operand's ValueRange from analyzer-computed entry
    // ranges so u64-narrow fast paths fire on values flowing through CFG
    // joins (see EVMRangeAnalyzer /
    // docs/changes/2026-05-07-value-range-cfg-join). EntryStackRanges[0] is the
    // bottom of entry stack; pop order is top-first.
    const auto &EntryRanges = BlockInfo.EntryStackRanges;
    const int32_t EntryTopIdx = static_cast<int32_t>(EntryRanges.size()) - 1;
    int32_t PopIter = 0;
    while (TotalPopSize > 0) {
      Operand Opnd = Builder.stackPop();
      const int32_t SlotIdx = EntryTopIdx - PopIter;
      if (SlotIdx >= 0 && SlotIdx < static_cast<int32_t>(EntryRanges.size())) {
        Opnd.setRange(EntryRanges[SlotIdx]);
      }
      ReverseStack.push(Opnd);
      ++PopIter;
      --TotalPopSize;
    }
    while (!ReverseStack.empty()) {
      Operand Opnd = ReverseStack.pop();
      Stack.push(Opnd);
    }
  }

  void
  materializeLiftedBlockMergeRequests(uint64_t BlockPC,
                                      const EVMAnalyzer::BlockInfo &BlockInfo) {
    for (const MergeMaterializationRequest &Request :
         StackLifter.getMergeMaterializationRequests(BlockPC)) {
      std::vector<std::pair<uint64_t, Operand>> IncomingValues;
      IncomingValues.reserve(Request.IncomingValues.size());
      for (const auto &IncomingValue : Request.IncomingValues) {
        IncomingValues.emplace_back(IncomingValue.PredBlockPC,
                                    IncomingValue.Value);
      }
      Operand Merge = materializeStackMergeOperandCompat(
          Request.ExpectedPredBlockPCs, IncomingValues);
      if (Request.SlotIndex < BlockInfo.EntryStackRanges.size()) {
        Merge.setRange(BlockInfo.EntryStackRanges[Request.SlotIndex]);
      }
      StackLifter.assignMergeOperand(BlockPC, Request.SlotIndex, Merge);
    }
  }

  void restoreLiftedBlockLogicalEntryState(uint64_t BlockPC) {
    std::vector<Operand> LogicalEntryState =
        StackLifter.getLogicalEntryState(BlockPC);
    if (!LogicalEntryState.empty()) {
      restoreLogicalStack(LogicalEntryState);
    }
  }

  void handleEndBlock() { finalizeBlockExit(drainLogicalStack(), true); }

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

  static bool hasLargeStaticWorkspaceVerifierResult(
      const LargeStaticWorkspaceVerifierResult &Result) {
    return Result.Candidates != 0 || Result.VerifiedSegments != 0 ||
           Result.Rejected != 0;
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

  BlockLinearPrecheckPlan analyzeLinearMstore8DirectMemoryBlockPrecheck(
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
          !consumeExpectedOpcode(Bytecode, BytecodeSize, MotifPC, OP_MSTORE8) ||
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
    Plan.CoveredOpcode = OP_MSTORE8;
    Plan.AccessWidth = 1;
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
    Plan = analyzeLinearMstoreDirectMemoryBlockPrecheck(Bytecode, BytecodeSize,
                                                        EntryPC);
    if (Plan.Eligible) {
      return Plan;
    }
    return analyzeLinearMstore8DirectMemoryBlockPrecheck(Bytecode, BytecodeSize,
                                                         EntryPC);
  }

  static bool isConstTwoWordKeccakHashPrepTail(
      const std::vector<AbstractConstU64> &SimStack,
      const BlockConstPrecheckPlan &Plan) {
    // This only gates the direct-memory precheck. KECCAK itself still runs
    // through the normal helper path.
    if (Plan.CoveredDirectOps < 2 || SimStack.size() < 2) {
      return false;
    }

    const AbstractConstU64 &Offset = SimStack.back();
    const AbstractConstU64 &Length = SimStack[SimStack.size() - 2];
    if (!Offset.Known || !Length.Known || Length.Value != 64) {
      return false;
    }

    uint64_t RequiredSize = 0;
    if (!addConstU64(Offset.Value, Length.Value, RequiredSize)) {
      return false;
    }

    uint64_t SecondWordOffset = 0;
    if (!addConstU64(Offset.Value, 32, SecondWordOffset)) {
      return false;
    }

    bool HasFirstWordStore = false;
    bool HasSecondWordStore = false;
    for (uint64_t StoreOffset : Plan.WordStoreOffsets) {
      HasFirstWordStore |= StoreOffset == Offset.Value;
      HasSecondWordStore |= StoreOffset == SecondWordOffset;
    }

    return HasFirstWordStore && HasSecondWordStore &&
           RequiredSize <= Plan.MaxRequiredSize;
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

  LargeStaticWorkspaceVerifierResult
  analyzeLargeStaticWorkspaceVerifier(const Byte *Bytecode, size_t BytecodeSize,
                                      uint64_t EntryPC) {
    LargeStaticWorkspaceVerifierResult Result;
    constexpr uint64_t InitialUnknownLiveIns = 128;
    constexpr uint64_t MinVerifiedDirectOps = 16;

    struct SegmentState {
      bool Active = false;
      bool DynamicOffset = false;
      bool OverflowRisk = false;
      uint64_t DirectOps = 0;
      uint64_t MLoadOps = 0;
      uint64_t MStoreOps = 0;
      uint64_t MStore8Ops = 0;
      uint64_t MaxRequiredSize = 0;
      uint64_t FirstDirectPC = 0;
      uint64_t LastDirectPC = 0;
    };

    enum class SegmentRejectReason : uint8_t {
      None,
      DynamicOffset,
      UnknownBase,
      OverflowRisk,
      SideEffect,
      HelperByteExactRisk,
      TooFewOps,
    };

    std::vector<AbstractConstU64> SimStack(
        static_cast<size_t>(InitialUnknownLiveIns), makeUnknownConstU64());
    SegmentState Segment;

    auto ResetSegment = [&]() { Segment = SegmentState(); };

    auto FinalizeSegment = [&](SegmentRejectReason Reason) {
      if (!Segment.Active || Segment.DirectOps == 0) {
        ResetSegment();
        return;
      }

      ++Result.Candidates;
      SegmentRejectReason FinalReason = Reason;
      if (FinalReason == SegmentRejectReason::None && Segment.DynamicOffset) {
        FinalReason = SegmentRejectReason::DynamicOffset;
      }
      if (FinalReason == SegmentRejectReason::None && Segment.OverflowRisk) {
        FinalReason = SegmentRejectReason::OverflowRisk;
      }
      if (FinalReason == SegmentRejectReason::None &&
          Segment.DirectOps < MinVerifiedDirectOps) {
        FinalReason = SegmentRejectReason::TooFewOps;
      }

      if (FinalReason == SegmentRejectReason::None) {
        ++Result.VerifiedSegments;
        Result.VerifiedOps += Segment.DirectOps;
        Result.VerifiedMLoadOps += Segment.MLoadOps;
        Result.VerifiedMStoreOps += Segment.MStoreOps;
        Result.VerifiedMStore8Ops += Segment.MStore8Ops;
        if (Segment.MaxRequiredSize > Result.MaxRequiredSize) {
          Result.MaxRequiredSize = Segment.MaxRequiredSize;
        }
        if (!Result.HasLoweringPlan ||
            Segment.DirectOps > Result.LoweringCoveredOps) {
          Result.HasLoweringPlan = true;
          Result.LoweringFirstPC = Segment.FirstDirectPC;
          Result.LoweringLastPC = Segment.LastDirectPC;
          Result.LoweringMaxRequiredSize = Segment.MaxRequiredSize;
          Result.LoweringCoveredOps = Segment.DirectOps;
          Result.LoweringCoveredMLoadOps = Segment.MLoadOps;
          Result.LoweringCoveredMStoreOps = Segment.MStoreOps;
          Result.LoweringCoveredMStore8Ops = Segment.MStore8Ops;
        }
      } else {
        ++Result.Rejected;
        switch (FinalReason) {
        case SegmentRejectReason::DynamicOffset:
          ++Result.RejectDynamicOffset;
          break;
        case SegmentRejectReason::UnknownBase:
          ++Result.RejectUnknownBase;
          break;
        case SegmentRejectReason::OverflowRisk:
          ++Result.RejectOverflowRisk;
          break;
        case SegmentRejectReason::SideEffect:
          ++Result.RejectSideEffect;
          break;
        case SegmentRejectReason::HelperByteExactRisk:
          ++Result.RejectHelperByteExactRisk;
          break;
        case SegmentRejectReason::TooFewOps:
          ++Result.RejectTooFewOps;
          break;
        case SegmentRejectReason::None:
          break;
        }
      }
      ResetSegment();
    };

    auto EnsureStack = [&](size_t Count) {
      while (SimStack.size() < Count) {
        SimStack.insert(SimStack.begin(), makeUnknownConstU64());
      }
    };

    auto Pop = [&]() {
      EnsureStack(1);
      AbstractConstU64 Value = SimStack.back();
      SimStack.pop_back();
      return Value;
    };

    auto Drop = [&](size_t Count) {
      EnsureStack(Count);
      while (Count-- != 0) {
        SimStack.pop_back();
      }
    };

    auto PushUnknown = [&]() { SimStack.push_back(makeUnknownConstU64()); };
    auto PushConst = [&](uint64_t Value) {
      SimStack.push_back(makeKnownConstU64(Value));
    };

    auto NoteDirectMemoryOp = [&](evmc_opcode Opcode, uint64_t OpPC,
                                  AbstractConstU64 Offset, uint64_t Size) {
      Segment.Active = true;
      if (Segment.DirectOps == 0) {
        Segment.FirstDirectPC = OpPC;
      }
      Segment.LastDirectPC = OpPC;
      ++Segment.DirectOps;
      switch (Opcode) {
      case OP_MLOAD:
        ++Segment.MLoadOps;
        break;
      case OP_MSTORE:
        ++Segment.MStoreOps;
        break;
      case OP_MSTORE8:
        ++Segment.MStore8Ops;
        break;
      default:
        break;
      }

      if (!Offset.Known) {
        Segment.DynamicOffset = true;
        return;
      }

      uint64_t RequiredSize = 0;
      if (!addConstU64(Offset.Value, Size, RequiredSize)) {
        Segment.OverflowRisk = true;
        return;
      }
      if (RequiredSize > Segment.MaxRequiredSize) {
        Segment.MaxRequiredSize = RequiredSize;
      }
    };

    auto HandleHelperSensitiveOpcode = [&](evmc_opcode Opcode) {
      FinalizeSegment(SegmentRejectReason::None);
      switch (Opcode) {
      case OP_KECCAK256:
        Drop(2);
        PushUnknown();
        break;
      case OP_CALLDATACOPY:
      case OP_CODECOPY:
      case OP_RETURNDATACOPY:
        Drop(3);
        break;
      case OP_EXTCODECOPY:
        Drop(4);
        break;
      case OP_LOG0:
        Drop(2);
        break;
      case OP_LOG1:
        Drop(3);
        break;
      case OP_LOG2:
        Drop(4);
        break;
      case OP_LOG3:
        Drop(5);
        break;
      case OP_LOG4:
        Drop(6);
        break;
      case OP_CREATE:
        Drop(3);
        PushUnknown();
        break;
      case OP_CREATE2:
        Drop(4);
        PushUnknown();
        break;
      case OP_CALL:
      case OP_CALLCODE:
        Drop(7);
        PushUnknown();
        break;
      case OP_DELEGATECALL:
      case OP_STATICCALL:
        Drop(6);
        PushUnknown();
        break;
      default:
        break;
      }
    };

    for (uint64_t ScanPC = EntryPC; ScanPC < BytecodeSize; ++ScanPC) {
      evmc_opcode Opcode = static_cast<evmc_opcode>(Bytecode[ScanPC]);
      if (ScanPC != EntryPC && Opcode == OP_JUMPDEST) {
        break;
      }

      if (isBlockTerminatorOpcode(Opcode)) {
        FinalizeSegment(SegmentRejectReason::None);
        break;
      }

      if (isHelperSensitiveOpcode(Opcode)) {
        HandleHelperSensitiveOpcode(Opcode);
        continue;
      }

      switch (Opcode) {
      case OP_JUMPDEST:
        break;
      case OP_PUSH0:
        PushConst(0);
        break;
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
          FinalizeSegment(SegmentRejectReason::UnknownBase);
          return Result;
        }
        PushConst(Value);
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
        if (NumBytes > BytecodeSize - ScanPC - 1) {
          FinalizeSegment(SegmentRejectReason::UnknownBase);
          return Result;
        }
        ScanPC += NumBytes;
        PushUnknown();
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
        EnsureStack(Index);
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
        EnsureStack(static_cast<size_t>(Index) + 1);
        std::swap(SimStack.back(), SimStack[SimStack.size() - Index - 1]);
        break;
      }
      case OP_POP:
        Drop(1);
        break;
      case OP_ADD: {
        AbstractConstU64 LHS = Pop();
        AbstractConstU64 RHS = Pop();
        uint64_t Sum = 0;
        if (LHS.Known && RHS.Known && addConstU64(LHS.Value, RHS.Value, Sum)) {
          PushConst(Sum);
        } else {
          PushUnknown();
        }
        break;
      }
      case OP_SUB: {
        AbstractConstU64 LHS = Pop();
        AbstractConstU64 RHS = Pop();
        if (LHS.Known && RHS.Known && LHS.Value >= RHS.Value) {
          PushConst(LHS.Value - RHS.Value);
        } else {
          PushUnknown();
        }
        break;
      }
      case OP_CALLDATALOAD:
        Drop(1);
        PushUnknown();
        break;
      case OP_CALLDATASIZE:
      case OP_CODESIZE:
      case OP_RETURNDATASIZE:
      case OP_PC:
      case OP_GAS:
      case OP_ADDRESS:
      case OP_ORIGIN:
      case OP_CALLER:
      case OP_CALLVALUE:
      case OP_GASPRICE:
      case OP_COINBASE:
      case OP_TIMESTAMP:
      case OP_NUMBER:
      case OP_PREVRANDAO:
      case OP_GASLIMIT:
      case OP_CHAINID:
      case OP_SELFBALANCE:
      case OP_BASEFEE:
      case OP_BLOBBASEFEE:
        PushUnknown();
        break;
      case OP_ISZERO:
      case OP_NOT:
      case OP_BYTE:
      case OP_BLOBHASH:
      case OP_BALANCE:
      case OP_EXTCODESIZE:
      case OP_EXTCODEHASH:
      case OP_BLOCKHASH:
        Drop(1);
        PushUnknown();
        break;
      case OP_MLOAD: {
        AbstractConstU64 Offset = Pop();
        NoteDirectMemoryOp(Opcode, ScanPC, Offset, 32);
        PushUnknown();
        break;
      }
      case OP_MSTORE: {
        AbstractConstU64 Offset = Pop();
        Drop(1);
        NoteDirectMemoryOp(Opcode, ScanPC, Offset, 32);
        break;
      }
      case OP_MSTORE8: {
        AbstractConstU64 Offset = Pop();
        Drop(1);
        NoteDirectMemoryOp(Opcode, ScanPC, Offset, 1);
        break;
      }
      case OP_MSIZE:
        PushUnknown();
        break;
      case OP_MCOPY:
        FinalizeSegment(SegmentRejectReason::HelperByteExactRisk);
        Drop(3);
        break;
      case OP_SLOAD:
      case OP_TLOAD:
        FinalizeSegment(SegmentRejectReason::SideEffect);
        Drop(1);
        PushUnknown();
        break;
      case OP_SSTORE:
      case OP_TSTORE:
        FinalizeSegment(SegmentRejectReason::SideEffect);
        Drop(2);
        break;
      case OP_MUL:
      case OP_DIV:
      case OP_SDIV:
      case OP_MOD:
      case OP_SMOD:
      case OP_EXP:
      case OP_SIGNEXTEND:
      case OP_LT:
      case OP_GT:
      case OP_SLT:
      case OP_SGT:
      case OP_EQ:
      case OP_AND:
      case OP_OR:
      case OP_XOR:
      case OP_SHL:
      case OP_SHR:
      case OP_SAR:
        Drop(2);
        PushUnknown();
        break;
      case OP_ADDMOD:
      case OP_MULMOD:
        Drop(3);
        PushUnknown();
        break;
      default:
        FinalizeSegment(SegmentRejectReason::UnknownBase);
        PushUnknown();
        break;
      }
    }

    FinalizeSegment(SegmentRejectReason::None);
    return Result;
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
      if (Opcode == OP_KECCAK256) {
        if (isConstTwoWordKeccakHashPrepTail(SimStack, Plan)) {
          Plan.Eligible = true;
          return Plan;
        }
        return {};
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
        Plan.WordStoreOffsets.push_back(Addr.Value);
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
      case OP_MCOPY: {
        if (SimStack.size() < 3) {
          return {};
        }
        AbstractConstU64 DestAddr = SimStack.back();
        SimStack.pop_back();
        AbstractConstU64 SrcAddr = SimStack.back();
        SimStack.pop_back();
        AbstractConstU64 Length = SimStack.back();
        SimStack.pop_back();
        if (!Length.Known) {
          return {};
        }
        if (Length.Value == 0) {
          break;
        }
        if (!DestAddr.Known || !SrcAddr.Known) {
          return {};
        }
        uint64_t DestRequiredSize = 0;
        uint64_t SrcRequiredSize = 0;
        if (!addConstU64(DestAddr.Value, Length.Value, DestRequiredSize) ||
            !addConstU64(SrcAddr.Value, Length.Value, SrcRequiredSize)) {
          return {};
        }
        Plan.MaxRequiredSize = std::max(
            Plan.MaxRequiredSize, std::max(DestRequiredSize, SrcRequiredSize));
        Plan.CoveredDirectOps++;
        SawDirectMemory = true;
        break;
      }
      case OP_MSIZE:
        if (SawDirectMemory) {
          Plan.Eligible = Plan.CoveredDirectOps >= 2;
          return Plan;
        }
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

  // Analyzer/codegen dispatch-consistency guard. Codegen emits the all-JUMPDEST
  // indirect switch exactly when the JUMP/JUMPI dest operand is non-constant
  // (evm_mir_compiler.cpp handleJump/handleJumpI else-branch). Soundness of
  // Stage 2 lifting relies on that direction implying the analyzer marked this
  // block dynamic (HasDynamicJump), which forces every JUMPDEST out of lifting.
  // If the visitor hands a non-constant dest while the analyzer resolved the
  // jump statically, the exclusion would not have fired and lifted JUMPDESTs
  // could be miscompiled: fail the compile loudly instead. This is a hard
  // check in every build configuration, not a debug-only assertion. It throws
  // a Compilation-phase Error rather than aborting: evm_compiler.cpp's compile
  // path catches std::exception and degrades to interpreter fallback, so a
  // constant-tracking mismatch logs and falls back instead of killing the
  // loading process. The invariant is config-independent and the check is
  // cheap, so it stays active in every build.
  void assertDynamicJumpConsistency(const EVMAnalyzer &Analyzer,
                                    const Operand &Dest) const {
    if (Dest.isConstant()) {
      return;
    }
    const auto &BlockInfos = Analyzer.getBlockInfos();
    auto It = BlockInfos.find(CurrentBlockEntryPC);
    if (It == BlockInfos.end() || !It->second.HasDynamicJump) {
      throw common::getError(
          common::ErrorCode::EVMDynamicJumpConsistencyFailed);
    }
  }

  void handleJumpOpcode(EVMAnalyzer &Analyzer, Operand Dest) {
    uint64_t SuccPC = 0;
    bool HasLiftedSucc = tryAssignConstantJumpEntryState(Analyzer, Dest);
    if (!HasLiftedSucc) {
      if (CurrentBlockLifted) {
        const bool HasKnownSucc =
            tryGetConstantJumpSuccessorPC(Analyzer, Dest, SuccPC);
        const bool HasKnownLiftedSucc = HasKnownSucc && isLiftedBlock(SuccPC);
        auto OutgoingStack = drainLogicalStack();
        if (HasKnownLiftedSucc) {
          assignLiftedEntryState(SuccPC, OutgoingStack);
        }
        if (!HasKnownSucc) {
          // SSA entry-state assignment is additive to materialization: lifted
          // compatible targets keep their zero-reload SSA entry, while the
          // materialized runtime stack backs non-lifted and out-of-model
          // targets.
          assignCompatibleDynamicJumpRegionEntryStates(Analyzer, OutgoingStack);
        }
        // A dynamic dispatch can land on any JUMPDEST via the jump table, so
        // the runtime stack must be valid at every dynamic exit; a dynamic dest
        // (!HasKnownSucc) therefore always materializes. Since
        // HasKnownLiftedSucc == HasKnownSucc && isLiftedBlock(SuccPC), the
        // condition (HasKnownSucc && !HasKnownLiftedSucc) || !HasKnownSucc
        // reduces to !HasKnownLiftedSucc: materialize unless the dest is a
        // known lifted successor.
        const bool NeedsRuntimeMaterialization = !HasKnownLiftedSucc;
        finalizeBlockExit(std::move(OutgoingStack),
                          NeedsRuntimeMaterialization);
      } else {
        handleEndBlock();
        if (!tryGetConstantJumpSuccessorPC(Analyzer, Dest, SuccPC)) {
          assignCompatibleDynamicJumpRegionEntryStatesFromRuntime(Analyzer);
        }
      }
      if (tryGetConstantJumpSuccessorPC(Analyzer, Dest, SuccPC) &&
          isLiftedBlock(SuccPC)) {
        assignLiftedEntryStateFromRuntime(Analyzer, SuccPC);
      }
    }
    const auto DispatchCandidates =
        Analyzer.getRuntimeDispatchCandidateTargetsForSourceBlock(
            CurrentBlockEntryPC);
    const auto *DispatchTargetPCs = DispatchCandidates.SafeForRuntimeDispatch
                                        ? &DispatchCandidates.TargetBlocks
                                        : nullptr;
    assertDynamicJumpConsistency(Analyzer, Dest);
    handleJumpCompat(Dest, DispatchTargetPCs);
  }

  void handleJumpIOpcode(EVMAnalyzer &Analyzer, Operand Dest, Operand Cond) {
    uint64_t JumpSuccPC = 0;
    bool HasJumpSucc =
        tryGetConstantJumpSuccessorPC(Analyzer, Dest, JumpSuccPC);
    const uint64_t RawFallthroughPC = PC + 1;
    const bool FallthroughStartsAtJumpDest =
        Analyzer.hasCanonicalJumpDest(RawFallthroughPC);
    uint64_t FallthroughPC = RawFallthroughPC;
    if (FallthroughStartsAtJumpDest) {
      FallthroughPC = Analyzer.getCanonicalJumpDestPC(RawFallthroughPC);
    }
    bool CanLiftFallthrough =
        CurrentBlockLifted && isLiftedBlock(FallthroughPC);
    bool CanLiftJump =
        HasJumpSucc && CurrentBlockLifted && isLiftedBlock(JumpSuccPC);
    bool CanPreassignFallthrough =
        CurrentBlockLifted && isLiftedBlock(FallthroughPC);
    bool CanPreassignJump =
        CurrentBlockLifted && HasJumpSucc && isLiftedBlock(JumpSuccPC);
    bool CanTransferWithoutMaterialize =
        CurrentBlockLifted && CanLiftFallthrough && CanLiftJump;

    if (CanTransferWithoutMaterialize) {
      auto OutgoingStack = drainLogicalStack();
      assignLiftedEntryState(FallthroughPC, OutgoingStack);
      assignLiftedEntryState(JumpSuccPC, OutgoingStack);
      finalizeBlockExit(std::move(OutgoingStack), false);
    } else {
      if (CurrentBlockLifted) {
        auto OutgoingStack = drainLogicalStack();
        if (CanPreassignFallthrough) {
          assignLiftedEntryState(FallthroughPC, OutgoingStack);
        }
        if (CanPreassignJump) {
          assignLiftedEntryState(JumpSuccPC, OutgoingStack);
        }
        if (!HasJumpSucc) {
          assignCompatibleDynamicJumpRegionEntryStates(Analyzer, OutgoingStack);
        }
        bool NeedsRuntimeMaterialization = !CanPreassignFallthrough;
        if (!HasJumpSucc) {
          // A dynamic dispatch can land on any JUMPDEST via the jump table, so
          // the runtime stack must be valid at every dynamic exit. The taken
          // edge of a dynamic-dest JUMPI forces materialization regardless of
          // fallthrough liftability; SSA assignment above stays additive.
          NeedsRuntimeMaterialization = true;
        } else if (!NeedsRuntimeMaterialization) {
          NeedsRuntimeMaterialization = !CanPreassignJump;
        }
        finalizeBlockExit(std::move(OutgoingStack),
                          NeedsRuntimeMaterialization);
      } else {
        handleEndBlock();
        if (isLiftedBlock(FallthroughPC)) {
          assignLiftedEntryStateFromRuntime(Analyzer, FallthroughPC);
        }
        if (HasJumpSucc) {
          if (isLiftedBlock(JumpSuccPC)) {
            assignLiftedEntryStateFromRuntime(Analyzer, JumpSuccPC);
          }
        } else {
          assignCompatibleDynamicJumpRegionEntryStatesFromRuntime(Analyzer);
        }
      }
    }
    const auto DispatchCandidates =
        Analyzer.getRuntimeDispatchCandidateTargetsForSourceBlock(
            CurrentBlockEntryPC);
    const auto *DispatchTargetPCs = DispatchCandidates.SafeForRuntimeDispatch
                                        ? &DispatchCandidates.TargetBlocks
                                        : nullptr;
    assertDynamicJumpConsistency(Analyzer, Dest);
    handleJumpICompat(Dest, Cond, DispatchTargetPCs);
    PC = FallthroughPC;
    if (FallthroughStartsAtJumpDest && isLiftedBlock(FallthroughPC)) {
      // handleJumpI leaves the builder in a one-predecessor staging BB. A
      // lifted shared JUMPDEST must materialize its merge state in the
      // canonical body instead, after the next decode iteration wires this
      // fallthrough edge through handleJumpDest.
      DeferredLiftedJumpDestFallthrough = true;
    } else {
      handleBeginBlock(Analyzer);
    }
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

  void meterOpcodeSequence(const uint8_t *Bytecode, uint64_t StartPC,
                           uint64_t EndPCExclusive) {
    for (uint64_t OpPC = StartPC; OpPC < EndPCExclusive;) {
      const evmc_opcode Op = static_cast<evmc_opcode>(Bytecode[OpPC]);
      Builder.meterOpcode(Op, OpPC);
      OpPC++;
      if (Op >= OP_PUSH0 && Op <= OP_PUSH32) {
        OpPC += static_cast<uint8_t>(Op) - static_cast<uint8_t>(OP_PUSH0);
      }
    }
  }

  bool tryHandleControlFlowMacroOp(EVMAnalyzer &Analyzer,
                                   const uint8_t *Bytecode, size_t BytecodeSize,
                                   evmc_opcode Opcode, const uint8_t *&Ip) {
    if (Opcode >= OP_PUSH0 && Opcode <= OP_PUSH32) {
      const uint8_t NumBytes =
          static_cast<uint8_t>(Opcode) - static_cast<uint8_t>(OP_PUSH0);
      const uint64_t JumpPC = PC + 1 + NumBytes;
      if (JumpPC < BytecodeSize) {
        const evmc_opcode NextOpcode =
            static_cast<evmc_opcode>(Bytecode[JumpPC]);
        if (NextOpcode == OP_JUMP || NextOpcode == OP_JUMPI) {
          Builder.meterOpcode(Opcode, PC);
          Builder.meterOpcode(NextOpcode, JumpPC);
          Operand Dest = buildPushOperandAt(PC, NumBytes);
          PC = JumpPC;
          if (NextOpcode == OP_JUMP) {
            handleJumpOpcode(Analyzer, Dest);
          } else {
            Operand Cond = pop();
            handleJumpIOpcode(Analyzer, Dest, Cond);
          }
          Ip += static_cast<ptrdiff_t>(NumBytes) + 1;
          return true;
        }
      }
      return false;
    }

    if (Opcode != OP_ISZERO) {
      return false;
    }

    const uint64_t PushPC = PC + 1;
    if (PushPC >= BytecodeSize) {
      return false;
    }

    const evmc_opcode PushOpcode = static_cast<evmc_opcode>(Bytecode[PushPC]);
    if (PushOpcode < OP_PUSH0 || PushOpcode > OP_PUSH32) {
      return false;
    }

    const uint8_t NumBytes =
        static_cast<uint8_t>(PushOpcode) - static_cast<uint8_t>(OP_PUSH0);
    const uint64_t JumpPC = PushPC + 1 + NumBytes;
    if (JumpPC >= BytecodeSize ||
        static_cast<evmc_opcode>(Bytecode[JumpPC]) != OP_JUMPI) {
      return false;
    }

    Builder.meterOpcode(Opcode, PC);
    Builder.meterOpcode(PushOpcode, PushPC);
    Builder.meterOpcode(OP_JUMPI, JumpPC);
    Operand Value = pop();
    Operand Dest = buildPushOperandAt(PushPC, NumBytes);
    Operand Cond = Builder.template handleCompareOp<CompareOperator::CO_EQZ>(
        Value, Operand());
    PC = JumpPC;
    handleJumpIOpcode(Analyzer, Dest, Cond);
    Ip += static_cast<ptrdiff_t>(NumBytes) + 2;
    return true;
  }

  bool tryHandleKeccakMacroOp(const uint8_t *Bytecode, size_t BytecodeSize,
                              evmc_opcode Opcode, const uint8_t *&Ip) {
    if (Opcode == OP_CALLER) {
      return tryHandleCallerSlotKeccakMacroOp(Bytecode, BytecodeSize, Ip);
    }

    if (Opcode >= OP_PUSH0 && Opcode <= OP_PUSH32) {
      return tryHandleCallDataSlotKeccakMacroOp(Bytecode, BytecodeSize, Opcode,
                                                Ip);
    }

    return false;
  }

  struct TwoWordKeccakStagingTail {
    uint64_t AddrPushPC = 0;
    uint64_t SlotPushPC = 0;
    uint64_t KeccakPC = 0;
    uint8_t AddrNumBytes = 0;
    uint8_t SlotNumBytes = 0;
  };

  bool parseTwoWordKeccakStagingTail(const uint8_t *Bytecode,
                                     size_t BytecodeSize, uint64_t AddrPushPC,
                                     TwoWordKeccakStagingTail &Tail) {
    const Byte *RawBytecode = reinterpret_cast<const Byte *>(Bytecode);
    if (AddrPushPC >= BytecodeSize) {
      return false;
    }

    evmc_opcode AddrPushOpcode = static_cast<evmc_opcode>(Bytecode[AddrPushPC]);
    if (AddrPushOpcode < OP_PUSH0 || AddrPushOpcode > OP_PUSH32) {
      return false;
    }

    const uint8_t AddrNumBytes =
        static_cast<uint8_t>(AddrPushOpcode) - static_cast<uint8_t>(OP_PUSH0);
    uint64_t AddrValue = 0;
    if (!parsePushConstU64(RawBytecode, BytecodeSize, AddrPushPC + 1,
                           AddrNumBytes, AddrValue)) {
      return false;
    }

    uint64_t ScanPC = AddrPushPC + 1 + AddrNumBytes;
    if (!consumeExpectedOpcode(RawBytecode, BytecodeSize, ScanPC, OP_MSTORE) ||
        ScanPC >= BytecodeSize) {
      return false;
    }

    const uint64_t SlotPushPC = ScanPC;
    evmc_opcode SlotPushOpcode = static_cast<evmc_opcode>(Bytecode[SlotPushPC]);
    if (SlotPushOpcode < OP_PUSH0 || SlotPushOpcode > OP_PUSH32) {
      return false;
    }
    const uint8_t SlotNumBytes =
        static_cast<uint8_t>(SlotPushOpcode) - static_cast<uint8_t>(OP_PUSH0);
    ScanPC += static_cast<uint64_t>(1 + SlotNumBytes);
    if (ScanPC >= BytecodeSize) {
      return false;
    }

    const uint64_t Addr2PushPC = ScanPC;
    evmc_opcode Addr2PushOpcode =
        static_cast<evmc_opcode>(Bytecode[Addr2PushPC]);
    if (Addr2PushOpcode < OP_PUSH0 || Addr2PushOpcode > OP_PUSH32) {
      return false;
    }

    const uint8_t Addr2NumBytes =
        static_cast<uint8_t>(Addr2PushOpcode) - static_cast<uint8_t>(OP_PUSH0);
    uint64_t Addr2Value = 0;
    if (!parsePushConstU64(RawBytecode, BytecodeSize, Addr2PushPC + 1,
                           Addr2NumBytes, Addr2Value)) {
      return false;
    }

    uint64_t ExpectedAddr2 = 0;
    if (!addConstU64(AddrValue, 32, ExpectedAddr2) ||
        Addr2Value != ExpectedAddr2) {
      return false;
    }

    ScanPC = Addr2PushPC + 1 + Addr2NumBytes;
    if (!consumeExpectedOpcode(RawBytecode, BytecodeSize, ScanPC, OP_MSTORE) ||
        ScanPC >= BytecodeSize) {
      return false;
    }

    const uint64_t LengthPushPC = ScanPC;
    evmc_opcode LengthPushOpcode =
        static_cast<evmc_opcode>(Bytecode[LengthPushPC]);
    if (LengthPushOpcode < OP_PUSH0 || LengthPushOpcode > OP_PUSH32) {
      return false;
    }
    const uint8_t LengthNumBytes =
        static_cast<uint8_t>(LengthPushOpcode) - static_cast<uint8_t>(OP_PUSH0);
    uint64_t LengthValue = 0;
    if (!parsePushConstU64(RawBytecode, BytecodeSize, LengthPushPC + 1,
                           LengthNumBytes, LengthValue) ||
        LengthValue != 64) {
      return false;
    }

    ScanPC = LengthPushPC + 1 + LengthNumBytes;
    if (ScanPC >= BytecodeSize) {
      return false;
    }

    const uint64_t BasePushPC = ScanPC;
    evmc_opcode BasePushOpcode = static_cast<evmc_opcode>(Bytecode[BasePushPC]);
    if (BasePushOpcode < OP_PUSH0 || BasePushOpcode > OP_PUSH32) {
      return false;
    }
    const uint8_t BaseNumBytes =
        static_cast<uint8_t>(BasePushOpcode) - static_cast<uint8_t>(OP_PUSH0);
    uint64_t BaseValue = 0;
    if (!parsePushConstU64(RawBytecode, BytecodeSize, BasePushPC + 1,
                           BaseNumBytes, BaseValue) ||
        BaseValue != AddrValue) {
      return false;
    }

    const uint64_t KeccakPC = BasePushPC + 1 + BaseNumBytes;
    if (KeccakPC >= BytecodeSize ||
        static_cast<evmc_opcode>(Bytecode[KeccakPC]) != OP_KECCAK256) {
      return false;
    }

    Tail.AddrPushPC = AddrPushPC;
    Tail.SlotPushPC = SlotPushPC;
    Tail.KeccakPC = KeccakPC;
    Tail.AddrNumBytes = AddrNumBytes;
    Tail.SlotNumBytes = SlotNumBytes;
    return true;
  }

  bool tryHandleCallerSlotKeccakMacroOp(const uint8_t *Bytecode,
                                        size_t BytecodeSize,
                                        const uint8_t *&Ip) {
    const uint64_t AddrPushPC = PC + 1;
    TwoWordKeccakStagingTail Tail;
    if (!parseTwoWordKeccakStagingTail(Bytecode, BytecodeSize, AddrPushPC,
                                       Tail)) {
      return false;
    }

    meterOpcodeSequence(Bytecode, PC, Tail.KeccakPC + 1);
    Builder.noteHelperOpcodeInBlock(OP_KECCAK256, Tail.KeccakPC);
    Operand Offset = buildPushOperandAt(Tail.AddrPushPC, Tail.AddrNumBytes);
    Operand SlotWord = buildPushOperandAt(Tail.SlotPushPC, Tail.SlotNumBytes);
    Operand Result = Builder.handleKeccak256CallerConstSlot(Offset, SlotWord);
    push(Result);
    Ip += static_cast<ptrdiff_t>(Tail.KeccakPC - PC);
    return true;
  }

  bool tryHandleCallDataSlotKeccakMacroOp(const uint8_t *Bytecode,
                                          size_t BytecodeSize,
                                          evmc_opcode Opcode,
                                          const uint8_t *&Ip) {
    const uint8_t CallDataOffsetNumBytes =
        static_cast<uint8_t>(Opcode) - static_cast<uint8_t>(OP_PUSH0);
    const uint64_t CallDataLoadPC = PC + 1 + CallDataOffsetNumBytes;
    if (CallDataLoadPC >= BytecodeSize ||
        static_cast<evmc_opcode>(Bytecode[CallDataLoadPC]) != OP_CALLDATALOAD) {
      return false;
    }

    const uint64_t AddrPushPC = CallDataLoadPC + 1;
    TwoWordKeccakStagingTail Tail;
    if (!parseTwoWordKeccakStagingTail(Bytecode, BytecodeSize, AddrPushPC,
                                       Tail)) {
      return false;
    }

    meterOpcodeSequence(Bytecode, PC, Tail.KeccakPC + 1);
    Builder.noteHelperOpcodeInBlock(OP_KECCAK256, Tail.KeccakPC);
    Operand Offset = buildPushOperandAt(Tail.AddrPushPC, Tail.AddrNumBytes);
    Operand CallDataOffset = buildPushOperandAt(PC, CallDataOffsetNumBytes);
    Operand SlotWord = buildPushOperandAt(Tail.SlotPushPC, Tail.SlotNumBytes);
    Operand Result = Builder.handleKeccak256CallDataConstSlot(
        Offset, CallDataOffset, SlotWord);
    push(Result);
    Ip += static_cast<ptrdiff_t>(Tail.KeccakPC - PC);
    return true;
  }

  bool tryHandleAddressMacroOp(const uint8_t *Bytecode, size_t BytecodeSize,
                               evmc_opcode Opcode, const uint8_t *&Ip) {
    if (Opcode >= OP_DUP1 && Opcode <= OP_DUP16) {
      const uint8_t DupIndex =
          static_cast<uint8_t>(Opcode) - static_cast<uint8_t>(OP_DUP1) + 1;
      const uint64_t AddPC = PC + 1;
      const uint64_t PostAddPC = AddPC + 1;
      if (AddPC < BytecodeSize &&
          static_cast<evmc_opcode>(Bytecode[AddPC]) == OP_ADD &&
          (PostAddPC >= BytecodeSize ||
           static_cast<evmc_opcode>(Bytecode[PostAddPC]) != OP_MSTORE)) {
        meterOpcodeSequence(Bytecode, PC, AddPC + 1);
        handleDupAddMacroOp(DupIndex);
        Ip += 1;
        return true;
      }
      return false;
    }

    if (Opcode < OP_PUSH0 || Opcode > OP_PUSH32) {
      return false;
    }

    const uint8_t NumBytes =
        static_cast<uint8_t>(Opcode) - static_cast<uint8_t>(OP_PUSH0);
    const uint64_t NextPC = PC + 1 + NumBytes;
    if (NextPC >= BytecodeSize) {
      return false;
    }

    Operand ConstOp = buildPushOperandAt(PC, NumBytes);
    evmc_opcode NextOpcode = static_cast<evmc_opcode>(Bytecode[NextPC]);
    const uint64_t PostAddPC = NextPC + 1;
    if (NextOpcode == OP_ADD &&
        (PostAddPC >= BytecodeSize ||
         static_cast<evmc_opcode>(Bytecode[PostAddPC]) != OP_MSTORE)) {
      meterOpcodeSequence(Bytecode, PC, NextPC + 1);
      handlePushConstAddMacroOp(ConstOp);
      Ip += static_cast<ptrdiff_t>(NumBytes) + 1;
      return true;
    }

    if (NextOpcode < OP_DUP1 || NextOpcode > OP_DUP16) {
      return false;
    }

    const uint8_t DupIndex =
        static_cast<uint8_t>(NextOpcode) - static_cast<uint8_t>(OP_DUP1) + 1;
    const uint64_t AddPC = NextPC + 1;
    const uint64_t PostAddPC2 = AddPC + 1;
    if (AddPC >= BytecodeSize ||
        static_cast<evmc_opcode>(Bytecode[AddPC]) != OP_ADD ||
        (PostAddPC2 < BytecodeSize &&
         static_cast<evmc_opcode>(Bytecode[PostAddPC2]) == OP_MSTORE)) {
      return false;
    }

    meterOpcodeSequence(Bytecode, PC, AddPC + 1);
    handlePushConstDupAddMacroOp(ConstOp, DupIndex);
    Ip += static_cast<ptrdiff_t>(NumBytes) + 2;
    return true;
  }

  bool tryHandleMemoryMacroOp(const uint8_t *Bytecode, size_t BytecodeSize,
                              evmc_opcode Opcode, const uint8_t *&Ip) {
    if (Opcode >= OP_PUSH0 && Opcode <= OP_PUSH32) {
      const uint8_t NumBytes =
          static_cast<uint8_t>(Opcode) - static_cast<uint8_t>(OP_PUSH0);
      const uint64_t MStorePC = PC + 1 + NumBytes;
      if (MStorePC < BytecodeSize &&
          static_cast<evmc_opcode>(Bytecode[MStorePC]) == OP_MSTORE) {
        meterOpcodeSequence(Bytecode, PC, MStorePC + 1);
        handlePushConstMStoreMacroOp(buildPushOperandAt(PC, NumBytes),
                                     MStorePC);
        Ip += static_cast<ptrdiff_t>(NumBytes) + 1;
        return true;
      }
      return false;
    }

    if (Opcode == OP_ADD) {
      const uint64_t MStorePC = PC + 1;
      if (MStorePC < BytecodeSize &&
          static_cast<evmc_opcode>(Bytecode[MStorePC]) == OP_MSTORE) {
        meterOpcodeSequence(Bytecode, PC, MStorePC + 1);
        handleAddMStoreMacroOp(MStorePC);
        Ip += 1;
        return true;
      }
      return false;
    }

    if (Opcode != OP_DUP1) {
      return false;
    }

    const uint64_t Dup1SecondPC = PC + 1;
    const uint64_t MStorePC = PC + 2;
    const uint64_t Dup2PC = PC + 3;
    const uint64_t AddPC = PC + 4;
    if (AddPC >= BytecodeSize) {
      return false;
    }
    if (static_cast<evmc_opcode>(Bytecode[Dup1SecondPC]) != OP_DUP1 ||
        static_cast<evmc_opcode>(Bytecode[MStorePC]) != OP_MSTORE ||
        static_cast<evmc_opcode>(Bytecode[Dup2PC]) != OP_DUP2 ||
        static_cast<evmc_opcode>(Bytecode[AddPC]) != OP_ADD) {
      return false;
    }

    meterOpcodeSequence(Bytecode, PC, AddPC + 1);
    handleLinearMStoreNextMacroOp(MStorePC);
    Ip += 4;
    return true;
  }

  void handleDupAddMacroOp(uint8_t DupIndex) {
    requireLogicalStackDepth(DupIndex);
    Operand DuplicatedValue = Stack.peek(DupIndex - 1);
    Operand TopValue = pop();
    Operand Result =
        Builder.template handleBinaryArithmetic<BinaryOperator::BO_ADD>(
            DuplicatedValue, TopValue);
    push(Result);
  }

  void handlePushConstAddMacroOp(const Operand &ConstOp) {
    requireLogicalStackDepth(1);
    Operand TopValue = pop();
    Operand Result =
        Builder.template handleBinaryArithmetic<BinaryOperator::BO_ADD>(
            ConstOp, TopValue);
    push(Result);
  }

  void handlePushConstDupAddMacroOp(const Operand &ConstOp, uint8_t DupIndex) {
    if (DupIndex > 1) {
      requireLogicalStackDepth(static_cast<uint32_t>(DupIndex) - 1u);
    }
    Operand SourceValue =
        DupIndex == 1 ? ConstOp
                      : Stack.peek(static_cast<uint32_t>(DupIndex) - 2u);
    Operand Result =
        Builder.template handleBinaryArithmetic<BinaryOperator::BO_ADD>(
            SourceValue, ConstOp);
    push(Result);
  }

  void handlePushConstMStoreMacroOp(const Operand &Addr, uint64_t MStorePC) {
    Builder.noteMemoryOpcodeInBlock(OP_MSTORE, MStorePC);
    maybePrepareLinearBlockMemoryPrecheck(OP_MSTORE);
    Operand Value = pop();
    Builder.handleMStore(Addr, Value);
  }

  void handleAddMStoreMacroOp(uint64_t MStorePC) {
    Operand AddLHS = pop();
    Operand AddRHS = pop();
    Operand Addr =
        Builder.template handleBinaryArithmetic<BinaryOperator::BO_ADD>(AddLHS,
                                                                        AddRHS);
    Builder.noteMemoryOpcodeInBlock(OP_MSTORE, MStorePC);
    maybePrepareLinearBlockMemoryPrecheck(OP_MSTORE);
    Operand Value = pop();
    Builder.handleMStore(Addr, Value);
  }

  void handleLinearMStoreNextMacroOp(uint64_t MStorePC) {
    requireLogicalStackDepth(2);
    Operand Current = Stack.peek(0);
    Operand Stride = Stack.peek(1);
    Builder.noteMemoryOpcodeInBlock(OP_MSTORE, MStorePC);
    maybePrepareLinearBlockMemoryPrecheck(OP_MSTORE);
    Builder.handleMStore(Current, Current);
    Operand Next =
        Builder.template handleBinaryArithmetic<BinaryOperator::BO_ADD>(Current,
                                                                        Stride);
    pop();
    push(Next);
  }

  void handlePush(uint8_t NumBytes) {
    Operand Result = buildPushOperandAt(PC, NumBytes);
    push(Result);
    PC += NumBytes;
  }

  Operand buildPushOperandAt(uint64_t OpcodePC, uint8_t NumBytes) {
    Bytes Data = readBytesAt(OpcodePC, NumBytes);
    return Builder.handlePush(Data);
  }

  Bytes readBytesAt(uint64_t OpcodePC, uint8_t Count) {
    const Byte *Bytecode = Ctx->getBytecode();
    uint64_t Start = OpcodePC + 1;
    uint64_t BytecodeSize = Ctx->getBytecodeSize();
    uint64_t Available = (Start < BytecodeSize) ? (BytecodeSize - Start) : 0;
    uint64_t ReadCount = (Count < Available) ? Count : Available;

    if (Count == 0) {
      return Bytes();
    }

    ZEN_ASSERT(Count <= EVM_MAX_PUSH_IMMEDIATE_SIZE);
    PushImmediateScratch.fill(Byte{0});
    for (uint64_t I = 0; I < ReadCount; ++I) {
      PushImmediateScratch[static_cast<size_t>(I)] = Bytecode[Start + I];
    }

    return Bytes(PushImmediateScratch.data(), Count);
  }

  std::array<Byte, EVM_MAX_PUSH_IMMEDIATE_SIZE> PushImmediateScratch = {};

  // DUP1-DUP16: Duplicate Nth stack item
  void handleDup(uint8_t Index) {
    requireLogicalStackDepth(Index);
    Operand Result = Stack.peek(Index - 1);
    push(Result);
  }

  // POP: Remove top stack item
  Operand handlePop() {
    Operand Result = pop();
    return Result;
  }

  // SWAP1-SWAP16: Swap top with Nth+1 stack item
  void handleSwap(uint8_t Index) {
    requireLogicalStackDepth(static_cast<uint32_t>(Index) + 1u);
    std::swap(Stack.peek(0), Stack.peek(Index));
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
  StackLifterType StackLifter;
  MemoryFactsBuilder MemoryFacts;
  bool InDeadCode = false;
  uint64_t PC = 0;
  uint64_t CurrentBlockEntryPC = 0;
  bool CurrentBlockLifted = false;
  bool DeferredLiftedJumpDestFallthrough = false;
};

} // namespace COMPILER

#endif // ZEN_ACTION_EVM_BYTECODE_VISITOR_H
