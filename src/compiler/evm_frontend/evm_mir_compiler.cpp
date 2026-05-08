// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "compiler/evm_frontend/evm_mir_compiler.h"
#include "action/evm_bytecode_visitor.h"
#include "compiler/evm_frontend/evm_imported.h"
#include "compiler/mir/constants.h"
#include "compiler/mir/module.h"
#include "evm/gas_storage_cost.h"
#include "runtime/evm_instance.h"
#include "utils/hash_utils.h"
#include "utils/logging.h"
#include "llvm/Support/Casting.h"
#include <cstdio>
#include <cstring>
#include <optional>
#include <queue>
#include <set>

#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
#include "compiler/llvm-prebuild/Target/X86/X86Subtarget.h"
#endif

namespace COMPILER {

// Hash table constants
constexpr uint64_t HashMultiplier = 0x9E3779B97F4A7C15ULL;
constexpr uint64_t MinHashSize = 5;
constexpr uint64_t MaxHashSize = 1024;
constexpr uint32_t InvalidJumpDestRunPC = 0xFFFFFFFFu;

zen::common::EVMU256Type *EVMFrontendContext::getEVMU256Type() {
  static zen::common::EVMU256Type U256Type;
  return &U256Type;
}

MType *EVMFrontendContext::getMIRTypeFromEVMType(EVMType Type) {
  switch (Type) {
  case EVMType::VOID:
    return &VoidType;
  case EVMType::UINT8:
    return &I8Type;
  case EVMType::UINT32:
    return &I32Type;
  case EVMType::UINT64:
    return &I64Type;
  case EVMType::UINT256:
    // U256 is represented as I64 for MIR operations, but we use EVMU256Type
    // to track the semantic meaning and provide proper 256-bit operations
    return &I64Type; // Primary component for MIR operations
  case EVMType::BYTES32:
    return &I64Type; // 32-byte data pointer as 64-bit value
  case EVMType::ADDRESS:
    return &I64Type; // Address as 64-bit value for simplicity
  case EVMType::BYTES:
    return &I32Type; // Byte array pointer
  default:
    ZEN_UNREACHABLE();
  }
}

void buildEVMFunction(EVMFrontendContext &Context, MModule &MMod,
                      const runtime::EVMModule &EVMMod) {
  CompileVector<MType *> MParamTypes(1, Context.ThreadMemPool);
  MParamTypes[0] = MPointerType::create(Context, Context.VoidType);
  MType *MRetType = Context.getMIRTypeFromEVMType(EVMType::VOID);
  MMod.addFuncType(MFunctionType::create(Context, *MRetType, MParamTypes));
}

// ==================== EVMFrontendContext Implementation ====================

EVMFrontendContext::EVMFrontendContext() {
  // Initialize basic DMIR context
}

EVMFrontendContext::EVMFrontendContext(const EVMFrontendContext &OtherCtx)
    : CompileContext(OtherCtx), Bytecode(OtherCtx.Bytecode),
      BytecodeSize(OtherCtx.BytecodeSize),
      GasMeteringEnabled(OtherCtx.GasMeteringEnabled),
      GasChunkEnd(OtherCtx.GasChunkEnd), GasChunkCost(OtherCtx.GasChunkCost),
      GasChunkSize(OtherCtx.GasChunkSize), Revision(OtherCtx.Revision),
      MemoryLinearStrideSkipLeadingZeroLimbStores(
          OtherCtx.MemoryLinearStrideSkipLeadingZeroLimbStores)
#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
      ,
      GasRegisterEnabled(OtherCtx.GasRegisterEnabled)
#endif
{
}

// ==================== EVMMirBuilder Implementation ====================

EVMMirBuilder::EVMMirBuilder(CompilerContext &Context, MFunction &MFunc)
    : Ctx(Context), CurFunc(&MFunc) {}

bool EVMMirBuilder::compile(CompilerContext *Context) {
  EVMByteCodeVisitor<EVMMirBuilder> Visitor(*this, Context);
  return Visitor.compile();
}

void EVMMirBuilder::registerDynamicJumpPhiIncomingBlock(uint64_t TargetBlockPC,
                                                        uint64_t PredBlockPC,
                                                        MBasicBlock *PredBB) {
  registerPhiIncomingBlock(TargetBlockPC, PredBlockPC, PredBB);
}

void EVMMirBuilder::registerPhiIncomingBlock(uint64_t TargetBlockPC,
                                             uint64_t PredBlockPC,
                                             MBasicBlock *PredBB) {
  const uint64_t CanonicalTargetPC = getCanonicalJumpDestPC(TargetBlockPC);
  DynamicPhiIncomingBlockTable[CanonicalTargetPC][PredBlockPC] =
      resolvePhiIncomingPredecessorBB(TargetBlockPC, PredBB);
}

MBasicBlock *EVMMirBuilder::getPhiIncomingBlock(uint64_t TargetBlockPC,
                                                uint64_t PredBlockPC) const {
  auto DynamicTargetIt =
      DynamicPhiIncomingBlockTable.find(getCanonicalJumpDestPC(TargetBlockPC));
  if (DynamicTargetIt != DynamicPhiIncomingBlockTable.end()) {
    auto DynamicPredIt = DynamicTargetIt->second.find(PredBlockPC);
    if (DynamicPredIt != DynamicTargetIt->second.end()) {
      return resolveReachablePhiIncomingPredecessorBB(TargetBlockPC,
                                                      DynamicPredIt->second);
    }
  }

  auto BlockIt = BlockEntryTable.find(PredBlockPC);
  if (BlockIt == BlockEntryTable.end()) {
    return nullptr;
  }
  return resolveReachablePhiIncomingPredecessorBB(TargetBlockPC,
                                                  BlockIt->second);
}

uint64_t EVMMirBuilder::getCanonicalJumpDestPC(uint64_t TargetBlockPC) const {
  auto It = JumpDestCanonicalPCTable.find(TargetBlockPC);
  return It == JumpDestCanonicalPCTable.end() ? TargetBlockPC : It->second;
}

MBasicBlock *EVMMirBuilder::resolvePhiIncomingPredecessorBB(
    uint64_t TargetBlockPC, MBasicBlock *DirectPredBB) const {
  const uint64_t CanonicalTargetPC = getCanonicalJumpDestPC(TargetBlockPC);
  auto BodyIt = JumpDestBodyTable.find(CanonicalTargetPC);
  if (BodyIt == JumpDestBodyTable.end()) {
    return DirectPredBB;
  }

  auto EntryIt = JumpDestTable.find(TargetBlockPC);
  if (EntryIt == JumpDestTable.end()) {
    return DirectPredBB;
  }

  return EntryIt->second == BodyIt->second ? DirectPredBB : EntryIt->second;
}

MBasicBlock *EVMMirBuilder::resolveReachablePhiIncomingPredecessorBB(
    uint64_t TargetBlockPC, MBasicBlock *CandidateBB) const {
  if (CandidateBB == nullptr) {
    return nullptr;
  }

  auto TargetIt = BlockEntryTable.find(TargetBlockPC);
  if (TargetIt == BlockEntryTable.end()) {
    return CandidateBB;
  }

  MBasicBlock *TargetBB = TargetIt->second;
  auto PredRange = TargetBB->predecessors();
  if (std::find(PredRange.begin(), PredRange.end(), CandidateBB) !=
      PredRange.end()) {
    return CandidateBB;
  }

  std::queue<MBasicBlock *> Worklist;
  std::set<MBasicBlock *> Visited;
  Worklist.push(CandidateBB);
  Visited.insert(CandidateBB);

  while (!Worklist.empty()) {
    MBasicBlock *CurrentBB = Worklist.front();
    Worklist.pop();

    for (MBasicBlock *SuccBB : CurrentBB->successors()) {
      if (SuccBB == nullptr || !Visited.insert(SuccBB).second) {
        continue;
      }
      if (std::find(PredRange.begin(), PredRange.end(), SuccBB) !=
          PredRange.end()) {
        return SuccBB;
      }
      Worklist.push(SuccBB);
    }
  }

  return CandidateBB;
}

void EVMMirBuilder::loadEVMInstanceAttr() {
  InstanceAddr = createInstruction<ConversionInstruction>(
      false, OP_ptrtoint, &Ctx.I64Type,
      createInstruction<DreadInstruction>(false, createVoidPtrType(), 0));

  // Initialize stack size variable
  StackSizeVar = CurFunc->createVariable(&Ctx.I64Type);
  const int32_t StackSizeOffset =
      zen::runtime::EVMInstance::getEVMStackSizeOffset();
  MInstruction *StackSize = getInstanceElement(&Ctx.I64Type, StackSizeOffset);
  createInstruction<DassignInstruction>(true, &(Ctx.VoidType), StackSize,
                                        StackSizeVar->getVarIdx());
  // Initialize stack top ptr int variable
  StackTopVar = CurFunc->createVariable(&Ctx.I64Type);
  MInstruction *StackPtrOffset = createIntConstInstruction(
      &Ctx.I64Type, zen::runtime::EVMInstance::getEVMStackOffset());
  MInstruction *StackBaseAddr = createInstruction<BinaryInstruction>(
      false, OP_add, &Ctx.I64Type, InstanceAddr, StackPtrOffset);
  MInstruction *StackTopAddr = createInstruction<BinaryInstruction>(
      false, OP_add, &Ctx.I64Type, StackBaseAddr, StackSize);
  createInstruction<DassignInstruction>(true, &(Ctx.VoidType), StackTopAddr,
                                        StackTopVar->getVarIdx());
  // Initialize jump target variable
  JumpTargetVar = CurFunc->createVariable(&Ctx.I64Type);

  // Cache memory base in a local for cheaper access
  MemoryBaseVar = CurFunc->createVariable(&Ctx.I64Type);
  MPointerType *VoidPtrType = createVoidPtrType();
  const int32_t MemoryBaseOffset =
      zen::runtime::EVMInstance::getMemoryBaseOffset();
  MInstruction *MemPtr = getInstanceElement(VoidPtrType, MemoryBaseOffset);
  MInstruction *MemBaseInt = createInstruction<ConversionInstruction>(
      false, OP_ptrtoint, &Ctx.I64Type, MemPtr);
  createInstruction<DassignInstruction>(true, &(Ctx.VoidType), MemBaseInt,
                                        MemoryBaseVar->getVarIdx());
  // Cache memory size in a local for MSIZE and memory growth checks
  MemorySizeVar = CurFunc->createVariable(&Ctx.I64Type);
  const int32_t MemorySizeOffset =
      zen::runtime::EVMInstance::getMemorySizeOffset();
  MInstruction *MemSize = getInstanceElement(&Ctx.I64Type, MemorySizeOffset);
  createInstruction<DassignInstruction>(true, &(Ctx.VoidType), MemSize,
                                        MemorySizeVar->getVarIdx());

  ExceptionReturnBB = CurFunc->createExceptionReturnBB();
}

MBasicBlock *EVMMirBuilder::getOrCreateIndirectJumpBB(uint64_t SourceBlockPC) {
  auto ExistingIt = IndirectJumpBBs.find(SourceBlockPC);
  if (ExistingIt != IndirectJumpBBs.end()) {
    return ExistingIt->second;
  }

  MBasicBlock *FromBB = CurBB;
  MBasicBlock *IndirectJumpBB = CurFunc->createBasicBlock();
  IndirectJumpBBs[SourceBlockPC] = IndirectJumpBB;
  setInsertBlock(IndirectJumpBB);
#ifdef ZEN_ENABLE_LINUX_PERF
  CurBB->setSourceOffset(CurPC);
  CurBB->setSourceName("SWITCH" + std::to_string(CurInstrIdx));
  CurInstrIdx++;
#endif // ZEN_ENABLE_LINUX_PERF

  MBasicBlock *FailureBB =
      getOrCreateExceptionSetBB(ErrorCode::EVMBadJumpDestination);
  MInstruction *JumpTarget = loadVariable(JumpTargetVar);
  MType *UInt64Type =
      EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);

  // If hash table is used, create mir to calculate hash index of JumpTarget
  // PC and create switch instruction with hash index
  if (!JumpHashTable.empty()) {
    // Initialize hash cases
    uint64_t MinHash = JumpHashTable.begin()->first;
    uint64_t MaxHash = JumpHashTable.rbegin()->first;
    CompileVector<std::pair<ConstantInstruction *, MBasicBlock *>> HashCases(
        MaxHash - MinHash + 1, Ctx.MemPool);

    // Calculate hash of JumpTarget
    MInstruction *MulConst =
        createIntConstInstruction(UInt64Type, HashMultiplier);
    MInstruction *MulResult = createInstruction<BinaryInstruction>(
        false, OP_mul, UInt64Type, JumpTarget, MulConst);
    MInstruction *AndResult = createInstruction<BinaryInstruction>(
        false, OP_and, UInt64Type, MulResult,
        createIntConstInstruction(UInt64Type, HashMask));
    MInstruction *HashDest = protectUnsafeValue(AndResult, UInt64Type);

    // Create cases for each hash entry
    for (uint64_t HashEntry = MinHash; HashEntry <= MaxHash; HashEntry++) {
      uint64_t HIndex = HashEntry - MinHash;
      HashCases[HIndex].first =
          createIntConstInstruction(UInt64Type, HashEntry);
      if (JumpHashTable.count(HashEntry) == 0) {
        // FailureBB for empty hash index
        HashCases[HIndex].second = FailureBB;
        addUniqueSuccessor(FailureBB);
        continue;
      }
      if (JumpHashTable[HashEntry].size() == 1) {
        // Even for single-entry hash buckets, we must explicitly verify that
        // the requested jump target matches the expected PC. Otherwise, any
        // invalid PC that collides with this hash bucket would wrongly jump to
        // this destination.
        MBasicBlock *OutsideBB = CurBB;
        MBasicBlock *CheckBB = createBasicBlock();
        CheckBB->setJumpDestBB(true);
        setInsertBlock(CheckBB);
        MInstruction *ExpectedPC = createIntConstInstruction(
            UInt64Type, JumpHashReverse[HashEntry][0]);
        MInstruction *IsMatch = createInstruction<CmpInstruction>(
            false, CmpInstruction::Predicate::ICMP_EQ, &Ctx.I64Type, JumpTarget,
            ExpectedPC);
        MBasicBlock *DestBB = JumpHashTable[HashEntry][0];
        registerDynamicJumpPhiIncomingBlock(JumpHashReverse[HashEntry][0],
                                            SourceBlockPC, CheckBB);
        createInstruction<BrIfInstruction>(true, Ctx, IsMatch, DestBB,
                                           FailureBB);
        addSuccessor(DestBB);
        addUniqueSuccessor(FailureBB);
        setInsertBlock(OutsideBB);
        HashCases[HIndex].second = CheckBB;
        addSuccessor(CheckBB);
      } else {
        // Create switch for conflict hash items
        MBasicBlock *OutsideBB = CurBB;
        MBasicBlock *SubCaseBB = createBasicBlock();
        SubCaseBB->setJumpDestBB(true);
        // Enter subcase BB
        setInsertBlock(SubCaseBB);
        auto &SubPCVec = JumpHashReverse[HashEntry];
        auto &SubDestBBVec = JumpHashTable[HashEntry];
        CompileVector<std::pair<ConstantInstruction *, MBasicBlock *>> SubCases(
            SubDestBBVec.size(), Ctx.MemPool);
        for (size_t I = 0; I < SubDestBBVec.size(); I++) {
          SubCases[I].first =
              createIntConstInstruction(UInt64Type, SubPCVec[I]);
          SubCases[I].second = SubDestBBVec[I];
          registerDynamicJumpPhiIncomingBlock(SubPCVec[I], SourceBlockPC,
                                              SubCaseBB);
          addSuccessor(SubDestBBVec[I]);
        }
        createInstruction<SwitchInstruction>(true, Ctx, JumpTarget, FailureBB,
                                             SubCases);
        addUniqueSuccessor(FailureBB);
        // Back to outside BB
        setInsertBlock(OutsideBB);
        HashCases[HIndex].second = SubCaseBB;
        addSuccessor(SubCaseBB);
      }
    }
    createInstruction<SwitchInstruction>(true, Ctx, HashDest, FailureBB,
                                         HashCases);
    addUniqueSuccessor(FailureBB);
    setInsertBlock(FromBB);
    return IndirectJumpBB;
  }

  CompileVector<std::pair<ConstantInstruction *, MBasicBlock *>> Cases(
      JumpDestTable.size(), Ctx.MemPool);

  uint64_t Index = 0;
  for (const auto &[DestPC, DestBB] : JumpDestTable) {
    Cases[Index].first = createIntConstInstruction(UInt64Type, DestPC);
    Cases[Index].second = DestBB;
    registerDynamicJumpPhiIncomingBlock(DestPC, SourceBlockPC, IndirectJumpBB);
    addSuccessor(DestBB);
    Index++;
  }

  createInstruction<SwitchInstruction>(true, Ctx, JumpTarget, FailureBB, Cases);
  addUniqueSuccessor(FailureBB);
  setInsertBlock(FromBB);
  return IndirectJumpBB;
}

void EVMMirBuilder::initEVM(CompilerContext *Context) {
  // Create entry basic block
  MBasicBlock *EntryBB = createBasicBlock();
  setInsertBlock(EntryBB);

  const auto *EvmCtx = static_cast<const EVMFrontendContext *>(&Ctx);
  const evmc_revision Rev = EvmCtx->getRevision();
  InstructionMetrics = evmc_get_instruction_metrics_table(Rev);
  InstructionNames = evmc_get_instruction_names_table(Rev);
  if (!InstructionMetrics) {
    InstructionMetrics =
        evmc_get_instruction_metrics_table(zen::evm::DEFAULT_REVISION);
  }
  if (!InstructionNames) {
    InstructionNames =
        evmc_get_instruction_names_table(zen::evm::DEFAULT_REVISION);
  }

  ReturnBB = createBasicBlock();
  loadEVMInstanceAttr();

  GasChunkEnd = EvmCtx->getGasChunkEnd();
  GasChunkCost = EvmCtx->getGasChunkCost();
  GasChunkSize = EvmCtx->getGasChunkSize();

#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
  initGasRegister();
#endif

  createJumpTable();

#ifdef ZEN_ENABLE_LINUX_PERF
  CurBB->setSourceOffset(1);
  CurBB->setSourceName("MAIN_ENTRY");
  CurPC = 0;
#endif // ZEN_ENABLE_LINUX_PERF
}

void EVMMirBuilder::finalizeEVMBase() {
  const auto &ExceptionSetBBs = CurFunc->getExceptionSetBBs();

  VariableIdx ExceptionIDIdx =
      CurFunc->createVariable(&Ctx.I32Type)->getVarIdx();
  MBasicBlock *ExceptionHandlingBB = CurFunc->createExceptionHandlingBB();

  auto GenExceptionSetBBs = [&]() {
    for (const auto [ErrCode, ExceptionSetBB] : ExceptionSetBBs) {
      setInsertBlock(ExceptionSetBB);
      // Fatal EVM exceptions must burn all remaining gas before bubbling up.
      drainGas();
      createInstruction<DassignInstruction>(
          true, &Ctx.VoidType,
          createIntConstInstruction(&Ctx.I32Type,
                                    common::to_underlying(ErrCode)),
          ExceptionIDIdx);
      createInstruction<BrInstruction>(true, Ctx, ExceptionHandlingBB);
      addSuccessor(ExceptionHandlingBB);
    }
  };

  auto HandleException = [&](uintptr_t ExceptionHandlerAddr) {
    MInstruction *HandlerAddr =
        createIntConstInstruction(&Ctx.I64Type, ExceptionHandlerAddr);

    CompileVector<MInstruction *> SetExceptionArgs{
        {
            InstanceAddr,
            createInstruction<DreadInstruction>(false, &Ctx.I32Type,
                                                ExceptionIDIdx),
        },
        Ctx.MemPool,
    };
    createInstruction<ICallInstruction>(true, &Ctx.VoidType, HandlerAddr,
                                        SetExceptionArgs);

    createInstruction<BrInstruction>(true, Ctx, ExceptionReturnBB);
    addSuccessor(ExceptionReturnBB);
  };

#if defined(ZEN_ENABLE_CPU_EXCEPTION) && !defined(ZEN_ENABLE_DWASM)
  // When check call exception after call_indirect or call hostapi, just
  // throw, no need set args again
  auto ThrowException = [&] {
    MInstruction *ThrowExceptionAddr = createIntConstInstruction(
        &Ctx.I64Type,
        uintptr_t(zen::runtime::EVMInstance::throwInstanceExceptionOnJIT));

    CompileVector<MInstruction *> ThrowExceptionArgs{
        {InstanceAddr},
        Ctx.MemPool,
    };
    createInstruction<ICallInstruction>(true, &Ctx.VoidType, ThrowExceptionAddr,
                                        ThrowExceptionArgs);
  };
  // Has exceptions that cannot be checked by cpu-hardware
  // No need to worry about underflow
  bool HasPureSoftException =
      ExceptionSetBBs.size() -
          ExceptionSetBBs.count(ErrorCode::OutOfBoundsMemory) >
      0;

  if (HasPureSoftException) {
    GenExceptionSetBBs();
    setInsertBlock(ExceptionHandlingBB);
    HandleException(
        uintptr_t(zen::runtime::EVMInstance::setInstanceExceptionOnJIT));
    setInsertBlock(ExceptionReturnBB);
    ThrowException();
    handleVoidReturn();
  } else {
    CurFunc->deleteMBasicBlock(ExceptionHandlingBB);
    CurFunc->deleteMBasicBlock(ExceptionReturnBB);
  }
#else
  GenExceptionSetBBs();
  setInsertBlock(ExceptionHandlingBB);
  HandleException(
      uintptr_t(zen::runtime::EVMInstance::triggerInstanceExceptionOnJIT));
  setInsertBlock(ExceptionReturnBB);
  handleVoidReturn();
#endif

  if (ReturnBB &&
      std::find(CurFunc->begin(), CurFunc->end(), ReturnBB) == CurFunc->end()) {
    CurFunc->deleteMBasicBlock(ReturnBB);
    ReturnBB = nullptr;
  }
}

LoadInstruction *EVMMirBuilder::getInstanceElement(MType *ValueType,
                                                   uint32_t Scale,
                                                   MInstruction *Index,
                                                   int32_t Offset) {
  MPointerType *ValuePtrType = MPointerType::create(Ctx, *ValueType);
  MInstruction *InstancePtr =
      createInstruction<DreadInstruction>(false, ValuePtrType, 0);
  return createInstruction<LoadInstruction>(false, ValueType, InstancePtr,
                                            Scale, Index, Offset);
}

StoreInstruction *EVMMirBuilder::setInstanceElement(MType *ValueType,
                                                    MInstruction *Value,
                                                    int32_t Offset) {
  ZEN_ASSERT(Offset >= 0);
  MPointerType *ValuePtrType = MPointerType::create(Ctx, *ValueType);
  MInstruction *InstancePtr =
      createInstruction<DreadInstruction>(false, ValuePtrType, 0);
  return createInstruction<StoreInstruction>(true, &Ctx.VoidType, Value,
                                             InstancePtr, Offset);
}

void EVMMirBuilder::meterOpcode(evmc_opcode Opcode, uint64_t PC) {
  if (!Ctx.isGasMeteringEnabled()) {
    return;
  }
  if (GasChunkEnd && GasChunkCost && PC < GasChunkSize) {
    if (GasChunkEnd[PC] > PC) {
      meterGas(GasChunkCost[PC]);
    }
    return;
  }
  const uint8_t Index = static_cast<uint8_t>(Opcode);
  const auto &Metrics = InstructionMetrics[Index];
  meterGas(static_cast<uint64_t>(Metrics.gas_cost));
}

void EVMMirBuilder::meterOpcodeRange(uint64_t StartPC,
                                     uint64_t EndPCExclusive) {
  if (!Ctx.isGasMeteringEnabled() || StartPC >= EndPCExclusive) {
    return;
  }

  // Fast path for merged consecutive JUMPDEST runs: the skipped cost for
  // [StartPC, EndPCExclusive) is precomputed once when building the jump table.
  if (StartPC < JumpDestRunLastPC.size()) {
    const uint32_t RunLastPC = JumpDestRunLastPC[static_cast<size_t>(StartPC)];
    if (RunLastPC != InvalidJumpDestRunPC &&
        static_cast<uint64_t>(RunLastPC) == EndPCExclusive) {
      meterGas(JumpDestRunSkipCost[static_cast<size_t>(StartPC)]);
      return;
    }
  }

  const auto *EvmCtx = static_cast<const EVMFrontendContext *>(&Ctx);
  const Byte *Bytecode = EvmCtx->getBytecode();
  if (!Bytecode) {
    return;
  }

  const uint64_t CodeSize = static_cast<uint64_t>(EvmCtx->getBytecodeSize());
  if (StartPC >= CodeSize) {
    return;
  }
  EndPCExclusive = std::min(EndPCExclusive, CodeSize);

  uint64_t TotalCost = 0;
  for (uint64_t PC = StartPC; PC < EndPCExclusive; ++PC) {
    uint64_t Cost = 0;
    if (GasChunkEnd && GasChunkCost && PC < GasChunkSize &&
        GasChunkEnd[PC] > PC) {
      Cost = GasChunkCost[PC];
    } else {
      const uint8_t Opcode = static_cast<uint8_t>(Bytecode[PC]);
      Cost = static_cast<uint64_t>(InstructionMetrics[Opcode].gas_cost);
    }

    if (UINT64_MAX - TotalCost < Cost) {
      TotalCost = UINT64_MAX;
      break;
    }
    TotalCost += Cost;
  }

  meterGas(TotalCost);
}

bool EVMMirBuilder::isOpcodeDefined(evmc_opcode Opcode) const {
  const uint8_t Index = static_cast<uint8_t>(Opcode);
  if (InstructionNames && InstructionNames[Index] != nullptr) {
    return true;
  }
  if (!InstructionMetrics) {
    return true;
  }
  const auto &Metrics = InstructionMetrics[Index];
  return Metrics.gas_cost != 0 || Metrics.stack_height_required != 0 ||
         Metrics.stack_height_change != 0;
}

void EVMMirBuilder::meterGas(uint64_t GasCost) {
  if (!Ctx.isGasMeteringEnabled() || GasCost == 0) {
    return;
  }

  MType *I64Type = EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);

#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
  if (Ctx.isGasRegisterEnabled() && GasRegVar) {
    // Pure register path: read from register, write to register only
    // Sync to memory happens at specific points (CALL/CREATE/return)
    MInstruction *CurrentGas = loadVariable(GasRegVar);
    MInstruction *GasCostValue = createIntConstInstruction(I64Type, GasCost);

    // Out-of-gas check
    MInstruction *IsOutOfGas = createInstruction<CmpInstruction>(
        false, CmpInstruction::Predicate::ICMP_ULT, &Ctx.I64Type, CurrentGas,
        GasCostValue);

    MBasicBlock *ContinueBB = createBasicBlock();
    MBasicBlock *OutOfGasBB =
        getOrCreateExceptionSetBB(ErrorCode::GasLimitExceeded);
    createInstruction<BrIfInstruction>(true, Ctx, IsOutOfGas, OutOfGasBB,
                                       ContinueBB);
    addUniqueSuccessor(OutOfGasBB);
    addSuccessor(ContinueBB);
    setInsertBlock(ContinueBB);

    // Subtract gas and update register only (no memory write)
    MInstruction *NewGas = createInstruction<BinaryInstruction>(
        false, OP_sub, I64Type, CurrentGas, GasCostValue);
    createInstruction<DassignInstruction>(true, &(Ctx.VoidType), NewGas,
                                          GasRegVar->getVarIdx());
    return;
  }
#endif

  // Memory-based gas metering (original implementation)
  MPointerType *VoidPtrType = createVoidPtrType();
  MPointerType *I64PtrType = MPointerType::create(Ctx, Ctx.I64Type);

  MInstruction *GasOffsetValue = createIntConstInstruction(
      I64Type, zen::runtime::EVMInstance::getGasFieldOffset());
  MInstruction *GasAddrInt = createInstruction<BinaryInstruction>(
      false, OP_add, I64Type, InstanceAddr, GasOffsetValue);
  MInstruction *GasPtr = createInstruction<ConversionInstruction>(
      false, OP_inttoptr, I64PtrType, GasAddrInt);
  MInstruction *GasValue =
      createInstruction<LoadInstruction>(false, I64Type, GasPtr);

  MInstruction *GasCostValue = createIntConstInstruction(I64Type, GasCost);
  MInstruction *IsOutOfGas = createInstruction<CmpInstruction>(
      false, CmpInstruction::Predicate::ICMP_ULT, &Ctx.I64Type, GasValue,
      GasCostValue);

  MBasicBlock *ContinueBB = createBasicBlock();
  MBasicBlock *OutOfGasBB =
      getOrCreateExceptionSetBB(ErrorCode::GasLimitExceeded);
  createInstruction<BrIfInstruction>(true, Ctx, IsOutOfGas, OutOfGasBB,
                                     ContinueBB);
  addUniqueSuccessor(OutOfGasBB);
  addSuccessor(ContinueBB);
  setInsertBlock(ContinueBB);

  MInstruction *NewGas = createInstruction<BinaryInstruction>(
      false, OP_sub, I64Type, GasValue, GasCostValue);

  createInstruction<StoreInstruction>(true, &Ctx.VoidType, NewGas, GasPtr);

  MInstruction *MsgPtr = getInstanceElement(
      VoidPtrType, zen::runtime::EVMInstance::getCurrentMessagePointerOffset());
  MInstruction *MsgPtrInt = createInstruction<ConversionInstruction>(
      false, OP_ptrtoint, I64Type, MsgPtr);
  MInstruction *Zero = createIntConstInstruction(I64Type, 0);
  MInstruction *HasMsg = createInstruction<CmpInstruction>(
      false, CmpInstruction::Predicate::ICMP_NE, &Ctx.I64Type, MsgPtrInt, Zero);
  MBasicBlock *MsgStoreBB = createBasicBlock();
  MBasicBlock *MsgSkipBB = createBasicBlock();
  createInstruction<BrIfInstruction>(true, Ctx, HasMsg, MsgStoreBB, MsgSkipBB);
  addSuccessor(MsgStoreBB);
  addSuccessor(MsgSkipBB);

  setInsertBlock(MsgStoreBB);
  MInstruction *MsgGasOffsetValue = createIntConstInstruction(
      I64Type, zen::runtime::EVMInstance::getMessageGasOffset());
  MInstruction *MsgGasAddrInt = createInstruction<BinaryInstruction>(
      false, OP_add, I64Type, MsgPtrInt, MsgGasOffsetValue);
  MInstruction *MsgGasPtr = createInstruction<ConversionInstruction>(
      false, OP_inttoptr, I64PtrType, MsgGasAddrInt);
  createInstruction<StoreInstruction>(true, &Ctx.VoidType, NewGas, MsgGasPtr);
  createInstruction<BrInstruction>(true, Ctx, MsgSkipBB);
  addSuccessor(MsgSkipBB);
  setInsertBlock(MsgSkipBB);
}

#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
void EVMMirBuilder::initGasRegister() {
  if (!Ctx.isGasRegisterEnabled()) {
    return;
  }

  MType *I64Type = EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);
  MPointerType *I64PtrType = MPointerType::create(Ctx, Ctx.I64Type);
  MPointerType *VoidPtrType = createVoidPtrType();

  // Load gas from message->gas
  MInstruction *MsgPtr = getInstanceElement(
      VoidPtrType, zen::runtime::EVMInstance::getCurrentMessagePointerOffset());
  MInstruction *MsgPtrInt = createInstruction<ConversionInstruction>(
      false, OP_ptrtoint, I64Type, MsgPtr);
  MInstruction *MsgGasOffsetValue = createIntConstInstruction(
      I64Type, zen::runtime::EVMInstance::getMessageGasOffset());
  MInstruction *MsgGasAddrInt = createInstruction<BinaryInstruction>(
      false, OP_add, I64Type, MsgPtrInt, MsgGasOffsetValue);
  MInstruction *MsgGasPtr = createInstruction<ConversionInstruction>(
      false, OP_inttoptr, I64PtrType, MsgGasAddrInt);
  MInstruction *GasValue =
      createInstruction<LoadInstruction>(false, I64Type, MsgGasPtr);

  // Create GasRegVar - will be allocated to virtual register
  // Explicit COPY instructions will be added during lowering
  GasRegVar = storeInstructionInTemp(GasValue, I64Type);

  // Store the VarIdx so lowering can identify this variable
  CurFunc->setGasRegisterVarIdx(GasRegVar->getVarIdx());
}

void EVMMirBuilder::syncGasToMemory() {
  if (!Ctx.isGasRegisterEnabled() || !GasRegVar) {
    return;
  }

  MType *I64Type = EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);
  MPointerType *I64PtrType = MPointerType::create(Ctx, Ctx.I64Type);

  MInstruction *GasValue = loadVariable(GasRegVar);

  // Only store to instance->Gas (runtime functions use getGas() which reads
  // this) Msg->gas is updated only in syncGasToMemoryFull() before returning
  MInstruction *GasOffsetValue = createIntConstInstruction(
      I64Type, zen::runtime::EVMInstance::getGasFieldOffset());
  MInstruction *GasAddrInt = createInstruction<BinaryInstruction>(
      false, OP_add, I64Type, InstanceAddr, GasOffsetValue);
  MInstruction *GasPtr = createInstruction<ConversionInstruction>(
      false, OP_inttoptr, I64PtrType, GasAddrInt);
  createInstruction<StoreInstruction>(true, &Ctx.VoidType, GasValue, GasPtr);
}

void EVMMirBuilder::syncGasToMemoryFull() {
  if (!Ctx.isGasRegisterEnabled() || !GasRegVar) {
    return;
  }

  MType *I64Type = EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);
  MPointerType *I64PtrType = MPointerType::create(Ctx, Ctx.I64Type);
  MPointerType *VoidPtrType = createVoidPtrType();

  MInstruction *GasValue = loadVariable(GasRegVar);

  // Store to instance->Gas
  MInstruction *GasOffsetValue = createIntConstInstruction(
      I64Type, zen::runtime::EVMInstance::getGasFieldOffset());
  MInstruction *GasAddrInt = createInstruction<BinaryInstruction>(
      false, OP_add, I64Type, InstanceAddr, GasOffsetValue);
  MInstruction *GasPtr = createInstruction<ConversionInstruction>(
      false, OP_inttoptr, I64PtrType, GasAddrInt);
  createInstruction<StoreInstruction>(true, &Ctx.VoidType, GasValue, GasPtr);

  // Store to message->gas
  MInstruction *MsgPtr = getInstanceElement(
      VoidPtrType, zen::runtime::EVMInstance::getCurrentMessagePointerOffset());
  MInstruction *MsgPtrInt = createInstruction<ConversionInstruction>(
      false, OP_ptrtoint, I64Type, MsgPtr);
  MInstruction *MsgGasOffsetValue = createIntConstInstruction(
      I64Type, zen::runtime::EVMInstance::getMessageGasOffset());
  MInstruction *MsgGasAddrInt = createInstruction<BinaryInstruction>(
      false, OP_add, I64Type, MsgPtrInt, MsgGasOffsetValue);
  MInstruction *MsgGasPtr = createInstruction<ConversionInstruction>(
      false, OP_inttoptr, I64PtrType, MsgGasAddrInt);
  createInstruction<StoreInstruction>(true, &Ctx.VoidType, GasValue, MsgGasPtr);
}

void EVMMirBuilder::reloadGasFromMemory() {
  if (!Ctx.isGasRegisterEnabled() || !GasRegVar) {
    return;
  }

  MType *I64Type = EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);
  MPointerType *I64PtrType = MPointerType::create(Ctx, Ctx.I64Type);

  // Reload from instance->Gas (consistent with syncGasToMemory)
  // Runtime functions update both Instance->Gas and Msg->gas, so either works
  MInstruction *GasOffsetValue = createIntConstInstruction(
      I64Type, zen::runtime::EVMInstance::getGasFieldOffset());
  MInstruction *GasAddrInt = createInstruction<BinaryInstruction>(
      false, OP_add, I64Type, InstanceAddr, GasOffsetValue);
  MInstruction *GasPtr = createInstruction<ConversionInstruction>(
      false, OP_inttoptr, I64PtrType, GasAddrInt);
  MInstruction *GasValue =
      createInstruction<LoadInstruction>(false, I64Type, GasPtr);

  createInstruction<DassignInstruction>(true, &(Ctx.VoidType), GasValue,
                                        GasRegVar->getVarIdx());
}
#endif

void EVMMirBuilder::createStackCheckBlock(int32_t MinSize, int32_t MaxSize) {
  // Create a new basic block for stack checking
  MType *I64Type = EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);
  // Get runtime stack size
  MInstruction *StackSize = loadVariable(StackSizeVar);
  if (MinSize > 0) {
    MInstruction *MinSizeConst =
        createIntConstInstruction(I64Type, MinSize * 32);
    // Check if StackSize less than MinSize
    MInstruction *IsUnderflow = createInstruction<CmpInstruction>(
        false, CmpInstruction::ICMP_ULT, &Ctx.I64Type, StackSize, MinSizeConst);
    // Handle EVMStackUnderflow in exception BB
    MBasicBlock *StackUnderflowBB = CurFunc->getOrCreateExceptionSetBB(
        common::ErrorCode::EVMStackUnderflow);
    MBasicBlock *MaxCheckBB = createBasicBlock();
    createInstruction<BrIfInstruction>(true, Ctx, IsUnderflow, StackUnderflowBB,
                                       MaxCheckBB);
    addUniqueSuccessor(StackUnderflowBB);
    addSuccessor(MaxCheckBB);
    setInsertBlock(MaxCheckBB);
  }

  MInstruction *MaxSizeConst = createIntConstInstruction(I64Type, MaxSize * 32);
  // Check if StackSize greater than MaxSize
  MInstruction *IsOverflow = createInstruction<CmpInstruction>(
      false, CmpInstruction::ICMP_UGT, &Ctx.I64Type, StackSize, MaxSizeConst);

  // Use an intermediate SyncBB to avoid a critical edge (multi-successor →
  // multi-predecessor) between this check and the shared StackOverflowBB.
  // Also sync StackSize to Instance for accurate diagnostics on overflow.
  MBasicBlock *SyncBB = createBasicBlock();
  MBasicBlock *StackOverflowBB =
      CurFunc->getOrCreateExceptionSetBB(common::ErrorCode::EVMStackOverflow);
  MBasicBlock *FollowBB = createBasicBlock();
  createInstruction<BrIfInstruction>(true, Ctx, IsOverflow, SyncBB, FollowBB);
  addSuccessor(SyncBB);
  addSuccessor(FollowBB);

  setInsertBlock(SyncBB);
  const int32_t StackSizeOffset =
      zen::runtime::EVMInstance::getEVMStackSizeOffset();
  setInstanceElement(&Ctx.I64Type, StackSize, StackSizeOffset);
  createInstruction<BrInstruction>(true, Ctx, StackOverflowBB);
  addUniqueSuccessor(StackOverflowBB);

  setInsertBlock(FollowBB);
}

MInstruction *EVMMirBuilder::getInstanceStackTopInt() {
  return loadVariable(StackTopVar);
}

MInstruction *EVMMirBuilder::getInstanceStackPeekInt(int32_t IndexFromTop) {
  MType *I64Type = EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);

  // Get runtime stack size from instance
  MInstruction *StackSize = loadVariable(StackSizeVar);
  MInstruction *StackTopInt = getInstanceStackTopInt();

  int32_t ConstOffset = (IndexFromTop + 1) * 32;
  MInstruction *TopOffset = createIntConstInstruction(I64Type, ConstOffset);

  MInstruction *PeekBase = createInstruction<BinaryInstruction>(
      false, OP_sub, &Ctx.I64Type, StackTopInt, TopOffset);
  return PeekBase;
}

void EVMMirBuilder::stackPush(Operand PushValue) {
  // This pushes element to stack with store
  U256Inst PushComponents = extractU256Operand(PushValue);
  MType *I64Type = EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);
  MPointerType *U64PtrType = MPointerType::create(Ctx, Ctx.I64Type);

  // Get runtime stack size from variable
  MInstruction *StackSize = loadVariable(StackSizeVar);

  // NewSize = StackSize + 32
  MInstruction *Const32 = createIntConstInstruction(I64Type, 32);
  MInstruction *NewSize = createInstruction<BinaryInstruction>(
      false, OP_add, I64Type, StackSize, Const32);

  // Save stack data to StackTopPtr
  const int32_t InnerOffsets[EVM_ELEMENTS_COUNT] = {0, 8, 16, 24};
  MInstruction *StackTopInt = getInstanceStackTopInt();
  MInstruction *StackTopPtr = createInstruction<ConversionInstruction>(
      false, OP_inttoptr, U64PtrType, StackTopInt);

  // Save stack data
  for (size_t I = 0; I < EVM_ELEMENTS_COUNT; ++I) {
    // Store to StackTopPtr + I * 8
    createInstruction<StoreInstruction>(true, &Ctx.VoidType, PushComponents[I],
                                        StackTopPtr, InnerOffsets[I]);
  }
  // Update stack top
  MInstruction *NewTop = createInstruction<BinaryInstruction>(
      false, OP_add, I64Type, StackTopInt, Const32);
  createInstruction<DassignInstruction>(true, &(Ctx.VoidType), NewTop,
                                        StackTopVar->getVarIdx());
  // Update stack size
  createInstruction<DassignInstruction>(true, &(Ctx.VoidType), NewSize,
                                        StackSizeVar->getVarIdx());
}

typename EVMMirBuilder::Operand EVMMirBuilder::stackPop() {
  MType *I64Type = EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);
  MPointerType *U64PtrType = MPointerType::create(Ctx, Ctx.I64Type);

  // Get runtime stack size from instance
  MInstruction *StackSize = loadVariable(StackSizeVar);

  // NewSize = StackSize - 32
  MInstruction *Const32 = createIntConstInstruction(I64Type, 32);
  MInstruction *NewSize = createInstruction<BinaryInstruction>(
      false, OP_sub, I64Type, StackSize, Const32);

  // Load stack data from StackPtr (top -32, -24, -16, -8)
  const int32_t SubInnerOffsets[EVM_ELEMENTS_COUNT] = {-32, -24, -16, -8};
  U256Inst PopComponents = {};
  MInstruction *StackTopInt = getInstanceStackTopInt();
  MInstruction *StackTopPtr = createInstruction<ConversionInstruction>(
      false, OP_inttoptr, U64PtrType, StackTopInt);

  for (size_t I = 0; I < EVM_ELEMENTS_COUNT; ++I) {
    // Load from StackPtr - SubInnerOffsets[I]
    MInstruction *LoadInstr = createInstruction<LoadInstruction>(
        false, I64Type, StackTopPtr, 1, nullptr, SubInnerOffsets[I]);
    Variable *ValVar = storeInstructionInTemp(LoadInstr, I64Type);
    PopComponents[I] = loadVariable(ValVar);
  }
  // Update stack top
  MInstruction *NewTop = createInstruction<BinaryInstruction>(
      false, OP_sub, I64Type, StackTopInt, Const32);
  createInstruction<DassignInstruction>(true, &(Ctx.VoidType), NewTop,
                                        StackTopVar->getVarIdx());
  // Update stack size
  createInstruction<DassignInstruction>(true, &(Ctx.VoidType), NewSize,
                                        StackSizeVar->getVarIdx());
  return Operand(PopComponents, EVMType::UINT256);
}

void EVMMirBuilder::stackSet(int32_t IndexFromTop, Operand SetValue) {
  // This set element to stack with index from top
  U256Inst SetComponents = extractU256Operand(SetValue);
  MType *I64Type = EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);
  MPointerType *U64PtrType = MPointerType::create(Ctx, Ctx.I64Type);

  MInstruction *PeekBase = getInstanceStackPeekInt(IndexFromTop);
  MInstruction *PeekPtr = createInstruction<ConversionInstruction>(
      false, OP_inttoptr, U64PtrType, PeekBase);

  // Stack offset from peek base
  const int32_t InnerOffsets[EVM_ELEMENTS_COUNT] = {0, 8, 16, 24};
  // Save stack data
  for (size_t I = 0; I < EVM_ELEMENTS_COUNT; ++I) {
    // Store to PeekPtr + I * 8
    createInstruction<StoreInstruction>(true, &Ctx.VoidType, SetComponents[I],
                                        PeekPtr, InnerOffsets[I]);
  }
}

typename EVMMirBuilder::Operand EVMMirBuilder::stackGet(int32_t IndexFromTop) {
  // This set element to stack with index from top
  MType *I64Type = EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);
  MPointerType *U64PtrType = MPointerType::create(Ctx, Ctx.I64Type);

  MInstruction *PeekBase = getInstanceStackPeekInt(IndexFromTop);
  MInstruction *PeekPtr = createInstruction<ConversionInstruction>(
      false, OP_inttoptr, U64PtrType, PeekBase);

  // Stack offset from peek base
  const int32_t InnerOffsets[EVM_ELEMENTS_COUNT] = {0, 8, 16, 24};
  U256Inst GetComponents = {};
  // Load stack data
  for (size_t I = 0; I < EVM_ELEMENTS_COUNT; ++I) {
    // Load from PeekPtr + I * 8
    MInstruction *LoadInstr = createInstruction<LoadInstruction>(
        false, I64Type, PeekPtr, 1, nullptr, InnerOffsets[I]);
    Variable *ValVar = storeInstructionInTemp(LoadInstr, I64Type);
    // Load from PeekPtr + I * 8
    GetComponents[I] = loadVariable(ValVar);
  }
  return Operand(GetComponents, EVMType::UINT256);
}

void EVMMirBuilder::setTrackedStackDepth(uint32_t Depth) {
  MType *I64Type = EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);
  uint64_t StackBytes = static_cast<uint64_t>(Depth) * 32ULL;
  MInstruction *StackSize = createIntConstInstruction(I64Type, StackBytes);
  createInstruction<DassignInstruction>(true, &(Ctx.VoidType), StackSize,
                                        StackSizeVar->getVarIdx());

  MInstruction *StackPtrOffset = createIntConstInstruction(
      &Ctx.I64Type, zen::runtime::EVMInstance::getEVMStackOffset());
  MInstruction *StackBaseAddr = createInstruction<BinaryInstruction>(
      false, OP_add, &Ctx.I64Type, InstanceAddr, StackPtrOffset);
  MInstruction *StackTopAddr = createInstruction<BinaryInstruction>(
      false, OP_add, &Ctx.I64Type, StackBaseAddr, StackSize);
  createInstruction<DassignInstruction>(true, &(Ctx.VoidType), StackTopAddr,
                                        StackTopVar->getVarIdx());
}

typename EVMMirBuilder::Operand EVMMirBuilder::createStackEntryOperand() {
  U256Var Vars = {};
  for (size_t I = 0; I < EVM_ELEMENTS_COUNT; ++I) {
    Vars[I] = CurFunc->createVariable(&Ctx.I64Type);
  }
  return Operand(Vars, EVMType::UINT256);
}

void EVMMirBuilder::assignStackEntryOperand(const Operand &Dest,
                                            const Operand &Value) {
  ZEN_ASSERT(Dest.isU256MultiComponent() && "stack entry operand must be U256");
  U256Var DestVars = Dest.getU256VarComponents();
  U256Inst Src = extractU256Operand(Value);
  for (size_t I = 0; I < EVM_ELEMENTS_COUNT; ++I) {
    ZEN_ASSERT(DestVars[I] != nullptr);
    createInstruction<DassignInstruction>(true, &(Ctx.VoidType), Src[I],
                                          DestVars[I]->getVarIdx());
  }
}

typename EVMMirBuilder::Operand
EVMMirBuilder::prepareStackPhiIncoming(const Operand &Value) {
  U256Inst Prepared = {};
  U256Inst Src = extractU256Operand(Value);
  for (size_t I = 0; I < EVM_ELEMENTS_COUNT; ++I) {
    Prepared[I] = protectUnsafeValue(Src[I], &Ctx.I64Type);
  }
  return Operand(Prepared, EVMType::UINT256);
}

void EVMMirBuilder::registerCurrentBlockPC(uint64_t BlockPC) {
  CurrentBlockPC = BlockPC;
  BlockEntryTable[BlockPC] = CurBB;
}

typename EVMMirBuilder::Operand EVMMirBuilder::materializeStackMergeOperand(
    const std::vector<uint64_t> &PredBlockPCs,
    const std::vector<std::pair<uint64_t, Operand>> &IncomingValues) {
  std::map<uint64_t, Operand> IncomingValueMap;
  for (const auto &[PredBlockPC, Value] : IncomingValues) {
    IncomingValueMap[PredBlockPC] = Value;
  }

  U256Inst PhiComponents = {};
  U256Var PhiVars = {};
  auto PredRange = CurBB->predecessors();
  const size_t ActualPredCount =
      static_cast<size_t>(std::distance(PredRange.begin(), PredRange.end()));
  for (size_t ComponentIndex = 0; ComponentIndex < EVM_ELEMENTS_COUNT;
       ++ComponentIndex) {
    PhiInstruction *Phi = createPendingPhi(&Ctx.I64Type, PredBlockPCs.size());
    auto &SlotMap = PhiIncomingSlotMap[Phi];
    for (size_t IncomingIndex = 0; IncomingIndex < PredBlockPCs.size();
         ++IncomingIndex) {
      uint64_t PredBlockPC = PredBlockPCs[IncomingIndex];
      SlotMap[PredBlockPC] = IncomingIndex;

      auto IncomingIt = IncomingValueMap.find(PredBlockPC);
      if (IncomingIt == IncomingValueMap.end()) {
        continue;
      }

      MBasicBlock *IncomingBB =
          getPhiIncomingBlock(CurrentBlockPC, PredBlockPC);
      if ((IncomingBB == nullptr ||
           std::find(PredRange.begin(), PredRange.end(), IncomingBB) ==
               PredRange.end()) &&
          IncomingIndex < ActualPredCount) {
        IncomingBB = *(PredRange.begin() + IncomingIndex);
      }
      ZEN_ASSERT(
          IncomingBB != nullptr &&
          "phi incoming block must be registered before materialization");
      U256Inst IncomingComponents = extractU256Operand(IncomingIt->second);
      Phi->setIncoming(IncomingIndex, IncomingBB,
                       IncomingComponents[ComponentIndex]);
    }
    PhiComponents[ComponentIndex] = Phi;
  }

  for (size_t ComponentIndex = 0; ComponentIndex < EVM_ELEMENTS_COUNT;
       ++ComponentIndex) {
    Variable *PhiVar =
        storeInstructionInTemp(PhiComponents[ComponentIndex], &Ctx.I64Type);
    PhiVars[ComponentIndex] = PhiVar;
    StackMergePhiVarMap[PhiVar->getVarIdx()] =
        llvm::cast<PhiInstruction>(PhiComponents[ComponentIndex]);
  }

  return Operand(PhiVars, EVMType::UINT256);
}

void EVMMirBuilder::assignStackMergeOperand(const Operand &Dest,
                                            uint64_t PredBlockPC,
                                            const Operand &Value) {
  U256Var DestVars = Dest.getU256VarComponents();
  U256Inst IncomingComponents = extractU256Operand(Value);
  MBasicBlock *IncomingBB = getPhiIncomingBlock(CurrentBlockPC, PredBlockPC);
  auto PredRange = CurBB->predecessors();
  const size_t ActualPredCount =
      static_cast<size_t>(std::distance(PredRange.begin(), PredRange.end()));
  for (size_t I = 0; I < EVM_ELEMENTS_COUNT; ++I) {
    ZEN_ASSERT(DestVars[I] != nullptr &&
               "stack merge operand must be anchored in temp vars");
    auto PhiIt = StackMergePhiVarMap.find(DestVars[I]->getVarIdx());
    ZEN_ASSERT(PhiIt != StackMergePhiVarMap.end() &&
               "phi temp var must resolve to pending phi");
    PhiInstruction *Phi = PhiIt->second;
    size_t IncomingSlot = getPhiIncomingSlot(Phi, PredBlockPC);
    if ((IncomingBB == nullptr || std::find(PredRange.begin(), PredRange.end(),
                                            IncomingBB) == PredRange.end()) &&
        IncomingSlot < ActualPredCount) {
      IncomingBB = *(PredRange.begin() + IncomingSlot);
    }
    ZEN_ASSERT(IncomingBB != nullptr &&
               "phi incoming block must be registered before patching");
    Phi->setIncoming(IncomingSlot, IncomingBB, IncomingComponents[I]);
  }
}

void EVMMirBuilder::spillTrackedStack(
    const std::vector<Operand> &TrackedStack) {
  spillTrackedStackPreservingPrefix(TrackedStack, 0);
}

void EVMMirBuilder::spillTrackedStackPreservingPrefix(
    const std::vector<Operand> &TrackedStack, uint32_t PrefixDepth) {
  MType *I64Type = EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);
  MPointerType *U64PtrType = MPointerType::create(Ctx, Ctx.I64Type);
  MInstruction *StackPtrOffset = createIntConstInstruction(
      &Ctx.I64Type, zen::runtime::EVMInstance::getEVMStackOffset());
  MInstruction *StackBaseAddr = createInstruction<BinaryInstruction>(
      false, OP_add, &Ctx.I64Type, InstanceAddr, StackPtrOffset);

  const int32_t InnerOffsets[EVM_ELEMENTS_COUNT] = {0, 8, 16, 24};
  const uint64_t PrefixBytes = static_cast<uint64_t>(PrefixDepth) * 32ULL;
  for (size_t Slot = 0; Slot < TrackedStack.size(); ++Slot) {
    U256Inst Components = extractU256Operand(TrackedStack[Slot]);
    uint64_t SlotOffset = PrefixBytes + static_cast<uint64_t>(Slot) * 32ULL;
    MInstruction *SlotOffsetInst =
        createIntConstInstruction(I64Type, SlotOffset);
    MInstruction *SlotAddr = createInstruction<BinaryInstruction>(
        false, OP_add, &Ctx.I64Type, StackBaseAddr, SlotOffsetInst);
    MInstruction *SlotPtr = createInstruction<ConversionInstruction>(
        false, OP_inttoptr, U64PtrType, SlotAddr);
    for (size_t I = 0; I < EVM_ELEMENTS_COUNT; ++I) {
      createInstruction<StoreInstruction>(true, &Ctx.VoidType, Components[I],
                                          SlotPtr, InnerOffsets[I]);
    }
  }

  const uint32_t FinalDepth =
      PrefixDepth + static_cast<uint32_t>(TrackedStack.size());
  setTrackedStackDepth(FinalDepth);
  const int32_t StackSizeOffset =
      zen::runtime::EVMInstance::getEVMStackSizeOffset();
  MInstruction *StackSize = createIntConstInstruction(
      I64Type, static_cast<uint64_t>(FinalDepth) * 32ULL);
  setInstanceElement(&Ctx.I64Type, StackSize, StackSizeOffset);
}

void EVMMirBuilder::handleStop() {
  auto Zero = createU256ConstOperand(intx::uint256{0});
  handleReturn(Zero, Zero);
}

void EVMMirBuilder::drainGas() {
  MType *I64Type = EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);
  MPointerType *VoidPtrType = createVoidPtrType();
  MPointerType *I64PtrType = MPointerType::create(Ctx, Ctx.I64Type);

#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
  // Set gas register to 0
  if (Ctx.isGasRegisterEnabled() && GasRegVar) {
    MInstruction *Zero = createIntConstInstruction(I64Type, 0);
    createInstruction<DassignInstruction>(true, &(Ctx.VoidType), Zero,
                                          GasRegVar->getVarIdx());
  }
#endif

  MInstruction *MsgPtr = getInstanceElement(
      VoidPtrType, zen::runtime::EVMInstance::getCurrentMessagePointerOffset());
  MInstruction *MsgPtrInt = createInstruction<ConversionInstruction>(
      false, OP_ptrtoint, I64Type, MsgPtr);

  MInstruction *MsgGasOffsetValue = createIntConstInstruction(
      I64Type, zen::runtime::EVMInstance::getMessageGasOffset());
  MInstruction *MsgGasAddrInt = createInstruction<BinaryInstruction>(
      false, OP_add, I64Type, MsgPtrInt, MsgGasOffsetValue);
  MInstruction *MsgGasPtr = createInstruction<ConversionInstruction>(
      false, OP_inttoptr, I64PtrType, MsgGasAddrInt);

  MInstruction *Zero = createIntConstInstruction(I64Type, 0);
  createInstruction<StoreInstruction>(true, &Ctx.VoidType, Zero, MsgGasPtr);

  MInstruction *GasOffsetValue = createIntConstInstruction(
      I64Type, zen::runtime::EVMInstance::getGasFieldOffset());
  MInstruction *GasAddrInt = createInstruction<BinaryInstruction>(
      false, OP_add, I64Type, InstanceAddr, GasOffsetValue);
  MInstruction *GasPtr = createInstruction<ConversionInstruction>(
      false, OP_inttoptr, I64PtrType, GasAddrInt);

  createInstruction<StoreInstruction>(true, &Ctx.VoidType, Zero, GasPtr);
}

void EVMMirBuilder::handleTrap(ErrorCode ErrCode) {
  MBasicBlock *TrapBB = getOrCreateExceptionSetBB(ErrCode);

  if (CurBB && !CurBB->empty()) {
    MInstruction *LastInst = *std::prev(CurBB->end());
    if (LastInst->isTerminator()) {
      setInsertBlock(TrapBB);
      return;
    }
  }

  drainGas();
  createInstruction<BrInstruction>(true, Ctx, TrapBB);
  addSuccessor(TrapBB);
  setInsertBlock(TrapBB);
}

void EVMMirBuilder::handleVoidReturn() {
  if (!CurBB->empty()) {
    MInstruction *LastInst = *std::prev(CurBB->end());
    if (LastInst->isTerminator()) {
      return;
    }
  }

#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
  // Full sync before returning (need to update Msg->gas for caller)
  syncGasToMemoryFull();
#endif

  createInstruction<ReturnInstruction>(true, &Ctx.VoidType, nullptr);
}

void EVMMirBuilder::createJumpTable() {
  const EVMFrontendContext *EvmCtx =
      static_cast<const EVMFrontendContext *>(&Ctx);
  const Byte *Bytecode = EvmCtx->getBytecode();
  size_t BytecodeSize = EvmCtx->getBytecodeSize();

  JumpDestTable.clear();
  JumpDestCanonicalPCTable.clear();
  JumpDestBodyTable.clear();
  JumpHashTable.clear();
  JumpHashReverse.clear();
  HashMask = 0;
  if (Ctx.isGasMeteringEnabled()) {
    JumpDestRunLastPC.assign(BytecodeSize, InvalidJumpDestRunPC);
    JumpDestRunSkipCost.assign(BytecodeSize, 0);
  } else {
    JumpDestRunLastPC.clear();
    JumpDestRunSkipCost.clear();
  }

  MBasicBlock *SavedInsertBB = CurBB;

  for (size_t PC = 0; PC < BytecodeSize; ++PC) {
    if (Bytecode[PC] == static_cast<Byte>(evmc_opcode::OP_JUMPDEST)) {
      const size_t RangeStart = PC;
      while (PC + 1 < BytecodeSize &&
             Bytecode[PC + 1] == static_cast<Byte>(evmc_opcode::OP_JUMPDEST)) {
        ++PC;
      }
      const size_t RangeEnd = PC;

      // Share one canonical execution block for the whole run.
      MBasicBlock *BodyBB = createBasicBlock();
      BodyBB->setJumpDestBB(true);

      for (size_t DestPC = RangeStart; DestPC <= RangeEnd; ++DestPC) {
        JumpDestCanonicalPCTable[DestPC] = static_cast<uint64_t>(RangeEnd);
        JumpDestBodyTable[DestPC] = BodyBB;
      }

      if (!Ctx.isGasMeteringEnabled() || RangeStart == RangeEnd) {
        for (size_t DestPC = RangeStart; DestPC <= RangeEnd; ++DestPC) {
          JumpDestTable[DestPC] = BodyBB;
        }
      } else {
        // For merged runs, materialize per-target entry thunks that charge the
        // exact skipped metering before entering the shared body.
        //
        // NOTE: We may create O(n) thunks for a run of length n. Avoid an
        // O(n^2) compile-time cost by precomputing the suffix sums of skipped
        // metering once for the run.
        const size_t SkipCount = RangeEnd - RangeStart; // exclude RangeEnd
        const uint64_t JumpDestBaseCost = static_cast<uint64_t>(
            InstructionMetrics[static_cast<uint8_t>(evmc_opcode::OP_JUMPDEST)]
                .gas_cost);
        std::vector<uint64_t> SkipCostByOffset(SkipCount, 0);
        if (SkipCount > 0) {
          uint64_t Running = 0;
          for (size_t Offset = SkipCount; Offset > 0; --Offset) {
            const size_t Pc = RangeStart + (Offset - 1);
            uint64_t Cost = 0;
            if (GasChunkEnd && GasChunkCost && Pc < GasChunkSize &&
                GasChunkEnd[Pc] > Pc) {
              Cost = GasChunkCost[Pc];
            } else {
              // All bytes in the run are JUMPDEST opcode bytes (PUSH payload is
              // skipped in the scan above), so the fallback is a constant.
              Cost = JumpDestBaseCost;
            }

            if (UINT64_MAX - Running < Cost) {
              Running = UINT64_MAX;
            } else {
              Running += Cost;
            }
            SkipCostByOffset[Pc - RangeStart] = Running;
          }
        }

        // Cache the total skipped cost at run start so the linear decode path
        // can reuse it without re-scanning the same consecutive JUMPDEST range.
        if (RangeStart < JumpDestRunLastPC.size()) {
          JumpDestRunLastPC[RangeStart] = static_cast<uint32_t>(RangeEnd);
          JumpDestRunSkipCost[RangeStart] = SkipCostByOffset[0];
        }

        for (size_t DestPC = RangeStart; DestPC < RangeEnd; ++DestPC) {
          MBasicBlock *EntryBB = createBasicBlock();
          EntryBB->setJumpDestBB(true);
          JumpDestTable[DestPC] = EntryBB;

          setInsertBlock(EntryBB);
          meterGas(SkipCostByOffset[DestPC - RangeStart]);
          createInstruction<BrInstruction>(true, Ctx, BodyBB);
          addSuccessor(BodyBB);
        }
        JumpDestTable[RangeEnd] = BodyBB;
      }
    } else {
      if (static_cast<Byte>(evmc_opcode::OP_PUSH0) <= Bytecode[PC] &&
          Bytecode[PC] <= static_cast<Byte>(evmc_opcode::OP_PUSH32)) {
        uint8_t PushSize = static_cast<uint8_t>(Bytecode[PC]) + 1 -
                           static_cast<uint8_t>(evmc_opcode::OP_PUSH1);
        PC += PushSize; // Skip the immediate data
      }
    }
  }

  setInsertBlock(SavedInsertBB);

  // If the size of JumpDests is greater than MinHashSize, create a hash table
  // which calculates the hash of DestPC and use it as the index to jump
  if (JumpDestTable.size() > MinHashSize) {
    uint64_t HashSize =
        std::min(nextPowerOfTwo(JumpDestTable.size()), MaxHashSize);
    HashMask = HashSize - 1;
    for (const auto &[DestPC, DestBB] : JumpDestTable) {
      // HashIndex(a) = (a * HashMultiplier) & (size - 1)
      uint64_t Index = (DestPC * HashMultiplier) & HashMask;
      JumpHashTable[Index].push_back(DestBB);
      JumpHashReverse[Index].push_back(DestPC);
    }
  }
}

void EVMMirBuilder::implementConstantJump(uint64_t ConstDest,
                                          MBasicBlock *FailureBB) {
  if (JumpDestTable.count(ConstDest)) {
    registerPhiIncomingBlock(ConstDest, CurrentBlockPC, CurBB);
    createInstruction<BrInstruction>(true, Ctx, JumpDestTable[ConstDest]);
    addSuccessor(JumpDestTable[ConstDest]);
  } else {
    createInstruction<BrInstruction>(true, Ctx, FailureBB);
    addSuccessor(FailureBB);
  }
}

void EVMMirBuilder::implementIndirectJump(MInstruction *JumpTarget,
                                          MBasicBlock *FailureBB) {
  if (JumpDestTable.empty()) {
    createInstruction<BrInstruction>(true, Ctx, FailureBB);
    addUniqueSuccessor(FailureBB);
    return;
  }
  HasIndirectJump = true;

  MBasicBlock *TargetBB = getOrCreateIndirectJumpBB(CurrentBlockPC);
  createInstruction<DassignInstruction>(true, &(Ctx.VoidType), JumpTarget,
                                        JumpTargetVar->getVarIdx());
  createInstruction<BrInstruction>(true, Ctx, TargetBB);
  addUniqueSuccessor(TargetBB);
}

// ==================== Stack Instruction Handlers ====================

// Convert big-endian bytes to uint256(4 x uint64_t)
EVMMirBuilder::U256Value EVMMirBuilder::createU256FromBytes(const Byte *Data,
                                                            size_t Length) {
  U256Value Result = {0, 0, 0, 0};

  size_t Start = (Length > 32) ? (Length - 32) : 0;
  size_t ActualLength = (Length > 32) ? 32 : Length;

  for (size_t I = 0; I < ActualLength; ++I) {
    size_t ByteIndex = Start + I;
    size_t GlobalBytePos = ActualLength - 1 - I; // Position from right (LSB)
    size_t U64Index = GlobalBytePos / 8;
    size_t ByteInU64 = GlobalBytePos % 8;

    if (U64Index < 4) {
      Result[U64Index] |=
          (static_cast<uint64_t>(Data[ByteIndex]) << (ByteInU64 * 8));
    }
  }

  return Result;
}

EVMMirBuilder::U256ConstInt
EVMMirBuilder::createU256Constants(const U256Value &Value) {
  EVMMirBuilder::U256ConstInt Result;

  for (size_t I = 0; I < EVM_ELEMENTS_COUNT; ++I) {
    Result[I] = MConstantInt::get(
        Ctx, *EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64),
        Value[I]);
  }
  return Result;
}

typename EVMMirBuilder::Operand EVMMirBuilder::handlePush(const Bytes &Data) {
  U256Value Value = bytesToU256(Data);
  return Operand(Value);
}

// ==================== Control Flow Instruction Handlers ====================

void EVMMirBuilder::handleJump(Operand Dest) {
  MBasicBlock *InvalidJumpBB =
      getOrCreateExceptionSetBB(ErrorCode::EVMBadJumpDestination);
  if (Dest.isConstant()) {
    const auto &ConstValue = Dest.getConstValue();
    if ((ConstValue[3] | ConstValue[2] | ConstValue[1]) != 0) {
      createInstruction<BrInstruction>(true, Ctx, InvalidJumpBB);
      addSuccessor(InvalidJumpBB);
      return;
    }
    uint64_t ConstDest = ConstValue[0];
    implementConstantJump(ConstDest, InvalidJumpBB);
    return;
  }

  U256Inst DestComponents = extractU256Operand(Dest);
  MInstruction *JumpTarget = DestComponents[0];
  MType *MirI64Type =
      EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);
  MInstruction *Zero = createIntConstInstruction(MirI64Type, 0);
  MInstruction *HighOr = createInstruction<BinaryInstruction>(
      false, OP_or, MirI64Type, DestComponents[1], DestComponents[2]);
  HighOr = createInstruction<BinaryInstruction>(false, OP_or, MirI64Type,
                                                HighOr, DestComponents[3]);
  MInstruction *HighNonZero = createInstruction<CmpInstruction>(
      false, CmpInstruction::Predicate::ICMP_NE, &Ctx.I64Type, HighOr, Zero);
  MBasicBlock *ValidJumpBB = createBasicBlock();
  createInstruction<BrIfInstruction>(true, Ctx, HighNonZero, InvalidJumpBB,
                                     ValidJumpBB);
  addSuccessor(InvalidJumpBB);
  addSuccessor(ValidJumpBB);
  setInsertBlock(ValidJumpBB);
  implementIndirectJump(JumpTarget, InvalidJumpBB);
}

void EVMMirBuilder::handleJumpI(Operand Dest, Operand Cond) {
  U256Inst DestComponents = extractU256Operand(Dest);
  U256Inst CondComponents = extractU256Operand(Cond);
  MInstruction *JumpTarget = DestComponents[0];

  MType *MirI64Type =
      EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);
  MInstruction *Zero = createIntConstInstruction(MirI64Type, 0);
  MInstruction *One = createIntConstInstruction(MirI64Type, 1);

  // Condition is true if any component is non-zero
  MInstruction *OrResult = createInstruction<BinaryInstruction>(
      false, OP_or, MirI64Type, CondComponents[0], CondComponents[1]);
  OrResult = createInstruction<BinaryInstruction>(false, OP_or, MirI64Type,
                                                  OrResult, CondComponents[2]);
  OrResult = createInstruction<BinaryInstruction>(false, OP_or, MirI64Type,
                                                  OrResult, CondComponents[3]);

  MInstruction *IsNonZero = createInstruction<CmpInstruction>(
      false, CmpInstruction::Predicate::ICMP_NE, &Ctx.I64Type, OrResult, Zero);
  IsNonZero = createInstruction<SelectInstruction>(false, MirI64Type, IsNonZero,
                                                   One, Zero);

  MBasicBlock *FallThroughBB = createBasicBlock();
  FallThroughBB->setJumpDestBB(true);
  MBasicBlock *InvalidJumpBB =
      getOrCreateExceptionSetBB(ErrorCode::EVMBadJumpDestination);

  if (JumpDestTable.empty()) {
    createInstruction<BrIfInstruction>(true, Ctx, IsNonZero, InvalidJumpBB,
                                       FallThroughBB);
    addUniqueSuccessor(InvalidJumpBB);
    addSuccessor(FallThroughBB);
  } else if (Dest.isConstant()) {
    const auto &ConstValue = Dest.getConstValue();
    if ((ConstValue[3] | ConstValue[2] | ConstValue[1]) != 0) {
      createInstruction<BrIfInstruction>(true, Ctx, IsNonZero, InvalidJumpBB,
                                         FallThroughBB);
      addUniqueSuccessor(InvalidJumpBB);
      addSuccessor(FallThroughBB);
    } else {
      uint64_t ConstDest = ConstValue[0];
      auto JumpIt = JumpDestTable.find(ConstDest);
      if (JumpIt == JumpDestTable.end()) {
        createInstruction<BrIfInstruction>(true, Ctx, IsNonZero, InvalidJumpBB,
                                           FallThroughBB);
        addUniqueSuccessor(InvalidJumpBB);
        addSuccessor(FallThroughBB);
      } else {
        registerPhiIncomingBlock(ConstDest, CurrentBlockPC, CurBB);
        createInstruction<BrIfInstruction>(true, Ctx, IsNonZero, JumpIt->second,
                                           FallThroughBB);
        addSuccessor(JumpIt->second);
        addSuccessor(FallThroughBB);
      }
    }
  } else {
    MBasicBlock *JumpTableBB = createBasicBlock();
    createInstruction<BrIfInstruction>(true, Ctx, IsNonZero, JumpTableBB,
                                       FallThroughBB);
    addSuccessor(JumpTableBB);
    addSuccessor(FallThroughBB);
    setInsertBlock(JumpTableBB);
    MInstruction *HighOr = createInstruction<BinaryInstruction>(
        false, OP_or, MirI64Type, DestComponents[1], DestComponents[2]);
    HighOr = createInstruction<BinaryInstruction>(false, OP_or, MirI64Type,
                                                  HighOr, DestComponents[3]);
    MInstruction *HighNonZero = createInstruction<CmpInstruction>(
        false, CmpInstruction::Predicate::ICMP_NE, &Ctx.I64Type, HighOr, Zero);
    MBasicBlock *ValidJumpBB = createBasicBlock();
    createInstruction<BrIfInstruction>(true, Ctx, HighNonZero, InvalidJumpBB,
                                       ValidJumpBB);
    addSuccessor(InvalidJumpBB);
    addSuccessor(ValidJumpBB);
    setInsertBlock(ValidJumpBB);
    implementIndirectJump(JumpTarget, InvalidJumpBB);
  }

  setInsertBlock(FallThroughBB);
}

void EVMMirBuilder::handleJumpDest(const uint64_t &PC) {
  auto BodyIt = JumpDestBodyTable.find(PC);
  ZEN_ASSERT(BodyIt != JumpDestBodyTable.end() && "JUMPDEST body not found");
  MBasicBlock *DestBB = BodyIt->second;
  // Only add successor if the current BB is not ExceptionSetBB,
  bool IsExceptionSetBB = false;
  for (auto &[EC, BB] : CurFunc->getExceptionSetBBs()) {
    if (CurBB == BB) {
      IsExceptionSetBB = true;
      break;
    }
  }
  if (CurBB != DestBB && !IsExceptionSetBB) {
    if (CurBB->empty()) {
      registerPhiIncomingBlock(PC, CurrentBlockPC, CurBB);
      CurBB->addSuccessor(DestBB);
      createInstruction<BrInstruction>(true, Ctx, DestBB);
    } else {
      MInstruction *LastInst = *std::prev(CurBB->end());
      if (!LastInst->isTerminator()) {
        registerPhiIncomingBlock(PC, CurrentBlockPC, CurBB);
        CurBB->addSuccessor(DestBB);
        createInstruction<BrInstruction>(true, Ctx, DestBB);
      }
    }
  }
  setInsertBlock(DestBB);
#ifdef ZEN_ENABLE_LINUX_PERF
  CurBB->setSourceOffset(PC);
  CurBB->setSourceName("JUMPDEST");
  CurPC = PC;
  CurInstrIdx = 0;
#endif // ZEN_ENABLE_LINUX_PERF
}

// ==================== Arithmetic Instruction Handlers ====================

MInstruction *EVMMirBuilder::createEvmUmul128(MInstruction *LHS,
                                              MInstruction *RHS) {
  return createInstruction<EvmUmul128Instruction>(false, OP_evm_umul128_lo,
                                                  &Ctx.I64Type, LHS, RHS);
}

MInstruction *EVMMirBuilder::createEvmUmul128Hi(MInstruction *MulInst) {
  return createInstruction<EvmUmul128HiInstruction>(false, &Ctx.I64Type,
                                                    MulInst);
}

MInstruction *EVMMirBuilder::createEvmUdiv128By64(MInstruction *Hi,
                                                  MInstruction *Lo,
                                                  MInstruction *Divisor) {
  return createInstruction<EvmUdiv128By64Instruction>(
      false, OP_evm_udiv128_by64, &Ctx.I64Type, Hi, Lo, Divisor);
}

MInstruction *EVMMirBuilder::createEvmUrem128By64(MInstruction *DivInst) {
  return createInstruction<EvmUrem128By64Instruction>(false, &Ctx.I64Type,
                                                      DivInst);
}

typename EVMMirBuilder::Operand
EVMMirBuilder::handleDivU64Divisor(const Operand &DividendOp,
                                   uint64_t Divisor) {
  MType *I64Type = &Ctx.I64Type;
  MInstruction *Zero = createIntConstInstruction(I64Type, 0);
  MInstruction *DivConst = createIntConstInstruction(I64Type, Divisor);

  U256Inst A = extractU256Operand(DividendOp);

  // Cascading division: (0:A[3]) / D, then (R3:A[2]) / D, ...
  MInstruction *Div3 = createEvmUdiv128By64(Zero, A[3], DivConst);
  MInstruction *Rem3 = createEvmUrem128By64(Div3);
  MInstruction *Div2 = createEvmUdiv128By64(Rem3, A[2], DivConst);
  MInstruction *Rem2 = createEvmUrem128By64(Div2);
  MInstruction *Div1 = createEvmUdiv128By64(Rem2, A[1], DivConst);
  MInstruction *Rem1 = createEvmUrem128By64(Div1);
  MInstruction *Div0 = createEvmUdiv128By64(Rem1, A[0], DivConst);

  U256Inst Result = {Div0, Div1, Div2, Div3};
  return Operand(Result, EVMType::UINT256);
}

typename EVMMirBuilder::Operand
EVMMirBuilder::handleModU64Divisor(const Operand &DividendOp,
                                   uint64_t Divisor) {
  MType *I64Type = &Ctx.I64Type;
  MInstruction *Zero = createIntConstInstruction(I64Type, 0);
  MInstruction *DivConst = createIntConstInstruction(I64Type, Divisor);

  U256Inst A = extractU256Operand(DividendOp);

  // Cascading division to get remainder
  MInstruction *Div3 = createEvmUdiv128By64(Zero, A[3], DivConst);
  MInstruction *Rem3 = createEvmUrem128By64(Div3);
  MInstruction *Div2 = createEvmUdiv128By64(Rem3, A[2], DivConst);
  MInstruction *Rem2 = createEvmUrem128By64(Div2);
  MInstruction *Div1 = createEvmUdiv128By64(Rem2, A[1], DivConst);
  MInstruction *Rem1 = createEvmUrem128By64(Div1);
  MInstruction *Div0 = createEvmUdiv128By64(Rem1, A[0], DivConst);
  MInstruction *Rem0 = createEvmUrem128By64(Div0);

  U256Inst Result = {Rem0, Zero, Zero, Zero};
  return Operand(Result, EVMType::UINT256);
}

typename EVMMirBuilder::Operand
EVMMirBuilder::handleDivU64Dividend(uint64_t Dividend,
                                    const Operand &DivisorOp) {
  MType *I64Type = &Ctx.I64Type;
  MInstruction *Zero = createIntConstInstruction(I64Type, 0);

  U256Inst B = extractU256Operand(DivisorOp);

  // If divisor has any upper limb set, b > a, so DIV = 0
  MInstruction *Upper = createInstruction<BinaryInstruction>(
      false, OP_or, I64Type, B[1],
      createInstruction<BinaryInstruction>(false, OP_or, I64Type, B[2], B[3]));
  MInstruction *HasUpper = createInstruction<CmpInstruction>(
      false, CmpInstruction::ICMP_NE, &Ctx.I64Type, Upper, Zero);

  // Guard B[0] against zero to prevent hardware divide-by-zero trap.
  // EVM DIV(a, 0) = 0, but x86 DIV with zero divisor raises SIGFPE.
  MInstruction *One = createIntConstInstruction(I64Type, 1);
  MInstruction *IsB0Zero = createInstruction<CmpInstruction>(
      false, CmpInstruction::ICMP_EQ, &Ctx.I64Type, B[0], Zero);
  MInstruction *SafeB0 =
      createInstruction<SelectInstruction>(false, I64Type, IsB0Zero, One, B[0]);

  MInstruction *A0 = createIntConstInstruction(I64Type, Dividend);
  MInstruction *Q64 =
      createInstruction<BinaryInstruction>(false, OP_udiv, I64Type, A0, SafeB0);
  // Chain two selects so lowerSelectExpr can fuse each CmpInstruction
  // condition directly into CMP+CMOVcc, avoiding SETcc+OR+TEST overhead.
  MInstruction *TmpResult =
      createInstruction<SelectInstruction>(false, I64Type, IsB0Zero, Zero, Q64);
  MInstruction *DivResult = createInstruction<SelectInstruction>(
      false, I64Type, HasUpper, Zero, TmpResult);

  U256Inst Result = {DivResult, Zero, Zero, Zero};
  return Operand(Result, EVMType::UINT256);
}

typename EVMMirBuilder::Operand
EVMMirBuilder::handleModU64Dividend(uint64_t Dividend,
                                    const Operand &DivisorOp) {
  MType *I64Type = &Ctx.I64Type;
  MInstruction *Zero = createIntConstInstruction(I64Type, 0);

  U256Inst B = extractU256Operand(DivisorOp);

  MInstruction *Upper = createInstruction<BinaryInstruction>(
      false, OP_or, I64Type, B[1],
      createInstruction<BinaryInstruction>(false, OP_or, I64Type, B[2], B[3]));
  MInstruction *HasUpper = createInstruction<CmpInstruction>(
      false, CmpInstruction::ICMP_NE, &Ctx.I64Type, Upper, Zero);

  // Guard B[0] against zero to prevent hardware divide-by-zero trap.
  // EVM MOD(a, 0) = 0, but x86 DIV with zero divisor raises SIGFPE.
  MInstruction *One = createIntConstInstruction(I64Type, 1);
  MInstruction *IsB0Zero = createInstruction<CmpInstruction>(
      false, CmpInstruction::ICMP_EQ, &Ctx.I64Type, B[0], Zero);
  MInstruction *SafeB0 =
      createInstruction<SelectInstruction>(false, I64Type, IsB0Zero, One, B[0]);

  MInstruction *A0 = createIntConstInstruction(I64Type, Dividend);
  MInstruction *R64 =
      createInstruction<BinaryInstruction>(false, OP_urem, I64Type, A0, SafeB0);
  // Chain two selects: IsB0Zero → 0 (div-by-zero), HasUpper → A0 (divisor >
  // dividend)
  MInstruction *TmpResult =
      createInstruction<SelectInstruction>(false, I64Type, IsB0Zero, Zero, R64);
  MInstruction *ModResult = createInstruction<SelectInstruction>(
      false, I64Type, HasUpper, A0, TmpResult);

  U256Inst Result = {ModResult, Zero, Zero, Zero};
  return Operand(Result, EVMType::UINT256);
}

typename EVMMirBuilder::Operand EVMMirBuilder::handleDivModGeneral(
    const Operand &DividendOp, const Operand &DivisorOp, bool WantQuotient) {
  MType *I64Type = &Ctx.I64Type;
  MInstruction *Zero = createIntConstInstruction(I64Type, 0);
  MInstruction *One = createIntConstInstruction(I64Type, 1);

  U256Inst A = extractU256Operand(DividendOp);
  U256Inst B = extractU256Operand(DivisorOp);

  // Check if divisor upper limbs are all zero (runtime 1-limb divisor)
  MInstruction *UpperOr = createInstruction<BinaryInstruction>(
      false, OP_or, I64Type, B[1],
      createInstruction<BinaryInstruction>(false, OP_or, I64Type, B[2], B[3]));
  MInstruction *HasUpperLimbs = createInstruction<CmpInstruction>(
      false, CmpInstruction::ICMP_NE, I64Type, UpperOr, Zero);

  // Guard B[0] against zero to prevent hardware divide-by-zero trap.
  // EVM DIV/MOD(a, 0) = 0, but x86 DIV with zero divisor raises SIGFPE.
  // Replace zero divisor with 1 (harmless), then select result to 0 afterward.
  MInstruction *IsB0Zero = createInstruction<CmpInstruction>(
      false, CmpInstruction::ICMP_EQ, I64Type, B[0], Zero);
  MInstruction *SafeB0 =
      createInstruction<SelectInstruction>(false, I64Type, IsB0Zero, One, B[0]);

  // Result variables for cross-BB communication
  U256Var ResultVars = {};
  for (size_t I = 0; I < EVM_ELEMENTS_COUNT; ++I) {
    ResultVars[I] = CurFunc->createVariable(I64Type);
  }

  auto storeResult = [&](const U256Inst &Values) {
    for (size_t I = 0; I < EVM_ELEMENTS_COUNT; ++I) {
      createInstruction<DassignInstruction>(true, &(Ctx.VoidType), Values[I],
                                            ResultVars[I]->getVarIdx());
    }
  };

  auto loadResult = [&]() -> U256Inst {
    U256Inst Values = {};
    for (size_t I = 0; I < EVM_ELEMENTS_COUNT; ++I) {
      Values[I] = loadVariable(ResultVars[I]);
    }
    return Values;
  };

  // Branch structure (3-block, matches handleDiv pattern):
  //   if (HasUpperLimbs) goto MultiLimbBB else goto SingleLimbBB
  //   SingleLimbBB: inline cascading 128/64 div with SafeB0; goto AfterBB
  //   MultiLimbBB: runtime call; goto AfterBB
  //   AfterBB: load result
  MBasicBlock *MultiLimbBB = createBasicBlock();
  MBasicBlock *SingleLimbBB = createBasicBlock();
  MBasicBlock *AfterBB = createBasicBlock();

  createInstruction<BrIfInstruction>(true, Ctx, HasUpperLimbs, MultiLimbBB,
                                     SingleLimbBB);
  addSuccessor(MultiLimbBB);
  addSuccessor(SingleLimbBB);

  // --- SingleLimbBB: 1-limb divisor, cascading 128/64 division ---
  // Uses SafeB0 (guaranteed non-zero) to avoid hardware DIV-by-zero.
  // If B[0] was actually zero, IsB0Zero selects result to 0 afterward.
  setInsertBlock(SingleLimbBB);
  // Cascading: (0:A[3])/SafeB0, (R3:A[2])/SafeB0, ...
  MInstruction *Div3 = createEvmUdiv128By64(Zero, A[3], SafeB0);
  MInstruction *Rem3 = createEvmUrem128By64(Div3);
  MInstruction *Div2 = createEvmUdiv128By64(Rem3, A[2], SafeB0);
  MInstruction *Rem2 = createEvmUrem128By64(Div2);
  MInstruction *Div1 = createEvmUdiv128By64(Rem2, A[1], SafeB0);
  MInstruction *Rem1 = createEvmUrem128By64(Div1);
  MInstruction *Div0 = createEvmUdiv128By64(Rem1, A[0], SafeB0);
  MInstruction *Rem0 = createEvmUrem128By64(Div0);

  if (WantQuotient) {
    // Select each quotient limb to 0 when divisor was zero
    U256Inst QuotResult = {createInstruction<SelectInstruction>(
                               false, I64Type, IsB0Zero, Zero, Div0),
                           createInstruction<SelectInstruction>(
                               false, I64Type, IsB0Zero, Zero, Div1),
                           createInstruction<SelectInstruction>(
                               false, I64Type, IsB0Zero, Zero, Div2),
                           createInstruction<SelectInstruction>(
                               false, I64Type, IsB0Zero, Zero, Div3)};
    storeResult(QuotResult);
  } else {
    // Select remainder to 0 when divisor was zero (only limb 0 matters)
    U256Inst RemResult = {createInstruction<SelectInstruction>(
                              false, I64Type, IsB0Zero, Zero, Rem0),
                          Zero, Zero, Zero};
    storeResult(RemResult);
  }
  createInstruction<BrInstruction>(true, Ctx, AfterBB);
  addSuccessor(AfterBB);

  // --- MultiLimbBB: multi-limb divisor, fall back to runtime ---
  setInsertBlock(MultiLimbBB);
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  Operand RuntimeResult;
  if (WantQuotient) {
    RuntimeResult = callRuntimeFor<const intx::uint256 *, const intx::uint256 &,
                                   const intx::uint256 &>(
        RuntimeFunctions.GetDiv, DividendOp, DivisorOp);
  } else {
    RuntimeResult = callRuntimeFor<const intx::uint256 *, const intx::uint256 &,
                                   const intx::uint256 &>(
        RuntimeFunctions.GetMod, DividendOp, DivisorOp);
  }
  storeResult(extractU256Operand(RuntimeResult));
  createInstruction<BrInstruction>(true, Ctx, AfterBB);
  addSuccessor(AfterBB);

  // --- AfterBB: merge results ---
  setInsertBlock(AfterBB);
  return Operand(loadResult(), EVMType::UINT256);
}

typename EVMMirBuilder::Operand EVMMirBuilder::handleMul(Operand MultiplicandOp,
                                                         Operand MultiplierOp) {
  // Phase 0: Constant folding
  if (MultiplicandOp.isConstant() && MultiplierOp.isConstant()) {
    intx::uint256 A = u256ValueToIntx(MultiplicandOp.getConstValue());
    intx::uint256 B = u256ValueToIntx(MultiplierOp.getConstValue());
    return Operand(intxToU256Value(A * B));
  }

  if (MultiplicandOp.isZeroConstant() || MultiplierOp.isZeroConstant()) {
    return Operand(U256Value{0, 0, 0, 0});
  }

  if (MultiplicandOp.isOneConstant()) {
    return MultiplierOp;
  }

  if (MultiplierOp.isOneConstant()) {
    return MultiplicandOp;
  }

  // Phase 1: Range-based u64×u64 → u128 fast path
  // When both operands provably fit in u64, a single 64×64→128 multiply
  // replaces the expensive 4×4 schoolbook multiplication.
  if (Operand::bothFitU64(MultiplicandOp, MultiplierOp) &&
      !MultiplicandOp.isConstant() && !MultiplierOp.isConstant()) {
    U256Inst A = extractU256Operand(MultiplicandOp);
    U256Inst B = extractU256Operand(MultiplierOp);
    MType *I64Type = &Ctx.I64Type;
    MInstruction *Zero = createIntConstInstruction(I64Type, 0);
    MInstruction *MulLo = createEvmUmul128(A[0], B[0]);
    MInstruction *MulHi = createEvmUmul128Hi(MulLo);
    U256Inst Result = {MulLo, MulHi, Zero, Zero};
    return Operand(Result, EVMType::UINT256, ValueRange::U128);
  }

  // Phase 4: u64 fast path - one operand fits in u64 (4x1 multiplication)
  bool AIsU64 = MultiplicandOp.isConstU64();
  bool BIsU64 = MultiplierOp.isConstU64();
  if (AIsU64 || BIsU64) {
    const Operand &U256Op = AIsU64 ? MultiplierOp : MultiplicandOp;
    const Operand &U64Op = AIsU64 ? MultiplicandOp : MultiplierOp;

    U256Inst A = extractU256Operand(U256Op);
    MType *I64Type = &Ctx.I64Type;
    MInstruction *B0 =
        createIntConstInstruction(I64Type, U64Op.getConstValue()[0]);
    MInstruction *Zero = createIntConstInstruction(I64Type, 0);

    // 4x1 schoolbook: Result = A * B0 (truncated to 256 bits)
    // P[i] = A[i] * B0, splitting into lo/hi 64-bit halves
    MInstruction *PLo[4];
    MInstruction *PHi[3];
    for (size_t I = 0; I < 4; ++I) {
      PLo[I] = createEvmUmul128(A[I], B0);
      if (I < 3)
        PHi[I] = createEvmUmul128Hi(PLo[I]);
    }

    using SumCarryPair = std::pair<MInstruction *, MInstruction *>;
    auto addTermWithCarry = [&](MInstruction *Sum, MInstruction *Carry,
                                MInstruction *Term) -> SumCarryPair {
      MInstruction *NewSum = createInstruction<BinaryInstruction>(
          false, OP_add, I64Type, Sum, Term);
      MInstruction *NewCarry =
          createInstruction<AdcInstruction>(false, I64Type, Carry, Zero, Zero);
      return {protectUnsafeValue(NewSum, I64Type),
              protectUnsafeValue(NewCarry, I64Type)};
    };

    auto addTermNoCarry = [&](MInstruction *Sum, MInstruction *Term) {
      MInstruction *NewSum = createInstruction<BinaryInstruction>(
          false, OP_add, I64Type, Sum, Term);
      return protectUnsafeValue(NewSum, I64Type);
    };

    // R[0] = PLo[0]
    MInstruction *R0 = PLo[0];

    // R[1] = PHi[0] + PLo[1]
    MInstruction *R1 = PHi[0];
    MInstruction *C1 = Zero;
    {
      auto [S1, C1a] = addTermWithCarry(R1, C1, PLo[1]);
      R1 = S1;
      C1 = C1a;
    }

    // R[2] = PHi[1] + PLo[2] + C1
    MInstruction *R2 = PHi[1];
    MInstruction *C2 = Zero;
    {
      auto [S1, C2a] = addTermWithCarry(R2, C2, PLo[2]);
      auto [S2, C2b] = addTermWithCarry(S1, C2a, C1);
      R2 = S2;
      C2 = C2b;
    }

    // R[3] = PHi[2] + PLo[3] + C2 (truncated, no carry out needed)
    MInstruction *R3 = PHi[2];
    R3 = addTermNoCarry(R3, PLo[3]);
    R3 = addTermNoCarry(R3, C2);

    U256Inst Result = {R0, R1, R2, R3};
    return Operand(Result, EVMType::UINT256);
  }

  // General case: use EvmU256MulInstruction for full 4x4 multiplication
  U256Inst A = extractU256Operand(MultiplicandOp);
  U256Inst B = extractU256Operand(MultiplierOp);
  MType *I64Type = &Ctx.I64Type;

  MInstruction *MulInst = createInstruction<EvmU256MulInstruction>(
      false, I64Type, A[0], A[1], A[2], A[3], B[0], B[1], B[2], B[3]);
  U256Inst Result = {MulInst,
                     createInstruction<EvmU256MulResultInstruction>(
                         false, I64Type, MulInst, 1),
                     createInstruction<EvmU256MulResultInstruction>(
                         false, I64Type, MulInst, 2),
                     createInstruction<EvmU256MulResultInstruction>(
                         false, I64Type, MulInst, 3)};
  return Operand(Result, EVMType::UINT256);
}

typename EVMMirBuilder::Operand EVMMirBuilder::handleDiv(Operand DividendOp,
                                                         Operand DivisorOp) {
  if (DividendOp.isConstant() && DivisorOp.isConstant()) {
    intx::uint256 D = u256ValueToIntx(DivisorOp.getConstValue());
    if (D == 0)
      return Operand(U256Value{0, 0, 0, 0});
    intx::uint256 N = u256ValueToIntx(DividendOp.getConstValue());
    return Operand(intxToU256Value(N / D));
  }

  // DIV(x, 2^n) -> SHR(x, n)
  if (DivisorOp.isConstant()) {
    intx::uint256 D = u256ValueToIntx(DivisorOp.getConstValue());
    if (D != 0 && (D & (D - 1)) == 0) {
      unsigned ShiftAmt = 0;
      intx::uint256 Tmp = D;
      while (Tmp > 1) {
        Tmp >>= 1;
        ++ShiftAmt;
      }
      Operand ShiftOp(U256Value{ShiftAmt, 0, 0, 0});
      return handleShift<BinaryOperator::BO_SHR_U>(ShiftOp, DividendOp);
    }
  }

  // Range-based u64÷u64 fast path: single OP_udiv with div-by-zero guard.
  // DIV(u64, u64) → u64 result.  Inserted before the isConstU64() path so
  // that non-constant operands with proven narrow range benefit too.
  if (Operand::bothFitU64(DividendOp, DivisorOp) && !DividendOp.isConstant() &&
      !DivisorOp.isConstant()) {
    U256Inst A = extractU256Operand(DividendOp);
    U256Inst B = extractU256Operand(DivisorOp);
    MType *I64Type = &Ctx.I64Type;
    MInstruction *Zero = createIntConstInstruction(I64Type, 0);
    MInstruction *One = createIntConstInstruction(I64Type, 1);

    // Guard against div-by-zero: EVM DIV(x, 0) = 0, but x86 traps
    MInstruction *IsZero = createInstruction<CmpInstruction>(
        false, CmpInstruction::ICMP_EQ, I64Type, B[0], Zero);
    MInstruction *SafeB =
        createInstruction<SelectInstruction>(false, I64Type, IsZero, One, B[0]);
    MInstruction *Quotient = createInstruction<BinaryInstruction>(
        false, OP_udiv, I64Type, A[0], SafeB);
    MInstruction *DivResult = createInstruction<SelectInstruction>(
        false, I64Type, IsZero, Zero, Quotient);

    U256Inst Result = {DivResult, Zero, Zero, Zero};
    return Operand(Result, EVMType::UINT256, ValueRange::U64);
  }

  // u64 divisor: inline cascading 128/64 division
  if (DivisorOp.isConstU64()) {
    uint64_t D = DivisorOp.getConstValue()[0];
    if (D != 0) {
      if (!DividendOp.isConstant()) {
        U256Inst A = extractU256Operand(DividendOp);
        MType *I64Type = &Ctx.I64Type;
        MInstruction *Zero = createIntConstInstruction(I64Type, 0);

        MInstruction *UpperAny = createInstruction<BinaryInstruction>(
            false, OP_or, I64Type, A[1],
            createInstruction<BinaryInstruction>(false, OP_or, I64Type, A[2],
                                                 A[3]));
        MInstruction *HasUpper = createInstruction<CmpInstruction>(
            false, CmpInstruction::ICMP_NE, I64Type, UpperAny, Zero);

        U256Var ResultVars = {};
        for (size_t I = 0; I < EVM_ELEMENTS_COUNT; ++I) {
          ResultVars[I] = CurFunc->createVariable(I64Type);
        }

        auto storeResult = [&](const U256Inst &Values) {
          for (size_t I = 0; I < EVM_ELEMENTS_COUNT; ++I) {
            createInstruction<DassignInstruction>(
                true, &(Ctx.VoidType), Values[I], ResultVars[I]->getVarIdx());
          }
        };

        auto loadResult = [&]() -> U256Inst {
          U256Inst Values = {};
          for (size_t I = 0; I < EVM_ELEMENTS_COUNT; ++I) {
            Values[I] = loadVariable(ResultVars[I]);
          }
          return Values;
        };

        MBasicBlock *KnownU64BB = createBasicBlock();
        MBasicBlock *SlowBB = createBasicBlock();
        MBasicBlock *AfterBB = createBasicBlock();
        createInstruction<BrIfInstruction>(true, Ctx, HasUpper, SlowBB,
                                           KnownU64BB);
        addSuccessor(SlowBB);
        addSuccessor(KnownU64BB);

        setInsertBlock(KnownU64BB);
        MInstruction *DivConst = createIntConstInstruction(I64Type, D);
        MInstruction *Quotient = createInstruction<BinaryInstruction>(
            false, OP_udiv, I64Type, A[0], DivConst);
        U256Inst FastResult = {Quotient, Zero, Zero, Zero};
        storeResult(FastResult);
        createInstruction<BrInstruction>(true, Ctx, AfterBB);
        addSuccessor(AfterBB);

        setInsertBlock(SlowBB);
        U256Inst SlowResult =
            extractU256Operand(handleDivU64Divisor(DividendOp, D));
        storeResult(SlowResult);
        createInstruction<BrInstruction>(true, Ctx, AfterBB);
        addSuccessor(AfterBB);

        setInsertBlock(AfterBB);
        return Operand(loadResult(), EVMType::UINT256);
      }
      return handleDivU64Divisor(DividendOp, D);
    }
  }

  // u64 dividend: OR-fold + select
  if (DividendOp.isConstU64()) {
    uint64_t A = DividendOp.getConstValue()[0];
    return handleDivU64Dividend(A, DivisorOp);
  }

  return handleDivModGeneral(DividendOp, DivisorOp, /*WantQuotient=*/true);
}

typename EVMMirBuilder::Operand EVMMirBuilder::handleSDiv(Operand DividendOp,
                                                          Operand DivisorOp) {
  if (DividendOp.isConstant() && DivisorOp.isConstant()) {
    intx::uint256 D = u256ValueToIntx(DivisorOp.getConstValue());
    if (D == 0)
      return Operand(U256Value{0, 0, 0, 0});
    intx::uint256 N = u256ValueToIntx(DividendOp.getConstValue());
    auto Result = intx::sdivrem(N, D);
    return Operand(intxToU256Value(Result.quot));
  }

  // u64 divisor (value fits in i63, so it's positive): use unsigned div + sign
  if (DivisorOp.isConstU64()) {
    uint64_t D = DivisorOp.getConstValue()[0];
    if (D != 0 && D <= INT64_MAX) {
      MType *I64Type = &Ctx.I64Type;
      MInstruction *Zero = createIntConstInstruction(I64Type, 0);
      U256Inst A = extractU256Operand(DividendOp);
      MInstruction *SignBit = createInstruction<CmpInstruction>(
          false, CmpInstruction::ICMP_SLT, &Ctx.I64Type, A[3], Zero);
      Operand NegA = handleNot(DividendOp);
      Operand AbsDividend =
          handleAddU64Const(NegA, Operand(U256Value{1, 0, 0, 0}));
      U256Inst AbsInst = extractU256Operand(AbsDividend);
      U256Inst SelA;
      for (size_t I = 0; I < EVM_ELEMENTS_COUNT; ++I) {
        SelA[I] = createInstruction<SelectInstruction>(false, I64Type, SignBit,
                                                       AbsInst[I], A[I]);
      }
      Operand AbsOp(SelA, EVMType::UINT256);
      Operand UnsignedResult = handleDivU64Divisor(AbsOp, D);
      Operand NegResult = handleNot(UnsignedResult);
      Operand NegResult1 =
          handleAddU64Const(NegResult, Operand(U256Value{1, 0, 0, 0}));
      U256Inst URes = extractU256Operand(UnsignedResult);
      U256Inst NRes = extractU256Operand(NegResult1);
      U256Inst FinalInst;
      for (size_t I = 0; I < EVM_ELEMENTS_COUNT; ++I) {
        FinalInst[I] = createInstruction<SelectInstruction>(
            false, I64Type, SignBit, NRes[I], URes[I]);
      }
      return Operand(FinalInst, EVMType::UINT256);
    }
  }

  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  return callRuntimeFor<const intx::uint256 *, const intx::uint256 &,
                        const intx::uint256 &>(RuntimeFunctions.GetSDiv,
                                               DividendOp, DivisorOp);
}

typename EVMMirBuilder::Operand EVMMirBuilder::handleMod(Operand DividendOp,
                                                         Operand DivisorOp) {
  if (DividendOp.isConstant() && DivisorOp.isConstant()) {
    intx::uint256 D = u256ValueToIntx(DivisorOp.getConstValue());
    if (D == 0)
      return Operand(U256Value{0, 0, 0, 0});
    intx::uint256 N = u256ValueToIntx(DividendOp.getConstValue());
    return Operand(intxToU256Value(N % D));
  }

  // MOD(x, 2^n) -> AND(x, 2^n - 1)
  if (DivisorOp.isConstant()) {
    intx::uint256 D = u256ValueToIntx(DivisorOp.getConstValue());
    if (D != 0 && (D & (D - 1)) == 0) {
      Operand MaskOp(intxToU256Value(D - 1));
      return handleBitwiseOp<BinaryOperator::BO_AND>(DividendOp, MaskOp);
    }
  }

  // Range-based u64%u64 fast path: single OP_urem with div-by-zero guard.
  // MOD(u64, u64) → u64 result (remainder < divisor).
  if (Operand::bothFitU64(DividendOp, DivisorOp) && !DividendOp.isConstant() &&
      !DivisorOp.isConstant()) {
    U256Inst A = extractU256Operand(DividendOp);
    U256Inst B = extractU256Operand(DivisorOp);
    MType *I64Type = &Ctx.I64Type;
    MInstruction *Zero = createIntConstInstruction(I64Type, 0);
    MInstruction *One = createIntConstInstruction(I64Type, 1);

    // Guard against div-by-zero: EVM MOD(x, 0) = 0
    MInstruction *IsZero = createInstruction<CmpInstruction>(
        false, CmpInstruction::ICMP_EQ, I64Type, B[0], Zero);
    MInstruction *SafeB =
        createInstruction<SelectInstruction>(false, I64Type, IsZero, One, B[0]);
    MInstruction *Remainder = createInstruction<BinaryInstruction>(
        false, OP_urem, I64Type, A[0], SafeB);
    MInstruction *ModResult = createInstruction<SelectInstruction>(
        false, I64Type, IsZero, Zero, Remainder);

    U256Inst Result = {ModResult, Zero, Zero, Zero};
    return Operand(Result, EVMType::UINT256, ValueRange::U64);
  }

  // u64 divisor: inline cascading 128/64 mod
  if (DivisorOp.isConstU64()) {
    uint64_t D = DivisorOp.getConstValue()[0];
    if (D != 0)
      return handleModU64Divisor(DividendOp, D);
  }

  // u64 dividend: OR-fold + select
  if (DividendOp.isConstU64()) {
    uint64_t A = DividendOp.getConstValue()[0];
    return handleModU64Dividend(A, DivisorOp);
  }

  return handleDivModGeneral(DividendOp, DivisorOp, /*WantQuotient=*/false);
}

typename EVMMirBuilder::Operand EVMMirBuilder::handleSMod(Operand DividendOp,
                                                          Operand DivisorOp) {
  if (DividendOp.isConstant() && DivisorOp.isConstant()) {
    intx::uint256 D = u256ValueToIntx(DivisorOp.getConstValue());
    if (D == 0)
      return Operand(U256Value{0, 0, 0, 0});
    intx::uint256 N = u256ValueToIntx(DividendOp.getConstValue());
    auto Result = intx::sdivrem(N, D);
    return Operand(intxToU256Value(Result.rem));
  }

  // u64 divisor (fits in i63): sign of result = sign of dividend
  if (DivisorOp.isConstU64()) {
    uint64_t D = DivisorOp.getConstValue()[0];
    if (D != 0 && D <= INT64_MAX) {
      MType *I64Type = &Ctx.I64Type;
      MInstruction *Zero = createIntConstInstruction(I64Type, 0);
      U256Inst A = extractU256Operand(DividendOp);
      MInstruction *SignBit = createInstruction<CmpInstruction>(
          false, CmpInstruction::ICMP_SLT, &Ctx.I64Type, A[3], Zero);
      Operand NegA = handleNot(DividendOp);
      Operand AbsDividend =
          handleAddU64Const(NegA, Operand(U256Value{1, 0, 0, 0}));
      U256Inst AbsInst = extractU256Operand(AbsDividend);
      U256Inst SelA;
      for (size_t I = 0; I < EVM_ELEMENTS_COUNT; ++I) {
        SelA[I] = createInstruction<SelectInstruction>(false, I64Type, SignBit,
                                                       AbsInst[I], A[I]);
      }
      Operand AbsOp(SelA, EVMType::UINT256);
      Operand UnsignedResult = handleModU64Divisor(AbsOp, D);
      Operand NegResult = handleNot(UnsignedResult);
      Operand NegResult1 =
          handleAddU64Const(NegResult, Operand(U256Value{1, 0, 0, 0}));
      U256Inst URes = extractU256Operand(UnsignedResult);
      U256Inst NRes = extractU256Operand(NegResult1);
      U256Inst FinalInst;
      for (size_t I = 0; I < EVM_ELEMENTS_COUNT; ++I) {
        FinalInst[I] = createInstruction<SelectInstruction>(
            false, I64Type, SignBit, NRes[I], URes[I]);
      }
      return Operand(FinalInst, EVMType::UINT256);
    }
  }

  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  return callRuntimeFor<const intx::uint256 *, const intx::uint256 &,
                        const intx::uint256 &>(RuntimeFunctions.GetSMod,
                                               DividendOp, DivisorOp);
}

typename EVMMirBuilder::Operand EVMMirBuilder::handleAddMod(Operand AugendOp,
                                                            Operand AddendOp,
                                                            Operand ModulusOp) {
  if (AugendOp.isConstant() && AddendOp.isConstant() &&
      ModulusOp.isConstant()) {
    intx::uint256 M = u256ValueToIntx(ModulusOp.getConstValue());
    if (M == 0)
      return Operand(U256Value{0, 0, 0, 0});
    intx::uint512 Sum =
        intx::uint512(u256ValueToIntx(AugendOp.getConstValue())) +
        intx::uint512(u256ValueToIntx(AddendOp.getConstValue()));
    intx::uint256 Result = intx::uint256(Sum % M);
    return Operand(intxToU256Value(Result));
  }

  MType *I64Type = EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);
  MInstruction *Zero = createIntConstInstruction(I64Type, 0);

  U256Inst Augend = extractU256Operand(AugendOp);
  U256Inst Addend = extractU256Operand(AddendOp);
  U256Inst Modulus = extractU256Operand(ModulusOp);

  // Fast-path eligibility: mod[3] != 0 && x[3] <= mod[3] && y[3] <= mod[3].
  // Invariant established: x < 2*mod and y < 2*mod, so a single conditional
  // subtraction is sufficient to normalize each operand into [0, mod).
  // Proof: x < (x[3]+1)*2^192 <= (mod[3]+1)*2^192 <= 2*mod[3]*2^192 <= 2*mod,
  // where the last two steps use mod[3] >= 1. Any weaker check (e.g. dropping
  // the high-limb bound) breaks this invariant and the fast path.
  // The mod == 0 case is routed to the runtime slow path, which returns 0.
  MInstruction *ModHi = Modulus[3];
  MInstruction *ModHiNonZero = createInstruction<CmpInstruction>(
      false, CmpInstruction::ICMP_NE, I64Type, ModHi, Zero);
  MInstruction *AugendHiLE = createInstruction<CmpInstruction>(
      false, CmpInstruction::ICMP_ULE, I64Type, Augend[3], ModHi);
  MInstruction *AddendHiLE = createInstruction<CmpInstruction>(
      false, CmpInstruction::ICMP_ULE, I64Type, Addend[3], ModHi);

  // FastEligible = ModHiNonZero && AugendHiLE && AddendHiLE
  MInstruction *FastEligible = createInstruction<BinaryInstruction>(
      false, OP_and, I64Type, ModHiNonZero, AugendHiLE);
  FastEligible = createInstruction<BinaryInstruction>(false, OP_and, I64Type,
                                                      FastEligible, AddendHiLE);

  // Cascaded u256 unsigned LT: returns i64 {0,1} for A < B, high limb first.
  auto u256UnsignedLT = [&](const U256Inst &A, const U256Inst &B) {
    MInstruction *CmpResult = nullptr;
    MInstruction *AllEqual = nullptr;
    for (int I = EVM_ELEMENTS_COUNT - 1; I >= 0; --I) {
      MInstruction *LT = createInstruction<CmpInstruction>(
          false, CmpInstruction::ICMP_ULT, I64Type, A[I], B[I]);
      MInstruction *EQ = createInstruction<CmpInstruction>(
          false, CmpInstruction::ICMP_EQ, I64Type, A[I], B[I]);
      if (CmpResult == nullptr) {
        CmpResult = LT;
        AllEqual = EQ;
      } else {
        CmpResult = createInstruction<SelectInstruction>(
            false, I64Type, AllEqual, LT, CmpResult);
        AllEqual = createInstruction<BinaryInstruction>(false, OP_and, I64Type,
                                                        AllEqual, EQ);
      }
    }
    return CmpResult;
  };

  // Prepare result variables
  U256Var ResultVars = {};
  for (size_t I = 0; I < EVM_ELEMENTS_COUNT; ++I) {
    ResultVars[I] = CurFunc->createVariable(I64Type);
  }

  auto storeResult = [&](const U256Inst &Values) {
    for (size_t I = 0; I < EVM_ELEMENTS_COUNT; ++I) {
      createInstruction<DassignInstruction>(true, &(Ctx.VoidType), Values[I],
                                            ResultVars[I]->getVarIdx());
    }
  };

  auto loadResult = [&]() -> U256Inst {
    U256Inst Values = {};
    for (size_t I = 0; I < EVM_ELEMENTS_COUNT; ++I) {
      Values[I] = loadVariable(ResultVars[I]);
    }
    return Values;
  };

  // Branch: FastEligible ? FastBB : SlowBB
  MBasicBlock *FastBB = createBasicBlock();
  MBasicBlock *SlowBB = createBasicBlock();
  MBasicBlock *AfterBB = createBasicBlock();
  createInstruction<BrIfInstruction>(true, Ctx, FastEligible, FastBB, SlowBB);
  addSuccessor(FastBB);
  addSuccessor(SlowBB);

  // === Fast path (inline addmod) ===
  setInsertBlock(FastBB);
  {
    // Step 1: Normalize augend — if augend >= mod, use augend - mod
    MInstruction *AugLtMod = u256UnsignedLT(Augend, Modulus);

    // Compute augend - mod (u256 SUB chain)
    Operand AugSubMod =
        handleBinaryArithmetic<BinaryOperator::BO_SUB>(AugendOp, ModulusOp);
    U256Inst AugDiff = extractU256Operand(AugSubMod);

    // NormAugend = AugLtMod ? Augend : AugDiff  (if augend < mod, keep augend)
    U256Inst NormAugend = {};
    for (size_t I = 0; I < EVM_ELEMENTS_COUNT; ++I) {
      NormAugend[I] = createInstruction<SelectInstruction>(
          false, I64Type, AugLtMod, Augend[I], AugDiff[I]);
    }

    // Step 2: Normalize addend — if addend >= mod, use addend - mod
    MInstruction *AddLtMod = u256UnsignedLT(Addend, Modulus);

    Operand AddSubMod =
        handleBinaryArithmetic<BinaryOperator::BO_SUB>(AddendOp, ModulusOp);
    U256Inst AddDiff = extractU256Operand(AddSubMod);

    // NormAddend = AddLtMod ? Addend : AddDiff
    U256Inst NormAddend = {};
    for (size_t I = 0; I < EVM_ELEMENTS_COUNT; ++I) {
      NormAddend[I] = createInstruction<SelectInstruction>(
          false, I64Type, AddLtMod, Addend[I], AddDiff[I]);
    }

    // Step 3: Sum = NormAugend + NormAddend (u256 ADD chain)
    Operand NormAugendOp(NormAugend, EVMType::UINT256);
    Operand NormAddendOp(NormAddend, EVMType::UINT256);
    Operand SumOp = handleBinaryArithmetic<BinaryOperator::BO_ADD>(
        NormAugendOp, NormAddendOp);
    U256Inst Sum = extractU256Operand(SumOp);

    // Detect overflow: sum < NormAugend (unsigned comparison)
    MInstruction *Overflow = u256UnsignedLT(Sum, NormAugend);

    // Step 4: SumSubMod = Sum - Mod (u256 SUB chain)
    Operand ModulusOpLocal(Modulus, EVMType::UINT256);
    Operand SumSubModOp =
        handleBinaryArithmetic<BinaryOperator::BO_SUB>(SumOp, ModulusOpLocal);
    U256Inst SumSubMod = extractU256Operand(SumSubModOp);

    // Detect borrow: Sum < Mod
    MInstruction *SumLtMod = u256UnsignedLT(Sum, Modulus);

    // Result selection: if (overflow || !borrow) use SumSubMod, else Sum
    // !borrow means Sum >= Mod, i.e., !SumLtMod
    // overflow || !SumLtMod  =>  use SumSubMod
    //
    // Equivalently: use Sum only when (!overflow && SumLtMod)
    // UseSumSubMod = Overflow || !SumLtMod
    // Since SumLtMod is 0 or 1:  !SumLtMod = (SumLtMod == 0)
    MInstruction *One = createIntConstInstruction(I64Type, 1);
    MInstruction *NotBorrow = createInstruction<BinaryInstruction>(
        false, OP_xor, I64Type, SumLtMod, One);
    MInstruction *UseSumSubMod = createInstruction<BinaryInstruction>(
        false, OP_or, I64Type, Overflow, NotBorrow);

    U256Inst FastResult = {};
    for (size_t I = 0; I < EVM_ELEMENTS_COUNT; ++I) {
      FastResult[I] = createInstruction<SelectInstruction>(
          false, I64Type, UseSumSubMod, SumSubMod[I], Sum[I]);
    }

    storeResult(FastResult);
    createInstruction<BrInstruction>(true, Ctx, AfterBB);
    addSuccessor(AfterBB);
  }

  // === Slow path (runtime call, handles mod == 0 and small moduli) ===
  setInsertBlock(SlowBB);
  {
    // Runtime handles all cases including mod == 0.
    const auto &RuntimeFunctions = getRuntimeFunctionTable();
    U256Inst SlowResult = extractU256Operand(
        callRuntimeFor<const intx::uint256 *, const intx::uint256 &,
                       const intx::uint256 &, const intx::uint256 &>(
            RuntimeFunctions.GetAddMod, AugendOp, AddendOp, ModulusOp));
    storeResult(SlowResult);
    createInstruction<BrInstruction>(true, Ctx, AfterBB);
    addSuccessor(AfterBB);
  }

  // === After block: load result ===
  setInsertBlock(AfterBB);
  return Operand(loadResult(), EVMType::UINT256);
}

typename EVMMirBuilder::Operand
EVMMirBuilder::handleMulMod(Operand MultiplicandOp, Operand MultiplierOp,
                            Operand ModulusOp) {
  if (MultiplicandOp.isConstant() && MultiplierOp.isConstant() &&
      ModulusOp.isConstant()) {
    intx::uint256 M = u256ValueToIntx(ModulusOp.getConstValue());
    if (M == 0)
      return Operand(U256Value{0, 0, 0, 0});
    intx::uint512 Product =
        intx::uint512(u256ValueToIntx(MultiplicandOp.getConstValue())) *
        intx::uint512(u256ValueToIntx(MultiplierOp.getConstValue()));
    intx::uint256 Result = intx::uint256(Product % M);
    return Operand(intxToU256Value(Result));
  }

  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  return callRuntimeFor<const intx::uint256 *, const intx::uint256 &,
                        const intx::uint256 &, const intx::uint256 &>(
      RuntimeFunctions.GetMulMod, MultiplicandOp, MultiplierOp, ModulusOp);
}

typename EVMMirBuilder::Operand EVMMirBuilder::handleExp(Operand BaseOp,
                                                         Operand ExponentOp) {
  MType *I64Type = EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);
  MInstruction *Zero = createIntConstInstruction(I64Type, 0);
  MInstruction *One = createIntConstInstruction(I64Type, 1);
  MInstruction *Const3 = createIntConstInstruction(I64Type, 3);
  MInstruction *Const2 = createIntConstInstruction(I64Type, 2);
  MInstruction *Const8 = createIntConstInstruction(I64Type, 8);

  U256Inst Base = extractU256Operand(BaseOp);
  U256Inst Exponent = extractU256Operand(ExponentOp);

  auto loadU256Vars = [&](const U256Var &Vars) -> U256Inst {
    U256Inst Result = {};
    for (size_t I = 0; I < EVM_ELEMENTS_COUNT; ++I) {
      Result[I] = loadVariable(Vars[I]);
    }
    return Result;
  };

  auto storeU256Vars = [&](const U256Inst &Values, const U256Var &Vars) {
    for (size_t I = 0; I < EVM_ELEMENTS_COUNT; ++I) {
      createInstruction<DassignInstruction>(true, &(Ctx.VoidType), Values[I],
                                            Vars[I]->getVarIdx());
    }
  };

  // Calculate exponent byte size for dynamic gas (EIP-160)
  auto computeExpByteSize = [&]() -> MInstruction * {
    MInstruction *Any01 = createInstruction<BinaryInstruction>(
        false, OP_or, I64Type, Exponent[0], Exponent[1]);
    MInstruction *Any23 = createInstruction<BinaryInstruction>(
        false, OP_or, I64Type, Exponent[2], Exponent[3]);
    MInstruction *Any = createInstruction<BinaryInstruction>(
        false, OP_or, I64Type, Any01, Any23);
    MInstruction *IsZero = createInstruction<CmpInstruction>(
        false, CmpInstruction::Predicate::ICMP_EQ, &Ctx.I64Type, Any, Zero);

    MInstruction *Has3 = createInstruction<CmpInstruction>(
        false, CmpInstruction::Predicate::ICMP_NE, &Ctx.I64Type, Exponent[3],
        Zero);
    MInstruction *Has2 = createInstruction<CmpInstruction>(
        false, CmpInstruction::Predicate::ICMP_NE, &Ctx.I64Type, Exponent[2],
        Zero);
    MInstruction *Has1 = createInstruction<CmpInstruction>(
        false, CmpInstruction::Predicate::ICMP_NE, &Ctx.I64Type, Exponent[1],
        Zero);

    MInstruction *Idx1 =
        createInstruction<SelectInstruction>(false, I64Type, Has1, One, Zero);
    MInstruction *Idx2 = createInstruction<SelectInstruction>(
        false, I64Type, Has2, Const2, Idx1);
    MInstruction *Idx = createInstruction<SelectInstruction>(
        false, I64Type, Has3, Const3, Idx2);

    MInstruction *Limb1 = createInstruction<SelectInstruction>(
        false, I64Type, Has1, Exponent[1], Exponent[0]);
    MInstruction *Limb2 = createInstruction<SelectInstruction>(
        false, I64Type, Has2, Exponent[2], Limb1);
    MInstruction *Limb = createInstruction<SelectInstruction>(
        false, I64Type, Has3, Exponent[3], Limb2);

    // Avoid clz(0) undefined behavior by forcing at least one bit set.
    MInstruction *SafeLimb =
        createInstruction<BinaryInstruction>(false, OP_or, I64Type, Limb, One);
    MInstruction *Clz =
        createInstruction<UnaryInstruction>(false, OP_clz, I64Type, SafeLimb);
    MInstruction *ClzBytes = createInstruction<BinaryInstruction>(
        false, OP_ushr, I64Type, Clz, Const3);
    MInstruction *SigBytes = createInstruction<BinaryInstruction>(
        false, OP_sub, I64Type, Const8, ClzBytes);
    MInstruction *IdxBytes = createInstruction<BinaryInstruction>(
        false, OP_mul, I64Type, Idx, Const8);
    MInstruction *TotalBytes = createInstruction<BinaryInstruction>(
        false, OP_add, I64Type, SigBytes, IdxBytes);

    return createInstruction<SelectInstruction>(false, I64Type, IsZero, Zero,
                                                TotalBytes);
  };

  const uint64_t GasPerByte = Ctx.getRevision() < EVMC_SPURIOUS_DRAGON
                                  ? zen::evm::EXP_BYTE_GAS_PRE_SPURIOUS_DRAGON
                                  : zen::evm::EXP_BYTE_GAS;
  MInstruction *ExpByteSize = computeExpByteSize();
  MInstruction *GasPerByteConst =
      createIntConstInstruction(I64Type, GasPerByte);
  MInstruction *ExpGas = createInstruction<BinaryInstruction>(
      false, OP_mul, I64Type, ExpByteSize, GasPerByteConst);
  chargeDynamicGasIR(ExpGas);

  // Initialize loop variables
  U256Var BaseVars = {};
  U256Var ExpVars = {};
  U256Var ResultVars = {};
  Operand ResultInit = createU256ConstOperand(intx::uint256{1});
  U256Inst ResultInitComponents = ResultInit.getU256Components();

  for (size_t I = 0; I < EVM_ELEMENTS_COUNT; ++I) {
    BaseVars[I] = CurFunc->createVariable(I64Type);
    ExpVars[I] = CurFunc->createVariable(I64Type);
    ResultVars[I] = CurFunc->createVariable(I64Type);
    createInstruction<DassignInstruction>(true, &(Ctx.VoidType), Base[I],
                                          BaseVars[I]->getVarIdx());
    createInstruction<DassignInstruction>(true, &(Ctx.VoidType), Exponent[I],
                                          ExpVars[I]->getVarIdx());
    createInstruction<DassignInstruction>(true, &(Ctx.VoidType),
                                          ResultInitComponents[I],
                                          ResultVars[I]->getVarIdx());
  }

  Variable *Exp64Var = CurFunc->createVariable(I64Type);
  createInstruction<DassignInstruction>(true, &(Ctx.VoidType), Exponent[0],
                                        Exp64Var->getVarIdx());

  Operand ShiftOne = createU256ConstOperand(intx::uint256{1});

  MInstruction *High01 = createInstruction<BinaryInstruction>(
      false, OP_or, I64Type, Exponent[1], Exponent[2]);
  MInstruction *HighAny = createInstruction<BinaryInstruction>(
      false, OP_or, I64Type, High01, Exponent[3]);
  MInstruction *HasHigh = createInstruction<CmpInstruction>(
      false, CmpInstruction::Predicate::ICMP_NE, &Ctx.I64Type, HighAny, Zero);

  MBasicBlock *FastCondBB = createBasicBlock();
  MBasicBlock *SlowCondBB = createBasicBlock();
  MBasicBlock *AfterBB = createBasicBlock();
  createInstruction<BrIfInstruction>(true, Ctx, HasHigh, SlowCondBB,
                                     FastCondBB);
  addSuccessor(SlowCondBB);
  addSuccessor(FastCondBB);

  // Fast path: 64-bit exponent loop when high limbs are zero.
  MBasicBlock *FastBodyBB = createBasicBlock();
  MBasicBlock *FastOddBB = createBasicBlock();
  MBasicBlock *FastEvenBB = createBasicBlock();
  MBasicBlock *FastContinueBB = createBasicBlock();
  MBasicBlock *FastBaseBB = createBasicBlock();

  setInsertBlock(FastCondBB);
  MInstruction *Exp64 = loadVariable(Exp64Var);
  MInstruction *FastIsNonZero = createInstruction<CmpInstruction>(
      false, CmpInstruction::Predicate::ICMP_NE, &Ctx.I64Type, Exp64, Zero);
  createInstruction<BrIfInstruction>(true, Ctx, FastIsNonZero, FastBodyBB,
                                     AfterBB);
  addSuccessor(FastBodyBB);
  addSuccessor(AfterBB);

  setInsertBlock(FastBodyBB);
  U256Inst FastBaseCur = loadU256Vars(BaseVars);
  Operand FastBaseOpCur(FastBaseCur, EVMType::UINT256);
  MInstruction *FastLsb =
      createInstruction<BinaryInstruction>(false, OP_and, I64Type, Exp64, One);
  MInstruction *FastIsOdd = createInstruction<CmpInstruction>(
      false, CmpInstruction::Predicate::ICMP_NE, &Ctx.I64Type, FastLsb, Zero);
  createInstruction<BrIfInstruction>(true, Ctx, FastIsOdd, FastOddBB,
                                     FastEvenBB);
  addSuccessor(FastOddBB);
  addSuccessor(FastEvenBB);

  setInsertBlock(FastOddBB);
  U256Inst FastResultCur = loadU256Vars(ResultVars);
  Operand FastResultOp(FastResultCur, EVMType::UINT256);
  Operand FastMulResOp = handleMul(FastResultOp, FastBaseOpCur);
  U256Inst FastMulRes = extractU256Operand(FastMulResOp);
  storeU256Vars(FastMulRes, ResultVars);
  createInstruction<BrInstruction>(true, Ctx, FastContinueBB);
  addSuccessor(FastContinueBB);

  setInsertBlock(FastEvenBB);
  createInstruction<BrInstruction>(true, Ctx, FastContinueBB);
  addSuccessor(FastContinueBB);

  setInsertBlock(FastContinueBB);
  MInstruction *FastShifted =
      createInstruction<BinaryInstruction>(false, OP_ushr, I64Type, Exp64, One);
  MInstruction *FastShiftZero = createInstruction<CmpInstruction>(
      false, CmpInstruction::Predicate::ICMP_EQ, &Ctx.I64Type, FastShifted,
      Zero);
  createInstruction<BrIfInstruction>(true, Ctx, FastShiftZero, AfterBB,
                                     FastBaseBB);
  addSuccessor(AfterBB);
  addSuccessor(FastBaseBB);

  setInsertBlock(FastBaseBB);
  createInstruction<DassignInstruction>(true, &(Ctx.VoidType), FastShifted,
                                        Exp64Var->getVarIdx());
  Operand FastBaseSquaredOp = handleMul(FastBaseOpCur, FastBaseOpCur);
  U256Inst FastBaseSquared = extractU256Operand(FastBaseSquaredOp);
  storeU256Vars(FastBaseSquared, BaseVars);
  createInstruction<BrInstruction>(true, Ctx, FastCondBB);
  addSuccessor(FastCondBB);

  // Slow path: full 256-bit exponent loop.
  MBasicBlock *SlowBodyBB = createBasicBlock();
  MBasicBlock *SlowOddBB = createBasicBlock();
  MBasicBlock *SlowEvenBB = createBasicBlock();
  MBasicBlock *SlowContinueBB = createBasicBlock();
  MBasicBlock *SlowBaseBB = createBasicBlock();

  setInsertBlock(SlowCondBB);
  U256Inst ExpCond = loadU256Vars(ExpVars);
  MInstruction *SlowAny01 = createInstruction<BinaryInstruction>(
      false, OP_or, I64Type, ExpCond[0], ExpCond[1]);
  MInstruction *SlowAny23 = createInstruction<BinaryInstruction>(
      false, OP_or, I64Type, ExpCond[2], ExpCond[3]);
  MInstruction *SlowAny = createInstruction<BinaryInstruction>(
      false, OP_or, I64Type, SlowAny01, SlowAny23);
  MInstruction *SlowIsNonZero = createInstruction<CmpInstruction>(
      false, CmpInstruction::Predicate::ICMP_NE, &Ctx.I64Type, SlowAny, Zero);
  createInstruction<BrIfInstruction>(true, Ctx, SlowIsNonZero, SlowBodyBB,
                                     AfterBB);
  addSuccessor(SlowBodyBB);
  addSuccessor(AfterBB);

  setInsertBlock(SlowBodyBB);
  U256Inst ExpCur = loadU256Vars(ExpVars);
  U256Inst BaseCur = loadU256Vars(BaseVars);
  Operand BaseOpCur(BaseCur, EVMType::UINT256);

  MInstruction *Lsb = createInstruction<BinaryInstruction>(
      false, OP_and, I64Type, ExpCur[0], One);
  MInstruction *IsOdd = createInstruction<CmpInstruction>(
      false, CmpInstruction::Predicate::ICMP_NE, &Ctx.I64Type, Lsb, Zero);
  createInstruction<BrIfInstruction>(true, Ctx, IsOdd, SlowOddBB, SlowEvenBB);
  addSuccessor(SlowOddBB);
  addSuccessor(SlowEvenBB);

  setInsertBlock(SlowOddBB);
  U256Inst ResultCur = loadU256Vars(ResultVars);
  Operand ResultOp(ResultCur, EVMType::UINT256);
  Operand MulResOp = handleMul(ResultOp, BaseOpCur);
  U256Inst MulRes = extractU256Operand(MulResOp);
  storeU256Vars(MulRes, ResultVars);
  createInstruction<BrInstruction>(true, Ctx, SlowContinueBB);
  addSuccessor(SlowContinueBB);

  setInsertBlock(SlowEvenBB);
  createInstruction<BrInstruction>(true, Ctx, SlowContinueBB);
  addSuccessor(SlowContinueBB);

  setInsertBlock(SlowContinueBB);
  Operand ExpShiftedOp = handleShift<BinaryOperator::BO_SHR_U>(
      ShiftOne, Operand(ExpCur, EVMType::UINT256));
  U256Inst ExpShifted = extractU256Operand(ExpShiftedOp);
  MInstruction *ShiftAny01 = createInstruction<BinaryInstruction>(
      false, OP_or, I64Type, ExpShifted[0], ExpShifted[1]);
  MInstruction *ShiftAny23 = createInstruction<BinaryInstruction>(
      false, OP_or, I64Type, ExpShifted[2], ExpShifted[3]);
  MInstruction *ShiftAny = createInstruction<BinaryInstruction>(
      false, OP_or, I64Type, ShiftAny01, ShiftAny23);
  MInstruction *ShiftIsZero = createInstruction<CmpInstruction>(
      false, CmpInstruction::Predicate::ICMP_EQ, &Ctx.I64Type, ShiftAny, Zero);
  createInstruction<BrIfInstruction>(true, Ctx, ShiftIsZero, AfterBB,
                                     SlowBaseBB);
  addSuccessor(AfterBB);
  addSuccessor(SlowBaseBB);

  setInsertBlock(SlowBaseBB);
  Operand BaseSquaredOp = handleMul(BaseOpCur, BaseOpCur);
  U256Inst BaseSquared = extractU256Operand(BaseSquaredOp);
  storeU256Vars(BaseSquared, BaseVars);
  storeU256Vars(ExpShifted, ExpVars);
  createInstruction<BrInstruction>(true, Ctx, SlowCondBB);
  addSuccessor(SlowCondBB);

  setInsertBlock(AfterBB);
  U256Inst ResultFinal = loadU256Vars(ResultVars);
  return Operand(ResultFinal, EVMType::UINT256);
}

EVMMirBuilder::U256Inst EVMMirBuilder::handleCompareEQZ(const U256Inst &LHS,
                                                        MType *ResultType,
                                                        bool IsNegated) {
  U256Inst Result = {};
  MType *MirI64Type =
      EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);

  // For ISZERO: OR all components, then compare with 0
  MInstruction *OrResult = nullptr;
  for (size_t I = 0; I < EVM_ELEMENTS_COUNT; ++I) {
    if (OrResult == nullptr) {
      OrResult = LHS[I];
    } else {
      OrResult = createInstruction<BinaryInstruction>(false, OP_or, MirI64Type,
                                                      OrResult, LHS[I]);
    }
  }

  // Final result is 1 if all are zero, 0 otherwise
  MInstruction *Zero = createIntConstInstruction(MirI64Type, 0);
  auto Predicate = IsNegated ? CmpInstruction::Predicate::ICMP_NE
                             : CmpInstruction::Predicate::ICMP_EQ;
  MInstruction *CmpResult = createInstruction<CmpInstruction>(
      false, Predicate, ResultType, OrResult, Zero);

  // Convert to u256: result[0] = CmpResult extended to i64, others = 0
  Result[0] = protectUnsafeValue(CmpResult, MirI64Type);
  for (size_t I = 1; I < EVM_ELEMENTS_COUNT; ++I) {
    Result[I] = Zero;
  }

  return Result;
}

EVMMirBuilder::U256Inst EVMMirBuilder::handleCompareEQ(const U256Inst &LHS,
                                                       const U256Inst &RHS,
                                                       MType *ResultType) {
  U256Inst Result = {};

  // For EQ: all components must be equal (AND all component comparisons)
  MInstruction *AndResult = nullptr;
  for (size_t I = 0; I < EVM_ELEMENTS_COUNT; ++I) {
    ZEN_ASSERT(LHS[I] && RHS[I]);
    auto Predicate = CmpInstruction::Predicate::ICMP_EQ;
    MInstruction *CmpResult = createInstruction<CmpInstruction>(
        false, Predicate, ResultType, LHS[I], RHS[I]);
    if (AndResult == nullptr) {
      AndResult = CmpResult;
    } else {
      AndResult = createInstruction<BinaryInstruction>(
          false, OP_and, ResultType, AndResult, CmpResult);
    }
  }

  MType *MirI64Type =
      EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);
  Result[0] = protectUnsafeValue(AndResult, MirI64Type);
  MInstruction *Zero = createIntConstInstruction(MirI64Type, 0);
  for (size_t I = 1; I < EVM_ELEMENTS_COUNT; ++I) {
    Result[I] = Zero;
  }

  return Result;
}

EVMMirBuilder::U256Inst
EVMMirBuilder::handleCompareGT_LT(const U256Inst &LHS, const U256Inst &RHS,
                                  MType *ResultType, CompareOperator Operator) {
  U256Inst Result = {};
  MType *MirI64Type =
      EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);

  // Compare from most significant to least significant component
  // If components are equal, continue to next
  MInstruction *FinalResult = nullptr;
  MInstruction *Zero = createIntConstInstruction(MirI64Type, 0);
  MInstruction *One = createIntConstInstruction(ResultType, 1);

  CmpInstruction::Predicate SignedPredicate;
  CmpInstruction::Predicate UnsignedPredicate;
  bool IsSigned = false;
  if (Operator == CompareOperator::CO_LT) {
    SignedPredicate = CmpInstruction::Predicate::ICMP_ULT;
    UnsignedPredicate = CmpInstruction::Predicate::ICMP_ULT;
  } else if (Operator == CompareOperator::CO_LT_S) {
    SignedPredicate = CmpInstruction::Predicate::ICMP_SLT;
    UnsignedPredicate = CmpInstruction::Predicate::ICMP_ULT;
    IsSigned = true;
  } else if (Operator == CompareOperator::CO_GT) {
    SignedPredicate = CmpInstruction::Predicate::ICMP_UGT;
    UnsignedPredicate = CmpInstruction::Predicate::ICMP_UGT;
  } else if (Operator == CompareOperator::CO_GT_S) {
    SignedPredicate = CmpInstruction::Predicate::ICMP_SGT;
    UnsignedPredicate = CmpInstruction::Predicate::ICMP_UGT;
    IsSigned = true;
  } else {
    ZEN_ASSERT_TODO();
  }
  auto EQPredicate = CmpInstruction::Predicate::ICMP_EQ;

  // Track if all higher components are equal
  MInstruction *AllEqual = nullptr;

  for (int I = EVM_ELEMENTS_COUNT - 1; I >= 0; --I) {
    ZEN_ASSERT(LHS[I] && RHS[I]);

    // For signed 256-bit comparison, only the most significant component
    // carries the sign bit; lower components are magnitude-only and must
    // use unsigned comparison.
    auto Pred = (IsSigned && I == EVM_ELEMENTS_COUNT - 1) ? SignedPredicate
                                                          : UnsignedPredicate;
    MInstruction *CompResult = createInstruction<CmpInstruction>(
        false, Pred, ResultType, LHS[I], RHS[I]);
    MInstruction *EqResult = createInstruction<CmpInstruction>(
        false, EQPredicate, ResultType, LHS[I], RHS[I]);

    if (FinalResult == nullptr) {
      FinalResult = CompResult;
      AllEqual = EqResult;
    } else {
      // FinalResult = EqResult_prev ? CompResult : FinalResult
      FinalResult = createInstruction<SelectInstruction>(
          false, ResultType, AllEqual, CompResult, FinalResult);
      // Update AllEqual: AllEqual = AllEqual_prev && EqResult
      AllEqual = createInstruction<BinaryInstruction>(false, OP_and, ResultType,
                                                      AllEqual, EqResult);
    }
  }

  ZEN_ASSERT(FinalResult);
  Result[0] = protectUnsafeValue(FinalResult, MirI64Type);
  for (size_t I = 1; I < EVM_ELEMENTS_COUNT; ++I) {
    Result[I] = Zero;
  }

  return Result;
}

typename EVMMirBuilder::Operand EVMMirBuilder::handleNot(const Operand &LHSOp) {
  // Phase 0: Constant folding
  if (LHSOp.isConstant()) {
    const auto &V = LHSOp.getConstValue();
    return Operand(U256Value{~V[0], ~V[1], ~V[2], ~V[3]});
  }

  if (LHSOp.isDeferredBitwiseNot()) {
    return Operand(LHSOp.getDeferredBaseComponents(), EVMType::UINT256);
  }

  return Operand::createDeferredBitwiseNot(extractU256Operand(LHSOp));
}

// ==================== u64 Fast Path Helpers ====================

typename EVMMirBuilder::Operand
EVMMirBuilder::handleAddU64Const(const Operand &FullOp,
                                 const Operand &U64ConstOp) {
  U256Inst LHS = extractU256Operand(FullOp);
  MType *MirI64Type =
      EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);
  MInstruction *Carry = createIntConstInstruction(MirI64Type, 0);

  MInstruction *RHS0 =
      createIntConstInstruction(MirI64Type, U64ConstOp.getConstValue()[0]);
  MInstruction *RHSZero = createIntConstInstruction(MirI64Type, 0);

  // Pre-materialize LHS operands for carry chain safety
  for (size_t I = 0; I < EVM_ELEMENTS_COUNT; ++I) {
    LHS[I] = protectUnsafeValue(LHS[I], MirI64Type);
  }
  // RHS constants (immediate MOV) never clobber flags — no barrier needed.

  U256Inst Result = {};
  // Limb 0: ADD with the actual u64 value
  Result[0] = protectUnsafeValue(createInstruction<BinaryInstruction>(
                                     false, OP_add, MirI64Type, LHS[0], RHS0),
                                 MirI64Type);
  // Limbs 1-3: ADC with zero (carry propagation only)
  for (size_t I = 1; I < EVM_ELEMENTS_COUNT; ++I) {
    MInstruction *AdcInst = createInstruction<AdcInstruction>(
        false, MirI64Type, LHS[I], RHSZero, Carry);
    // Last ADC: carry flag is dead after this point, no subsequent ADC
    // consumes it. The barrier is only needed for intermediate ADCs to
    // force immediate execution while CF is live.
    if (I < EVM_ELEMENTS_COUNT - 1) {
      Result[I] = protectUnsafeValue(AdcInst, MirI64Type);
    } else {
      Result[I] = AdcInst;
    }
  }
  return Operand(Result, EVMType::UINT256);
}

typename EVMMirBuilder::Operand
EVMMirBuilder::handleSubU64Const(const Operand &LHSOp,
                                 const Operand &U64ConstRHSOp) {
  U256Inst LHS = extractU256Operand(LHSOp);
  MType *MirI64Type =
      EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);

  MInstruction *RHS0 =
      createIntConstInstruction(MirI64Type, U64ConstRHSOp.getConstValue()[0]);

  // Limb 0: full sub
  MInstruction *Diff0 = createInstruction<BinaryInstruction>(
      false, OP_sub, MirI64Type, LHS[0], RHS0);
  // Borrow from limb 0: LHS[0] < RHS0
  auto LTPredicate = CmpInstruction::Predicate::ICMP_ULT;
  MInstruction *Borrow = createInstruction<CmpInstruction>(
      false, LTPredicate, &Ctx.I64Type, LHS[0], RHS0);
  Borrow = zeroExtendToI64(Borrow);

  U256Inst Result = {};
  // No SBB instructions used — explicit borrow computation means carry flag
  // is never live, so no protectUnsafeValue barriers are needed.
  Result[0] = Diff0;

  // Limbs 1-3: only subtract the borrow (RHS is 0 for upper limbs)
  for (size_t I = 1; I < EVM_ELEMENTS_COUNT; ++I) {
    MInstruction *Diff = createInstruction<BinaryInstruction>(
        false, OP_sub, MirI64Type, LHS[I], Borrow);
    Result[I] = Diff;

    if (I < EVM_ELEMENTS_COUNT - 1) {
      // New borrow: LHS[I] < Borrow
      MInstruction *NewBorrow = createInstruction<CmpInstruction>(
          false, LTPredicate, &Ctx.I64Type, LHS[I], Borrow);
      Borrow = zeroExtendToI64(NewBorrow);
    }
  }
  return Operand(Result, EVMType::UINT256);
}

typename EVMMirBuilder::Operand
EVMMirBuilder::handleCompareEqU64(const Operand &FullOp, uint64_t U64Val) {
  U256Inst LHS = extractU256Operand(FullOp);
  MType *MirI64Type =
      EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);
  MInstruction *Zero = createIntConstInstruction(MirI64Type, 0);

  // Check low limb against the u64 value
  MInstruction *CmpVal = createIntConstInstruction(MirI64Type, U64Val);
  auto EqPred = CmpInstruction::Predicate::ICMP_EQ;
  MInstruction *LowEq = createInstruction<CmpInstruction>(
      false, EqPred, &Ctx.I64Type, LHS[0], CmpVal);

  // Check that upper limbs are all zero via OR-fold
  MInstruction *Upper = createInstruction<BinaryInstruction>(
      false, OP_or, MirI64Type, LHS[1], LHS[2]);
  Upper = createInstruction<BinaryInstruction>(false, OP_or, MirI64Type, Upper,
                                               LHS[3]);
  MInstruction *UpperZero = createInstruction<CmpInstruction>(
      false, EqPred, &Ctx.I64Type, Upper, Zero);

  // Final: low matches AND upper is zero
  MInstruction *FinalResult = createInstruction<BinaryInstruction>(
      false, OP_and, &Ctx.I64Type, LowEq, UpperZero);

  U256Inst Result = {};
  Result[0] = protectUnsafeValue(FinalResult, MirI64Type);
  for (size_t I = 1; I < EVM_ELEMENTS_COUNT; ++I) {
    Result[I] = Zero;
  }
  return Operand(Result, EVMType::UINT256, ValueRange::U64);
}

typename EVMMirBuilder::Operand
EVMMirBuilder::handleCompareLtRhsU64(const Operand &LHSOp, uint64_t RhsU64) {
  // LT(a, u64_b): a < b where b fits in u64
  // If a >= 2^64 (upper limbs non-zero), then a > any u64, so result = false
  // Otherwise, compare a[0] < b
  U256Inst LHS = extractU256Operand(LHSOp);
  MType *MirI64Type =
      EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);
  MInstruction *Zero = createIntConstInstruction(MirI64Type, 0);

  MInstruction *Upper = createInstruction<BinaryInstruction>(
      false, OP_or, MirI64Type, LHS[1], LHS[2]);
  Upper = createInstruction<BinaryInstruction>(false, OP_or, MirI64Type, Upper,
                                               LHS[3]);
  auto NePred = CmpInstruction::Predicate::ICMP_NE;
  MInstruction *HasUpper = createInstruction<CmpInstruction>(
      false, NePred, &Ctx.I64Type, Upper, Zero);

  MInstruction *RhsVal = createIntConstInstruction(MirI64Type, RhsU64);
  auto LtPred = CmpInstruction::Predicate::ICMP_ULT;
  MInstruction *LowLt = createInstruction<CmpInstruction>(
      false, LtPred, &Ctx.I64Type, LHS[0], RhsVal);

  // result = hasUpper ? 0 : lowLt
  MInstruction *FinalResult = createInstruction<SelectInstruction>(
      false, &Ctx.I64Type, HasUpper, Zero, LowLt);

  U256Inst Result = {};
  Result[0] = protectUnsafeValue(FinalResult, MirI64Type);
  for (size_t I = 1; I < EVM_ELEMENTS_COUNT; ++I) {
    Result[I] = Zero;
  }
  return Operand(Result, EVMType::UINT256, ValueRange::U64);
}

typename EVMMirBuilder::Operand
EVMMirBuilder::handleCompareGtRhsU64(const Operand &LHSOp, uint64_t RhsU64) {
  // GT(a, u64_b): a > b where b fits in u64
  // If a >= 2^64 (upper limbs non-zero), then a > any u64, so result = true
  // Otherwise, compare a[0] > b
  U256Inst LHS = extractU256Operand(LHSOp);
  MType *MirI64Type =
      EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);
  MInstruction *Zero = createIntConstInstruction(MirI64Type, 0);
  MInstruction *One = createIntConstInstruction(MirI64Type, 1);

  MInstruction *Upper = createInstruction<BinaryInstruction>(
      false, OP_or, MirI64Type, LHS[1], LHS[2]);
  Upper = createInstruction<BinaryInstruction>(false, OP_or, MirI64Type, Upper,
                                               LHS[3]);
  auto NePred = CmpInstruction::Predicate::ICMP_NE;
  MInstruction *HasUpper = createInstruction<CmpInstruction>(
      false, NePred, &Ctx.I64Type, Upper, Zero);

  MInstruction *RhsVal = createIntConstInstruction(MirI64Type, RhsU64);
  auto GtPred = CmpInstruction::Predicate::ICMP_UGT;
  MInstruction *LowGt = createInstruction<CmpInstruction>(
      false, GtPred, &Ctx.I64Type, LHS[0], RhsVal);

  // result = hasUpper ? 1 : lowGt
  MInstruction *FinalResult = createInstruction<SelectInstruction>(
      false, &Ctx.I64Type, HasUpper, One, LowGt);

  U256Inst Result = {};
  Result[0] = protectUnsafeValue(FinalResult, MirI64Type);
  for (size_t I = 1; I < EVM_ELEMENTS_COUNT; ++I) {
    Result[I] = Zero;
  }
  return Operand(Result, EVMType::UINT256, ValueRange::U64);
}

typename EVMMirBuilder::Operand
EVMMirBuilder::handleClz(const Operand &ValueOp) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  return callRuntimeFor<const intx::uint256 *, const intx::uint256 &>(
      RuntimeFunctions.GetClz, ValueOp);
}

namespace {
// Extract constant shift amount from MInstruction if it is a constant.
std::optional<uint64_t> getConstShiftAmount(MInstruction *Inst) {
  if (auto *CI = llvm::dyn_cast<ConstantInstruction>(Inst)) {
    if (auto *IntConst = llvm::dyn_cast<MConstantInt>(&CI->getConstant())) {
      return IntConst->getValue().getZExtValue();
    }
  }
  return std::nullopt;
}
} // namespace

EVMMirBuilder::U256Inst
EVMMirBuilder::handleLeftShift(const U256Inst &Value, MInstruction *ShiftAmount,
                               MInstruction *IsLargeShift) {
  MType *MirI64Type =
      EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);
  U256Inst Result = {};

  MInstruction *Zero = createIntConstInstruction(MirI64Type, 0);

  // Fast path: constant shift amount — direct limb logic, no Select/cmp loops.
  if (auto ShiftOpt = getConstShiftAmount(ShiftAmount)) {
    uint64_t Shift = *ShiftOpt;
    if (Shift >= 256) {
      for (size_t I = 0; I < EVM_ELEMENTS_COUNT; ++I)
        Result[I] = Zero;
      return Result;
    }
    uint64_t CompShift = Shift / 64;
    uint64_t ShiftMod = Shift % 64;

    // Hoist loop-invariant constant instructions out of the limb loop.
    MInstruction *ShiftModConst = nullptr;
    MInstruction *RemainingBitsConst = nullptr;
    if (ShiftMod != 0) {
      ShiftModConst = createIntConstInstruction(MirI64Type, ShiftMod);
    }
    if (ShiftMod != 0 && (64 - ShiftMod) > 0) {
      RemainingBitsConst = createIntConstInstruction(MirI64Type, 64 - ShiftMod);
    }

    for (size_t I = 0; I < EVM_ELEMENTS_COUNT; ++I) {
      MInstruction *R = Zero;
      if (I >= CompShift) {
        size_t SrcIdx = I - CompShift;
        if (ShiftMod == 0) {
          // Pure limb shift (multiple of 64): no intra-limb shift/carry needed.
          R = Value[SrcIdx];
        } else {
          MInstruction *SrcVal = Value[SrcIdx];
          MInstruction *Shifted = createInstruction<BinaryInstruction>(
              false, OP_shl, MirI64Type, SrcVal, ShiftModConst);
          if (SrcIdx > 0 && RemainingBitsConst) {
            MInstruction *Carry = createInstruction<BinaryInstruction>(
                false, OP_ushr, MirI64Type, Value[SrcIdx - 1],
                RemainingBitsConst);
            R = createInstruction<BinaryInstruction>(false, OP_or, MirI64Type,
                                                     Shifted, Carry);
          } else {
            R = Shifted;
          }
        }
      }
      // Guard with IsLargeShift: if the full 256-bit shift has high limbs set,
      // the result must be zero per EVM spec.
      R = createInstruction<SelectInstruction>(false, MirI64Type, IsLargeShift,
                                               Zero, R);
      Result[I] = protectUnsafeValue(R, MirI64Type);
    }
    return Result;
  }

  MInstruction *One = createIntConstInstruction(MirI64Type, 1);
  MInstruction *Const64 = createIntConstInstruction(MirI64Type, 64);

  // EVM SHL operation: result = value << shift
  // DMIR implementation maps 256-bit shift to 4x64-bit components
  // shift_mod = shift % 64 (shift amount within 64-bit range)
  // shift_comp = shift / 64 (which component index shift from)
  // remaining_bits = 64 - shift_mod (remaining bits for carry calculation)
  // Strength-reduce: shift % 64 == shift & 63, shift / 64 == shift >> 6
  MInstruction *Const63 = createIntConstInstruction(MirI64Type, 63);
  MInstruction *Const6 = createIntConstInstruction(MirI64Type, 6);
  MInstruction *ShiftMod64 = createInstruction<BinaryInstruction>(
      false, OP_and, MirI64Type, ShiftAmount, Const63);
  MInstruction *ComponentShift = createInstruction<BinaryInstruction>(
      false, OP_ushr, MirI64Type, ShiftAmount, Const6);
  MInstruction *RemainingBits = createInstruction<BinaryInstruction>(
      false, OP_sub, MirI64Type, Const64, ShiftMod64);

  MInstruction *MaxIndex =
      createIntConstInstruction(MirI64Type, EVM_ELEMENTS_COUNT);

  // Process each 64-bit component from low to high
  // Example: For shift=72 (1*64 + 8), component_shift=1, shift_mod=8
  // Component 0 gets bits from component -1 (invalid, use 0)
  // Component 1 gets bits from component 0 shifted left by 8
  // Component 2 gets bits from component 1 shifted left by 8
  // Component 3 gets bits from component 2 shifted left by 8
  for (size_t I = 0; I < EVM_ELEMENTS_COUNT; ++I) {
    MInstruction *CurrentIdx = createIntConstInstruction(MirI64Type, I);

    // Calculate source component index: current index - component shift
    MInstruction *SrcIdx = createInstruction<BinaryInstruction>(
        false, OP_sub, MirI64Type, CurrentIdx, ComponentShift);

    // Validate source index bounds
    // if (0 <= src_idx < EVM_ELEMENTS_COUNT) use Value[src_idx] else 0
    MInstruction *IsValidLow = createInstruction<CmpInstruction>(
        false, CmpInstruction::Predicate::ICMP_UGE, &Ctx.I64Type, SrcIdx, Zero);
    MInstruction *IsValidHigh = createInstruction<CmpInstruction>(
        false, CmpInstruction::Predicate::ICMP_ULT, &Ctx.I64Type, SrcIdx,
        MaxIndex);
    MInstruction *IsInBounds = createInstruction<BinaryInstruction>(
        false, OP_and, MirI64Type, IsValidLow, IsValidHigh);

    // Select source value from the appropriate component
    // src_value = (src_idx == J) ? Value[J] : 0 for all J
    MInstruction *SrcValue = Zero;
    for (size_t J = 0; J < EVM_ELEMENTS_COUNT; ++J) {
      MInstruction *TargetIdx = createIntConstInstruction(MirI64Type, J);
      MInstruction *IsMatch = createInstruction<CmpInstruction>(
          false, CmpInstruction::Predicate::ICMP_EQ, &Ctx.I64Type, SrcIdx,
          TargetIdx);
      SrcValue = createInstruction<SelectInstruction>(
          false, MirI64Type, IsMatch, Value[J], SrcValue);
    }
    SrcValue = createInstruction<SelectInstruction>(false, MirI64Type,
                                                    IsInBounds, SrcValue, Zero);

    // Calculate previous component index for carry bits
    // prev_idx = src_idx - 1
    MInstruction *PrevIdx = createInstruction<BinaryInstruction>(
        false, OP_sub, MirI64Type, SrcIdx, One);

    // Validate previous component bounds
    // if (0 <= prev_idx < EVM_ELEMENTS_COUNT) use Value[prev_idx] else 0
    MInstruction *IsValidPrevLow = createInstruction<CmpInstruction>(
        false, CmpInstruction::Predicate::ICMP_UGE, &Ctx.I64Type, PrevIdx,
        Zero);
    MInstruction *IsValidPrevHigh = createInstruction<CmpInstruction>(
        false, CmpInstruction::Predicate::ICMP_ULT, &Ctx.I64Type, PrevIdx,
        MaxIndex);
    MInstruction *IsPrevValid = createInstruction<BinaryInstruction>(
        false, OP_and, MirI64Type, IsValidPrevLow, IsValidPrevHigh);

    // Only calculate carry when there is actual bit-level shifting (ShiftMod64
    // > 0)
    // carry_bits = (prev_idx == K) ? (Value[K] >> remaining_bits) : 0
    MInstruction *HasBitShift = createInstruction<CmpInstruction>(
        false, CmpInstruction::Predicate::ICMP_NE, &Ctx.I64Type, ShiftMod64,
        Zero);
    MInstruction *CarryValue = Zero;
    for (size_t K = 0; K < EVM_ELEMENTS_COUNT; ++K) {
      MInstruction *TargetIdx = createIntConstInstruction(MirI64Type, K);
      MInstruction *IsMatch = createInstruction<CmpInstruction>(
          false, CmpInstruction::Predicate::ICMP_EQ, &Ctx.I64Type, PrevIdx,
          TargetIdx);
      MInstruction *PrevValue = createInstruction<SelectInstruction>(
          false, MirI64Type, IsMatch, Value[K], Zero);
      PrevValue = createInstruction<SelectInstruction>(
          false, MirI64Type, IsPrevValid, PrevValue, Zero);

      // Extract carry bits by shifting right the remaining bits
      // Avoid undefined behavior when RemainingBits >= 64
      MInstruction *IsValidShift = createInstruction<CmpInstruction>(
          false, CmpInstruction::Predicate::ICMP_ULT, &Ctx.I64Type,
          RemainingBits, Const64);
      MInstruction *CarryBits = createInstruction<BinaryInstruction>(
          false, OP_ushr, MirI64Type, PrevValue, RemainingBits);
      // Use carry bits only if shift amount is valid (< 64) AND there is
      // bit-level shifting
      MInstruction *UseCarry = createInstruction<BinaryInstruction>(
          false, OP_and, MirI64Type, IsValidShift, HasBitShift);
      CarryBits = createInstruction<SelectInstruction>(
          false, MirI64Type, UseCarry, CarryBits, Zero);
      CarryValue = createInstruction<SelectInstruction>(
          false, MirI64Type, IsMatch, CarryBits, CarryValue);
    }

    // Shift the source value left by the modulo amount
    // shifted_value = src_value << shift_mod
    MInstruction *ShiftedValue = createInstruction<BinaryInstruction>(
        false, OP_shl, MirI64Type, SrcValue, ShiftMod64);

    // combined_value = shifted_value | carry_bits
    MInstruction *CombinedValue = createInstruction<BinaryInstruction>(
        false, OP_or, MirI64Type, ShiftedValue, CarryValue);

    // Final result selection based on bounds checking and large shift flag
    // result[I] = IsLargeShift ? 0 : (IsInBounds ? CombinedValue : 0)
    MInstruction *FinalValue = createInstruction<SelectInstruction>(
        false, MirI64Type, IsLargeShift, Zero,
        createInstruction<SelectInstruction>(false, MirI64Type, IsInBounds,
                                             CombinedValue, Zero));
    Result[I] = protectUnsafeValue(FinalValue, MirI64Type);
  }

  return Result;
}

EVMMirBuilder::U256Inst
EVMMirBuilder::handleLogicalRightShift(const U256Inst &Value,
                                       MInstruction *ShiftAmount,
                                       MInstruction *IsLargeShift) {
  MType *MirI64Type =
      EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);
  U256Inst Result = {};

  MInstruction *Zero = createIntConstInstruction(MirI64Type, 0);

  // Fast path: constant shift amount — direct limb logic, no Select/cmp loops.
  if (auto ShiftOpt = getConstShiftAmount(ShiftAmount)) {
    uint64_t Shift = *ShiftOpt;
    if (Shift >= 256) {
      for (size_t I = 0; I < EVM_ELEMENTS_COUNT; ++I)
        Result[I] = Zero;
      return Result;
    }
    uint64_t CompShift = Shift / 64;
    uint64_t ShiftMod = Shift % 64;

    // If the shift is a multiple of 64, we only need to move whole limbs.
    if (ShiftMod == 0) {
      for (size_t I = 0; I < EVM_ELEMENTS_COUNT; ++I) {
        MInstruction *R = Zero;
        if (I + CompShift < EVM_ELEMENTS_COUNT) {
          size_t SrcIdx = I + CompShift;
          R = Value[SrcIdx];
        }
        // Guard with IsLargeShift for correctness with 256-bit shift values.
        R = createInstruction<SelectInstruction>(false, MirI64Type,
                                                 IsLargeShift, Zero, R);
        Result[I] = protectUnsafeValue(R, MirI64Type);
      }
      return Result;
    }

    // Hoist loop-invariant shift constants out of the limb loop.
    MInstruction *ShiftModConst =
        createIntConstInstruction(MirI64Type, ShiftMod);
    uint64_t CarryShift = 64 - ShiftMod;
    MInstruction *CarryShiftConst =
        createIntConstInstruction(MirI64Type, CarryShift);

    for (size_t I = 0; I < EVM_ELEMENTS_COUNT; ++I) {
      MInstruction *R = Zero;
      if (I + CompShift < EVM_ELEMENTS_COUNT) {
        size_t SrcIdx = I + CompShift;
        MInstruction *SrcVal = Value[SrcIdx];
        MInstruction *Shifted = createInstruction<BinaryInstruction>(
            false, OP_ushr, MirI64Type, SrcVal, ShiftModConst);
        if (SrcIdx + 1 < EVM_ELEMENTS_COUNT) {
          MInstruction *Carry = createInstruction<BinaryInstruction>(
              false, OP_shl, MirI64Type, Value[SrcIdx + 1], CarryShiftConst);
          R = createInstruction<BinaryInstruction>(false, OP_or, MirI64Type,
                                                   Shifted, Carry);
        } else {
          R = Shifted;
        }
      }
      // Guard with IsLargeShift for correctness with 256-bit shift values.
      R = createInstruction<SelectInstruction>(false, MirI64Type, IsLargeShift,
                                               Zero, R);
      Result[I] = protectUnsafeValue(R, MirI64Type);
    }
    return Result;
  }

  MInstruction *One = createIntConstInstruction(MirI64Type, 1);
  MInstruction *Const64 = createIntConstInstruction(MirI64Type, 64);

  // EVM SHR operation: result = value >> shift (logical right shift)
  // DMIR implementation maps 256-bit shift to 4x64-bit components
  // shift_mod = shift % 64 (shift amount within 64-bit range)
  // shift_comp = shift / 64 (which component index shift from)
  // Strength-reduce: shift % 64 == shift & 63, shift / 64 == shift >> 6
  MInstruction *Const63 = createIntConstInstruction(MirI64Type, 63);
  MInstruction *Const6 = createIntConstInstruction(MirI64Type, 6);
  MInstruction *ShiftMod64 = createInstruction<BinaryInstruction>(
      false, OP_and, MirI64Type, ShiftAmount, Const63);
  MInstruction *ComponentShift = createInstruction<BinaryInstruction>(
      false, OP_ushr, MirI64Type, ShiftAmount, Const6);

  MInstruction *MaxIndex =
      createIntConstInstruction(MirI64Type, EVM_ELEMENTS_COUNT);

  // Process each 64-bit component from low to high
  // Example: For shift=72 (1*64 + 8), component_shift=1, shift_mod=8
  // Component 0 gets bits from component 1 shifted right by 8
  // Component 1 gets bits from component 2 shifted right by 8
  // Component 2 gets bits from component 3 shifted right by 8
  // Component 3 gets bits from component 4 (invalid, use 0)
  for (size_t I = 0; I < EVM_ELEMENTS_COUNT; ++I) {
    MInstruction *CurrentIdx = createIntConstInstruction(MirI64Type, I);

    // Calculate source component index: current index + component shift
    MInstruction *SrcIdx = createInstruction<BinaryInstruction>(
        false, OP_add, MirI64Type, CurrentIdx, ComponentShift);

    // Validate source index bounds
    // if (0 <= src_idx < EVM_ELEMENTS_COUNT) use Value[src_idx] else 0
    MInstruction *IsValidLow = createInstruction<CmpInstruction>(
        false, CmpInstruction::Predicate::ICMP_UGE, &Ctx.I64Type, SrcIdx, Zero);
    MInstruction *IsValidHigh = createInstruction<CmpInstruction>(
        false, CmpInstruction::Predicate::ICMP_ULT, &Ctx.I64Type, SrcIdx,
        MaxIndex);
    MInstruction *IsInBounds = createInstruction<BinaryInstruction>(
        false, OP_and, MirI64Type, IsValidLow, IsValidHigh);

    // Select source value from the appropriate component
    // src_value = (src_idx == J) ? Value[J] : 0 for all J
    MInstruction *SrcValue = Zero;
    for (size_t J = 0; J < EVM_ELEMENTS_COUNT; ++J) {
      MInstruction *TargetIdx = createIntConstInstruction(MirI64Type, J);
      MInstruction *IsMatch = createInstruction<CmpInstruction>(
          false, CmpInstruction::Predicate::ICMP_EQ, &Ctx.I64Type, SrcIdx,
          TargetIdx);
      SrcValue = createInstruction<SelectInstruction>(
          false, MirI64Type, IsMatch, Value[J], SrcValue);
    }
    SrcValue = createInstruction<SelectInstruction>(false, MirI64Type,
                                                    IsInBounds, SrcValue, Zero);

    // Calculate next component index for carry bits
    // next_idx = src_idx + 1
    MInstruction *NextIdx = createInstruction<BinaryInstruction>(
        false, OP_add, MirI64Type, SrcIdx, One);

    // Validate next component bounds
    // if (0 <= next_idx < EVM_ELEMENTS_COUNT) use Value[next_idx] else 0
    MInstruction *IsValidNextLow = createInstruction<CmpInstruction>(
        false, CmpInstruction::Predicate::ICMP_UGE, &Ctx.I64Type, NextIdx,
        Zero);
    MInstruction *IsValidNextHigh = createInstruction<CmpInstruction>(
        false, CmpInstruction::Predicate::ICMP_ULT, &Ctx.I64Type, NextIdx,
        MaxIndex);
    MInstruction *IsNextValid = createInstruction<BinaryInstruction>(
        false, OP_and, MirI64Type, IsValidNextLow, IsValidNextHigh);

    // Calculate carry bits from the next component
    // carry_bits = (next_idx == K) ? (Value[K] << (64 - shift_mod)) : 0
    MInstruction *HasBitShift = createInstruction<CmpInstruction>(
        false, CmpInstruction::Predicate::ICMP_NE, &Ctx.I64Type, ShiftMod64,
        Zero);
    MInstruction *CarryShift = createInstruction<SelectInstruction>(
        false, MirI64Type, HasBitShift,
        createInstruction<BinaryInstruction>(false, OP_sub, MirI64Type, Const64,
                                             ShiftMod64),
        Zero);
    MInstruction *CarryValue = Zero;
    for (size_t K = 0; K < EVM_ELEMENTS_COUNT; ++K) {
      MInstruction *TargetIdx = createIntConstInstruction(MirI64Type, K);
      MInstruction *IsMatch = createInstruction<CmpInstruction>(
          false, CmpInstruction::Predicate::ICMP_EQ, &Ctx.I64Type, NextIdx,
          TargetIdx);
      MInstruction *NextValue = createInstruction<SelectInstruction>(
          false, MirI64Type, IsMatch, Value[K], Zero);
      NextValue = createInstruction<SelectInstruction>(
          false, MirI64Type, IsNextValid, NextValue, Zero);

      // Extract carry bits by shifting left the remaining bits
      MInstruction *CarryBits = createInstruction<BinaryInstruction>(
          false, OP_shl, MirI64Type, NextValue, CarryShift);
      CarryBits = createInstruction<SelectInstruction>(
          false, MirI64Type, HasBitShift, CarryBits, Zero);
      CarryValue = createInstruction<SelectInstruction>(
          false, MirI64Type, IsMatch, CarryBits, CarryValue);
    }

    // Shift the source value right by the modulo amount
    // shifted_value = src_value >> shift_mod
    MInstruction *ShiftedValue = createInstruction<BinaryInstruction>(
        false, OP_ushr, MirI64Type, SrcValue, ShiftMod64);

    // combined_value = shifted_value | carry_bits
    MInstruction *CombinedValue = createInstruction<BinaryInstruction>(
        false, OP_or, MirI64Type, ShiftedValue, CarryValue);

    // Final result selection based on bounds checking and large shift flag
    // result[I] = IsLargeShift ? 0 : (IsInBounds ? CombinedValue : 0)
    MInstruction *FinalValue = createInstruction<SelectInstruction>(
        false, MirI64Type, IsLargeShift, Zero,
        createInstruction<SelectInstruction>(false, MirI64Type, IsInBounds,
                                             CombinedValue, Zero));
    Result[I] = protectUnsafeValue(FinalValue, MirI64Type);
  }

  return Result;
}

EVMMirBuilder::U256Inst
EVMMirBuilder::handleArithmeticRightShift(const U256Inst &Value,
                                          MInstruction *ShiftAmount,
                                          MInstruction *IsLargeShift) {
  MType *MirI64Type =
      EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);
  U256Inst Result = {};

  MInstruction *Zero = createIntConstInstruction(MirI64Type, 0);
  MInstruction *AllOnes = createIntConstInstruction(MirI64Type, ~0ULL);

  // Check sign bit (bit 63 of highest component) for large-shift result
  MInstruction *HighComponent = Value[EVM_ELEMENTS_COUNT - 1];
  MInstruction *Const63 = createIntConstInstruction(MirI64Type, 63);
  MInstruction *SignBit = createInstruction<BinaryInstruction>(
      false, OP_ushr, MirI64Type, HighComponent, Const63);
  MInstruction *One = createIntConstInstruction(MirI64Type, 1);
  MInstruction *IsNegative = createInstruction<CmpInstruction>(
      false, CmpInstruction::Predicate::ICMP_EQ, &Ctx.I64Type, SignBit, One);
  MInstruction *LargeShiftResult = createInstruction<SelectInstruction>(
      false, MirI64Type, IsNegative, AllOnes, Zero);

  // Fast path: constant shift amount — direct limb logic, no Select/cmp loops.
  if (auto ShiftOpt = getConstShiftAmount(ShiftAmount)) {
    uint64_t Shift = *ShiftOpt;
    if (Shift >= 256) {
      for (size_t I = 0; I < EVM_ELEMENTS_COUNT; ++I)
        Result[I] = LargeShiftResult;
      return Result;
    }
    uint64_t CompShift = Shift / 64;
    uint64_t ShiftMod = Shift % 64;

    // If the shift is a multiple of 64, we only need to move whole limbs.
    if (ShiftMod == 0) {
      for (size_t I = 0; I < EVM_ELEMENTS_COUNT; ++I) {
        MInstruction *R = LargeShiftResult;
        if (I + CompShift < EVM_ELEMENTS_COUNT) {
          size_t SrcIdx = I + CompShift;
          R = Value[SrcIdx];
        }
        // Guard with IsLargeShift for correctness with 256-bit shift values.
        R = createInstruction<SelectInstruction>(
            false, MirI64Type, IsLargeShift, LargeShiftResult, R);
        Result[I] = protectUnsafeValue(R, MirI64Type);
      }
      return Result;
    }

    // Hoist loop-invariant shift constants out of the limb loop.
    MInstruction *ShiftModConst =
        createIntConstInstruction(MirI64Type, ShiftMod);
    uint64_t CarryShift = 64 - ShiftMod;
    MInstruction *CarryShiftConst =
        createIntConstInstruction(MirI64Type, CarryShift);

    for (size_t I = 0; I < EVM_ELEMENTS_COUNT; ++I) {
      MInstruction *R = LargeShiftResult;
      if (I + CompShift < EVM_ELEMENTS_COUNT) {
        size_t SrcIdx = I + CompShift;
        MInstruction *SrcVal = Value[SrcIdx];
        // Use arithmetic shift for the high component (contains sign bit)
        bool UseArithShift = (SrcIdx == EVM_ELEMENTS_COUNT - 1);
        MInstruction *Shifted = createInstruction<BinaryInstruction>(
            false, UseArithShift ? OP_sshr : OP_ushr, MirI64Type, SrcVal,
            ShiftModConst);
        if (SrcIdx + 1 < EVM_ELEMENTS_COUNT) {
          MInstruction *Carry = createInstruction<BinaryInstruction>(
              false, OP_shl, MirI64Type, Value[SrcIdx + 1], CarryShiftConst);
          R = createInstruction<BinaryInstruction>(false, OP_or, MirI64Type,
                                                   Shifted, Carry);
        } else {
          R = Shifted;
        }
      }
      // Guard with IsLargeShift for correctness with 256-bit shift values.
      R = createInstruction<SelectInstruction>(false, MirI64Type, IsLargeShift,
                                               LargeShiftResult, R);
      Result[I] = protectUnsafeValue(R, MirI64Type);
    }
    return Result;
  }

  // intra-component shifts = shift % 64
  // shift_comp = shift / 64 (which component index shift from)
  // Strength-reduce: shift % 64 == shift & 63, shift / 64 == shift >> 6
  MInstruction *Const64 = createIntConstInstruction(MirI64Type, 64);
  MInstruction *Const6 = createIntConstInstruction(MirI64Type, 6);
  MInstruction *ShiftMod64 = createInstruction<BinaryInstruction>(
      false, OP_and, MirI64Type, ShiftAmount, Const63);
  MInstruction *ComponentShift = createInstruction<BinaryInstruction>(
      false, OP_ushr, MirI64Type, ShiftAmount, Const6);

  MInstruction *MaxIndex =
      createIntConstInstruction(MirI64Type, EVM_ELEMENTS_COUNT);

  // Process each component from low to high
  for (size_t I = 0; I < EVM_ELEMENTS_COUNT; ++I) {
    MInstruction *CurrentIdx = createIntConstInstruction(MirI64Type, I);

    MInstruction *SrcIdx = createInstruction<BinaryInstruction>(
        false, OP_add, MirI64Type, CurrentIdx, ComponentShift);

    // Validate source index bounds
    // if (0 <= src_idx < EVM_ELEMENTS_COUNT) use Value[src_idx] else 0
    MInstruction *IsValidLow = createInstruction<CmpInstruction>(
        false, CmpInstruction::Predicate::ICMP_UGE, &Ctx.I64Type, SrcIdx, Zero);
    MInstruction *IsValidHigh = createInstruction<CmpInstruction>(
        false, CmpInstruction::Predicate::ICMP_ULT, &Ctx.I64Type, SrcIdx,
        MaxIndex);
    MInstruction *IsInBounds = createInstruction<BinaryInstruction>(
        false, OP_and, MirI64Type, IsValidLow, IsValidHigh);

    // Select source value from the component at SrcIdx index
    MInstruction *SrcValue = LargeShiftResult;
    for (size_t J = 0; J < EVM_ELEMENTS_COUNT; ++J) {
      MInstruction *TargetIdx = createIntConstInstruction(MirI64Type, J);
      MInstruction *IsMatch = createInstruction<CmpInstruction>(
          false, CmpInstruction::Predicate::ICMP_EQ, &Ctx.I64Type, SrcIdx,
          TargetIdx);
      SrcValue = createInstruction<SelectInstruction>(
          false, MirI64Type, IsMatch, Value[J], SrcValue);
    }
    SrcValue = createInstruction<SelectInstruction>(
        false, MirI64Type, IsInBounds, SrcValue, LargeShiftResult);

    // Calculate next component index for carry bits
    // next_idx = src_idx + 1
    MInstruction *NextIdx = createInstruction<BinaryInstruction>(
        false, OP_add, MirI64Type, SrcIdx, One);

    // Validate next component bounds
    // if (0 <= next_idx < EVM_ELEMENTS_COUNT) use Value[next_idx] else
    // sign_extend
    MInstruction *IsValidNextLow = createInstruction<CmpInstruction>(
        false, CmpInstruction::Predicate::ICMP_UGE, &Ctx.I64Type, NextIdx,
        Zero);
    MInstruction *IsValidNextHigh = createInstruction<CmpInstruction>(
        false, CmpInstruction::Predicate::ICMP_ULT, &Ctx.I64Type, NextIdx,
        MaxIndex);
    MInstruction *IsNextValid = createInstruction<BinaryInstruction>(
        false, OP_and, MirI64Type, IsValidNextLow, IsValidNextHigh);

    // Calculate carry bits from the next component (higher index).
    MInstruction *HasShift = createInstruction<CmpInstruction>(
        false, CmpInstruction::Predicate::ICMP_NE, &Ctx.I64Type, ShiftMod64,
        Zero);
    MInstruction *CarryShift = createInstruction<SelectInstruction>(
        false, MirI64Type, HasShift,
        createInstruction<BinaryInstruction>(false, OP_sub, MirI64Type, Const64,
                                             ShiftMod64),
        Zero);
    MInstruction *NextValue = LargeShiftResult;
    for (size_t K = 0; K < EVM_ELEMENTS_COUNT; ++K) {
      MInstruction *TargetIdx = createIntConstInstruction(MirI64Type, K);
      MInstruction *IsMatch = createInstruction<CmpInstruction>(
          false, CmpInstruction::Predicate::ICMP_EQ, &Ctx.I64Type, NextIdx,
          TargetIdx);
      NextValue = createInstruction<SelectInstruction>(
          false, MirI64Type, IsMatch, Value[K], NextValue);
    }
    NextValue = createInstruction<SelectInstruction>(
        false, MirI64Type, IsNextValid, NextValue, LargeShiftResult);

    // Extract low bits from next component as carry. When next_idx is out of
    // bounds, use sign-extension bits from LargeShiftResult.
    MInstruction *CarryBits = createInstruction<BinaryInstruction>(
        false, OP_shl, MirI64Type, NextValue, CarryShift);
    MInstruction *CarryValue = createInstruction<SelectInstruction>(
        false, MirI64Type, HasShift, CarryBits, Zero);

    // Use logical right shift; sign extension is handled via LargeShiftResult.
    MInstruction *ShiftedValue = createInstruction<BinaryInstruction>(
        false, OP_ushr, MirI64Type, SrcValue, ShiftMod64);
    MInstruction *CombinedValue = createInstruction<BinaryInstruction>(
        false, OP_or, MirI64Type, ShiftedValue, CarryValue);

    MInstruction *FinalValue = createInstruction<SelectInstruction>(
        false, MirI64Type, IsLargeShift, LargeShiftResult,
        createInstruction<SelectInstruction>(false, MirI64Type, IsInBounds,
                                             CombinedValue, LargeShiftResult));
    Result[I] = protectUnsafeValue(FinalValue, MirI64Type);
  }

  return Result;
}

// EVM BYTE opcode: extracts the byte at position 'index' from a 256-bit value
// BYTE(index, value) = 0 if index ≥ 32, otherwise the byte at position index
// (value >> (8 × (31 - index))) & 0xFF
typename EVMMirBuilder::Operand EVMMirBuilder::handleByte(Operand IndexOp,
                                                          Operand ValueOp) {
  MType *MirI64Type =
      EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);
  MInstruction *Zero = createIntConstInstruction(MirI64Type, 0);
  MInstruction *ConstFF = createIntConstInstruction(MirI64Type, 0xFF);

  auto buildByteResult = [&](MInstruction *SelectedComponent,
                             MInstruction *BitOffset,
                             MInstruction *IsOutOfBounds = nullptr) {
    MInstruction *ShiftedValue = createInstruction<BinaryInstruction>(
        false, OP_ushr, MirI64Type, SelectedComponent, BitOffset);
    MInstruction *ByteValue = createInstruction<BinaryInstruction>(
        false, OP_and, MirI64Type, ShiftedValue, ConstFF);
    MInstruction *Result =
        IsOutOfBounds ? createInstruction<SelectInstruction>(
                            false, MirI64Type, IsOutOfBounds, Zero, ByteValue)
                      : ByteValue;

    U256Inst ResultComponents = {};
    ResultComponents[0] = protectUnsafeValue(Result, MirI64Type);
    for (size_t I = 1; I < EVM_ELEMENTS_COUNT; ++I) {
      ResultComponents[I] = Zero;
    }
    // BYTE always produces a single byte value (0..255)
    return Operand(ResultComponents, EVMType::UINT256, ValueRange::U64);
  };

  if (IndexOp.isConstant() && ValueOp.isConstant()) {
    const auto &IndexConst = IndexOp.getConstValue();
    if (IndexConst[1] != 0 || IndexConst[2] != 0 || IndexConst[3] != 0 ||
        IndexConst[0] >= 32) {
      return Operand(U256Value{0, 0, 0, 0});
    }

    uint64_t Index = IndexConst[0];
    size_t ComponentIndex = 3 - static_cast<size_t>(Index >> 3);
    uint64_t BitOffset = (7 - (Index & 7)) << 3;
    uint64_t ByteValue =
        (ValueOp.getConstValue()[ComponentIndex] >> BitOffset) & 0xFF;
    return Operand(U256Value{ByteValue, 0, 0, 0});
  }

  U256Inst ValueComponents = extractU256Operand(ValueOp);

  if (IndexOp.isConstant()) {
    const auto &IndexConst = IndexOp.getConstValue();
    if (IndexConst[1] != 0 || IndexConst[2] != 0 || IndexConst[3] != 0 ||
        IndexConst[0] >= 32) {
      return Operand(U256Value{0, 0, 0, 0});
    }

    uint64_t Index = IndexConst[0];
    size_t ComponentIndex = 3 - static_cast<size_t>(Index >> 3);
    uint64_t BitOffset = (7 - (Index & 7)) << 3;
    return buildByteResult(ValueComponents[ComponentIndex],
                           createIntConstInstruction(MirI64Type, BitOffset));
  }

  U256Inst IndexComponents = extractU256Operand(IndexOp);

  // Check if index >= 32 (out of bounds).
  MInstruction *IsOutOfBounds = isU256GreaterOrEqual(IndexComponents, 32);
  MInstruction *IndexLow = IndexComponents[0];
  MInstruction *Const1 = createIntConstInstruction(MirI64Type, 1);
  MInstruction *Const2 = createIntConstInstruction(MirI64Type, 2);
  MInstruction *Const3 = createIntConstInstruction(MirI64Type, 3);
  MInstruction *Const7 = createIntConstInstruction(MirI64Type, 7);

  // Use byte-granular arithmetic directly:
  //   component_index = 3 - (index / 8)
  //   bit_offset = (7 - (index % 8)) * 8
  MInstruction *GroupIndex = createInstruction<BinaryInstruction>(
      false, OP_ushr, MirI64Type, IndexLow, Const3);
  MInstruction *ByteInGroup = createInstruction<BinaryInstruction>(
      false, OP_and, MirI64Type, IndexLow, Const7);
  MInstruction *ByteShiftInComponent = createInstruction<BinaryInstruction>(
      false, OP_sub, MirI64Type, Const7, ByteInGroup);
  MInstruction *BitOffset = createInstruction<BinaryInstruction>(
      false, OP_shl, MirI64Type, ByteShiftInComponent, Const3);

  // Pick the source limb with a two-level select tree to shorten live ranges:
  // [3,2] and [1,0] are selected independently, then merged.
  MInstruction *GroupLowBit = createInstruction<BinaryInstruction>(
      false, OP_and, MirI64Type, GroupIndex, Const1);
  MInstruction *IsSecondInPair = createInstruction<CmpInstruction>(
      false, CmpInstruction::Predicate::ICMP_NE, &Ctx.I64Type, GroupLowBit,
      Zero);
  MInstruction *IsLowerPair = createInstruction<CmpInstruction>(
      false, CmpInstruction::Predicate::ICMP_UGE, &Ctx.I64Type, GroupIndex,
      Const2);
  MInstruction *UpperPair = createInstruction<SelectInstruction>(
      false, MirI64Type, IsSecondInPair, ValueComponents[2],
      ValueComponents[3]);
  MInstruction *LowerPair = createInstruction<SelectInstruction>(
      false, MirI64Type, IsSecondInPair, ValueComponents[0],
      ValueComponents[1]);
  MInstruction *SelectedComponent = createInstruction<SelectInstruction>(
      false, MirI64Type, IsLowerPair, LowerPair, UpperPair);

  return buildByteResult(SelectedComponent, BitOffset, IsOutOfBounds);
}

// EVM SIGNEXTEND opcode: sign-extends a signed integer from (index+1) bytes to
// 256 bits SIGNEXTEND(index, value) = value if index >= 31, otherwise
// sign-extended value The sign bit is at position (index * 8 + 7), and all
// higher bits are set to the sign bit value.
// Examples:
//   SIGNEXTEND(0, 0x80) = 0xFF...FF80 (sign-extends 0x80 from 1 byte)
//   SIGNEXTEND(1, 0x7FFF) = 0x00...007FFF (sign-extends 0x7FFF from 2 bytes)
//   SIGNEXTEND(31, 0x1234) = 0x1234 (no extension when index >= 31)
typename EVMMirBuilder::Operand
EVMMirBuilder::handleSignextend(Operand IndexOp, Operand ValueOp) {
  U256Inst IndexComponents = extractU256Operand(IndexOp);
  U256Inst ValueComponents = extractU256Operand(ValueOp);

  // Check if index >= 31 (no sign extension needed)
  MInstruction *NoExtension = isU256GreaterOrEqual(IndexComponents, 31);

  MType *MirI64Type =
      EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);
  MType *MirI8Type = EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT8);

  MInstruction *Const7 = createIntConstInstruction(MirI64Type, 7);
  MInstruction *Const3 = createIntConstInstruction(MirI64Type, 3);
  MInstruction *Const63 = createIntConstInstruction(MirI64Type, 63);
  MInstruction *AllOnes = createIntConstInstruction(MirI64Type, ~0ULL);
  MInstruction *Zero = createIntConstInstruction(MirI64Type, 0);

  // Match the interpreter strategy:
  //   sign_word_index = index / 8
  //   sign_byte_index = index % 8
  //   sign_word = value[sign_word_index]
  //   sign_word' = sext(int8(sign_word >> (sign_byte_index * 8)))
  //   upper words = sign fill
  MInstruction *SignWordIndex = createInstruction<BinaryInstruction>(
      false, OP_ushr, MirI64Type, IndexComponents[0], Const3);
  MInstruction *SignByteIndex = createInstruction<BinaryInstruction>(
      false, OP_and, MirI64Type, IndexComponents[0], Const7);
  MInstruction *SignByteOffset = createInstruction<BinaryInstruction>(
      false, OP_shl, MirI64Type, SignByteIndex, Const3);

  MInstruction *SelectedWord = ValueComponents[0];
  for (size_t I = 1; I < EVM_ELEMENTS_COUNT; ++I) {
    MInstruction *IsThisWord = createInstruction<CmpInstruction>(
        false, CmpInstruction::Predicate::ICMP_EQ, &Ctx.I64Type, SignWordIndex,
        createIntConstInstruction(MirI64Type, I));
    SelectedWord = createInstruction<SelectInstruction>(
        false, MirI64Type, IsThisWord, ValueComponents[I], SelectedWord);
  }

  MInstruction *ShiftedWord = createInstruction<BinaryInstruction>(
      false, OP_ushr, MirI64Type, SelectedWord, SignByteOffset);
  MInstruction *ConstFF = createIntConstInstruction(MirI64Type, 0xFF);
  MInstruction *SignByte = createInstruction<BinaryInstruction>(
      false, OP_and, MirI64Type, ShiftedWord, ConstFF);
  MInstruction *SignByteI8 = createInstruction<ConversionInstruction>(
      false, OP_trunc, MirI8Type, SignByte);
  MInstruction *SextByte = createInstruction<ConversionInstruction>(
      false, OP_sext, MirI64Type, SignByteI8);

  MInstruction *SignMask = createInstruction<BinaryInstruction>(
      false, OP_shl, MirI64Type, AllOnes, SignByteOffset);
  MInstruction *LowerMask = createInstruction<BinaryInstruction>(
      false, OP_xor, MirI64Type, SignMask, AllOnes);
  MInstruction *LowerBits = createInstruction<BinaryInstruction>(
      false, OP_and, MirI64Type, SelectedWord, LowerMask);
  MInstruction *SextWord = createInstruction<BinaryInstruction>(
      false, OP_shl, MirI64Type, SextByte, SignByteOffset);
  MInstruction *ExtendedSelectedWord = createInstruction<BinaryInstruction>(
      false, OP_or, MirI64Type, SextWord, LowerBits);
  MInstruction *HighValue = createInstruction<BinaryInstruction>(
      false, OP_sshr, MirI64Type, SextByte, Const63);

  // Create sign extension for each component
  U256Inst ResultComponents = {};
  for (int I = 0; I < 4; I++) {
    MInstruction *CompIdx = createIntConstInstruction(MirI64Type, I);
    MInstruction *IsAbove = createInstruction<CmpInstruction>(
        false, CmpInstruction::Predicate::ICMP_UGT, &Ctx.I64Type, CompIdx,
        SignWordIndex);
    MInstruction *IsEqual = createInstruction<CmpInstruction>(
        false, CmpInstruction::Predicate::ICMP_EQ, &Ctx.I64Type, CompIdx,
        SignWordIndex);

    // Select appropriate value based on position relative to sign bit
    MInstruction *SameOrBelow = createInstruction<SelectInstruction>(
        false, MirI64Type, IsEqual, ExtendedSelectedWord, ValueComponents[I]);
    MInstruction *ComponentResult = createInstruction<SelectInstruction>(
        false, MirI64Type, IsAbove, HighValue, SameOrBelow);

    // If index >= 31, use original value; otherwise use sign-extended value
    ResultComponents[I] =
        protectUnsafeValue(createInstruction<SelectInstruction>(
                               false, MirI64Type, NoExtension,
                               ValueComponents[I], ComponentResult),
                           MirI64Type);
  }

  return Operand(ResultComponents, EVMType::UINT256);
}

// ==================== Environment Instruction Handlers ====================

typename EVMMirBuilder::Operand EVMMirBuilder::handlePC(const uint64_t &PC) {
  MType *UInt64Type =
      EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);
  MInstruction *PCInst = createIntConstInstruction(UInt64Type, PC);
  // Spill the constant through a temporary so it can be safely re-read across
  // basic blocks (e.g. when the value is later consumed in the slow path of
  // ADDMOD/MULMOD). Without this, cross-BB reuse of the constant instruction
  // can hit a stale vreg in the lowering expression cache.
  PCInst = protectUnsafeValue(PCInst, UInt64Type);

  // Convert the 64-bit PC value to U256 format (EVM specification)
  return convertSingleInstrToU256Operand(PCInst);
}

typename EVMMirBuilder::Operand EVMMirBuilder::handleGas() {
  MType *I64Type = EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);
#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
  if (Ctx.isGasRegisterEnabled() && GasRegVar) {
    MInstruction *GasValue =
        protectUnsafeValue(loadVariable(GasRegVar), I64Type);
    return convertSingleInstrToU256Operand(GasValue);
  }
#endif
  MInstruction *GasValue = getInstanceElement(
      &Ctx.I64Type, zen::runtime::EVMInstance::getGasFieldOffset());
  GasValue = protectUnsafeValue(GasValue, I64Type);
  return convertSingleInstrToU256Operand(GasValue);
}

typename EVMMirBuilder::Operand EVMMirBuilder::handleAddress() {
  MInstruction *MsgPtr = loadProtectedInstancePointer(
      zen::runtime::EVMInstance::getCurrentMessagePointerOffset());
  return loadProtectedAddressFieldAsU256(
      MsgPtr, zen::runtime::EVMInstance::getMessageRecipientOffset());
}

typename EVMMirBuilder::Operand EVMMirBuilder::handleBalance(Operand Address) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
  syncGasToMemory();
#endif
  auto Result = callRuntimeFor<const intx::uint256 *, const uint8_t *>(
      RuntimeFunctions.GetBalance, Address);
#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
  reloadGasFromMemory();
#endif
  return Result;
}

typename EVMMirBuilder::Operand EVMMirBuilder::handleOrigin() {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  return callRuntimeFor(RuntimeFunctions.GetOrigin);
}

typename EVMMirBuilder::Operand EVMMirBuilder::handleCaller() {
  MInstruction *MsgPtr = loadProtectedInstancePointer(
      zen::runtime::EVMInstance::getCurrentMessagePointerOffset());
  return loadProtectedAddressFieldAsU256(
      MsgPtr, zen::runtime::EVMInstance::getMessageSenderOffset());
}

typename EVMMirBuilder::Operand EVMMirBuilder::handleCallValue() {
  MInstruction *MsgPtr = loadProtectedInstancePointer(
      zen::runtime::EVMInstance::getCurrentMessagePointerOffset());
  return loadProtectedBytes32FieldAsU256(
      MsgPtr, zen::runtime::EVMInstance::getMessageValueOffset());
}

typename EVMMirBuilder::Operand
EVMMirBuilder::handleCallDataLoad(Operand Offset) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  uint64_t Non64Value = std::numeric_limits<uint64_t>::max();
  normalizeOperandU64(Offset, &Non64Value);
  return callRuntimeFor<const uint8_t *, uint64_t>(
      RuntimeFunctions.GetCallDataLoad, Offset);
}

typename EVMMirBuilder::Operand EVMMirBuilder::handleGasPrice() {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  return callRuntimeFor(RuntimeFunctions.GetGasPrice);
}

typename EVMMirBuilder::Operand EVMMirBuilder::handleCallDataSize() {
  MInstruction *MsgPtr = loadProtectedInstancePointer(
      zen::runtime::EVMInstance::getCurrentMessagePointerOffset());
  MInstruction *InputSize = loadProtectedU64Field(
      MsgPtr, zen::runtime::EVMInstance::getMessageInputSizeOffset());
  return convertSingleInstrToU256Operand(InputSize);
}

typename EVMMirBuilder::Operand EVMMirBuilder::handleCodeSize() {
  MInstruction *ModulePtr = loadProtectedInstancePointer(
      zen::runtime::EVMInstance::getModuleOffset());
  MInstruction *CodeSize = loadProtectedU64Field(
      ModulePtr, zen::runtime::EVMModule::getCodeSizeOffset());
  return convertSingleInstrToU256Operand(CodeSize);
}

void EVMMirBuilder::handleCodeCopy(Operand DestOffsetComponents,
                                   Operand OffsetComponents,
                                   Operand SizeComponents) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  normalizeOffsetWithSize(DestOffsetComponents, SizeComponents);
  uint64_t Non64Value = std::numeric_limits<uint64_t>::max();
  normalizeOperandU64(OffsetComponents, &Non64Value);
#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
  syncGasToMemory();
#endif
  callRuntimeFor<void, uint64_t, uint64_t, uint64_t>(
      RuntimeFunctions.SetCodeCopy, DestOffsetComponents, OffsetComponents,
      SizeComponents);
#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
  reloadGasFromMemory();
#endif
  reloadMemorySizeFromInstance();
}

typename EVMMirBuilder::Operand
EVMMirBuilder::handleExtCodeSize(Operand Address) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
  syncGasToMemory();
#endif
  auto Result = callRuntimeFor<uint64_t, const uint8_t *>(
      RuntimeFunctions.GetExtCodeSize, Address);
#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
  reloadGasFromMemory();
#endif
  return Result;
}

typename EVMMirBuilder::Operand
EVMMirBuilder::handleExtCodeHash(Operand Address) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
  syncGasToMemory();
#endif
  auto Result = callRuntimeFor<const intx::uint256 *, const uint8_t *>(
      RuntimeFunctions.GetExtCodeHash, Address);
#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
  reloadGasFromMemory();
#endif
  return Result;
}

typename EVMMirBuilder::Operand
EVMMirBuilder::handleBlockHash(Operand BlockNumber) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  uint64_t Non64Value = std::numeric_limits<uint64_t>::max();
  normalizeOperandU64(BlockNumber, &Non64Value);
  return callRuntimeFor<const uint8_t *, int64_t>(RuntimeFunctions.GetBlockHash,
                                                  BlockNumber);
}

typename EVMMirBuilder::Operand EVMMirBuilder::handleCoinBase() {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  return callRuntimeFor(RuntimeFunctions.GetCoinBase);
}

typename EVMMirBuilder::Operand EVMMirBuilder::handleTimestamp() {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  return callRuntimeFor(RuntimeFunctions.GetTimestamp);
}

typename EVMMirBuilder::Operand EVMMirBuilder::handleNumber() {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  return callRuntimeFor(RuntimeFunctions.GetNumber);
}

typename EVMMirBuilder::Operand EVMMirBuilder::handlePrevRandao() {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  return callRuntimeFor(RuntimeFunctions.GetPrevRandao);
}

typename EVMMirBuilder::Operand EVMMirBuilder::handleGasLimit() {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  return callRuntimeFor(RuntimeFunctions.GetGasLimit);
}

typename EVMMirBuilder::Operand EVMMirBuilder::handleChainId() {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  return callRuntimeFor(RuntimeFunctions.GetChainId);
}

typename EVMMirBuilder::Operand EVMMirBuilder::handleSelfBalance() {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  return callRuntimeFor(RuntimeFunctions.GetSelfBalance);
}

typename EVMMirBuilder::Operand EVMMirBuilder::handleBaseFee() {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  return callRuntimeFor(RuntimeFunctions.GetBaseFee);
}

typename EVMMirBuilder::Operand EVMMirBuilder::handleBlobHash(Operand Index) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  // Use max uint64_t value if the index is not 64-bit, because the blob hash
  // won't trigger out-of-gas when the index is out of range.
  uint64_t Non64Value = std::numeric_limits<uint64_t>::max();
  normalizeOperandU64(Index, &Non64Value);
  return callRuntimeFor<const uint8_t *, uint64_t>(RuntimeFunctions.GetBlobHash,
                                                   Index);
}

typename EVMMirBuilder::Operand EVMMirBuilder::handleBlobBaseFee() {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  return callRuntimeFor(RuntimeFunctions.GetBlobBaseFee);
}

typename EVMMirBuilder::Operand EVMMirBuilder::handleMSize() {
  MInstruction *MemSize = getMemorySize();
  // Capture MSIZE at this opcode to prevent later memory growth reordering.
  MemSize = protectUnsafeValue(MemSize, &Ctx.I64Type);
  return convertSingleInstrToU256Operand(MemSize);
}

void EVMMirBuilder::fallbackToInterpreter(uint64_t targetPC) {
  // Phase 1 implementation: Basic fallback infrastructure
  // This method provides the interface for JIT-to-interpreter fallback
  //
  // The method generates MIR instructions to:
  // 1. Synchronize current execution state (stack, memory) with EVMInstance
  // 2. Call the runtime fallback function with the target PC
  //
  // State synchronization is handled automatically by the existing
  // EVMInstance state management, so we can directly call the runtime function.

#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
  syncGasToMemory();
#endif
  // Sync stack size to memory, all stack elements should be synced before
  // calling this function
  const int32_t StackSizeOffset =
      zen::runtime::EVMInstance::getEVMStackSizeOffset();
  MInstruction *StackSize = loadVariable(StackSizeVar);
  setInstanceElement(&Ctx.I64Type, StackSize, StackSizeOffset);

  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  // Create a constant instruction for the target PC
  MType *I64Type = &Ctx.I64Type;
  MInstruction *PCConst = createIntConstInstruction(I64Type, targetPC);

  // Call the runtime fallback function
  // This will transfer control to the interpreter at the specified PC
  callRuntimeFor<void, uint64_t>(RuntimeFunctions.HandleFallback,
                                 Operand(PCConst, EVMType::UINT64));

  createInstruction<BrInstruction>(true, Ctx, ReturnBB);
  addSuccessor(ReturnBB);

  if (ReturnBB->empty()) {
    setInsertBlock(ReturnBB);
    handleVoidReturn();
  }
}

typename EVMMirBuilder::Operand
EVMMirBuilder::handleMLoad(Operand AddrComponents) {
#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
  syncGasToMemory();
#endif
  MType *I64Type = &Ctx.I64Type;
  uint64_t ConstAddr = 0;
  const bool CanUseConstBaseDispPath =
      AddrComponents.isConstU64() &&
      (ConstAddr = AddrComponents.getConstValue()[0]) <=
          static_cast<uint64_t>(INT32_MAX - 24);

  const bool CanUseLinearU64AddrFastPath =
      CurBlockLinearPrecheckPlan.Active &&
      CurBlockLinearPrecheckPlan.CoveredDirectOpsRemaining != 0;
  MInstruction *Offset = nullptr;
  bool UsedLinearPrecheck = false;
  if (CanUseLinearU64AddrFastPath) {
    Offset = extractKnownU64LowOperand(AddrComponents);
    UsedLinearPrecheck = tryConsumeLinearBlockMemoryPrecheck(Offset, nullptr);
  }
  if (!UsedLinearPrecheck) {
    normalizeOperandU64(AddrComponents);
    Offset = extractKnownU64LowOperand(AddrComponents);
  }
  bool UsedSharedPrecheck =
      UsedLinearPrecheck || tryConsumeConstBlockMemoryPrecheck();
  if (!UsedSharedPrecheck) {
    MInstruction *SizeConst = createIntConstInstruction(I64Type, 32);
    MInstruction *RequiredSize = createInstruction<BinaryInstruction>(
        false, OP_add, I64Type, Offset, SizeConst);
    MInstruction *Overflow = createInstruction<CmpInstruction>(
        false, CmpInstruction::Predicate::ICMP_ULT, I64Type, RequiredSize,
        Offset);
#ifdef ZEN_ENABLE_MULTIPASS_JIT_LOGGING
    ++MemStats.MLoadExpandCount;
    if (CurBlockMemStats.Active) {
      CurBlockMemStats.ExpandCallCount++;
    }
#endif // ZEN_ENABLE_MULTIPASS_JIT_LOGGING
    expandMemoryIR(RequiredSize, Overflow);
  }

  Operand Result;
  if (!UsedLinearPrecheck && UsedSharedPrecheck && CanUseConstBaseDispPath) {
    MInstruction *BasePtr = getConstBlockDirectMemoryBasePtr();
    Result = loadU256FromBytes32BaseDisplaced(BasePtr, ConstAddr);
#ifdef ZEN_ENABLE_MULTIPASS_JIT_LOGGING
    ++MemStats.ConstDispBytes32MLoadCount;
    if (CurBlockMemStats.Active) {
      ++CurBlockMemStats.ConstDispBytes32MLoadCount;
    }
#endif // ZEN_ENABLE_MULTIPASS_JIT_LOGGING
  } else {
    MInstruction *MemBase = getDirectMemoryDataPointer(UsedSharedPrecheck);
    MInstruction *MemAddrInt = createInstruction<BinaryInstruction>(
        false, OP_add, I64Type, MemBase, Offset);
    MInstruction *MemPtr = createInstruction<ConversionInstruction>(
        false, OP_inttoptr, createVoidPtrType(), MemAddrInt);
    MemPtr = anchorDirectMemoryPointer(MemPtr);
    Result = loadU256FromBytes32PointerDisplaced(MemPtr);
  }

  // Pin loaded values into local variables so the backend cannot reschedule
  // the memory reads past later function calls (e.g. CODECOPY / MSTORE) that
  // may modify the same memory region.  Without this, an MLOAD result that
  // stays on the EVM stack across a memory-writing opcode could observe the
  // *new* contents instead of the value at the time of the MLOAD.
  U256Inst Parts = extractU256Operand(Result);
  for (int I = 0; I < static_cast<int>(EVM_ELEMENTS_COUNT); ++I) {
    Parts[I] = protectUnsafeValue(Parts[I], I64Type);
  }
  Result = Operand(Parts, EVMType::UINT256);

#ifdef ZEN_ENABLE_MULTIPASS_JIT_LOGGING
  if (UsedLinearPrecheck) {
    ++MemStats.LinearU64AddrFastPathCount;
    ++MemStats.LinearU64MLoadFastPathCount;
    if (CurBlockMemStats.Active) {
      ++CurBlockMemStats.LinearU64AddrFastPathCount;
      ++CurBlockMemStats.LinearU64MLoadFastPathCount;
    }
  }
  if (UsedSharedPrecheck) {
    ++MemStats.PrecheckedMLoadOpCount;
    if (CurBlockMemStats.Active) {
      ++CurBlockMemStats.PrecheckedMLoadOpCount;
    }
  }
  ++MemStats.DispBytes32MLoadCount;
  if (CurBlockMemStats.Active) {
    ++CurBlockMemStats.DispBytes32MLoadCount;
  }
#endif // ZEN_ENABLE_MULTIPASS_JIT_LOGGING

#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
  reloadGasFromMemory();
#endif
  return Result;
}

void EVMMirBuilder::handleMStore(Operand AddrComponents,
                                 Operand ValueComponents) {
#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
  syncGasToMemory();
#endif
  MType *I64Type = &Ctx.I64Type;
  uint64_t ConstAddr = 0;
  const bool CanUseConstBaseDispPath =
      AddrComponents.isConstU64() &&
      (ConstAddr = AddrComponents.getConstValue()[0]) <=
          static_cast<uint64_t>(INT32_MAX - 24);

  U256Inst ValueParts = {};
  bool HasValueParts = false;
  bool CanReuseAddrAsValue =
      CurBlockLinearPrecheckPlan.Active &&
      CurBlockLinearPrecheckPlan.CoveredDirectOpsRemaining != 0 &&
      CurBlockLinearPrecheckPlan.ValueEqualsFirstAddr;
  const bool CanUseLinearU64AddrFastPath =
      CurBlockLinearPrecheckPlan.Active &&
      CurBlockLinearPrecheckPlan.CoveredDirectOpsRemaining != 0;
  MInstruction *Offset = nullptr;
  bool UsedLinearPrecheck = false;
  if (CanUseLinearU64AddrFastPath) {
    Offset = extractKnownU64LowOperand(AddrComponents);
    UsedLinearPrecheck = tryConsumeLinearBlockMemoryPrecheck(Offset, nullptr);
  }
  if (!UsedLinearPrecheck) {
    normalizeOperandU64(AddrComponents);
    Offset = extractKnownU64LowOperand(AddrComponents);
  }
  bool UsedSharedPrecheck =
      UsedLinearPrecheck || tryConsumeConstBlockMemoryPrecheck();
  if (!UsedSharedPrecheck) {
    ValueParts = extractU256Operand(ValueComponents);
    HasValueParts = true;
    MInstruction *SizeConst = createIntConstInstruction(I64Type, 32);
    MInstruction *RequiredSize = createInstruction<BinaryInstruction>(
        false, OP_add, I64Type, Offset, SizeConst);
    // Tie expansion ordering to the stored value to prevent reordering on the
    // fallback path that still emits a per-op expand sequence.
    MInstruction *Zero = createIntConstInstruction(I64Type, 0);
    MInstruction *ValueDep = createInstruction<BinaryInstruction>(
        false, OP_or, I64Type, ValueParts[0], ValueParts[1]);
    ValueDep = createInstruction<BinaryInstruction>(false, OP_or, I64Type,
                                                    ValueDep, ValueParts[2]);
    ValueDep = createInstruction<BinaryInstruction>(false, OP_or, I64Type,
                                                    ValueDep, ValueParts[3]);
    ValueDep = createInstruction<BinaryInstruction>(false, OP_and, I64Type,
                                                    ValueDep, Zero);
    RequiredSize = createInstruction<BinaryInstruction>(false, OP_add, I64Type,
                                                        RequiredSize, ValueDep);
    MInstruction *Overflow = createInstruction<CmpInstruction>(
        false, CmpInstruction::Predicate::ICMP_ULT, I64Type, RequiredSize,
        Offset);
#ifdef ZEN_ENABLE_MULTIPASS_JIT_LOGGING
    ++MemStats.MStoreExpandCount;
    if (CurBlockMemStats.Active) {
      CurBlockMemStats.ExpandCallCount++;
    }
#endif // ZEN_ENABLE_MULTIPASS_JIT_LOGGING
    expandMemoryIR(RequiredSize, Overflow);
  }

  if (!HasValueParts && UsedSharedPrecheck && CanReuseAddrAsValue) {
    MInstruction *Zero = createIntConstInstruction(I64Type, 0);
    ValueParts = {Offset, Zero, Zero, Zero};
    HasValueParts = true;
#ifdef ZEN_ENABLE_MULTIPASS_JIT_LOGGING
    ++MemStats.MStoreAddrValueAliasReuseCount;
    if (CurBlockMemStats.Active) {
      ++CurBlockMemStats.MStoreAddrValueAliasReuseCount;
    }
#endif // ZEN_ENABLE_MULTIPASS_JIT_LOGGING
  }

  if (!HasValueParts) {
    ValueParts = extractU256Operand(ValueComponents);
  }
  const bool IsFirstLinearStore =
      UsedLinearPrecheck &&
      CurBlockLinearPrecheckPlan.CoveredDirectOpsTotal != 0 &&
      (CurBlockLinearPrecheckPlan.CoveredDirectOpsRemaining + 1) ==
          CurBlockLinearPrecheckPlan.CoveredDirectOpsTotal;
  uint64_t SkipLeadingZeroLimbStores = 0;
  if (UsedLinearPrecheck && CanReuseAddrAsValue && !IsFirstLinearStore) {
    SkipLeadingZeroLimbStores =
        Ctx.getMemoryLinearStrideSkipLeadingZeroLimbStores();
  }

  if (!UsedLinearPrecheck && UsedSharedPrecheck && CanUseConstBaseDispPath) {
    MInstruction *BasePtr = getConstBlockDirectMemoryBasePtr();
    storeU256ToBytes32BaseDisplaced(BasePtr, ConstAddr, ValueParts,
                                    SkipLeadingZeroLimbStores);
#ifdef ZEN_ENABLE_MULTIPASS_JIT_LOGGING
    ++MemStats.ConstDispBytes32MStoreCount;
    ++MemStats.DispBytes32MStoreCount;
    if (CurBlockMemStats.Active) {
      ++CurBlockMemStats.ConstDispBytes32MStoreCount;
      ++CurBlockMemStats.DispBytes32MStoreCount;
    }
#endif // ZEN_ENABLE_MULTIPASS_JIT_LOGGING
  } else {
    MInstruction *MemBase = getDirectMemoryDataPointer(UsedSharedPrecheck);
    MInstruction *BaseAddrInt = createInstruction<BinaryInstruction>(
        false, OP_add, I64Type, MemBase, Offset);
    MInstruction *BasePtr = createInstruction<ConversionInstruction>(
        false, OP_inttoptr, createVoidPtrType(), BaseAddrInt);
    BasePtr = anchorDirectMemoryPointer(BasePtr);
    storeU256ToBytes32Pointer(BasePtr, ValueParts, SkipLeadingZeroLimbStores);
#ifdef ZEN_ENABLE_MULTIPASS_JIT_LOGGING
    ++MemStats.DispBytes32MStoreCount;
    if (CurBlockMemStats.Active) {
      ++CurBlockMemStats.DispBytes32MStoreCount;
    }
#endif // ZEN_ENABLE_MULTIPASS_JIT_LOGGING
  }
#ifdef ZEN_ENABLE_MULTIPASS_JIT_LOGGING
  if (UsedLinearPrecheck) {
    ++MemStats.LinearU64AddrFastPathCount;
    ++MemStats.LinearU64MStoreFastPathCount;
    if (CurBlockMemStats.Active) {
      ++CurBlockMemStats.LinearU64AddrFastPathCount;
      ++CurBlockMemStats.LinearU64MStoreFastPathCount;
    }
  }
  if (UsedSharedPrecheck) {
    ++MemStats.PrecheckedMStoreOpCount;
    if (CurBlockMemStats.Active) {
      ++CurBlockMemStats.PrecheckedMStoreOpCount;
    }
  }
#endif // ZEN_ENABLE_MULTIPASS_JIT_LOGGING
#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
  reloadGasFromMemory();
#endif
}

void EVMMirBuilder::handleMStore8(Operand AddrComponents,
                                  Operand ValueComponents) {
  uint64_t ConstAddr = 0;
  const bool CanUseConstBaseDispPath =
      AddrComponents.isConstU64() &&
      (ConstAddr = AddrComponents.getConstValue()[0]) <=
          static_cast<uint64_t>(INT32_MAX);
  normalizeOperandU64(AddrComponents);
#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
  syncGasToMemory();
#endif
  MType *I64Type = &Ctx.I64Type;

  U256Inst AddrParts = extractU256Operand(AddrComponents);
  MInstruction *Offset = AddrParts[0];
  U256Inst ValueParts = extractU256Operand(ValueComponents);

  MInstruction *SizeConst = createIntConstInstruction(I64Type, 1);
  MInstruction *RequiredSize = createInstruction<BinaryInstruction>(
      false, OP_add, I64Type, Offset, SizeConst);
  // Tie expansion ordering to the stored value to prevent reordering.
  MInstruction *Zero = createIntConstInstruction(I64Type, 0);
  MInstruction *ValueDep = createInstruction<BinaryInstruction>(
      false, OP_and, I64Type, ValueParts[0], Zero);
  RequiredSize = createInstruction<BinaryInstruction>(false, OP_add, I64Type,
                                                      RequiredSize, ValueDep);
  MInstruction *Overflow = createInstruction<CmpInstruction>(
      false, CmpInstruction::Predicate::ICMP_ULT, I64Type, RequiredSize,
      Offset);
  bool UsedSharedPrecheck = tryConsumeConstBlockMemoryPrecheck();
  if (!UsedSharedPrecheck) {
#ifdef ZEN_ENABLE_MULTIPASS_JIT_LOGGING
    ++MemStats.MStore8ExpandCount;
    if (CurBlockMemStats.Active) {
      CurBlockMemStats.ExpandCallCount++;
    }
#endif // ZEN_ENABLE_MULTIPASS_JIT_LOGGING
    expandMemoryIR(RequiredSize, Overflow);
  }

  MInstruction *Low64 = ValueParts[0];
  MInstruction *Mask = createIntConstInstruction(I64Type, 0xFF);
  MInstruction *Masked =
      createInstruction<BinaryInstruction>(false, OP_and, I64Type, Low64, Mask);
  MInstruction *ByteValue = createInstruction<ConversionInstruction>(
      false, OP_trunc, &Ctx.I8Type, Masked);
  if (UsedSharedPrecheck && CanUseConstBaseDispPath) {
    MInstruction *BasePtr = getConstBlockDirectMemoryBasePtr();
    createInstruction<StoreInstruction>(true, &Ctx.VoidType, ByteValue, BasePtr,
                                        static_cast<int32_t>(ConstAddr));
  } else {
    MInstruction *MemBase = getDirectMemoryDataPointer(UsedSharedPrecheck);
    MInstruction *AddrInt = createInstruction<BinaryInstruction>(
        false, OP_add, I64Type, MemBase, Offset);

    MPointerType *I8PtrType = MPointerType::create(Ctx, Ctx.I8Type);
    MInstruction *AddrPtr = createInstruction<ConversionInstruction>(
        false, OP_inttoptr, I8PtrType, AddrInt);
    createInstruction<StoreInstruction>(true, &Ctx.VoidType, ByteValue,
                                        AddrPtr);
  }
#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
  reloadGasFromMemory();
#endif
}
void EVMMirBuilder::handleMCopy(Operand DestAddrComponents,
                                Operand SrcAddrComponents,
                                Operand LengthComponents) {
  MType *I64Type = &Ctx.I64Type;
  MInstruction *Zero = createIntConstInstruction(I64Type, 0);

  U256Inst LenParts = extractU256Operand(LengthComponents);
  MInstruction *LenOr = createInstruction<BinaryInstruction>(
      false, OP_or, I64Type, LenParts[0], LenParts[1]);
  LenOr = createInstruction<BinaryInstruction>(false, OP_or, I64Type, LenOr,
                                               LenParts[2]);
  LenOr = createInstruction<BinaryInstruction>(false, OP_or, I64Type, LenOr,
                                               LenParts[3]);
  MInstruction *IsZero = createInstruction<CmpInstruction>(
      false, CmpInstruction::Predicate::ICMP_EQ, I64Type, LenOr, Zero);

  MBasicBlock *CopyBB = createBasicBlock();
  MBasicBlock *DoneBB = createBasicBlock();
  createInstruction<BrIfInstruction>(true, Ctx, IsZero, DoneBB, CopyBB);
  addSuccessor(DoneBB);
  addSuccessor(CopyBB);

  setInsertBlock(CopyBB);

  normalizeOperandU64(DestAddrComponents);
  normalizeOperandU64(SrcAddrComponents);
  normalizeOperandU64(LengthComponents);
#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
  syncGasToMemory();
#endif

  U256Inst DestParts = extractU256Operand(DestAddrComponents);
  U256Inst SrcParts = extractU256Operand(SrcAddrComponents);
  U256Inst LenPartsNorm = extractU256Operand(LengthComponents);
  MInstruction *DestOffset = DestParts[0];
  MInstruction *SrcOffset = SrcParts[0];
  MInstruction *Len = LenPartsNorm[0];

  // Charge word copy gas: words = (len + 31) / 32
  MInstruction *Const31 = createIntConstInstruction(I64Type, 31);
  MInstruction *Shift5 = createIntConstInstruction(I64Type, 5);
  MInstruction *LenPlus31 = createInstruction<BinaryInstruction>(
      false, OP_add, I64Type, Len, Const31);
  MInstruction *Words = createInstruction<BinaryInstruction>(
      false, OP_ushr, I64Type, LenPlus31, Shift5);
  MInstruction *WordCopyCost =
      createIntConstInstruction(I64Type, zen::evm::WORD_COPY_COST);
  MInstruction *CopyGas = createInstruction<BinaryInstruction>(
      false, OP_mul, I64Type, Words, WordCopyCost);
  chargeDynamicGasIR(CopyGas);

  // Expand memory for both source and destination ranges.
  MInstruction *DestEnd = createInstruction<BinaryInstruction>(
      false, OP_add, I64Type, DestOffset, Len);
  MInstruction *SrcEnd = createInstruction<BinaryInstruction>(
      false, OP_add, I64Type, SrcOffset, Len);
  MInstruction *DestOverflow = createInstruction<CmpInstruction>(
      false, CmpInstruction::Predicate::ICMP_ULT, I64Type, DestEnd, DestOffset);
  MInstruction *SrcOverflow = createInstruction<CmpInstruction>(
      false, CmpInstruction::Predicate::ICMP_ULT, I64Type, SrcEnd, SrcOffset);
  MInstruction *Overflow = createInstruction<BinaryInstruction>(
      false, OP_or, I64Type, DestOverflow, SrcOverflow);

  MInstruction *DestGreater = createInstruction<CmpInstruction>(
      false, CmpInstruction::Predicate::ICMP_UGT, I64Type, DestEnd, SrcEnd);
  MInstruction *RequiredSize = createInstruction<SelectInstruction>(
      false, I64Type, DestGreater, DestEnd, SrcEnd);
#ifdef ZEN_ENABLE_MULTIPASS_JIT_LOGGING
  ++MemStats.MCopyExpandCount;
  if (CurBlockMemStats.Active) {
    CurBlockMemStats.ExpandCallCount++;
  }
#endif // ZEN_ENABLE_MULTIPASS_JIT_LOGGING
  expandMemoryIR(RequiredSize, Overflow);

  MInstruction *MemBase = getMemoryDataPointer();
  MInstruction *DestBase = createInstruction<BinaryInstruction>(
      false, OP_add, I64Type, MemBase, DestOffset);
  MInstruction *SrcBase = createInstruction<BinaryInstruction>(
      false, OP_add, I64Type, MemBase, SrcOffset);
  MPointerType *VoidPtrType = createVoidPtrType();
  MInstruction *DestPtr = createInstruction<ConversionInstruction>(
      false, OP_inttoptr, VoidPtrType, DestBase);
  MInstruction *SrcPtr = createInstruction<ConversionInstruction>(
      false, OP_inttoptr, VoidPtrType, SrcBase);
  MInstruction *MemmoveAddr = createIntConstInstruction(
      I64Type, reinterpret_cast<uint64_t>(std::memmove));
  CompileVector<MInstruction *> MemmoveArgs{
      {DestPtr, SrcPtr, Len},
      Ctx.MemPool,
  };
  createInstruction<ICallInstruction>(true, &Ctx.VoidType, MemmoveAddr,
                                      MemmoveArgs);
#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
  reloadGasFromMemory();
#endif
  createInstruction<BrInstruction>(true, Ctx, DoneBB);
  addSuccessor(DoneBB);

  setInsertBlock(DoneBB);
}

template <size_t NumTopics, typename... TopicArgs>
void EVMMirBuilder::handleLogWithTopics(Operand OffsetOp, Operand SizeOp,
                                        TopicArgs... Topics) {
  ZEN_STATIC_ASSERT(NumTopics <= 4);
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  normalizeOffsetWithSize(OffsetOp, SizeOp);

#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
  syncGasToMemory();
#endif
  if constexpr (NumTopics == 0) {
    callRuntimeFor<void, uint64_t, uint64_t>(RuntimeFunctions.EmitLog0,
                                             OffsetOp, SizeOp);
  } else if constexpr (NumTopics == 1) {
    callRuntimeFor<void, uint64_t, uint64_t, const uint8_t *>(
        RuntimeFunctions.EmitLog1, OffsetOp, SizeOp, Topics...);
  } else if constexpr (NumTopics == 2) {
    callRuntimeFor<void, uint64_t, uint64_t, const uint8_t *, const uint8_t *>(
        RuntimeFunctions.EmitLog2, OffsetOp, SizeOp, Topics...);
  } else if constexpr (NumTopics == 3) {
    callRuntimeFor<void, uint64_t, uint64_t, const uint8_t *, const uint8_t *,
                   const uint8_t *>(RuntimeFunctions.EmitLog3, OffsetOp, SizeOp,
                                    Topics...);
  } else { // NumTopics == 4
    callRuntimeFor<void, uint64_t, uint64_t, const uint8_t *, const uint8_t *,
                   const uint8_t *, const uint8_t *>(
        RuntimeFunctions.EmitLog4, OffsetOp, SizeOp, Topics...);
  }
#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
  reloadGasFromMemory();
#endif
  reloadMemorySizeFromInstance();
}

typename EVMMirBuilder::Operand
EVMMirBuilder::handleCreate(Operand ValueOp, Operand OffsetOp, Operand SizeOp) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  normalizeOffsetWithSize(OffsetOp, SizeOp);
#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
  syncGasToMemoryFull();
#endif
  auto Result = callRuntimeFor<const uint8_t *, const intx::uint256 &, uint64_t,
                               uint64_t>(RuntimeFunctions.HandleCreate, ValueOp,
                                         OffsetOp, SizeOp);
#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
  reloadGasFromMemory();
#endif
  reloadMemorySizeFromInstance();
  return Result;
}

typename EVMMirBuilder::Operand EVMMirBuilder::handleCreate2(Operand ValueOp,
                                                             Operand OffsetOp,
                                                             Operand SizeOp,
                                                             Operand SaltOp) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  normalizeOffsetWithSize(OffsetOp, SizeOp);
#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
  syncGasToMemoryFull();
#endif
  auto Result = callRuntimeFor<const uint8_t *, const intx::uint256 &, uint64_t,
                               uint64_t, const uint8_t *>(
      RuntimeFunctions.HandleCreate2, ValueOp, OffsetOp, SizeOp, SaltOp);
#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
  reloadGasFromMemory();
#endif
  reloadMemorySizeFromInstance();
  return Result;
}

typename EVMMirBuilder::Operand
EVMMirBuilder::handleCall(Operand GasOp, Operand ToAddrOp, Operand ValueOp,
                          Operand ArgsOffsetOp, Operand ArgsSizeOp,
                          Operand RetOffsetOp, Operand RetSizeOp) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  // When gas value exceeds 64 bits, use max uint64 as fallback.
  // The runtime will cap it to available gas per EIP-150.
  uint64_t Non64Value = std::numeric_limits<uint64_t>::max();
  normalizeOperandU64(GasOp, &Non64Value);
  normalizeOffsetWithSize(ArgsOffsetOp, ArgsSizeOp);
  normalizeOffsetWithSize(RetOffsetOp, RetSizeOp);

#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
  syncGasToMemoryFull();
#endif
  auto Result =
      callRuntimeFor<uint64_t, uint64_t, const uint8_t *, const intx::uint256 &,
                     uint64_t, uint64_t, uint64_t, uint64_t>(
          RuntimeFunctions.HandleCall, GasOp, ToAddrOp, ValueOp, ArgsOffsetOp,
          ArgsSizeOp, RetOffsetOp, RetSizeOp);
#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
  reloadGasFromMemory();
#endif
  reloadMemorySizeFromInstance();
  return Result;
}

typename EVMMirBuilder::Operand
EVMMirBuilder::handleCallCode(Operand GasOp, Operand ToAddrOp, Operand ValueOp,
                              Operand ArgsOffsetOp, Operand ArgsSizeOp,
                              Operand RetOffsetOp, Operand RetSizeOp) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  // When gas value exceeds 64 bits, use max uint64 as fallback.
  // The runtime will cap it to available gas per EIP-150.
  uint64_t Non64Value = std::numeric_limits<uint64_t>::max();
  normalizeOperandU64(GasOp, &Non64Value);
  normalizeOffsetWithSize(ArgsOffsetOp, ArgsSizeOp);
  normalizeOffsetWithSize(RetOffsetOp, RetSizeOp);

#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
  syncGasToMemoryFull();
#endif
  auto Result =
      callRuntimeFor<uint64_t, uint64_t, const uint8_t *, const intx::uint256 &,
                     uint64_t, uint64_t, uint64_t, uint64_t>(
          RuntimeFunctions.HandleCallCode, GasOp, ToAddrOp, ValueOp,
          ArgsOffsetOp, ArgsSizeOp, RetOffsetOp, RetSizeOp);
#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
  reloadGasFromMemory();
#endif
  reloadMemorySizeFromInstance();
  return Result;
}

void EVMMirBuilder::handleReturn(Operand MemOffsetComponents,
                                 Operand LengthComponents) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  uint64_t Non64Value = std::numeric_limits<uint64_t>::max();
  normalizeOperandU64(MemOffsetComponents, &Non64Value);
  normalizeOperandU64(LengthComponents, &Non64Value);
#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
  syncGasToMemoryFull();
#endif
  callRuntimeFor<void, uint64_t, uint64_t>(
      RuntimeFunctions.SetReturn, MemOffsetComponents, LengthComponents);

  // The runtime SetReturn may charge memory expansion gas via chargeGas(),
  // which updates Instance->Gas directly. We must NOT branch to the shared
  // ReturnBB because its syncGasToMemoryFull() would overwrite the correct
  // Instance->Gas with the stale gas register value.
  MBasicBlock *ReturnDirectBB = createBasicBlock();
  createInstruction<BrInstruction>(true, Ctx, ReturnDirectBB);
  addSuccessor(ReturnDirectBB);
  setInsertBlock(ReturnDirectBB);
  createInstruction<ReturnInstruction>(true, &Ctx.VoidType, nullptr);

  MBasicBlock *PostReturnBB = createBasicBlock();
  setInsertBlock(PostReturnBB);
}

typename EVMMirBuilder::Operand
EVMMirBuilder::handleDelegateCall(Operand GasOp, Operand ToAddrOp,
                                  Operand ArgsOffsetOp, Operand ArgsSizeOp,
                                  Operand RetOffsetOp, Operand RetSizeOp) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  // When gas value exceeds 64 bits, use max uint64 as fallback.
  // The runtime will cap it to available gas per EIP-150.
  uint64_t Non64Value = std::numeric_limits<uint64_t>::max();
  normalizeOperandU64(GasOp, &Non64Value);
  normalizeOffsetWithSize(ArgsOffsetOp, ArgsSizeOp);
  normalizeOffsetWithSize(RetOffsetOp, RetSizeOp);

#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
  syncGasToMemoryFull();
#endif
  auto Result = callRuntimeFor<uint64_t, uint64_t, const uint8_t *, uint64_t,
                               uint64_t, uint64_t, uint64_t>(
      RuntimeFunctions.HandleDelegateCall, GasOp, ToAddrOp, ArgsOffsetOp,
      ArgsSizeOp, RetOffsetOp, RetSizeOp);
#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
  reloadGasFromMemory();
#endif
  reloadMemorySizeFromInstance();
  return Result;
}

typename EVMMirBuilder::Operand
EVMMirBuilder::handleStaticCall(Operand GasOp, Operand ToAddrOp,
                                Operand ArgsOffsetOp, Operand ArgsSizeOp,
                                Operand RetOffsetOp, Operand RetSizeOp) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  // When gas value exceeds 64 bits, use max uint64 as fallback.
  // The runtime will cap it to available gas per EIP-150.
  uint64_t Non64Value = std::numeric_limits<uint64_t>::max();
  normalizeOperandU64(GasOp, &Non64Value);
  normalizeOffsetWithSize(ArgsOffsetOp, ArgsSizeOp);
  normalizeOffsetWithSize(RetOffsetOp, RetSizeOp);

#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
  syncGasToMemoryFull();
#endif
  auto Result = callRuntimeFor<uint64_t, uint64_t, const uint8_t *, uint64_t,
                               uint64_t, uint64_t, uint64_t>(
      RuntimeFunctions.HandleStaticCall, GasOp, ToAddrOp, ArgsOffsetOp,
      ArgsSizeOp, RetOffsetOp, RetSizeOp);
#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
  reloadGasFromMemory();
#endif
  reloadMemorySizeFromInstance();
  return Result;
}

void EVMMirBuilder::handleRevert(Operand OffsetOp, Operand SizeOp) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  uint64_t Non64Value = std::numeric_limits<uint64_t>::max();
  normalizeOperandU64(OffsetOp, &Non64Value);
  normalizeOperandU64(SizeOp, &Non64Value);
#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
  syncGasToMemoryFull();
#endif
  callRuntimeFor<void, uint64_t, uint64_t>(RuntimeFunctions.SetRevert, OffsetOp,
                                           SizeOp);

  // The runtime SetRevert may charge memory expansion gas via chargeGas(),
  // which updates Instance->Gas directly. We must NOT branch to the shared
  // ReturnBB because its syncGasToMemoryFull() would overwrite the correct
  // Instance->Gas with the stale gas register value.
  MBasicBlock *RevertReturnBB = createBasicBlock();
  createInstruction<BrInstruction>(true, Ctx, RevertReturnBB);
  addSuccessor(RevertReturnBB);
  setInsertBlock(RevertReturnBB);
  createInstruction<ReturnInstruction>(true, &Ctx.VoidType, nullptr);

  MBasicBlock *PostRevertBB = createBasicBlock();
  setInsertBlock(PostRevertBB);
}

void EVMMirBuilder::handleInvalid() {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
  syncGasToMemoryFull();
#endif
  callRuntimeFor(RuntimeFunctions.HandleInvalid);

  // HandleInvalid sets Instance->Gas to 0. We must NOT branch to the shared
  // ReturnBB because its syncGasToMemoryFull() would overwrite the zeroed gas
  // with the stale gas register value.
  MBasicBlock *InvalidReturnBB = createBasicBlock();
  createInstruction<BrInstruction>(true, Ctx, InvalidReturnBB);
  addSuccessor(InvalidReturnBB);
  setInsertBlock(InvalidReturnBB);
  createInstruction<ReturnInstruction>(true, &Ctx.VoidType, nullptr);
}

void EVMMirBuilder::handleUndefined() {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
  syncGasToMemoryFull();
#endif
  callRuntimeFor(RuntimeFunctions.HandleUndefined);

  // HandleUndefined sets Instance->Gas to 0. We must NOT branch to the shared
  // ReturnBB because its syncGasToMemoryFull() would overwrite the zeroed gas
  // with the stale gas register value.
  MBasicBlock *UndefinedReturnBB = createBasicBlock();
  createInstruction<BrInstruction>(true, Ctx, UndefinedReturnBB);
  addSuccessor(UndefinedReturnBB);
  setInsertBlock(UndefinedReturnBB);
  createInstruction<ReturnInstruction>(true, &Ctx.VoidType, nullptr);
}
typename EVMMirBuilder::Operand
EVMMirBuilder::handleSLoad(Operand KeyComponents) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
  syncGasToMemory();
#endif
  auto Result = callRuntimeFor<const intx::uint256 *, const intx::uint256 &>(
      RuntimeFunctions.GetSLoad, KeyComponents);
#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
  reloadGasFromMemory();
#endif
  return Result;
}
void EVMMirBuilder::handleSStore(Operand KeyComponents,
                                 Operand ValueComponents) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
  syncGasToMemory();
#endif
  callRuntimeFor<void, const intx::uint256 &, const intx::uint256 &>(
      RuntimeFunctions.SetSStore, KeyComponents, ValueComponents);
#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
  reloadGasFromMemory();
#endif
}
typename EVMMirBuilder::Operand EVMMirBuilder::handleTLoad(Operand Index) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  return callRuntimeFor<const intx::uint256 *, const intx::uint256 &>(
      RuntimeFunctions.GetTLoad, Index);
}
void EVMMirBuilder::handleTStore(Operand Index, Operand ValueComponents) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  callRuntimeFor<void, const intx::uint256 &, const intx::uint256 &>(
      RuntimeFunctions.SetTStore, Index, ValueComponents);
}
void EVMMirBuilder::handleSelfDestruct(Operand Beneficiary) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
  // SELFDESTRUCT is a terminating opcode. Flush the live gas register so the
  // runtime helper observes the current callee gas and returns the correct
  // leftover amount to the caller.
  syncGasToMemoryFull();
#endif
  callRuntimeFor<void, const uint8_t *>(RuntimeFunctions.HandleSelfDestruct,
                                        Beneficiary);

  // The runtime function (evmHandleSelfDestruct) calls popMessage() which may
  // set CurrentMessage to nullptr when there is no parent frame. The shared
  // ReturnBB uses syncGasToMemoryFull() which writes to Msg->gas via
  // CurrentMessage, causing a null pointer write (SEGV at address 0x10).
  // Use a dedicated return block with a plain return instruction instead.
  MBasicBlock *SelfDestructReturnBB = createBasicBlock();
  createInstruction<BrInstruction>(true, Ctx, SelfDestructReturnBB);
  addSuccessor(SelfDestructReturnBB);
  setInsertBlock(SelfDestructReturnBB);
  createInstruction<ReturnInstruction>(true, &Ctx.VoidType, nullptr);

  MBasicBlock *PostSelfDestructBB = createBasicBlock();
  setInsertBlock(PostSelfDestructBB);
}

typename EVMMirBuilder::Operand
EVMMirBuilder::handleKeccak256(Operand OffsetComponents,
                               Operand LengthComponents) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  normalizeOffsetWithSize(OffsetComponents, LengthComponents);
#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
  syncGasToMemory();
#endif
  auto Result = callRuntimeFor<const uint8_t *, uint64_t, uint64_t>(
      RuntimeFunctions.GetKeccak256, OffsetComponents, LengthComponents);
#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
  reloadGasFromMemory();
#endif
  reloadMemorySizeFromInstance();
  return Result;
}

// ==================== Private Helper Methods ====================

typename EVMMirBuilder::Operand
EVMMirBuilder::createU256ConstOperand(const intx::uint256 &V) {
  // Get EVMU256Type to guide proper component creation
  zen::common::EVMU256Type *U256Type = EVMFrontendContext::getEVMU256Type();
  MType *I64Type = EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);

  // Use EVMU256Type's element count and structure
  std::array<uint64_t, EVM_ELEMENTS_COUNT> Components{};
  for (size_t I = 0; I < EVM_ELEMENTS_COUNT; ++I) {
    Components[I] =
        static_cast<uint64_t>((V >> (I * 64)) & 0xFFFFFFFFFFFFFFFFULL);
  }

  // Create constant instructions based on EVMU256Type's inner types
  U256Inst ComponentInstrs;
  for (size_t I = 0; I < EVM_ELEMENTS_COUNT; ++I) {
    MConstant *Constant = MConstantInt::get(Ctx, *I64Type, Components[I]);
    ComponentInstrs[I] =
        createInstruction<ConstantInstruction>(false, I64Type, *Constant);
  }

  return Operand(ComponentInstrs, EVMType::UINT256);
}

EVMMirBuilder::U256Inst EVMMirBuilder::extractU256Operand(const Operand &Opnd) {
  U256Inst Result = {};

  if (Opnd.isEmpty()) {
    return Result;
  }

  if (Opnd.isConstant()) {
    U256ConstInt Constants = createU256Constants(Opnd.getConstValue());
    for (size_t I = 0; I < EVM_ELEMENTS_COUNT; ++I) {
      Result[I] = createInstruction<ConstantInstruction>(
          false, EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT256),
          *Constants[I]);
    }
    return Result;
  }

  if (Opnd.isDeferredBitwiseNot()) {
    const U256Inst &Base = Opnd.getDeferredBaseComponents();
    MType *MirI64Type =
        EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);
    for (size_t I = 0; I < EVM_ELEMENTS_COUNT; ++I) {
      MInstruction *LocalResult =
          createInstruction<NotInstruction>(false, MirI64Type, Base[I]);
      Result[I] = protectUnsafeValue(LocalResult, MirI64Type);
    }
    return Result;
  }

  if (Opnd.isDeferredZeroTest()) {
    return handleCompareEQZ(Opnd.getDeferredBaseComponents(), &Ctx.I64Type,
                            Opnd.isDeferredZeroTestNegated());
  }

  if (Opnd.isU256MultiComponent()) {
    U256Inst Instrs = Opnd.getU256Components();
    if (Instrs[0] != nullptr) {
      return Instrs;
    }

    U256Var Vars = Opnd.getU256VarComponents();
    if (Vars[0] != nullptr) {
      for (size_t I = 0; I < EVM_ELEMENTS_COUNT; ++I) {
        ZEN_ASSERT(Vars[I] != nullptr);
        Result[I] = createInstruction<DreadInstruction>(
            false, Vars[I]->getType(), Vars[I]->getVarIdx());
      }
    }
  }

  // Auto-convert BYTES32 operands to U256 when needed
  if (Opnd.getType() == EVMType::BYTES32) {
    Operand U256Op = convertBytes32ToU256Operand(Opnd);
    return U256Op.getU256Components();
  }

  // Auto-convert UINT64 operands to U256 when needed
  if (Opnd.getType() == EVMType::UINT64) {
    Operand U256Op = convertSingleInstrToU256Operand(Opnd.getInstr());
    return U256Op.getU256Components();
  }

  return Result;
}

// ==================== EVMU256 Helper Methods ====================

MInstruction *EVMMirBuilder::zeroExtendToI64(MInstruction *Value) {
  MType *I64Type = EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);
  MType *ValueType = Value->getType();

  if (ValueType->isI64()) {
    return Value;
  }

  ZEN_ASSERT(ValueType->isI8() || ValueType->isI16() || ValueType->isI32());
  return createInstruction<ConversionInstruction>(false, OP_uext, I64Type,
                                                  Value);
}

EVMMirBuilder::U256Value EVMMirBuilder::bytesToU256(const Bytes &Data) {
  return createU256FromBytes(Data.data(), Data.size());
}

typename EVMMirBuilder::Operand
EVMMirBuilder::convertSingleInstrToU256Operand(MInstruction *SingleInstr) {
  // Convert single instruction to U256 with little-endian storage
  U256Inst Result = {};
  MType *I64Type = EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);

  // Convert the single instruction result to I64 and place it in low component
  Result[0] = zeroExtendToI64(SingleInstr);

  // Each limb needs its own zero constant (dMIR tree IR: one parent per expr)
  for (size_t I = 1; I < EVM_ELEMENTS_COUNT; ++I) {
    Result[I] = createIntConstInstruction(I64Type, 0);
  }
  return Operand(Result, EVMType::UINT256);
}

Variable *EVMMirBuilder::storeInstructionInTemp(MInstruction *Value,
                                                MType *Type) {
  Variable *TempVar = CurFunc->createVariable(Type);
  createInstruction<DassignInstruction>(true, &(Ctx.VoidType), Value,
                                        TempVar->getVarIdx());
  return TempVar;
}

MInstruction *EVMMirBuilder::loadVariable(Variable *Var) {
  return createInstruction<DreadInstruction>(false, Var->getType(),
                                             Var->getVarIdx());
}

PhiInstruction *EVMMirBuilder::createPendingPhi(MType *Type,
                                                size_t NumIncoming) {
  return createInstruction<PhiInstruction>(true, Type, NumIncoming);
}

size_t EVMMirBuilder::getPhiIncomingSlot(PhiInstruction *Phi,
                                         uint64_t PredBlockPC) const {
  auto PhiIt = PhiIncomingSlotMap.find(Phi);
  ZEN_ASSERT(PhiIt != PhiIncomingSlotMap.end());
  auto SlotIt = PhiIt->second.find(PredBlockPC);
  ZEN_ASSERT(SlotIt != PhiIt->second.end());
  return SlotIt->second;
}

MInstruction *EVMMirBuilder::protectUnsafeValue(MInstruction *Value,
                                                MType *Type) {
  Variable *ReusableVar = CurFunc->createVariable(Type);
  VariableIdx ReusableVarIdx = ReusableVar->getVarIdx();
  createInstruction<DassignInstruction>(true, &(Ctx.VoidType), Value,
                                        ReusableVarIdx);
  return createInstruction<DreadInstruction>(false, ReusableVar->getType(),
                                             ReusableVarIdx);
}

MInstruction *EVMMirBuilder::anchorDirectMemoryPointer(MInstruction *Ptr) {
  return protectUnsafeValue(Ptr, Ptr->getType());
}

MInstruction *EVMMirBuilder::loadProtectedInstancePointer(int32_t Offset) {
  MPointerType *VoidPtrType = createVoidPtrType();
  MInstruction *Ptr = getInstanceElement(VoidPtrType, Offset);
  return protectUnsafeValue(Ptr, VoidPtrType);
}

MInstruction *EVMMirBuilder::getProtectedFieldAddress(MInstruction *BasePtr,
                                                      int32_t Offset,
                                                      MType *PointerType) {
  MType *I64Type = EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);
  MInstruction *BaseAddr = BasePtr;

  if (BasePtr->getType()->isPointer()) {
    BaseAddr = createInstruction<ConversionInstruction>(false, OP_ptrtoint,
                                                        I64Type, BasePtr);
  } else if (!BasePtr->getType()->isI64()) {
    BaseAddr = zeroExtendToI64(BasePtr);
  }

  BaseAddr = protectUnsafeValue(BaseAddr, I64Type);
  MInstruction *OffsetValue =
      createIntConstInstruction(I64Type, static_cast<uint64_t>(Offset));
  MInstruction *FieldAddr = createInstruction<BinaryInstruction>(
      false, OP_add, I64Type, BaseAddr, OffsetValue);
  MInstruction *FieldPtr = createInstruction<ConversionInstruction>(
      false, OP_inttoptr, PointerType, FieldAddr);
  return protectUnsafeValue(FieldPtr, PointerType);
}

MInstruction *EVMMirBuilder::loadProtectedU64Field(MInstruction *BasePtr,
                                                   int32_t Offset) {
  MType *I64Type = EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);
  MPointerType *I64PtrType = MPointerType::create(Ctx, *I64Type);
  MInstruction *FieldPtr =
      getProtectedFieldAddress(BasePtr, Offset, I64PtrType);
  MInstruction *Value =
      createInstruction<LoadInstruction>(false, I64Type, FieldPtr);
  return protectUnsafeValue(Value, I64Type);
}

typename EVMMirBuilder::Operand
EVMMirBuilder::loadProtectedBytes32FieldAsU256(MInstruction *BasePtr,
                                               int32_t Offset) {
  MType *I64Type = EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);
  MInstruction *FieldPtr =
      getProtectedFieldAddress(BasePtr, Offset, createVoidPtrType());
  Operand Bytes32Op(FieldPtr, EVMType::BYTES32);
  U256Inst Components =
      convertBytes32ToU256Operand(Bytes32Op).getU256Components();
  for (size_t I = 0; I < EVM_ELEMENTS_COUNT; ++I) {
    Components[I] = protectUnsafeValue(Components[I], I64Type);
  }
  return Operand(Components, EVMType::UINT256);
}

typename EVMMirBuilder::Operand
EVMMirBuilder::loadProtectedAddressFieldAsU256(MInstruction *BasePtr,
                                               int32_t Offset) {
  MType *I64Type = EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);
  MPointerType *I64PtrType = MPointerType::create(Ctx, *I64Type);
  MInstruction *AddressPtr =
      getProtectedFieldAddress(BasePtr, Offset, I64PtrType);

  auto LoadAddressChunk = [&](int32_t InnerOffset) -> MInstruction * {
    MInstruction *Raw = createInstruction<LoadInstruction>(
        false, I64Type, AddressPtr, 1, nullptr, InnerOffset);
    MInstruction *Swapped =
        createInstruction<UnaryInstruction>(false, OP_bswap, I64Type, Raw);
    return protectUnsafeValue(Swapped, I64Type);
  };

  MInstruction *Low64 = LoadAddressChunk(12);
  MInstruction *Mid64 = LoadAddressChunk(4);
  MInstruction *High64 = LoadAddressChunk(0);
  MInstruction *Shift = createIntConstInstruction(I64Type, 32);
  MInstruction *High32 = createInstruction<BinaryInstruction>(
      false, OP_ushr, I64Type, High64, Shift);
  High32 = protectUnsafeValue(High32, I64Type);
  MInstruction *Zero = createIntConstInstruction(I64Type, 0);

  U256Inst Components = {Low64, Mid64, High32, Zero};
  return Operand(Components, EVMType::UINT256);
}

MInstruction *EVMMirBuilder::getHostArgScratchPtr(std::size_t ScratchSlot) {
  ZEN_ASSERT(ScratchSlot < zen::runtime::EVMInstance::HostArgScratchSlots);

  MType *I64Type = EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);
  const int32_t BaseOffset =
      zen::runtime::EVMInstance::getHostArgScratchOffset() +
      static_cast<int32_t>(
          ScratchSlot * zen::runtime::EVMInstance::getHostArgScratchSlotSize());

  MInstruction *OffsetValue = createIntConstInstruction(I64Type, BaseOffset);
  MInstruction *ScratchAddrInt = createInstruction<BinaryInstruction>(
      false, OP_add, I64Type, InstanceAddr, OffsetValue);

  return createInstruction<ConversionInstruction>(
      false, OP_inttoptr, createVoidPtrType(), ScratchAddrInt);
}
typename EVMMirBuilder::Operand
EVMMirBuilder::convertU256InstrToU256Operand(MInstruction *U256Instr) {
  U256Inst Result = {};
  MType *I64Type = EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);
  MType *PtrType = U256Instr->getType();
  if (!PtrType->isPointer()) {
    return convertSingleInstrToU256Operand(U256Instr);
  }

  Variable *PtrVar = storeInstructionInTemp(U256Instr, PtrType);
  const int32_t Offsets[] = {0, 8, 16, 24};
  MPointerType *U64PtrType = MPointerType::create(Ctx, Ctx.I64Type);

  for (int I = 0; I < static_cast<int>(EVM_ELEMENTS_COUNT); ++I) {
    MInstruction *BaseValue = loadVariable(PtrVar);
    MInstruction *BaseAddr = BaseValue;

    if (BaseValue->getType()->isPointer()) {
      BaseAddr = createInstruction<ConversionInstruction>(
          false, OP_ptrtoint, &Ctx.I64Type, BaseValue);
    } else if (!BaseValue->getType()->isI64()) {
      BaseAddr = zeroExtendToI64(BaseValue);
    }

    MInstruction *OffsetValue = createIntConstInstruction(I64Type, Offsets[I]);
    MInstruction *IndexedAddr = createInstruction<BinaryInstruction>(
        false, OP_add, &Ctx.I64Type, BaseAddr, OffsetValue);
    MInstruction *IndexedPtr = createInstruction<ConversionInstruction>(
        false, OP_inttoptr, U64PtrType, IndexedAddr);

    MInstruction *LoadInstr =
        createInstruction<LoadInstruction>(false, I64Type, IndexedPtr);
    Variable *ValVar = storeInstructionInTemp(LoadInstr, I64Type);
    Result[I] = loadVariable(ValVar);
  }

  return Operand(Result, EVMType::UINT256);
}

typename EVMMirBuilder::Operand
EVMMirBuilder::convertBytes32ToU256Operand(const Operand &Bytes32Op) {
  // Convert BYTES32 pointer to 4-component U256 representation with
  // little-endian storage
  ZEN_ASSERT(Bytes32Op.getType() == EVMType::BYTES32);

  MInstruction *Bytes32Ptr = Bytes32Op.getInstr();
  if (Bytes32Ptr->getType()->isPointer()) {
    return loadU256FromBytes32PointerDisplaced(Bytes32Ptr);
  }

  U256Inst Result = {};
  MType *I64Type = EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);
  MPointerType *U64PtrType = MPointerType::create(Ctx, Ctx.I64Type);

  auto ByteSwap64 = [&](MInstruction *Value) -> MInstruction * {
    return createInstruction<UnaryInstruction>(false, OP_bswap, I64Type, Value);
  };

  for (int Component = 0; Component < 4; ++Component) {
    int BaseOffset = (3 - Component) * 8;
    MInstruction *Offset =
        createIntConstInstruction(I64Type, static_cast<uint64_t>(BaseOffset));
    MInstruction *Addr = createInstruction<BinaryInstruction>(
        false, OP_add, &Ctx.I64Type, Bytes32Ptr, Offset);
    MInstruction *ComponentPtr = createInstruction<ConversionInstruction>(
        false, OP_inttoptr, U64PtrType, Addr);
    MInstruction *RawValue =
        createInstruction<LoadInstruction>(false, I64Type, ComponentPtr);
    Result[Component] = ByteSwap64(RawValue);
  }

  return Operand(Result, EVMType::UINT256);
}

typename EVMMirBuilder::Operand
EVMMirBuilder::loadU256FromBytes32PointerDisplaced(MInstruction *Bytes32Ptr) {
  U256Inst Result = {};
  MType *I64Type = EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);

  auto ByteSwap64 = [&](MInstruction *Value) -> MInstruction * {
    return createInstruction<UnaryInstruction>(false, OP_bswap, I64Type, Value);
  };

  for (int Component = 0; Component < 4; ++Component) {
    MInstruction *RawValue = createInstruction<LoadInstruction>(
        false, I64Type, Bytes32Ptr, 1, nullptr, (3 - Component) * 8);

    Result[Component] = ByteSwap64(RawValue);
  }

  return Operand(Result, EVMType::UINT256);
}

typename EVMMirBuilder::Operand
EVMMirBuilder::loadU256FromBytes32BaseDisplaced(MInstruction *BytesBasePtr,
                                                uint64_t BaseOffset) {
  ZEN_ASSERT(BaseOffset <= static_cast<uint64_t>(INT32_MAX - 24) &&
             "base displacement must fit in i32");

  U256Inst Result = {};
  MType *I64Type = EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);

  auto ByteSwap64 = [&](MInstruction *Value) -> MInstruction * {
    return createInstruction<UnaryInstruction>(false, OP_bswap, I64Type, Value);
  };

  for (int Component = 0; Component < 4; ++Component) {
    const int32_t Offset = static_cast<int32_t>(BaseOffset) +
                           static_cast<int32_t>((3 - Component) * 8);
    MInstruction *RawValue = createInstruction<LoadInstruction>(
        false, I64Type, BytesBasePtr, 1, nullptr, Offset);
    Result[Component] = ByteSwap64(RawValue);
  }

  return Operand(Result, EVMType::UINT256);
}

void EVMMirBuilder::storeU256ToBytes32Pointer(
    MInstruction *Bytes32Ptr, const U256Inst &ValueParts,
    uint64_t SkipLeadingZeroLimbStores) {
  MType *I64Type = &Ctx.I64Type;
  MInstruction *Zero = createIntConstInstruction(I64Type, 0);

  auto ByteSwap64 = [&](MInstruction *Value) -> MInstruction * {
    return createInstruction<UnaryInstruction>(false, OP_bswap, I64Type, Value);
  };
  auto IsConstZeroI64 = [&](MInstruction *Value) -> bool {
    auto *ConstInstr = llvm::dyn_cast<ConstantInstruction>(Value);
    if (!ConstInstr) {
      return false;
    }
    auto *ConstInt = llvm::dyn_cast<MConstantInt>(&ConstInstr->getConstant());
    return ConstInt && ConstInt->getValue() == 0;
  };

  for (int Component = 0; Component < 4; ++Component) {
    MInstruction *RawValue = ValueParts[3 - Component];
    MInstruction *StoredValue = nullptr;
    if (IsConstZeroI64(RawValue)) {
      if (static_cast<uint64_t>(Component) < SkipLeadingZeroLimbStores) {
#ifdef ZEN_ENABLE_MULTIPASS_JIT_LOGGING
        ++MemStats.MStoreOverlapElidedLimbCount;
        if (CurBlockMemStats.Active) {
          ++CurBlockMemStats.MStoreOverlapElidedLimbCount;
        }
#endif // ZEN_ENABLE_MULTIPASS_JIT_LOGGING
        continue;
      }
      StoredValue = Zero;
#ifdef ZEN_ENABLE_MULTIPASS_JIT_LOGGING
      ++MemStats.MStoreZeroLimbStoreCount;
      if (CurBlockMemStats.Active) {
        ++CurBlockMemStats.MStoreZeroLimbStoreCount;
      }
#endif // ZEN_ENABLE_MULTIPASS_JIT_LOGGING
    } else {
      StoredValue = ByteSwap64(RawValue);
    }
    createInstruction<StoreInstruction>(true, &Ctx.VoidType, StoredValue,
                                        Bytes32Ptr, Component * 8);
  }
}

void EVMMirBuilder::storeU256ToBytes32BaseDisplaced(
    MInstruction *BytesBasePtr, uint64_t BaseOffset, const U256Inst &ValueParts,
    uint64_t SkipLeadingZeroLimbStores) {
  ZEN_ASSERT(BaseOffset <= static_cast<uint64_t>(INT32_MAX - 24) &&
             "base displacement must fit in i32");

  MType *I64Type = &Ctx.I64Type;
  MInstruction *Zero = createIntConstInstruction(I64Type, 0);

  auto ByteSwap64 = [&](MInstruction *Value) -> MInstruction * {
    return createInstruction<UnaryInstruction>(false, OP_bswap, I64Type, Value);
  };
  auto IsConstZeroI64 = [&](MInstruction *Value) -> bool {
    auto *ConstInstr = llvm::dyn_cast<ConstantInstruction>(Value);
    if (!ConstInstr) {
      return false;
    }
    auto *ConstInt = llvm::dyn_cast<MConstantInt>(&ConstInstr->getConstant());
    return ConstInt && ConstInt->getValue() == 0;
  };

  for (int Component = 0; Component < 4; ++Component) {
    MInstruction *RawValue = ValueParts[3 - Component];
    MInstruction *StoredValue = nullptr;
    if (IsConstZeroI64(RawValue)) {
      if (static_cast<uint64_t>(Component) < SkipLeadingZeroLimbStores) {
#ifdef ZEN_ENABLE_MULTIPASS_JIT_LOGGING
        ++MemStats.MStoreOverlapElidedLimbCount;
        if (CurBlockMemStats.Active) {
          ++CurBlockMemStats.MStoreOverlapElidedLimbCount;
        }
#endif // ZEN_ENABLE_MULTIPASS_JIT_LOGGING
        continue;
      }
      StoredValue = Zero;
#ifdef ZEN_ENABLE_MULTIPASS_JIT_LOGGING
      ++MemStats.MStoreZeroLimbStoreCount;
      if (CurBlockMemStats.Active) {
        ++CurBlockMemStats.MStoreZeroLimbStoreCount;
      }
#endif // ZEN_ENABLE_MULTIPASS_JIT_LOGGING
    } else {
      StoredValue = ByteSwap64(RawValue);
    }
    const int32_t Offset =
        static_cast<int32_t>(BaseOffset) + static_cast<int32_t>(Component * 8);
    createInstruction<StoreInstruction>(true, &Ctx.VoidType, StoredValue,
                                        BytesBasePtr, Offset);
  }
}

MInstruction *EVMMirBuilder::isU256GreaterOrEqual(const U256Inst &Value,
                                                  uint64_t Threshold) {
  MType *MirI64Type =
      EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);
  MInstruction *Zero = createIntConstInstruction(MirI64Type, 0);

  // Check if any high component is non-zero
  MInstruction *HighBits12 = createInstruction<BinaryInstruction>(
      false, OP_or, MirI64Type, Value[1], Value[2]);
  MInstruction *HighBits = createInstruction<BinaryInstruction>(
      false, OP_or, MirI64Type, HighBits12, Value[3]);
  MInstruction *IsHighNonZero = createInstruction<CmpInstruction>(
      false, CmpInstruction::Predicate::ICMP_NE, &Ctx.I64Type, HighBits, Zero);

  MInstruction *ThresholdConst =
      createIntConstInstruction(MirI64Type, Threshold);
  // Check if low component >= threshold
  MInstruction *IsLowGE = createInstruction<CmpInstruction>(
      false, CmpInstruction::Predicate::ICMP_UGE, &Ctx.I64Type, Value[0],
      ThresholdConst);

  // Combine result: any high component non-zero OR low component >= threshold
  return createInstruction<BinaryInstruction>(false, OP_or, MirI64Type,
                                              IsHighNonZero, IsLowGE);
}

// ==================== EVM to MIR Opcode Mapping ====================

Opcode EVMMirBuilder::getMirOpcode(BinaryOperator BinOpr) {
  switch (BinOpr) {
  case BinaryOperator::BO_ADD:
    return OP_add;
  case BinaryOperator::BO_SUB:
    return OP_sub;
  case BinaryOperator::BO_MUL:
    return OP_mul;
  case BinaryOperator::BO_AND:
    return OP_and;
  case BinaryOperator::BO_OR:
    return OP_or;
  case BinaryOperator::BO_XOR:
    return OP_xor;
  default:
    ZEN_UNREACHABLE();
  }
}

// ==================== Interface Helper Methods ====================

// Helper template functions for runtime call type mapping
template <typename RetType> MType *EVMMirBuilder::getMIRReturnType() {
  if constexpr (std::is_same_v<RetType, intx::uint256> ||
                std::is_same_v<RetType, const intx::uint256 *>) {
    return MPointerType::create(Ctx, Ctx.I64Type);
  } else if constexpr (std::is_same_v<RetType, const uint8_t *>) {
    return EVMFrontendContext::getMIRTypeFromEVMType(EVMType::BYTES32);
  } else if constexpr (std::is_same_v<RetType, uint64_t>) {
    return EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);
  } else if constexpr (std::is_same_v<RetType, void>) {
    return EVMFrontendContext::getMIRTypeFromEVMType(EVMType::VOID);
  }
  return EVMFrontendContext::getMIRTypeFromEVMType(EVMType::VOID);
}

template <typename RetType>
typename EVMMirBuilder::Operand
EVMMirBuilder::convertCallResult(MInstruction *CallInstr) {
  if constexpr (std::is_same_v<RetType, intx::uint256> ||
                std::is_same_v<RetType, const intx::uint256 *>) {
    return convertU256InstrToU256Operand(CallInstr);
  } else if constexpr (std::is_same_v<RetType, const uint8_t *>) {
    Variable *PtrVar = storeInstructionInTemp(CallInstr, CallInstr->getType());
    MInstruction *PtrValue = loadVariable(PtrVar);
    return Operand(PtrValue, EVMType::BYTES32);
  } else if constexpr (std::is_same_v<RetType, uint64_t>) {
    Variable *ValVar = storeInstructionInTemp(CallInstr, CallInstr->getType());
    MInstruction *Val = loadVariable(ValVar);
    return convertSingleInstrToU256Operand(Val);
  } else if constexpr (std::is_same_v<RetType, void>) {
    return Operand();
  }
  return Operand();
}

void EVMMirBuilder::normalizeOperandU64(Operand &Param, uint64_t *Value) {
  if (Param.getType() == EVMType::BYTES32) {
    Param = convertBytes32ToU256Operand(Param);
  }
  if (Param.getType() != EVMType::UINT256) {
    return;
  }
  if (Param.isConstant()) {
    normalizeOperandU64Const(Param, Value);
  } else {
    normalizeOperandU64NonConst(Param, Value);
  }
}

void EVMMirBuilder::normalizeOperandU64Const(Operand &Param, uint64_t *Value) {
  const auto &C = Param.getConstValue();
  bool FitsU64 = (C[1] == 0 && C[2] == 0 && C[3] == 0);

  MType *I64Type = EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);
  if (!FitsU64) {
    if (Value != nullptr) {
      // Convert Value to const U256 and assign to Param
      U256Value NewConstValue = {*Value, 0, 0, 0};
      Param = Operand(NewConstValue);
      return;
    }
    MInstruction *TrueCond = createIntConstInstruction(I64Type, 1);
    MBasicBlock *TrapBB =
        getOrCreateExceptionSetBB(ErrorCode::GasLimitExceeded);
    MBasicBlock *ContinueBB = createBasicBlock();
    createInstruction<BrIfInstruction>(true, Ctx, TrueCond, TrapBB, ContinueBB);
    addUniqueSuccessor(TrapBB);
    addSuccessor(ContinueBB);
    setInsertBlock(ContinueBB);
  }
  uint64_t Selected = C[0];

  // Rebuild Param as a normalized U256 with low64=Selected, others=0
  MInstruction *Low = createIntConstInstruction(I64Type, Selected);
  MInstruction *Zero = createIntConstInstruction(I64Type, 0);
  U256Inst NewVal = {Low, Zero, Zero, Zero};
  Param = Operand(NewVal, EVMType::UINT256);
}

void EVMMirBuilder::normalizeOperandU64NonConst(Operand &Param,
                                                uint64_t *Value) {
  // Extract four 64-bit parts [low, mid-low, mid-high, high]
  U256Inst Parts = extractU256Operand(Param);

  MType *I64Type = EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);
  MInstruction *Zero = createIntConstInstruction(I64Type, 0);

  // IsU64 = (part[1] == 0) && (part[2] == 0) && (part[3] == 0)
  MInstruction *IsZero1 = createInstruction<CmpInstruction>(
      false, CmpInstruction::Predicate::ICMP_EQ, &Ctx.I64Type, Parts[1], Zero);
  MInstruction *IsZero2 = createInstruction<CmpInstruction>(
      false, CmpInstruction::Predicate::ICMP_EQ, &Ctx.I64Type, Parts[2], Zero);
  MInstruction *IsZero3 = createInstruction<CmpInstruction>(
      false, CmpInstruction::Predicate::ICMP_EQ, &Ctx.I64Type, Parts[3], Zero);

  // Combine to a single condition using 64-bit ANDs
  MInstruction *Cond12 = createInstruction<BinaryInstruction>(
      false, OP_and, I64Type, IsZero1, IsZero2);
  MInstruction *IsU64 = createInstruction<BinaryInstruction>(
      false, OP_and, I64Type, Cond12, IsZero3);

  MInstruction *ZeroCond = createIntConstInstruction(I64Type, 0);
  MInstruction *IsInvalid = createInstruction<CmpInstruction>(
      false, CmpInstruction::Predicate::ICMP_EQ, &Ctx.I64Type, IsU64, ZeroCond);

  if (Value != nullptr) {
    // Use SelectInstruction to choose between Param's first part and provided
    // Value
    MInstruction *ValueInst = createIntConstInstruction(I64Type, *Value);
    MInstruction *SelectedLow = createInstruction<SelectInstruction>(
        false, I64Type, IsU64, Parts[0], ValueInst);

    // Rebuild Param as a normalized U256 with selected low part, others=0
    U256Inst NewVal = {SelectedLow, Zero, Zero, Zero};
    Param = Operand(NewVal, EVMType::UINT256);
  } else {
    MBasicBlock *TrapBB =
        getOrCreateExceptionSetBB(ErrorCode::GasLimitExceeded);
    MBasicBlock *ContinueBB = createBasicBlock();
    createInstruction<BrIfInstruction>(true, Ctx, IsInvalid, TrapBB,
                                       ContinueBB);
    addUniqueSuccessor(TrapBB);
    addSuccessor(ContinueBB);
    setInsertBlock(ContinueBB);

    // Normalize Param to U256: [Selected, 0, 0, 0]
    U256Inst NewVal = {Parts[0], Zero, Zero, Zero};
    Param = Operand(NewVal, EVMType::UINT256);
  }
}

MInstruction *EVMMirBuilder::extractKnownU64LowOperand(const Operand &Opnd) {
  MType *I64Type = EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);

  if (Opnd.isEmpty()) {
    return createIntConstInstruction(I64Type, 0);
  }

  if (Opnd.isConstant()) {
    return createIntConstInstruction(I64Type, Opnd.getConstValue()[0]);
  }

  if (Opnd.getType() == EVMType::UINT64) {
    return Opnd.getInstr();
  }

  if (Opnd.isU256MultiComponent()) {
    U256Inst Instrs = Opnd.getU256Components();
    if (Instrs[0] != nullptr) {
      return Instrs[0];
    }

    U256Var Vars = Opnd.getU256VarComponents();
    if (Vars[0] != nullptr) {
      return createInstruction<DreadInstruction>(false, Vars[0]->getType(),
                                                 Vars[0]->getVarIdx());
    }
  }

  if (Opnd.getType() == EVMType::BYTES32) {
    Operand U256Op = convertBytes32ToU256Operand(Opnd);
    return extractKnownU64LowOperand(U256Op);
  }

  return extractU256Operand(Opnd)[0];
}

void EVMMirBuilder::normalizeOffsetWithSize(Operand &Offset, Operand &Size) {
  normalizeOperandU64(Size);
  if (Offset.getType() == EVMType::BYTES32) {
    Offset = convertBytes32ToU256Operand(Offset);
  }
  if (Offset.getType() != EVMType::UINT256) {
    return;
  }

  U256Inst SizeParts = extractU256Operand(Size);
  U256Inst OffsetParts = extractU256Operand(Offset);

  MType *I64Type = EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);
  MInstruction *Zero = createIntConstInstruction(I64Type, 0);

  MInstruction *IsSizeZero = createInstruction<CmpInstruction>(
      false, CmpInstruction::Predicate::ICMP_EQ, &Ctx.I64Type, SizeParts[0],
      Zero);

  MInstruction *IsZero1 = createInstruction<CmpInstruction>(
      false, CmpInstruction::Predicate::ICMP_EQ, &Ctx.I64Type, OffsetParts[1],
      Zero);
  MInstruction *IsZero2 = createInstruction<CmpInstruction>(
      false, CmpInstruction::Predicate::ICMP_EQ, &Ctx.I64Type, OffsetParts[2],
      Zero);
  MInstruction *IsZero3 = createInstruction<CmpInstruction>(
      false, CmpInstruction::Predicate::ICMP_EQ, &Ctx.I64Type, OffsetParts[3],
      Zero);

  MInstruction *Cond12 = createInstruction<BinaryInstruction>(
      false, OP_and, I64Type, IsZero1, IsZero2);
  MInstruction *IsOffsetU64 = createInstruction<BinaryInstruction>(
      false, OP_and, I64Type, Cond12, IsZero3);

  MInstruction *IsOffsetInvalid = createInstruction<CmpInstruction>(
      false, CmpInstruction::Predicate::ICMP_EQ, &Ctx.I64Type, IsOffsetU64,
      Zero);
  MInstruction *IsSizeNonZero = createInstruction<CmpInstruction>(
      false, CmpInstruction::Predicate::ICMP_EQ, &Ctx.I64Type, IsSizeZero,
      Zero);
  MInstruction *ShouldTrap = createInstruction<BinaryInstruction>(
      false, OP_and, I64Type, IsSizeNonZero, IsOffsetInvalid);

  MBasicBlock *TrapBB = getOrCreateExceptionSetBB(ErrorCode::GasLimitExceeded);
  MBasicBlock *ContinueBB = createBasicBlock();
  createInstruction<BrIfInstruction>(true, Ctx, ShouldTrap, TrapBB, ContinueBB);
  addUniqueSuccessor(TrapBB);
  addSuccessor(ContinueBB);
  setInsertBlock(ContinueBB);

  MInstruction *SelectedLow = createInstruction<SelectInstruction>(
      false, I64Type, IsSizeZero, Zero, OffsetParts[0]);
  U256Inst NewVal = {SelectedLow, Zero, Zero, Zero};
  Offset = Operand(NewVal, EVMType::UINT256);
}

// Template function for no-argument runtime calls
template <typename RetType>
typename EVMMirBuilder::Operand
EVMMirBuilder::callRuntimeFor(RetType (*RuntimeFunc)(runtime::EVMInstance *)) {
  MType *I64Type = EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);

  uint64_t FuncAddr = getFunctionAddress(RuntimeFunc);
  MInstruction *FuncAddrInst = createIntConstInstruction(I64Type, FuncAddr);
  MInstruction *InstancePtr = getCurrentInstancePointer();

  MType *ReturnType = getMIRReturnType<RetType>();
  const bool IsStmt = std::is_same_v<RetType, void>;
  MInstruction *CallInstr = createInstruction<ICallInstruction>(
      IsStmt, ReturnType, FuncAddrInst,
      llvm::ArrayRef<MInstruction *>(InstancePtr));

  return convertCallResult<RetType>(CallInstr);
}

// Template helper function to handle uintN_t type conversion (N*64 bits)
// example: Support multiple sources for U256 argument:
// - BYTES32 pointer -> load 32 bytes and split into 4xI64
// - Multi-component U256 -> pass components directly
// - Constant U256 -> materialize constants
// - Single-instr U256 -> split via shifts/truncs
template <size_t N>
EVMMirBuilder::U256Inst
EVMMirBuilder::convertOperandToUNInstruction(const Operand &Param) {
  ZEN_STATIC_ASSERT(1 <= N && N <= EVM_ELEMENTS_COUNT);

  U256Inst Result = {};
  MType *I64Type = EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);

  if (Param.isEmpty()) {
    for (size_t I = 0; I < N; ++I) {
      Result[I] = createIntConstInstruction(I64Type, 0);
    }
  } else if (Param.getType() == EVMType::BYTES32) {
    auto U256Op = convertBytes32ToU256Operand(Param);
    auto Components = U256Op.getU256Components();
    for (size_t I = 0; I < N; ++I) {
      Result[I] = Components[I];
    }
  } else if (Param.isDeferredValue()) {
    auto Components = extractU256Operand(Param);
    for (size_t I = 0; I < N; ++I) {
      Result[I] = Components[I];
    }
  } else if (Param.isU256MultiComponent()) {
    auto Components = Param.getU256Components();
    if (Components[0] != nullptr) {
      for (size_t I = 0; I < N; ++I) {
        Result[I] = Components[I];
      }
    } else {
      auto Vars = Param.getU256VarComponents();
      for (size_t I = 0; I < N; ++I) {
        ZEN_ASSERT(Vars[I] != nullptr);
        Result[I] = createInstruction<DreadInstruction>(
            false, Vars[I]->getType(), Vars[I]->getVarIdx());
      }
    }
  } else if (Param.isConstant()) {
    const U256Value &U256Value = Param.getConstValue();
    for (size_t I = 0; I < N; ++I) {
      Result[I] = createIntConstInstruction(I64Type, U256Value[I]);
    }
  } else if (auto *Instr = Param.getInstr()) {
    auto U256Op = convertU256InstrToU256Operand(Instr);
    auto Components = U256Op.getU256Components();
    for (size_t I = 0; I < N; ++I) {
      Result[I] = Components[I];
    }
  } else {
    ZEN_ASSERT(false && "Unsupported operand for uintN conversion");
  }

  // Initialize high components to zero for types smaller than U256
  for (size_t I = N; I < EVM_ELEMENTS_COUNT; ++I) {
    Result[I] = createIntConstInstruction(I64Type, 0);
  }

  return Result;
}

// Template function for single-argument runtime calls
template <typename ArgType>
EVMMirBuilder::U256Inst
EVMMirBuilder::convertOperandToInstruction(const Operand &Param) {
  EVMMirBuilder::U256Inst Result = {};

  using CleanArgT = std::remove_cv_t<std::remove_reference_t<ArgType>>;

  if constexpr (std::is_same_v<CleanArgT, int64_t> ||
                std::is_same_v<CleanArgT, uint64_t>) {
    Result = convertOperandToUNInstruction<1>(Param); // 64 = 1 * 64
  } else if constexpr (std::is_same_v<CleanArgT, const uint8_t *>) {
    Result[0] = Param.getInstr();
  } else if constexpr (std::is_same_v<CleanArgT, intx::uint128>) {
    Result = convertOperandToUNInstruction<2>(Param); // 128 = 2 * 64
  } else if constexpr (std::is_same_v<CleanArgT, intx::uint256>) {
    Result = convertOperandToUNInstruction<4>(Param); // 256 = 4 * 64
  } else {
    ZEN_ASSERT(false &&
               "Unsupported argument type in convertOperandToInstruction");
  }

  return Result;
}

MInstruction *EVMMirBuilder::packU256Argument(const Operand &Param,
                                              std::size_t ScratchSlot) {
  ZEN_ASSERT(ScratchSlot < zen::runtime::EVMInstance::HostArgScratchSlots);

  auto Components = convertOperandToInstruction<intx::uint256>(Param);
  MType *I64Type = EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);

  const int32_t BaseOffset =
      zen::runtime::EVMInstance::getHostArgScratchOffset() +
      static_cast<int32_t>(
          ScratchSlot * zen::runtime::EVMInstance::getHostArgScratchSlotSize());

  for (std::size_t Index = 0; Index < EVM_ELEMENTS_COUNT; ++Index) {
    MInstruction *Component = Components[Index];
    if (Component == nullptr) {
      Component = createIntConstInstruction(I64Type, 0);
    } else if (auto *ConstInstr =
                   llvm::dyn_cast<ConstantInstruction>(Component)) {
      // Re-materialize constants near the store to avoid long live ranges that
      // cause the register allocator to spill them. Stale stack slots produce
      // garbage on reload (root cause of issue #487).
      auto *IntConst = llvm::cast<MConstantInt>(&ConstInstr->getConstant());
      Component = createIntConstInstruction(
          I64Type, IntConst->getValue().getZExtValue());
    }

    const int32_t Offset =
        BaseOffset + static_cast<int32_t>(Index * sizeof(uint64_t));
    setInstanceElement(I64Type, Component, Offset);
  }

  MInstruction *OffsetValue = createIntConstInstruction(I64Type, BaseOffset);
  MInstruction *ScratchAddrInt = createInstruction<BinaryInstruction>(
      false, OP_add, I64Type, InstanceAddr, OffsetValue);

  return createInstruction<ConversionInstruction>(
      false, OP_inttoptr, createVoidPtrType(), ScratchAddrInt);
}

template <typename ArgType>
void EVMMirBuilder::appendRuntimeArg(std::vector<MInstruction *> &Args,
                                     const Operand &Param,
                                     std::size_t &ScratchCursor) {
  using BaseT = std::remove_cv_t<std::remove_reference_t<ArgType>>;

  if constexpr (std::is_same_v<BaseT, intx::uint256>) {
    ZEN_ASSERT(ScratchCursor < zen::runtime::EVMInstance::HostArgScratchSlots);
    MInstruction *Ptr = packU256Argument(Param, ScratchCursor);
    ++ScratchCursor;
    Args.push_back(Ptr);
  } else if constexpr (std::is_pointer_v<BaseT>) {
    bool NeedsScratch = Param.isConstant() || Param.isU256MultiComponent() ||
                        Param.getInstr() == nullptr;

    if (!NeedsScratch) {
      switch (Param.getType()) {
      case EVMType::UINT256:
      case EVMType::BYTES32:
      case EVMType::ADDRESS:
        NeedsScratch = true;
        break;
      default:
        break;
      }
    }

    if (NeedsScratch) {
      ZEN_ASSERT(ScratchCursor <
                 zen::runtime::EVMInstance::HostArgScratchSlots);
      MInstruction *Ptr = packU256Argument(Param, ScratchCursor);
      ++ScratchCursor;
      Args.push_back(Ptr);
    } else {
      Args.push_back(Param.getInstr());
    }
  } else {
    auto Insts = convertOperandToInstruction<ArgType>(Param);
    constexpr size_t WORD_BYTES = sizeof(uint64_t);
    constexpr size_t REQUIRED_WORDS =
        (sizeof(BaseT) + WORD_BYTES - 1) / WORD_BYTES;
    constexpr size_t NORMALIZED_WORDS =
        REQUIRED_WORDS == 0 ? size_t{1} : REQUIRED_WORDS;
    constexpr size_t MAX_WORDS = NORMALIZED_WORDS > EVM_ELEMENTS_COUNT
                                     ? EVM_ELEMENTS_COUNT
                                     : NORMALIZED_WORDS;

    for (size_t Index = 0; Index < MAX_WORDS; ++Index) {
      if (Insts[Index] != nullptr) {
        Args.push_back(Insts[Index]);
      }
    }
  }
}

template <typename RetType, typename... ArgTypes, typename... ParamTypes>
EVMMirBuilder::Operand EVMMirBuilder::callRuntimeFor(
    RetType (*RuntimeFunc)(runtime::EVMInstance *, ArgTypes...),
    const ParamTypes &...Params) {
  MType *I64Type = EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);
  uint64_t FuncAddr = getFunctionAddress(RuntimeFunc);
  MInstruction *FuncAddrInst = createIntConstInstruction(I64Type, FuncAddr);
  MInstruction *InstancePtr = getCurrentInstancePointer();

  std::vector<MInstruction *> Args = {InstancePtr};

  auto ParamsTuple = std::forward_as_tuple(Params...);
  std::size_t ScratchCursor = 0;

  auto PushOne = [this, &Args, &ParamsTuple, &ScratchCursor](auto IndexTag) {
    constexpr std::size_t I = decltype(IndexTag)::value;
    using ArgT = typename std::tuple_element<I, std::tuple<ArgTypes...>>::type;
    this->appendRuntimeArg<ArgT>(Args, std::get<I>(ParamsTuple), ScratchCursor);
  };

  auto PushAll = [&](auto Self, auto IndexTag) -> void {
    constexpr std::size_t I = decltype(IndexTag)::value;
    if constexpr (I < sizeof...(ArgTypes)) {
      PushOne(IndexTag);
      Self(Self, std::integral_constant<std::size_t, I + 1>{});
    }
  };

  PushAll(PushAll, std::integral_constant<std::size_t, 0>{});

  MType *ReturnType = getMIRReturnType<RetType>();
  const bool IsStmt = std::is_same_v<RetType, void>;
  MInstruction *CallInstr = createInstruction<ICallInstruction>(
      IsStmt, ReturnType, FuncAddrInst, llvm::ArrayRef<MInstruction *>{Args});

  return convertCallResult<RetType>(CallInstr);
}

MInstruction *EVMMirBuilder::getCurrentInstancePointer() {
  ZEN_ASSERT(InstanceAddr);
  // Convert instance address back to pointer type
  return createInstruction<ConversionInstruction>(
      false, OP_inttoptr, createVoidPtrType(), InstanceAddr);
}

void EVMMirBuilder::handleCallDataCopy(Operand DestOffsetComponents,
                                       Operand OffsetComponents,
                                       Operand SizeComponents) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  uint64_t Non64Value = std::numeric_limits<uint64_t>::max();
  normalizeOperandU64(DestOffsetComponents, &Non64Value);
  normalizeOperandU64(OffsetComponents, &Non64Value);
  normalizeOperandU64(SizeComponents, &Non64Value);
#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
  syncGasToMemory();
#endif
  callRuntimeFor<void, uint64_t, uint64_t, uint64_t>(
      RuntimeFunctions.SetCallDataCopy, DestOffsetComponents, OffsetComponents,
      SizeComponents);
#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
  reloadGasFromMemory();
#endif
  reloadMemorySizeFromInstance();
}

void EVMMirBuilder::handleExtCodeCopy(Operand AddressComponents,
                                      Operand DestOffsetComponents,
                                      Operand OffsetComponents,
                                      Operand SizeComponents) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  // Use max uint64_t value if the offset/size is not 64-bit, because the
  // extcodecopy will fill zeros when offset is beyond code size or handle large
  // size properly.
  uint64_t Non64Value = std::numeric_limits<uint64_t>::max();
  normalizeOperandU64(DestOffsetComponents, &Non64Value);
  normalizeOperandU64(OffsetComponents, &Non64Value);
  normalizeOperandU64(SizeComponents, &Non64Value);
#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
  syncGasToMemory();
#endif
  callRuntimeFor<void, const uint8_t *, uint64_t, uint64_t, uint64_t>(
      RuntimeFunctions.SetExtCodeCopy, AddressComponents, DestOffsetComponents,
      OffsetComponents, SizeComponents);
#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
  reloadGasFromMemory();
#endif
  reloadMemorySizeFromInstance();
}

void EVMMirBuilder::handleReturnDataCopy(Operand DestOffsetComponents,
                                         Operand OffsetComponents,
                                         Operand SizeComponents) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  // Use max uint64_t value if the offset/size is not 64-bit, because the
  // returndatacopy will trigger memory access error instead of out-of-gas
  // when offset/size is very large.
  uint64_t Non64Value = std::numeric_limits<uint64_t>::max();
  normalizeOperandU64(DestOffsetComponents, &Non64Value);
  normalizeOperandU64(OffsetComponents, &Non64Value);
  normalizeOperandU64(SizeComponents, &Non64Value);
#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
  syncGasToMemory();
#endif
  callRuntimeFor<void, uint64_t, uint64_t, uint64_t>(
      RuntimeFunctions.SetReturnDataCopy, DestOffsetComponents,
      OffsetComponents, SizeComponents);
#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
  reloadGasFromMemory();
#endif
  reloadMemorySizeFromInstance();
}

typename EVMMirBuilder::Operand EVMMirBuilder::handleReturnDataSize() {
  MInstruction *ReturnDataSize = getInstanceElement(
      &Ctx.I64Type, zen::runtime::EVMInstance::getReturnDataSizeOffset());
  ReturnDataSize = protectUnsafeValue(ReturnDataSize, &Ctx.I64Type);
  return convertSingleInstrToU256Operand(ReturnDataSize);
}

bool EVMMirBuilder::hasMemoryCompileStats() const {
  return MemStats.MLoadExpandCount != 0 || MemStats.MStoreExpandCount != 0 ||
         MemStats.MStore8ExpandCount != 0 || MemStats.MCopyExpandCount != 0 ||
         MemStats.BlockConstPrecheckCount != 0 ||
         MemStats.LinearU64AddrFastPathCount != 0 ||
         MemStats.ConstBasePtrInitCount != 0 ||
         MemStats.ConstBasePtrReuseCount != 0 ||
         MemStats.ConstDispBytes32MLoadCount != 0 ||
         MemStats.ConstDispBytes32MStoreCount != 0 ||
         MemStats.DispBytes32MLoadCount != 0 ||
         MemStats.DispBytes32MStoreCount != 0 ||
         MemStats.MStoreZeroLimbStoreCount != 0 ||
         MemStats.MStoreOverlapElidedLimbCount != 0 ||
         MemStats.ReloadMemorySizeCount != 0 ||
         MemStats.GetMemoryDataPointerCount != 0 ||
         MemStats.ExpandNeedExpandCFGCount != 0;
}

void EVMMirBuilder::noteBlockMemoryEventPC(uint64_t PC) {
#ifdef ZEN_ENABLE_MULTIPASS_JIT_LOGGING
  if (!CurBlockMemStats.Active) {
    return;
  }
  if (!CurBlockMemStats.HasMemoryEvent) {
    CurBlockMemStats.FirstMemoryEventPC = PC;
    CurBlockMemStats.HasMemoryEvent = true;
  }
  CurBlockMemStats.LastMemoryEventPC = PC;
#else
  (void)PC;
#endif // ZEN_ENABLE_MULTIPASS_JIT_LOGGING
}

bool EVMMirBuilder::hasCurrentMemoryBlockStats() const {
#ifdef ZEN_ENABLE_MULTIPASS_JIT_LOGGING
  return CurBlockMemStats.Active && CurBlockMemStats.HasMemoryEvent;
#else
  return false;
#endif // ZEN_ENABLE_MULTIPASS_JIT_LOGGING
}

void EVMMirBuilder::dumpMemoryCompileStats() const {
  if (!hasMemoryCompileStats()) {
    return;
  }

#ifdef ZEN_ENABLE_MULTIPASS_JIT_LOGGING
  ZEN_LOG_DEBUG(
      "[EVM-MEM-SUMMARY] mload_expand=%llu mstore_expand=%llu "
      "mstore8_expand=%llu mcopy_expand=%llu block_const_precheck=%llu "
      "block_linear_precheck=%llu prechecked_mload_ops=%llu "
      "prechecked_mstore_ops=%llu reload_mem_size=%llu get_mem_ptr=%llu "
      "mem_base_instance_loads=%llu mem_base_cache_uses=%llu "
      "linear_u64_addr_fast_ops=%llu linear_u64_mload_fast_ops=%llu "
      "linear_u64_mstore_fast_ops=%llu "
      "const_base_ptr_inits=%llu const_base_ptr_reuses=%llu "
      "const_disp_bytes32_mload_ops=%llu const_disp_bytes32_mstore_ops=%llu "
      "disp_bytes32_mload_ops=%llu disp_bytes32_mstore_ops=%llu "
      "mstore_zero_limb_stores=%llu mstore_overlap_elided_limbs=%llu "
      "mstore_addr_value_alias_reuse=%llu "
      "need_expand_cfg=%llu",
      static_cast<unsigned long long>(MemStats.MLoadExpandCount),
      static_cast<unsigned long long>(MemStats.MStoreExpandCount),
      static_cast<unsigned long long>(MemStats.MStore8ExpandCount),
      static_cast<unsigned long long>(MemStats.MCopyExpandCount),
      static_cast<unsigned long long>(MemStats.BlockConstPrecheckCount),
      static_cast<unsigned long long>(MemStats.BlockLinearPrecheckCount),
      static_cast<unsigned long long>(MemStats.PrecheckedMLoadOpCount),
      static_cast<unsigned long long>(MemStats.PrecheckedMStoreOpCount),
      static_cast<unsigned long long>(MemStats.ReloadMemorySizeCount),
      static_cast<unsigned long long>(MemStats.GetMemoryDataPointerCount),
      static_cast<unsigned long long>(MemStats.MemoryBaseInstanceLoadCount),
      static_cast<unsigned long long>(MemStats.MemoryBaseCacheUseCount),
      static_cast<unsigned long long>(MemStats.LinearU64AddrFastPathCount),
      static_cast<unsigned long long>(MemStats.LinearU64MLoadFastPathCount),
      static_cast<unsigned long long>(MemStats.LinearU64MStoreFastPathCount),
      static_cast<unsigned long long>(MemStats.ConstBasePtrInitCount),
      static_cast<unsigned long long>(MemStats.ConstBasePtrReuseCount),
      static_cast<unsigned long long>(MemStats.ConstDispBytes32MLoadCount),
      static_cast<unsigned long long>(MemStats.ConstDispBytes32MStoreCount),
      static_cast<unsigned long long>(MemStats.DispBytes32MLoadCount),
      static_cast<unsigned long long>(MemStats.DispBytes32MStoreCount),
      static_cast<unsigned long long>(MemStats.MStoreZeroLimbStoreCount),
      static_cast<unsigned long long>(MemStats.MStoreOverlapElidedLimbCount),
      static_cast<unsigned long long>(MemStats.MStoreAddrValueAliasReuseCount),
      static_cast<unsigned long long>(MemStats.ExpandNeedExpandCFGCount));
#endif // ZEN_ENABLE_MULTIPASS_JIT_LOGGING
}

void EVMMirBuilder::beginMemoryCompileBlock(uint64_t EntryPC) {
  CurBlockMemStats = MemoryBlockCompileStats();
  CurBlockConstPrecheckPlan = MemoryBlockConstPrecheckPlan();
  CurBlockLinearPrecheckPlan = MemoryBlockLinearPrecheckPlan();
  CurBlockMemStats.Active = true;
#ifdef ZEN_ENABLE_MULTIPASS_JIT_LOGGING
  CurBlockMemStats.BlockSeqId = ++NextMemoryBlockSeqId;
  CurBlockMemStats.BlockEntryPC = EntryPC;
#else
  (void)EntryPC;
#endif // ZEN_ENABLE_MULTIPASS_JIT_LOGGING
}

void EVMMirBuilder::setMemoryCompileBlockConstPrecheckPlan(
    uint64_t MaxRequiredSize, uint64_t CoveredDirectOps) {
  if (!CurBlockMemStats.Active || CoveredDirectOps < 2) {
    return;
  }
  CurBlockConstPrecheckPlan = MemoryBlockConstPrecheckPlan();
  CurBlockConstPrecheckPlan.Active = true;
  CurBlockConstPrecheckPlan.MaxRequiredSize = MaxRequiredSize;
  CurBlockConstPrecheckPlan.CoveredDirectOpsTotal = CoveredDirectOps;
  CurBlockConstPrecheckPlan.CoveredDirectOpsRemaining = CoveredDirectOps;
}

void EVMMirBuilder::setMemoryCompileBlockLinearPrecheckPlan(
    uint64_t AccessWidth, uint64_t CoveredDirectOps,
    bool ValueEqualsFirstAddr) {
  if (!CurBlockMemStats.Active || CoveredDirectOps < 2) {
    return;
  }
  CurBlockLinearPrecheckPlan = MemoryBlockLinearPrecheckPlan();
  CurBlockLinearPrecheckPlan.Active = true;
  CurBlockLinearPrecheckPlan.ValueEqualsFirstAddr = ValueEqualsFirstAddr;
  CurBlockLinearPrecheckPlan.AccessWidth = AccessWidth;
  CurBlockLinearPrecheckPlan.CoveredDirectOpsTotal = CoveredDirectOps;
  CurBlockLinearPrecheckPlan.CoveredDirectOpsRemaining = CoveredDirectOps;
}

void EVMMirBuilder::prepareLinearBlockMemoryPrecheck(Operand StrideComponents) {
  if (!CurBlockLinearPrecheckPlan.Active ||
      CurBlockLinearPrecheckPlan.Emitted) {
    return;
  }
  CurBlockLinearPrecheckPlan.PendingStrideComponents = StrideComponents;
  CurBlockLinearPrecheckPlan.HasPendingStride = true;
}

void EVMMirBuilder::noteMemoryOpcodeInBlock(evmc_opcode Opcode, uint64_t PC) {
  if (!CurBlockMemStats.Active) {
    return;
  }

#ifdef ZEN_ENABLE_MULTIPASS_JIT_LOGGING
  noteBlockMemoryEventPC(PC);
  CurBlockMemStats.DirectMemoryOpCount++;
  switch (Opcode) {
  case OP_MLOAD:
    CurBlockMemStats.MLoadCount++;
    break;
  case OP_MSTORE:
    CurBlockMemStats.MStoreCount++;
    break;
  case OP_MSTORE8:
    CurBlockMemStats.MStore8Count++;
    break;
  case OP_MSIZE:
    CurBlockMemStats.MSizeCount++;
    break;
  case OP_MCOPY:
    CurBlockMemStats.MCopyCount++;
    break;
  default:
    break;
  }
#else
  (void)Opcode;
  (void)PC;
#endif // ZEN_ENABLE_MULTIPASS_JIT_LOGGING
}

void EVMMirBuilder::noteHelperOpcodeInBlock(evmc_opcode Opcode, uint64_t PC) {
  if (!CurBlockMemStats.Active) {
    return;
  }

#ifdef ZEN_ENABLE_MULTIPASS_JIT_LOGGING
  noteBlockMemoryEventPC(PC);
  CurBlockMemStats.HelperSensitiveOpCount++;
  CurBlockMemStats.HasHelperBarrier = true;
  CurBlockMemStats.DirectMemoryOnlyCandidate = false;
  switch (Opcode) {
  case OP_LOG0:
  case OP_LOG1:
  case OP_LOG2:
  case OP_LOG3:
  case OP_LOG4:
    CurBlockMemStats.LogCount++;
    break;
  case OP_KECCAK256:
    CurBlockMemStats.KeccakCount++;
    break;
  case OP_CALLDATACOPY:
  case OP_CODECOPY:
  case OP_EXTCODECOPY:
  case OP_RETURNDATACOPY:
    CurBlockMemStats.CopyFamilyCount++;
    break;
  case OP_CALL:
  case OP_CALLCODE:
  case OP_DELEGATECALL:
  case OP_STATICCALL:
    CurBlockMemStats.CallFamilyCount++;
    break;
  case OP_CREATE:
  case OP_CREATE2:
    CurBlockMemStats.CreateFamilyCount++;
    break;
  default:
    break;
  }
#else
  (void)Opcode;
  (void)PC;
#endif // ZEN_ENABLE_MULTIPASS_JIT_LOGGING
}

void EVMMirBuilder::endMemoryCompileBlock() {
#ifdef ZEN_ENABLE_MULTIPASS_JIT_LOGGING
  if (!hasCurrentMemoryBlockStats()) {
    CurBlockMemStats.Active = false;
    CurBlockConstPrecheckPlan = MemoryBlockConstPrecheckPlan();
    CurBlockLinearPrecheckPlan = MemoryBlockLinearPrecheckPlan();
    return;
  }

  ZEN_LOG_DEBUG(
      "[EVM-MEM-BLOCK] seq=%llu entry_pc=%llu first_mem_pc=%llu "
      "last_mem_pc=%llu direct_ops=%llu mload=%llu mstore=%llu "
      "mstore8=%llu msize=%llu mcopy=%llu helper_ops=%llu "
      "helper_barrier=%d log=%llu keccak=%llu copy=%llu call=%llu "
      "create=%llu expand_calls=%llu need_expand_cfg=%llu "
      "get_mem_ptr=%llu mem_base_instance_loads=%llu "
      "mem_base_cache_uses=%llu reload_mem_size=%llu "
      "block_const_precheck=%llu block_linear_precheck=%llu "
      "prechecked_direct_ops=%llu prechecked_mload_ops=%llu "
      "prechecked_mstore_ops=%llu linear_u64_addr_fast_ops=%llu "
      "linear_u64_mload_fast_ops=%llu linear_u64_mstore_fast_ops=%llu "
      "const_base_ptr_inits=%llu const_base_ptr_reuses=%llu "
      "const_disp_bytes32_mload_ops=%llu const_disp_bytes32_mstore_ops=%llu "
      "disp_bytes32_mload_ops=%llu disp_bytes32_mstore_ops=%llu "
      "mstore_zero_limb_stores=%llu mstore_overlap_elided_limbs=%llu "
      "mstore_addr_value_alias_reuse=%llu "
      "direct_only_candidate=%d",
      static_cast<unsigned long long>(CurBlockMemStats.BlockSeqId),
      static_cast<unsigned long long>(CurBlockMemStats.BlockEntryPC),
      static_cast<unsigned long long>(CurBlockMemStats.FirstMemoryEventPC),
      static_cast<unsigned long long>(CurBlockMemStats.LastMemoryEventPC),
      static_cast<unsigned long long>(CurBlockMemStats.DirectMemoryOpCount),
      static_cast<unsigned long long>(CurBlockMemStats.MLoadCount),
      static_cast<unsigned long long>(CurBlockMemStats.MStoreCount),
      static_cast<unsigned long long>(CurBlockMemStats.MStore8Count),
      static_cast<unsigned long long>(CurBlockMemStats.MSizeCount),
      static_cast<unsigned long long>(CurBlockMemStats.MCopyCount),
      static_cast<unsigned long long>(CurBlockMemStats.HelperSensitiveOpCount),
      CurBlockMemStats.HasHelperBarrier ? 1 : 0,
      static_cast<unsigned long long>(CurBlockMemStats.LogCount),
      static_cast<unsigned long long>(CurBlockMemStats.KeccakCount),
      static_cast<unsigned long long>(CurBlockMemStats.CopyFamilyCount),
      static_cast<unsigned long long>(CurBlockMemStats.CallFamilyCount),
      static_cast<unsigned long long>(CurBlockMemStats.CreateFamilyCount),
      static_cast<unsigned long long>(CurBlockMemStats.ExpandCallCount),
      static_cast<unsigned long long>(CurBlockMemStats.NeedExpandCFGCount),
      static_cast<unsigned long long>(CurBlockMemStats.GetMemPtrCount),
      static_cast<unsigned long long>(
          CurBlockMemStats.MemoryBaseInstanceLoadCount),
      static_cast<unsigned long long>(CurBlockMemStats.MemoryBaseCacheUseCount),
      static_cast<unsigned long long>(CurBlockMemStats.ReloadMemSizeCount),
      static_cast<unsigned long long>(CurBlockMemStats.BlockConstPrecheckCount),
      static_cast<unsigned long long>(
          CurBlockMemStats.BlockLinearPrecheckCount),
      static_cast<unsigned long long>(CurBlockMemStats.PrecheckedDirectOpCount),
      static_cast<unsigned long long>(CurBlockMemStats.PrecheckedMLoadOpCount),
      static_cast<unsigned long long>(CurBlockMemStats.PrecheckedMStoreOpCount),
      static_cast<unsigned long long>(
          CurBlockMemStats.LinearU64AddrFastPathCount),
      static_cast<unsigned long long>(
          CurBlockMemStats.LinearU64MLoadFastPathCount),
      static_cast<unsigned long long>(
          CurBlockMemStats.LinearU64MStoreFastPathCount),
      static_cast<unsigned long long>(CurBlockMemStats.ConstBasePtrInitCount),
      static_cast<unsigned long long>(CurBlockMemStats.ConstBasePtrReuseCount),
      static_cast<unsigned long long>(
          CurBlockMemStats.ConstDispBytes32MLoadCount),
      static_cast<unsigned long long>(
          CurBlockMemStats.ConstDispBytes32MStoreCount),
      static_cast<unsigned long long>(CurBlockMemStats.DispBytes32MLoadCount),
      static_cast<unsigned long long>(CurBlockMemStats.DispBytes32MStoreCount),
      static_cast<unsigned long long>(
          CurBlockMemStats.MStoreZeroLimbStoreCount),
      static_cast<unsigned long long>(
          CurBlockMemStats.MStoreOverlapElidedLimbCount),
      static_cast<unsigned long long>(
          CurBlockMemStats.MStoreAddrValueAliasReuseCount),
      CurBlockMemStats.DirectMemoryOnlyCandidate ? 1 : 0);
#endif // ZEN_ENABLE_MULTIPASS_JIT_LOGGING

  CurBlockMemStats.Active = false;
  CurBlockConstPrecheckPlan = MemoryBlockConstPrecheckPlan();
  CurBlockLinearPrecheckPlan = MemoryBlockLinearPrecheckPlan();
}

bool EVMMirBuilder::tryConsumeConstBlockMemoryPrecheck() {
  if (!CurBlockConstPrecheckPlan.Active ||
      CurBlockConstPrecheckPlan.CoveredDirectOpsRemaining == 0) {
    return false;
  }

  if (!CurBlockConstPrecheckPlan.Emitted) {
    MType *I64Type = &Ctx.I64Type;
    MInstruction *RequiredSize = createIntConstInstruction(
        I64Type, CurBlockConstPrecheckPlan.MaxRequiredSize);
    MInstruction *NoOverflow = createIntConstInstruction(I64Type, 0);
    expandMemoryIR(RequiredSize, NoOverflow);
    CurBlockConstPrecheckPlan.Emitted = true;

#ifdef ZEN_ENABLE_MULTIPASS_JIT_LOGGING
    ++MemStats.BlockConstPrecheckCount;
    if (CurBlockMemStats.Active) {
      CurBlockMemStats.BlockConstPrecheckCount++;
      CurBlockMemStats.PrecheckedDirectOpCount =
          CurBlockConstPrecheckPlan.CoveredDirectOpsTotal;
      CurBlockMemStats.ExpandCallCount++;
    }
#endif // ZEN_ENABLE_MULTIPASS_JIT_LOGGING
  }

  CurBlockConstPrecheckPlan.CoveredDirectOpsRemaining--;
  if (CurBlockConstPrecheckPlan.CoveredDirectOpsRemaining == 0) {
    CurBlockConstPrecheckPlan.Active = false;
  }
  return true;
}

MInstruction *EVMMirBuilder::getConstBlockDirectMemoryBasePtr() {
  ZEN_ASSERT(CurBlockConstPrecheckPlan.Emitted &&
             "const block base pointer requires emitted precheck");

  if (CurBlockConstPrecheckPlan.HasAnchoredBasePtr &&
      CurBlockConstPrecheckPlan.AnchoredBasePtrVar != nullptr) {
#ifdef ZEN_ENABLE_MULTIPASS_JIT_LOGGING
    ++MemStats.ConstBasePtrReuseCount;
    if (CurBlockMemStats.Active) {
      ++CurBlockMemStats.ConstBasePtrReuseCount;
    }
#endif // ZEN_ENABLE_MULTIPASS_JIT_LOGGING
    return loadVariable(CurBlockConstPrecheckPlan.AnchoredBasePtrVar);
  }

  MInstruction *MemBase = getDirectMemoryDataPointer(true);
  MInstruction *BasePtr = createInstruction<ConversionInstruction>(
      false, OP_inttoptr, createVoidPtrType(), MemBase);
  BasePtr = anchorDirectMemoryPointer(BasePtr);
  Variable *BasePtrVar = storeInstructionInTemp(BasePtr, BasePtr->getType());
  CurBlockConstPrecheckPlan.HasAnchoredBasePtr = true;
  CurBlockConstPrecheckPlan.AnchoredBasePtrVar = BasePtrVar;

#ifdef ZEN_ENABLE_MULTIPASS_JIT_LOGGING
  ++MemStats.ConstBasePtrInitCount;
  if (CurBlockMemStats.Active) {
    ++CurBlockMemStats.ConstBasePtrInitCount;
  }
#endif // ZEN_ENABLE_MULTIPASS_JIT_LOGGING

  return loadVariable(BasePtrVar);
}

bool EVMMirBuilder::tryConsumeLinearBlockMemoryPrecheck(
    MInstruction *FirstAddr, MInstruction *OrderingDep) {
  if (!CurBlockLinearPrecheckPlan.Active ||
      CurBlockLinearPrecheckPlan.CoveredDirectOpsRemaining == 0) {
    return false;
  }

  if (!CurBlockLinearPrecheckPlan.Emitted) {
    if (!CurBlockLinearPrecheckPlan.HasPendingStride) {
      return false;
    }

    Operand StrideComponents =
        CurBlockLinearPrecheckPlan.PendingStrideComponents;
    normalizeOperandU64(StrideComponents);

    MType *I64Type = &Ctx.I64Type;
    U256Inst StrideParts = extractU256Operand(StrideComponents);
    MInstruction *Stride = StrideParts[0];
    MInstruction *LastAddr = FirstAddr;
    MInstruction *Overflow = createIntConstInstruction(I64Type, 0);

    const uint64_t LastIndex =
        CurBlockLinearPrecheckPlan.CoveredDirectOpsTotal - 1;
    if (LastIndex != 0) {
      MInstruction *LastIndexConst =
          createIntConstInstruction(I64Type, LastIndex);
      MInstruction *MaxStride =
          createIntConstInstruction(I64Type, UINT64_MAX / LastIndex);
      MInstruction *MulOverflow = createInstruction<CmpInstruction>(
          false, CmpInstruction::Predicate::ICMP_UGT, I64Type, Stride,
          MaxStride);
      MInstruction *StrideDelta = createInstruction<BinaryInstruction>(
          false, OP_mul, I64Type, Stride, LastIndexConst);
      LastAddr = createInstruction<BinaryInstruction>(false, OP_add, I64Type,
                                                      FirstAddr, StrideDelta);
      MInstruction *AddrOverflow = createInstruction<CmpInstruction>(
          false, CmpInstruction::Predicate::ICMP_ULT, I64Type, LastAddr,
          FirstAddr);
      Overflow = createInstruction<BinaryInstruction>(
          false, OP_or, I64Type, MulOverflow, AddrOverflow);
    }

    MInstruction *AccessWidth = createIntConstInstruction(
        I64Type, CurBlockLinearPrecheckPlan.AccessWidth);
    MInstruction *RequiredSize = createInstruction<BinaryInstruction>(
        false, OP_add, I64Type, LastAddr, AccessWidth);
    MInstruction *SizeOverflow = createInstruction<CmpInstruction>(
        false, CmpInstruction::Predicate::ICMP_ULT, I64Type, RequiredSize,
        LastAddr);
    Overflow = createInstruction<BinaryInstruction>(false, OP_or, I64Type,
                                                    Overflow, SizeOverflow);
    if (OrderingDep != nullptr) {
      RequiredSize = createInstruction<BinaryInstruction>(
          false, OP_add, I64Type, RequiredSize, OrderingDep);
    }

    expandMemoryIR(RequiredSize, Overflow);
    CurBlockLinearPrecheckPlan.Emitted = true;
    CurBlockLinearPrecheckPlan.HasPendingStride = false;

#ifdef ZEN_ENABLE_MULTIPASS_JIT_LOGGING
    ++MemStats.BlockLinearPrecheckCount;
    if (CurBlockMemStats.Active) {
      CurBlockMemStats.BlockLinearPrecheckCount++;
      CurBlockMemStats.PrecheckedDirectOpCount =
          CurBlockLinearPrecheckPlan.CoveredDirectOpsTotal;
      CurBlockMemStats.ExpandCallCount++;
    }
#endif // ZEN_ENABLE_MULTIPASS_JIT_LOGGING
  }

  CurBlockLinearPrecheckPlan.CoveredDirectOpsRemaining--;
  if (CurBlockLinearPrecheckPlan.CoveredDirectOpsRemaining == 0) {
    CurBlockLinearPrecheckPlan.Active = false;
  }
  return true;
}

// ==================== Memory Operation Helper Methods ====================

MInstruction *EVMMirBuilder::getMemoryDataPointer() {
#ifdef ZEN_ENABLE_MULTIPASS_JIT_LOGGING
  ++MemStats.GetMemoryDataPointerCount;
  ++MemStats.MemoryBaseInstanceLoadCount;
  if (CurBlockMemStats.Active) {
    CurBlockMemStats.GetMemPtrCount++;
    ++CurBlockMemStats.MemoryBaseInstanceLoadCount;
  }
#endif // ZEN_ENABLE_MULTIPASS_JIT_LOGGING
  MType *I64Type = &Ctx.I64Type;
  MPointerType *VoidPtrType = createVoidPtrType();
  const int32_t MemoryBaseOffset =
      zen::runtime::EVMInstance::getMemoryBaseOffset();
  MInstruction *MemPtr = getInstanceElement(VoidPtrType, MemoryBaseOffset);
  MInstruction *MemBaseInt = createInstruction<ConversionInstruction>(
      false, OP_ptrtoint, I64Type, MemPtr);
  if (MemoryBaseVar) {
    createInstruction<DassignInstruction>(true, &(Ctx.VoidType), MemBaseInt,
                                          MemoryBaseVar->getVarIdx());
  }
  return MemBaseInt;
}

MInstruction *EVMMirBuilder::getDirectMemoryDataPointer(bool PreferCachedBase) {
#ifdef ZEN_ENABLE_MULTIPASS_JIT_LOGGING
  ++MemStats.GetMemoryDataPointerCount;
  if (CurBlockMemStats.Active) {
    CurBlockMemStats.GetMemPtrCount++;
  }
#endif // ZEN_ENABLE_MULTIPASS_JIT_LOGGING

  if (PreferCachedBase && MemoryBaseVar) {
#ifdef ZEN_ENABLE_MULTIPASS_JIT_LOGGING
    ++MemStats.MemoryBaseCacheUseCount;
    if (CurBlockMemStats.Active) {
      ++CurBlockMemStats.MemoryBaseCacheUseCount;
    }
#endif // ZEN_ENABLE_MULTIPASS_JIT_LOGGING
    return loadVariable(MemoryBaseVar);
  }

#ifdef ZEN_ENABLE_MULTIPASS_JIT_LOGGING
  ++MemStats.MemoryBaseInstanceLoadCount;
  if (CurBlockMemStats.Active) {
    ++CurBlockMemStats.MemoryBaseInstanceLoadCount;
  }
#endif // ZEN_ENABLE_MULTIPASS_JIT_LOGGING
  MType *I64Type = &Ctx.I64Type;
  MPointerType *VoidPtrType = createVoidPtrType();
  const int32_t MemoryBaseOffset =
      zen::runtime::EVMInstance::getMemoryBaseOffset();
  MInstruction *MemPtr = getInstanceElement(VoidPtrType, MemoryBaseOffset);
  MInstruction *MemBaseInt = createInstruction<ConversionInstruction>(
      false, OP_ptrtoint, I64Type, MemPtr);
  if (MemoryBaseVar) {
    createInstruction<DassignInstruction>(true, &(Ctx.VoidType), MemBaseInt,
                                          MemoryBaseVar->getVarIdx());
  }
  return MemBaseInt;
}

MInstruction *EVMMirBuilder::getMemorySize() {
  if (MemorySizeVar) {
    return loadVariable(MemorySizeVar);
  }
  MType *I64Type = &Ctx.I64Type;
  const int32_t MemorySizeOffset =
      zen::runtime::EVMInstance::getMemorySizeOffset();
  return getInstanceElement(I64Type, MemorySizeOffset);
}

void EVMMirBuilder::reloadMemorySizeFromInstance() {
#ifdef ZEN_ENABLE_MULTIPASS_JIT_LOGGING
  ++MemStats.ReloadMemorySizeCount;
  if (CurBlockMemStats.Active) {
    CurBlockMemStats.ReloadMemSizeCount++;
  }
#endif // ZEN_ENABLE_MULTIPASS_JIT_LOGGING
  if (!MemorySizeVar) {
    return;
  }
  MType *I64Type = &Ctx.I64Type;
  const int32_t MemorySizeOffset =
      zen::runtime::EVMInstance::getMemorySizeOffset();
  MInstruction *MemSize = getInstanceElement(I64Type, MemorySizeOffset);
  createInstruction<DassignInstruction>(true, &(Ctx.VoidType), MemSize,
                                        MemorySizeVar->getVarIdx());
}

MInstruction *
EVMMirBuilder::calculateMemoryGasCostIR(MInstruction *SizeInBytes) {
  // EVM memory gas cost formula:
  // cost = (sizeInWords^2 / 512) + (3 * sizeInWords)
  // where sizeInWords = (sizeInBytes + 31) / 32

  MType *I64Type = &Ctx.I64Type;

  // Convert bytes to words: (SizeInBytes + 31) / 32
  MInstruction *Const31 = createIntConstInstruction(I64Type, 31);
  MInstruction *Shift5 = createIntConstInstruction(I64Type, 5);
  MInstruction *SizePlus31 = createInstruction<BinaryInstruction>(
      false, OP_add, I64Type, SizeInBytes, Const31);
  MInstruction *SizeInWords = createInstruction<BinaryInstruction>(
      false, OP_ushr, I64Type, SizePlus31, Shift5);

  // Calculate sizeInWords^2
  MInstruction *SizeSquared = createInstruction<BinaryInstruction>(
      false, OP_mul, I64Type, SizeInWords, SizeInWords);

  // Calculate sizeInWords^2 / 512
  MInstruction *Const512 = createIntConstInstruction(I64Type, 512);
  MInstruction *QuadraticCost = createInstruction<BinaryInstruction>(
      false, OP_udiv, I64Type, SizeSquared, Const512);

  // Calculate 3 * sizeInWords
  MInstruction *Const3 = createIntConstInstruction(I64Type, 3);
  MInstruction *LinearCost = createInstruction<BinaryInstruction>(
      false, OP_mul, I64Type, Const3, SizeInWords);

  // Total cost = QuadraticCost + LinearCost
  MInstruction *TotalCost = createInstruction<BinaryInstruction>(
      false, OP_add, I64Type, QuadraticCost, LinearCost);

  return TotalCost;
}

void EVMMirBuilder::chargeDynamicGasIR(MInstruction *GasCost) {
  MType *I64Type = &Ctx.I64Type;

#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
  if (Ctx.isGasRegisterEnabled() && GasRegVar) {
    MInstruction *CurrentGas = loadVariable(GasRegVar);

    MInstruction *IsOutOfGas = createInstruction<CmpInstruction>(
        false, CmpInstruction::Predicate::ICMP_ULT, &Ctx.I64Type, CurrentGas,
        GasCost);

    MBasicBlock *ContinueBB = createBasicBlock();
    MBasicBlock *OutOfGasBB =
        getOrCreateExceptionSetBB(ErrorCode::GasLimitExceeded);
    createInstruction<BrIfInstruction>(true, Ctx, IsOutOfGas, OutOfGasBB,
                                       ContinueBB);
    addUniqueSuccessor(OutOfGasBB);
    addSuccessor(ContinueBB);
    setInsertBlock(ContinueBB);

    MInstruction *NewGas = createInstruction<BinaryInstruction>(
        false, OP_sub, I64Type, CurrentGas, GasCost);
    createInstruction<DassignInstruction>(true, &(Ctx.VoidType), NewGas,
                                          GasRegVar->getVarIdx());

    syncGasToMemory();
    return;
  }
#endif

  MInstruction *GasOffsetValue = createIntConstInstruction(
      I64Type, zen::runtime::EVMInstance::getGasFieldOffset());
  MInstruction *GasAddrInt = createInstruction<BinaryInstruction>(
      false, OP_add, I64Type, InstanceAddr, GasOffsetValue);

  MPointerType *I64PtrType = MPointerType::create(Ctx, Ctx.I64Type);
  MInstruction *GasPtr = createInstruction<ConversionInstruction>(
      false, OP_inttoptr, I64PtrType, GasAddrInt);

  // Load current gas
  MInstruction *GasValue =
      createInstruction<LoadInstruction>(false, I64Type, GasPtr);

  // Check if we have enough gas
  MInstruction *IsOutOfGas = createInstruction<CmpInstruction>(
      false, CmpInstruction::Predicate::ICMP_ULT, I64Type, GasValue, GasCost);

  // Branch on out of gas condition
  MBasicBlock *OutOfGasBB =
      getOrCreateExceptionSetBB(ErrorCode::GasLimitExceeded);
  MBasicBlock *ContinueBB = createBasicBlock();

  createInstruction<BrIfInstruction>(true, Ctx, IsOutOfGas, OutOfGasBB,
                                     ContinueBB);
  addSuccessor(OutOfGasBB);
  addSuccessor(ContinueBB);

  // Continue: subtract gas and store back
  setInsertBlock(ContinueBB);
  MInstruction *NewGas = createInstruction<BinaryInstruction>(
      false, OP_sub, I64Type, GasValue, GasCost);
  createInstruction<StoreInstruction>(true, &Ctx.VoidType, NewGas, GasPtr);

  // Also update the message gas field
  const int32_t CurrentMessageOffset =
      zen::runtime::EVMInstance::getCurrentMessagePointerOffset();
  MPointerType *VoidPtrType = createVoidPtrType();
  MInstruction *MsgPtr = getInstanceElement(VoidPtrType, CurrentMessageOffset);
  MInstruction *MsgPtrInt = createInstruction<ConversionInstruction>(
      false, OP_ptrtoint, I64Type, MsgPtr);
  MInstruction *Zero = createIntConstInstruction(I64Type, 0);
  MInstruction *HasMsg = createInstruction<CmpInstruction>(
      false, CmpInstruction::Predicate::ICMP_NE, I64Type, MsgPtrInt, Zero);
  MBasicBlock *MsgStoreBB = createBasicBlock();
  MBasicBlock *MsgSkipBB = createBasicBlock();
  createInstruction<BrIfInstruction>(true, Ctx, HasMsg, MsgStoreBB, MsgSkipBB);
  addSuccessor(MsgStoreBB);
  addSuccessor(MsgSkipBB);

  setInsertBlock(MsgStoreBB);
  const int32_t MsgGasOffset = zen::runtime::EVMInstance::getMessageGasOffset();
  MInstruction *MsgGasOffsetVal =
      createIntConstInstruction(I64Type, MsgGasOffset);
  MInstruction *MsgGasAddrInt = createInstruction<BinaryInstruction>(
      false, OP_add, I64Type, MsgPtrInt, MsgGasOffsetVal);
  MInstruction *MsgGasPtr = createInstruction<ConversionInstruction>(
      false, OP_inttoptr, I64PtrType, MsgGasAddrInt);

  // Store new gas to message (as int64_t)
  createInstruction<StoreInstruction>(true, &Ctx.VoidType, NewGas, MsgGasPtr);
  createInstruction<BrInstruction>(true, Ctx, MsgSkipBB);
  addSuccessor(MsgSkipBB);
  setInsertBlock(MsgSkipBB);
}

void EVMMirBuilder::chargeMemoryExpansionGasIR(MInstruction *OldSize,
                                               MInstruction *NewSize) {
  // Calculate expansion cost: cost(new) - cost(old)
  MInstruction *NewCost = calculateMemoryGasCostIR(NewSize);
  MInstruction *OldCost = calculateMemoryGasCostIR(OldSize);

  MInstruction *ExpansionCost = createInstruction<BinaryInstruction>(
      false, OP_sub, &Ctx.I64Type, NewCost, OldCost);
  chargeDynamicGasIR(ExpansionCost);
}

void EVMMirBuilder::expandMemoryIR(MInstruction *RequiredSize,
                                   MInstruction *Overflow) {
  // This function expands memory if needed
  // For now, we still call the runtime function for actual resize
  // but we inline the gas calculation

  MType *I64Type = &Ctx.I64Type;

  MInstruction *MaxSize =
      createIntConstInstruction(I64Type, zen::evm::MAX_REQUIRED_MEMORY_SIZE);
  MInstruction *TooLarge = createInstruction<CmpInstruction>(
      false, CmpInstruction::Predicate::ICMP_UGT, I64Type, RequiredSize,
      MaxSize);
  MInstruction *InvalidSize = TooLarge;
  if (Overflow != nullptr) {
    InvalidSize = createInstruction<BinaryInstruction>(false, OP_or, I64Type,
                                                       Overflow, TooLarge);
  }

  MBasicBlock *InvalidBB =
      getOrCreateExceptionSetBB(ErrorCode::GasLimitExceeded);
  MBasicBlock *ValidBB = createBasicBlock();
  createInstruction<BrIfInstruction>(true, Ctx, InvalidSize, InvalidBB,
                                     ValidBB);
  addSuccessor(InvalidBB);
  addSuccessor(ValidBB);

  setInsertBlock(ValidBB);

  // Load current memory size
  MInstruction *CurrentSize = getMemorySize();

  // Check if expansion is needed
#ifdef ZEN_ENABLE_MULTIPASS_JIT_LOGGING
  ++MemStats.ExpandNeedExpandCFGCount;
  if (CurBlockMemStats.Active) {
    CurBlockMemStats.NeedExpandCFGCount++;
  }
#endif // ZEN_ENABLE_MULTIPASS_JIT_LOGGING
  MInstruction *NeedExpand = createInstruction<CmpInstruction>(
      false, CmpInstruction::Predicate::ICMP_UGT, I64Type, RequiredSize,
      CurrentSize);

  MBasicBlock *ExpandBB = createBasicBlock();
  MBasicBlock *ContinueBB = createBasicBlock();

  createInstruction<BrIfInstruction>(true, Ctx, NeedExpand, ExpandBB,
                                     ContinueBB);
  addSuccessor(ExpandBB);
  addSuccessor(ContinueBB);

  // ExpandBB: Calculate aligned size and charge gas
  setInsertBlock(ExpandBB);

  // Align to 32 bytes: newSize = (requiredSize + 31) / 32 * 32
  MInstruction *Const31 = createIntConstInstruction(I64Type, 31);
  MInstruction *Shift5 = createIntConstInstruction(I64Type, 5);
  MInstruction *AlignedWords = createInstruction<BinaryInstruction>(
      false, OP_add, I64Type, RequiredSize, Const31);
  AlignedWords = createInstruction<BinaryInstruction>(false, OP_ushr, I64Type,
                                                      AlignedWords, Shift5);
  MInstruction *AlignedSize = createInstruction<BinaryInstruction>(
      false, OP_shl, I64Type, AlignedWords, Shift5);

  // Charge memory expansion gas
  chargeMemoryExpansionGasIR(CurrentSize, AlignedSize);

  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  callRuntimeFor<void, uint64_t>(RuntimeFunctions.ExpandMemoryNoGas,
                                 Operand(AlignedSize, EVMType::UINT64));
  if (MemorySizeVar) {
    createInstruction<DassignInstruction>(true, &(Ctx.VoidType), AlignedSize,
                                          MemorySizeVar->getVarIdx());
  }
  if (MemoryBaseVar) {
    MPointerType *VoidPtrType = createVoidPtrType();
    const int32_t MemoryBaseOffset =
        zen::runtime::EVMInstance::getMemoryBaseOffset();
    MInstruction *MemPtr = getInstanceElement(VoidPtrType, MemoryBaseOffset);
    MInstruction *MemBaseInt = createInstruction<ConversionInstruction>(
        false, OP_ptrtoint, I64Type, MemPtr);
    createInstruction<DassignInstruction>(true, &(Ctx.VoidType), MemBaseInt,
                                          MemoryBaseVar->getVarIdx());
  }

  createInstruction<BrInstruction>(true, Ctx, ContinueBB);
  addSuccessor(ContinueBB);

  setInsertBlock(ContinueBB);
}

} // namespace COMPILER
