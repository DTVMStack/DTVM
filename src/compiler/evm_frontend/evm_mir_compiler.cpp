// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "compiler/evm_frontend/evm_mir_compiler.h"
#include "action/evm_bytecode_visitor.h"
#include "compiler/evm_frontend/evm_imported.h"
#include "compiler/mir/module.h"
#include "evm/gas_storage_cost.h"
#include "runtime/evm_instance.h"
#include "utils/hash_utils.h"
#include <cstring>
#include <unordered_set>

#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
#include "compiler/llvm-prebuild/Target/X86/X86Subtarget.h"
#endif

namespace COMPILER {

// Hash table constants
constexpr uint64_t HashMultiplier = 0x9E3779B97F4A7C15ULL;
constexpr uint64_t MinHashSize = 5;
constexpr uint64_t MaxHashSize = 1024;

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
      GasChunkSize(OtherCtx.GasChunkSize), Revision(OtherCtx.Revision)
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

MBasicBlock *EVMMirBuilder::getOrCreateIndirectJumpBB() {
  if (IndirectJumpBB) {
    return IndirectJumpBB;
  }

  MBasicBlock *FromBB = CurBB;
  IndirectJumpBB = CurFunc->createBasicBlock();
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
        // JumpDest BB for no-conflict hash index
        HashCases[HIndex].second = JumpHashTable[HashEntry][0];
        addSuccessor(JumpHashTable[HashEntry][0]);
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

  createJumpTable();
  ReturnBB = createBasicBlock();
  loadEVMInstanceAttr();

  GasChunkEnd = EvmCtx->getGasChunkEnd();
  GasChunkCost = EvmCtx->getGasChunkCost();
  GasChunkSize = EvmCtx->getGasChunkSize();

#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
  initGasRegister();
#endif

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
  // Handle EVMStackOverflow in exception BB
  MBasicBlock *StackOverflowBB =
      CurFunc->getOrCreateExceptionSetBB(common::ErrorCode::EVMStackOverflow);
  // Handle EVMStackOverflow in exception BB
  MBasicBlock *FollowBB = createBasicBlock();
  createInstruction<BrIfInstruction>(true, Ctx, IsOverflow, StackOverflowBB,
                                     FollowBB);
  addUniqueSuccessor(StackOverflowBB);
  addSuccessor(FollowBB);
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

  for (size_t PC = 0; PC < BytecodeSize; ++PC) {
    if (Bytecode[PC] == static_cast<Byte>(evmc_opcode::OP_JUMPDEST)) {
      MBasicBlock *DestBB = createBasicBlock();
      DestBB->setJumpDestBB(true);
      JumpDestTable[PC] = DestBB;
    } else if (static_cast<Byte>(evmc_opcode::OP_PUSH0) <= Bytecode[PC] &&
               Bytecode[PC] <= static_cast<Byte>(evmc_opcode::OP_PUSH32)) {
      uint8_t PushSize = static_cast<uint8_t>(Bytecode[PC]) + 1 -
                         static_cast<uint8_t>(evmc_opcode::OP_PUSH1);
      PC += PushSize; // Skip the immediate data
    }
  }

  // If the size of JumpDests is greater than MinHashSize, create a hash table
  // which calculates the hash of DestPC and use it as the index to jump
  if (JumpDestTable.size() > MinHashSize) {
    uint64_t HashSize =
        std::min(nextPowerOfTwo(JumpDestTable.size()), MaxHashSize);
    HashMask = HashSize - 1;
    std::vector<std::vector<MBasicBlock *>> HashDests(HashSize);
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

  MBasicBlock *TargetBB = getOrCreateIndirectJumpBB();
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
    uint64_t ConstDest = Dest.getConstValue()[0];
    implementConstantJump(ConstDest, InvalidJumpBB);
  } else {
    U256Inst DestComponents = extractU256Operand(Dest);
    MInstruction *JumpTarget = DestComponents[0];
    implementIndirectJump(JumpTarget, InvalidJumpBB);
  }
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
  } else {
    MBasicBlock *JumpTableBB = createBasicBlock();
    createInstruction<BrIfInstruction>(true, Ctx, IsNonZero, JumpTableBB,
                                       FallThroughBB);
    addSuccessor(JumpTableBB);
    addSuccessor(FallThroughBB);
    setInsertBlock(JumpTableBB);
    if (Dest.isConstant()) {
      uint64_t ConstDest = Dest.getConstValue()[0];
      implementConstantJump(ConstDest, InvalidJumpBB);
    } else {
      implementIndirectJump(JumpTarget, InvalidJumpBB);
    }
  }

  setInsertBlock(FallThroughBB);
}

void EVMMirBuilder::handleJumpDest(const uint64_t &PC) {
  MBasicBlock *DestBB = JumpDestTable.at(PC);
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
      CurBB->addSuccessor(DestBB);
      createInstruction<BrInstruction>(true, Ctx, DestBB);
    } else {
      MInstruction *LastInst = *std::prev(CurBB->end());
      if (!LastInst->isTerminator()) {
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

typename EVMMirBuilder::Operand EVMMirBuilder::handleMul(Operand MultiplicandOp,
                                                         Operand MultiplierOp) {
  // Optimized schoolbook multiplication for U256 (4x64-bit limbs)
  // U256 layout: [0]=lo64, [1]=mid-lo, [2]=mid-hi, [3]=hi64
  //
  // For 256-bit truncated result, we need products where i+j < 4:
  //   R[0] = P00_lo
  //   R[1] = P00_hi + P01_lo + P10_lo
  //   R[2] = P01_hi + P10_hi + P02_lo + P11_lo + P20_lo
  //   R[3] = P02_hi + P11_hi + P20_hi + P03_lo + P12_lo + P21_lo + P30_lo

  U256Inst A = extractU256Operand(MultiplicandOp);
  U256Inst B = extractU256Operand(MultiplierOp);

  MType *I64Type = &Ctx.I64Type;
  MInstruction *Zero = createIntConstInstruction(I64Type, 0);

  // Pre-compute partial products
  // PLo[i][j] = (A[i] * B[j])_lo, PHi[i][j] = (A[i] * B[j])_hi
  MInstruction *PLo[4][4] = {};
  MInstruction *PHi[4][4] = {};

  for (size_t I = 0; I < 4; ++I) {
    for (size_t J = 0; J < 4; ++J) {
      if (I + J < 4) {
        PLo[I][J] = createEvmUmul128(A[I], B[J]);
      }
      if (I + J < 3) {
        PHi[I][J] = createEvmUmul128Hi(PLo[I][J]);
      }
    }
  }

  using SumCarryPair = std::pair<MInstruction *, MInstruction *>;

  // Helper: add a term into sum and accumulate overflow count in Carry.
  auto addTermWithCarry = [&](MInstruction *Sum, MInstruction *Carry,
                              MInstruction *Term) -> SumCarryPair {
    MInstruction *NewSum =
        createInstruction<BinaryInstruction>(false, OP_add, I64Type, Sum, Term);
    MInstruction *NewCarry =
        createInstruction<AdcInstruction>(false, I64Type, Carry, Zero, Zero);
    return {protectUnsafeValue(NewSum, I64Type),
            protectUnsafeValue(NewCarry, I64Type)};
  };

  auto addTermNoCarry = [&](MInstruction *Sum, MInstruction *Term) {
    MInstruction *NewSum =
        createInstruction<BinaryInstruction>(false, OP_add, I64Type, Sum, Term);
    return protectUnsafeValue(NewSum, I64Type);
  };

  // Accumulate each result limb
  // Using sequential addition with carry propagation

  // R[0] = P00_lo (no overflow possible for single value)
  MInstruction *R0 = PLo[0][0];

  // R[1] = P00_hi + P01_lo + P10_lo
  MInstruction *R1 = PHi[0][0];
  MInstruction *C1 = Zero;
  {
    auto [S1, C1a] = addTermWithCarry(R1, C1, PLo[0][1]);
    auto [S2, C1b] = addTermWithCarry(S1, C1a, PLo[1][0]);
    R1 = S2;
    C1 = C1b;
  }

  // R[2] = P01_hi + P10_hi + P02_lo + P11_lo + P20_lo + C1
  MInstruction *R2 = PHi[0][1];
  MInstruction *C2 = Zero;
  {
    auto [S1, C2a] = addTermWithCarry(R2, C2, PHi[1][0]);
    auto [S2, C2b] = addTermWithCarry(S1, C2a, PLo[0][2]);
    auto [S3, C2c] = addTermWithCarry(S2, C2b, PLo[1][1]);
    auto [S4, C2d] = addTermWithCarry(S3, C2c, PLo[2][0]);
    auto [S5, C2e] = addTermWithCarry(S4, C2d, C1);
    R2 = S5;
    C2 = C2e;
  }

  // R[3] = P02_hi + P11_hi + P20_hi + P03_lo + P12_lo + P21_lo + P30_lo + C2
  // (no need to track carry out since we truncate to 256 bits)
  MInstruction *R3 = PHi[0][2];
  {
    R3 = addTermNoCarry(R3, PHi[1][1]);
    R3 = addTermNoCarry(R3, PHi[2][0]);
    R3 = addTermNoCarry(R3, PLo[0][3]);
    R3 = addTermNoCarry(R3, PLo[1][2]);
    R3 = addTermNoCarry(R3, PLo[2][1]);
    R3 = addTermNoCarry(R3, PLo[3][0]);
    R3 = addTermNoCarry(R3, C2);
    // Ignore carries - they overflow into bit 256+
  }

  U256Inst Result = {R0, R1, R2, R3};
  return Operand(Result, EVMType::UINT256);
}

typename EVMMirBuilder::Operand EVMMirBuilder::handleDiv(Operand DividendOp,
                                                         Operand DivisorOp) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  return callRuntimeFor<const intx::uint256 *, const intx::uint256 &,
                        const intx::uint256 &>(RuntimeFunctions.GetDiv,
                                               DividendOp, DivisorOp);
}

typename EVMMirBuilder::Operand EVMMirBuilder::handleSDiv(Operand DividendOp,
                                                          Operand DivisorOp) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  return callRuntimeFor<const intx::uint256 *, const intx::uint256 &,
                        const intx::uint256 &>(RuntimeFunctions.GetSDiv,
                                               DividendOp, DivisorOp);
}

typename EVMMirBuilder::Operand EVMMirBuilder::handleMod(Operand DividendOp,
                                                         Operand DivisorOp) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  return callRuntimeFor<const intx::uint256 *, const intx::uint256 &,
                        const intx::uint256 &>(RuntimeFunctions.GetMod,
                                               DividendOp, DivisorOp);
}

typename EVMMirBuilder::Operand EVMMirBuilder::handleSMod(Operand DividendOp,
                                                          Operand DivisorOp) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  return callRuntimeFor<const intx::uint256 *, const intx::uint256 &,
                        const intx::uint256 &>(RuntimeFunctions.GetSMod,
                                               DividendOp, DivisorOp);
}

typename EVMMirBuilder::Operand EVMMirBuilder::handleAddMod(Operand AugendOp,
                                                            Operand AddendOp,
                                                            Operand ModulusOp) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  return callRuntimeFor<const intx::uint256 *, const intx::uint256 &,
                        const intx::uint256 &, const intx::uint256 &>(
      RuntimeFunctions.GetAddMod, AugendOp, AddendOp, ModulusOp);
}

typename EVMMirBuilder::Operand
EVMMirBuilder::handleMulMod(Operand MultiplicandOp, Operand MultiplierOp,
                            Operand ModulusOp) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  return callRuntimeFor<const intx::uint256 *, const intx::uint256 &,
                        const intx::uint256 &, const intx::uint256 &>(
      RuntimeFunctions.GetMulMod, MultiplicandOp, MultiplierOp, ModulusOp);
}

typename EVMMirBuilder::Operand EVMMirBuilder::handleExp(Operand BaseOp,
                                                         Operand ExponentOp) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  return callRuntimeFor<const intx::uint256 *, const intx::uint256 &,
                        const intx::uint256 &>(RuntimeFunctions.GetExp, BaseOp,
                                               ExponentOp);
}

EVMMirBuilder::U256Inst EVMMirBuilder::handleCompareEQZ(const U256Inst &LHS,
                                                        MType *ResultType) {
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
  auto Predicate = CmpInstruction::Predicate::ICMP_EQ;
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

  CmpInstruction::Predicate LTPredicate;
  if (Operator == CompareOperator::CO_LT) {
    LTPredicate = CmpInstruction::Predicate::ICMP_ULT;
  } else if (Operator == CompareOperator::CO_LT_S) {
    LTPredicate = CmpInstruction::Predicate::ICMP_SLT;
  } else if (Operator == CompareOperator::CO_GT) {
    LTPredicate = CmpInstruction::Predicate::ICMP_UGT;
  } else if (Operator == CompareOperator::CO_GT_S) {
    LTPredicate = CmpInstruction::Predicate::ICMP_SGT;
  } else {
    ZEN_ASSERT_TODO();
  }
  auto EQPredicate = CmpInstruction::Predicate::ICMP_EQ;

  // Track if all higher components are equal
  MInstruction *AllEqual = nullptr;

  for (int I = EVM_ELEMENTS_COUNT - 1; I >= 0; --I) {
    ZEN_ASSERT(LHS[I] && RHS[I]);

    MInstruction *CompResult = createInstruction<CmpInstruction>(
        false, LTPredicate, ResultType, LHS[I], RHS[I]);
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
  U256Inst Result = {};
  U256Inst LHS = extractU256Operand(LHSOp);

  MType *MirI64Type =
      EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);

  for (size_t I = 0; I < EVM_ELEMENTS_COUNT; ++I) {
    MInstruction *LocalResult =
        createInstruction<NotInstruction>(false, MirI64Type, LHS[I]);
    Result[I] = protectUnsafeValue(LocalResult, MirI64Type);
  }

  return Operand(Result, EVMType::UINT256);
}

EVMMirBuilder::U256Inst
EVMMirBuilder::handleLeftShift(const U256Inst &Value, MInstruction *ShiftAmount,
                               MInstruction *IsLargeShift) {
  MType *MirI64Type =
      EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);
  U256Inst Result = {};

  MInstruction *Zero = createIntConstInstruction(MirI64Type, 0);
  MInstruction *One = createIntConstInstruction(MirI64Type, 1);
  MInstruction *Const64 = createIntConstInstruction(MirI64Type, 64);

  // EVM SHL operation: result = value << shift
  // DMIR implementation maps 256-bit shift to 4x64-bit components
  // shift_mod = shift % 64 (shift amount within 64-bit range)
  // shift_comp = shift / 64 (which component index shift from)
  // remaining_bits = 64 - shift_mod (remaining bits for carry calculation)
  MInstruction *ShiftMod64 = createInstruction<BinaryInstruction>(
      false, OP_urem, MirI64Type, ShiftAmount, Const64);
  MInstruction *ComponentShift = createInstruction<BinaryInstruction>(
      false, OP_udiv, MirI64Type, ShiftAmount, Const64);
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
  MInstruction *One = createIntConstInstruction(MirI64Type, 1);
  MInstruction *Const64 = createIntConstInstruction(MirI64Type, 64);

  // EVM SHR operation: result = value >> shift (logical right shift)
  // DMIR implementation maps 256-bit shift to 4x64-bit components
  // shift_mod = shift % 64 (shift amount within 64-bit range)
  // shift_comp = shift / 64 (which component index shift from)
  MInstruction *ShiftMod64 = createInstruction<BinaryInstruction>(
      false, OP_urem, MirI64Type, ShiftAmount, Const64);
  MInstruction *ComponentShift = createInstruction<BinaryInstruction>(
      false, OP_udiv, MirI64Type, ShiftAmount, Const64);

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

  // Arithmetic right shift: sign-extend when shift >= 256
  MInstruction *Zero = createIntConstInstruction(MirI64Type, 0);
  MInstruction *AllOnes = createIntConstInstruction(MirI64Type, ~0ULL);

  // Check sign bit (bit 63 of highest component)
  MInstruction *HighComponent = Value[EVM_ELEMENTS_COUNT - 1];
  MInstruction *Const63 = createIntConstInstruction(MirI64Type, 63);
  MInstruction *SignBit = createInstruction<BinaryInstruction>(
      false, OP_ushr, MirI64Type, HighComponent, Const63);

  // Sign bit is 1 if negative
  MInstruction *One = createIntConstInstruction(MirI64Type, 1);
  MInstruction *IsNegative = createInstruction<CmpInstruction>(
      false, CmpInstruction::Predicate::ICMP_EQ, &Ctx.I64Type, SignBit, One);

  // Large shift result: all 1s if negative, all 0s if positive
  MInstruction *LargeShiftResult = createInstruction<SelectInstruction>(
      false, MirI64Type, IsNegative, AllOnes, Zero);

  // intra-component shifts = shift % 64
  // shift_comp = shift / 64 (which component index shift from)
  MInstruction *Const64 = createIntConstInstruction(MirI64Type, 64);
  MInstruction *ShiftMod64 = createInstruction<BinaryInstruction>(
      false, OP_urem, MirI64Type, ShiftAmount, Const64);
  MInstruction *ComponentShift = createInstruction<BinaryInstruction>(
      false, OP_udiv, MirI64Type, ShiftAmount, Const64);

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
  U256Inst IndexComponents = extractU256Operand(IndexOp);
  U256Inst ValueComponents = extractU256Operand(ValueOp);

  // Check if index >= 32 (out of bounds)
  MInstruction *IsOutOfBounds = isU256GreaterOrEqual(IndexComponents, 32);

  MType *MirI64Type =
      EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);

  // Calculate bit shift: (31 - index) * 8
  MInstruction *Const31 = createIntConstInstruction(MirI64Type, 31);
  MInstruction *ByteIndex = createInstruction<BinaryInstruction>(
      false, OP_sub, MirI64Type, Const31, IndexComponents[0]);
  MInstruction *Const8 = createIntConstInstruction(MirI64Type, 8);
  MInstruction *BitShift = createInstruction<BinaryInstruction>(
      false, OP_mul, MirI64Type, ByteIndex, Const8);

  // Determine which 64-bit component contains the byte
  MInstruction *Const64 = createIntConstInstruction(MirI64Type, 64);
  MInstruction *ComponentIndex = createInstruction<BinaryInstruction>(
      false, OP_udiv, MirI64Type, BitShift, Const64);

  // Calculate the bit offset within the selected 64-bit component
  MInstruction *BitOffset = createInstruction<BinaryInstruction>(
      false, OP_urem, MirI64Type, BitShift, Const64);

  // Select the appropriate 64-bit component based on component_index
  // Example: bit_shift=248 → component_index=3 (248/64=3), bit_offset=56
  // This means target byte is in the highest component (comp3) at bit offset 56
  MInstruction *SelectedComponent = ValueComponents[0];
  for (size_t I = 1; I < EVM_ELEMENTS_COUNT; ++I) {
    MInstruction *IsThisComponent = createInstruction<CmpInstruction>(
        false, CmpInstruction::Predicate::ICMP_EQ, &Ctx.I64Type, ComponentIndex,
        createIntConstInstruction(MirI64Type, I));
    SelectedComponent = createInstruction<SelectInstruction>(
        false, MirI64Type, IsThisComponent, ValueComponents[I],
        SelectedComponent);
  }

  // Extract the byte by shifting right and masking
  // Shift the selected component right by bit_offset to move target byte to LSB
  // Then mask with 0xFF to extract the lowest 8 bits
  MInstruction *ShiftedValue = createInstruction<BinaryInstruction>(
      false, OP_ushr, MirI64Type, SelectedComponent, BitOffset);
  MInstruction *ConstFF = createIntConstInstruction(MirI64Type, 0xFF);
  MInstruction *ByteValue = createInstruction<BinaryInstruction>(
      false, OP_and, MirI64Type, ShiftedValue, ConstFF);

  MInstruction *Zero = createIntConstInstruction(MirI64Type, 0);
  // Return 0 if out of bounds, otherwise return the extracted byte value
  MInstruction *Result = createInstruction<SelectInstruction>(
      false, MirI64Type, IsOutOfBounds, Zero, ByteValue);

  // Create U256 result with only the low component set
  // High components are zeroed out as per EVM specification
  U256Inst ResultComponents = {};
  ResultComponents[0] = Result;
  for (size_t I = 1; I < EVM_ELEMENTS_COUNT; ++I) {
    ResultComponents[I] = Zero;
  }

  return Operand(ResultComponents, EVMType::UINT256);
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

  // Calculate sign bit position: index * 8 + 7
  MInstruction *Const8 = createIntConstInstruction(MirI64Type, 8);
  MInstruction *ByteBitPos = createInstruction<BinaryInstruction>(
      false, OP_mul, MirI64Type, IndexComponents[0], Const8);
  MInstruction *Const7 = createIntConstInstruction(MirI64Type, 7);
  MInstruction *SignBitPos = createInstruction<BinaryInstruction>(
      false, OP_add, MirI64Type, ByteBitPos, Const7);

  // ComponentIndex = (index * 8 + 7) / 64
  MInstruction *Const64 = createIntConstInstruction(MirI64Type, 64);
  MInstruction *ComponentIndex = createInstruction<BinaryInstruction>(
      false, OP_udiv, MirI64Type, SignBitPos, Const64);
  // BitOffset = (index * 8 + 7) % 64
  MInstruction *BitOffset = createInstruction<BinaryInstruction>(
      false, OP_urem, MirI64Type, SignBitPos, Const64);

  // Calculate sign extension mask
  // FullMask = (1 << (BitOffset + 1)) - 1
  // InvMask = ~FullMask = FullMask ^ AllOnes
  MInstruction *One = createIntConstInstruction(MirI64Type, 1);
  MInstruction *AllOnes = createIntConstInstruction(MirI64Type, ~0ULL);
  MInstruction *MaskBits = createInstruction<BinaryInstruction>(
      false, OP_add, MirI64Type, BitOffset, One);
  MInstruction *Mask = createInstruction<BinaryInstruction>(
      false, OP_shl, MirI64Type, One, MaskBits);
  MInstruction *FullMask = createInstruction<BinaryInstruction>(
      false, OP_sub, MirI64Type, Mask, One);
  MInstruction *InvMask = createInstruction<BinaryInstruction>(
      false, OP_xor, MirI64Type, FullMask, AllOnes);

  // Extract sign bit
  MInstruction *Zero = createIntConstInstruction(MirI64Type, 0);
  MInstruction *SignBit = Zero;
  for (int I = 0; I < 4; I++) {
    MInstruction *IsComp = createInstruction<CmpInstruction>(
        false, CmpInstruction::Predicate::ICMP_EQ, &Ctx.I64Type, ComponentIndex,
        createIntConstInstruction(MirI64Type, I));
    // Shifted = ValueComponents[I] >> BitOffset
    MInstruction *Shifted = createInstruction<BinaryInstruction>(
        false, OP_ushr, MirI64Type, ValueComponents[I], BitOffset);
    // Bit = Shifted & 1
    MInstruction *Bit = createInstruction<BinaryInstruction>(
        false, OP_and, MirI64Type, Shifted, One);
    // SignBit = IsComp ? Bit : SignBit
    SignBit = createInstruction<SelectInstruction>(false, MirI64Type, IsComp,
                                                   Bit, SignBit);
  }

  // Create sign extension for each component
  U256Inst ResultComponents = {};
  for (int I = 0; I < 4; I++) {
    MInstruction *CompIdx = createIntConstInstruction(MirI64Type, I);
    MInstruction *IsAbove = createInstruction<CmpInstruction>(
        false, CmpInstruction::Predicate::ICMP_UGT, &Ctx.I64Type, CompIdx,
        ComponentIndex);
    MInstruction *IsEqual = createInstruction<CmpInstruction>(
        false, CmpInstruction::Predicate::ICMP_EQ, &Ctx.I64Type, CompIdx,
        ComponentIndex);

    // For components above sign bit: all 1s if negative, all 0s if positive
    MInstruction *HighValue = createInstruction<SelectInstruction>(
        false, MirI64Type, SignBit, AllOnes, Zero);

    // For sign component: apply mask and sign extension
    MInstruction *SignCompValue = createInstruction<BinaryInstruction>(
        false, OP_and, MirI64Type, ValueComponents[I], FullMask);
    MInstruction *SignExtBits = createInstruction<BinaryInstruction>(
        false, OP_and, MirI64Type, InvMask, HighValue);
    MInstruction *ExtendedSignComp = createInstruction<BinaryInstruction>(
        false, OP_or, MirI64Type, SignCompValue, SignExtBits);

    // Select appropriate value based on position relative to sign bit
    MInstruction *ComponentResult = createInstruction<SelectInstruction>(
        false, MirI64Type, IsAbove, HighValue,
        createInstruction<SelectInstruction>(
            false, MirI64Type, IsEqual, ExtendedSignComp, ValueComponents[I]));

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

  // Convert the 64-bit PC value to U256 format (EVM specification)
  return convertSingleInstrToU256Operand(PCInst);
}

typename EVMMirBuilder::Operand EVMMirBuilder::handleGas() {
#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
  syncGasToMemory();
#endif
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  return callRuntimeFor<uint64_t>(RuntimeFunctions.GetGas);
}

typename EVMMirBuilder::Operand EVMMirBuilder::handleAddress() {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  return callRuntimeFor(RuntimeFunctions.GetAddress);
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
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  return callRuntimeFor(RuntimeFunctions.GetCaller);
}

typename EVMMirBuilder::Operand EVMMirBuilder::handleCallValue() {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  return callRuntimeFor(RuntimeFunctions.GetCallValue);
}

typename EVMMirBuilder::Operand
EVMMirBuilder::handleCallDataLoad(Operand Offset) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  normalizeOperandU64(Offset);
  return callRuntimeFor<const uint8_t *, uint64_t>(
      RuntimeFunctions.GetCallDataLoad, Offset);
}

typename EVMMirBuilder::Operand EVMMirBuilder::handleGasPrice() {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  return callRuntimeFor(RuntimeFunctions.GetGasPrice);
}

typename EVMMirBuilder::Operand EVMMirBuilder::handleCallDataSize() {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  return callRuntimeFor(RuntimeFunctions.GetCallDataSize);
}

typename EVMMirBuilder::Operand EVMMirBuilder::handleCodeSize() {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  return callRuntimeFor(RuntimeFunctions.GetCodeSize);
}

void EVMMirBuilder::handleCodeCopy(Operand DestOffsetComponents,
                                   Operand OffsetComponents,
                                   Operand SizeComponents) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  normalizeOperandU64(DestOffsetComponents);
  normalizeOperandU64(OffsetComponents);
  normalizeOperandU64(SizeComponents);
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
  auto Result = callRuntimeFor<const uint8_t *, const uint8_t *>(
      RuntimeFunctions.GetExtCodeHash, Address);
#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
  reloadGasFromMemory();
#endif
  return Result;
}

typename EVMMirBuilder::Operand
EVMMirBuilder::handleBlockHash(Operand BlockNumber) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
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
typename EVMMirBuilder::Operand
EVMMirBuilder::handleMLoad(Operand AddrComponents) {
  normalizeOperandU64(AddrComponents);
#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
  syncGasToMemory();
#endif
  MType *I64Type = &Ctx.I64Type;

  U256Inst AddrParts = extractU256Operand(AddrComponents);
  MInstruction *Offset = AddrParts[0];

  MInstruction *SizeConst = createIntConstInstruction(I64Type, 32);
  MInstruction *RequiredSize = createInstruction<BinaryInstruction>(
      false, OP_add, I64Type, Offset, SizeConst);
  MInstruction *Overflow = createInstruction<CmpInstruction>(
      false, CmpInstruction::Predicate::ICMP_ULT, I64Type, RequiredSize,
      Offset);
  expandMemoryIR(RequiredSize, Overflow);

  MInstruction *MemBase = getMemoryDataPointer();
  MInstruction *MemAddrInt = createInstruction<BinaryInstruction>(
      false, OP_add, I64Type, MemBase, Offset);
  MInstruction *MemPtr = createInstruction<ConversionInstruction>(
      false, OP_inttoptr, createVoidPtrType(), MemAddrInt);

  Operand Bytes32Op(MemPtr, EVMType::BYTES32);
  Operand Result = convertBytes32ToU256Operand(Bytes32Op);
#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
  reloadGasFromMemory();
#endif
  return Result;
}

void EVMMirBuilder::handleMStore(Operand AddrComponents,
                                 Operand ValueComponents) {
  normalizeOperandU64(AddrComponents);
#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
  syncGasToMemory();
#endif
  MType *I64Type = &Ctx.I64Type;

  U256Inst AddrParts = extractU256Operand(AddrComponents);
  MInstruction *Offset = AddrParts[0];
  U256Inst ValueParts = extractU256Operand(ValueComponents);

  MInstruction *SizeConst = createIntConstInstruction(I64Type, 32);
  MInstruction *RequiredSize = createInstruction<BinaryInstruction>(
      false, OP_add, I64Type, Offset, SizeConst);
  // Tie expansion ordering to the stored value to prevent reordering.
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
  expandMemoryIR(RequiredSize, Overflow);

  MInstruction *MemBase = getMemoryDataPointer();
  MInstruction *BaseAddrInt = createInstruction<BinaryInstruction>(
      false, OP_add, I64Type, MemBase, Offset);

  MPointerType *U64PtrType = MPointerType::create(Ctx, Ctx.I64Type);

  auto ByteSwap64 = [&](MInstruction *Value) -> MInstruction * {
    return createInstruction<UnaryInstruction>(false, OP_bswap, I64Type, Value);
  };

  for (int Component = 0; Component < 4; ++Component) {
    MInstruction *RawValue = ValueParts[3 - Component];
    MInstruction *Swapped = ByteSwap64(RawValue);

    MInstruction *OffsetValue = createIntConstInstruction(
        I64Type, static_cast<uint64_t>(Component * 8));
    MInstruction *Addr = createInstruction<BinaryInstruction>(
        false, OP_add, I64Type, BaseAddrInt, OffsetValue);
    MInstruction *Ptr = createInstruction<ConversionInstruction>(
        false, OP_inttoptr, U64PtrType, Addr);
    createInstruction<StoreInstruction>(true, &Ctx.VoidType, Swapped, Ptr);
  }
#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
  reloadGasFromMemory();
#endif
}

void EVMMirBuilder::handleMStore8(Operand AddrComponents,
                                  Operand ValueComponents) {
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
  expandMemoryIR(RequiredSize, Overflow);

  MInstruction *MemBase = getMemoryDataPointer();
  MInstruction *AddrInt = createInstruction<BinaryInstruction>(
      false, OP_add, I64Type, MemBase, Offset);

  MPointerType *I8PtrType = MPointerType::create(Ctx, Ctx.I8Type);
  MInstruction *AddrPtr = createInstruction<ConversionInstruction>(
      false, OP_inttoptr, I8PtrType, AddrInt);

  MInstruction *Low64 = ValueParts[0];
  MInstruction *Mask = createIntConstInstruction(I64Type, 0xFF);
  MInstruction *Masked =
      createInstruction<BinaryInstruction>(false, OP_and, I64Type, Low64, Mask);
  MInstruction *ByteValue = createInstruction<ConversionInstruction>(
      false, OP_trunc, &Ctx.I8Type, Masked);
  createInstruction<StoreInstruction>(true, &Ctx.VoidType, ByteValue, AddrPtr);
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
  normalizeOperandU64(OffsetOp);
  normalizeOperandU64(SizeOp);

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
}

typename EVMMirBuilder::Operand
EVMMirBuilder::handleCreate(Operand ValueOp, Operand OffsetOp, Operand SizeOp) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  normalizeOperandU64(OffsetOp);
  normalizeOperandU64(SizeOp);
#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
  syncGasToMemoryFull();
#endif
  auto Result =
      callRuntimeFor<const uint8_t *, intx::uint128, uint64_t, uint64_t>(
          RuntimeFunctions.HandleCreate, ValueOp, OffsetOp, SizeOp);
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
  normalizeOperandU64(OffsetOp);
  normalizeOperandU64(SizeOp);
#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
  syncGasToMemoryFull();
#endif
  auto Result = callRuntimeFor<const uint8_t *, intx::uint128, uint64_t,
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
      callRuntimeFor<uint64_t, uint64_t, const uint8_t *, intx::uint128,
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
      callRuntimeFor<uint64_t, uint64_t, const uint8_t *, intx::uint128,
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

  createInstruction<BrInstruction>(true, Ctx, ReturnBB);
  addSuccessor(ReturnBB);

  if (ReturnBB->empty()) {
    setInsertBlock(ReturnBB);
    handleVoidReturn();
  }

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
  normalizeOperandU64(OffsetOp);
  normalizeOperandU64(SizeOp);
#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
  syncGasToMemoryFull();
#endif
  callRuntimeFor<void, uint64_t, uint64_t>(RuntimeFunctions.SetRevert, OffsetOp,
                                           SizeOp);

  createInstruction<BrInstruction>(true, Ctx, ReturnBB);
  addSuccessor(ReturnBB);

  if (ReturnBB->empty()) {
    setInsertBlock(ReturnBB);
    handleVoidReturn();
  }

  MBasicBlock *PostRevertBB = createBasicBlock();
  setInsertBlock(PostRevertBB);
#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
  reloadGasFromMemory();
#endif
}

void EVMMirBuilder::handleInvalid() {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  callRuntimeFor(RuntimeFunctions.HandleInvalid);

  createInstruction<BrInstruction>(true, Ctx, ReturnBB);
  addSuccessor(ReturnBB);

  if (ReturnBB->empty()) {
    setInsertBlock(ReturnBB);
    handleVoidReturn();
  }
}

void EVMMirBuilder::handleUndefined() {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  callRuntimeFor(RuntimeFunctions.HandleUndefined);

  createInstruction<BrInstruction>(true, Ctx, ReturnBB);
  addSuccessor(ReturnBB);

  if (ReturnBB->empty()) {
    setInsertBlock(ReturnBB);
    handleVoidReturn();
  }
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
  callRuntimeFor<void, const uint8_t *>(RuntimeFunctions.HandleSelfDestruct,
                                        Beneficiary);

  createInstruction<BrInstruction>(true, Ctx, ReturnBB);
  addSuccessor(ReturnBB);

  if (ReturnBB->empty()) {
    setInsertBlock(ReturnBB);
    handleVoidReturn();
  }

  MBasicBlock *PostSelfDestructBB = createBasicBlock();
  setInsertBlock(PostSelfDestructBB);
#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
  reloadGasFromMemory();
#endif
}

typename EVMMirBuilder::Operand
EVMMirBuilder::handleKeccak256(Operand OffsetComponents,
                               Operand LengthComponents) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  normalizeOperandU64(OffsetComponents);
  normalizeOperandU64(LengthComponents);
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

  // Fill the remaining components with zeros
  MInstruction *Zero = createIntConstInstruction(I64Type, 0);
  for (size_t I = 1; I < EVM_ELEMENTS_COUNT; ++I) {
    Result[I] = Zero;
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

MInstruction *EVMMirBuilder::protectUnsafeValue(MInstruction *Value,
                                                MType *Type) {
  Variable *ReusableVar = CurFunc->createVariable(Type);
  VariableIdx ReusableVarIdx = ReusableVar->getVarIdx();
  createInstruction<DassignInstruction>(true, &(Ctx.VoidType), Value,
                                        ReusableVarIdx);
  return createInstruction<DreadInstruction>(false, ReusableVar->getType(),
                                             ReusableVarIdx);
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

  U256Inst Result = {};
  MType *I64Type = EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);
  MInstruction *Bytes32Ptr = Bytes32Op.getInstr();
  MPointerType *U64PtrType = MPointerType::create(Ctx, Ctx.I64Type);

  // Materialize the base address as an integer for pointer arithmetic
  MInstruction *BaseAddr = Bytes32Ptr;
  if (Bytes32Ptr->getType()->isPointer()) {
    BaseAddr = createInstruction<ConversionInstruction>(
        false, OP_ptrtoint, &Ctx.I64Type, Bytes32Ptr);
  }

  auto ByteSwap64 = [&](MInstruction *Value) -> MInstruction * {
    return createInstruction<UnaryInstruction>(false, OP_bswap, I64Type, Value);
  };

  for (int Component = 0; Component < 4; ++Component) {
    // Component 0 corresponds to bytes 24-31 (least significant 64 bits)
    // Component 3 corresponds to bytes 0-7 (most significant 64 bits)
    int BaseOffset = (3 - Component) * 8;

    MInstruction *Offset =
        createIntConstInstruction(I64Type, static_cast<uint64_t>(BaseOffset));
    MInstruction *Addr = createInstruction<BinaryInstruction>(
        false, OP_add, &Ctx.I64Type, BaseAddr, Offset);
    MInstruction *ComponentPtr = createInstruction<ConversionInstruction>(
        false, OP_inttoptr, U64PtrType, Addr);
    MInstruction *RawValue =
        createInstruction<LoadInstruction>(false, I64Type, ComponentPtr);

    Result[Component] = ByteSwap64(RawValue);
  }

  return Operand(Result, EVMType::UINT256);
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

void EVMMirBuilder::normalizeOffsetWithSize(Operand &Offset, Operand &Size) {
  normalizeOperandU64(Size);
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
  MInstruction *Zero = createIntConstInstruction(I64Type, 0);

  if (Param.isEmpty()) {
    for (size_t I = 0; I < N; ++I) {
      Result[I] = Zero;
    }
  } else if (Param.getType() == EVMType::BYTES32) {
    auto U256Op = convertBytes32ToU256Operand(Param);
    auto Components = U256Op.getU256Components();
    for (size_t I = 0; I < N; ++I) {
      Result[I] = Components[I];
    }
  } else if (Param.isU256MultiComponent()) {
    auto Components = Param.getU256Components();
    for (size_t I = 0; I < N; ++I) {
      Result[I] = Components[I];
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
    Result[I] = Zero;
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
  normalizeOperandU64(DestOffsetComponents);

  uint64_t Non64Value = std::numeric_limits<uint64_t>::max();
  normalizeOperandU64(OffsetComponents, &Non64Value);
  normalizeOperandU64(SizeComponents);
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
  normalizeOperandU64(DestOffsetComponents);
  // Use max uint64_t value if the offset/size is not 64-bit, because the
  // returndatacopy will trigger memory access error instead of out-of-gas
  // when offset/size is is very large.
  uint64_t Non64Value = std::numeric_limits<uint64_t>::max();
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
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  return callRuntimeFor<uint64_t>(RuntimeFunctions.GetReturnDataSize);
}

// ==================== Memory Operation Helper Methods ====================

MInstruction *EVMMirBuilder::getMemoryDataPointer() {
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
