// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "compiler/evm_frontend/evm_mir_compiler.h"
#include "action/evm_bytecode_visitor.h"
#include "compiler/evm_frontend/evm_imported.h"
#include "compiler/mir/module.h"
#include "runtime/evm_instance.h"
#include "utils/hash_utils.h"

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
    throw getErrorWithPhase(ErrorCode::UnexpectedType, ErrorPhase::Compilation,
                            ErrorSubphase::MIREmission);
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
      GasChunkSize(OtherCtx.GasChunkSize) {}

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

  ExceptionReturnBB = CurFunc->createExceptionReturnBB();
}

void EVMMirBuilder::initEVM(CompilerContext *Context) {
  // Create entry basic block
  MBasicBlock *EntryBB = createBasicBlock();
  setInsertBlock(EntryBB);

  InstructionMetrics =
      evmc_get_instruction_metrics_table(zen::evm::DEFAULT_REVISION);

  createJumpTable();
  ReturnBB = createBasicBlock();
  loadEVMInstanceAttr();

  const auto *EvmCtx = static_cast<const EVMFrontendContext *>(&Ctx);
  GasChunkEnd = EvmCtx->getGasChunkEnd();
  GasChunkCost = EvmCtx->getGasChunkCost();
  GasChunkSize = EvmCtx->getGasChunkSize();

  if (Ctx.isGasMeteringEnabled()) {
    meterGas(zen::evm::BASIC_EXECUTION_COST);
  }
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

void EVMMirBuilder::meterGas(uint64_t GasCost) {
  if (!Ctx.isGasMeteringEnabled() || GasCost == 0) {
    return;
  }

  MType *I64Type = EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);
  MPointerType *VoidPtrType = createVoidPtrType();
  MPointerType *I64PtrType = MPointerType::create(Ctx, Ctx.I64Type);

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

  MInstruction *MsgGasValue =
      createInstruction<LoadInstruction>(false, I64Type, MsgGasPtr);

  MInstruction *GasCostValue = createIntConstInstruction(I64Type, GasCost);
  MInstruction *IsOutOfGas = createInstruction<CmpInstruction>(
      false, CmpInstruction::Predicate::ICMP_ULT, &Ctx.I64Type, MsgGasValue,
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
      false, OP_sub, I64Type, MsgGasValue, GasCostValue);

  MInstruction *GasOffsetValue = createIntConstInstruction(
      I64Type, zen::runtime::EVMInstance::getGasFieldOffset());
  MInstruction *GasAddrInt = createInstruction<BinaryInstruction>(
      false, OP_add, I64Type, InstanceAddr, GasOffsetValue);
  MInstruction *GasPtr = createInstruction<ConversionInstruction>(
      false, OP_inttoptr, I64PtrType, GasAddrInt);

  createInstruction<StoreInstruction>(true, &Ctx.VoidType, NewGas, GasPtr);
  createInstruction<StoreInstruction>(true, &Ctx.VoidType, NewGas, MsgGasPtr);
}

void EVMMirBuilder::createStackCheckBlock() {
  // Create a new basic block for stack checking
}

void EVMMirBuilder::updateStackCheckBlock(int32_t MinSize, int32_t MaxSize) {
  // Add checks in stack check BB
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

  // Check if IndexFromTop exceeds stack size
  MInstruction *IsUnderflow = createInstruction<CmpInstruction>(
      false, CmpInstruction::ICMP_UGT, &Ctx.I64Type, TopOffset, StackSize);
  // Handle EVMStackOverflow in exception BB
  MBasicBlock *StackUnderflowBB =
      CurFunc->getOrCreateExceptionSetBB(common::ErrorCode::EVMStackUnderflow);
  MBasicBlock *FollowBB = createBasicBlock();
  createInstruction<BrIfInstruction>(true, Ctx, IsUnderflow, StackUnderflowBB,
                                     FollowBB);
  addUniqueSuccessor(StackUnderflowBB);
  addSuccessor(FollowBB);
  setInsertBlock(FollowBB);

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

  // TODO: handle EVMStackOverflow
  MBasicBlock *StackOverflowBB =
      CurFunc->getOrCreateExceptionSetBB(common::ErrorCode::EVMStackOverflow);

  // NewSize = StackSize + 32
  MInstruction *Const32 = createIntConstInstruction(I64Type, 32);
  MInstruction *NewSize = createInstruction<BinaryInstruction>(
      false, OP_add, I64Type, StackSize, Const32);

  // Check if NewSize exceeds stack boundary
  MInstruction *StackBoundary = createIntConstInstruction(
      I64Type, zen::runtime::EVMInstance::EVMStackCapacity);
  MInstruction *IsOverflow = createInstruction<CmpInstruction>(
      false, CmpInstruction::ICMP_UGT, &Ctx.I64Type, NewSize, StackBoundary);

  // Handle EVMStackOverflow in exception BB
  MBasicBlock *StoreBB = createBasicBlock();
  createInstruction<BrIfInstruction>(true, Ctx, IsOverflow, StackOverflowBB,
                                     StoreBB);
  addUniqueSuccessor(StackOverflowBB);
  addSuccessor(StoreBB);
  setInsertBlock(StoreBB);

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

  // Handle EVMStackUnderflow in exception BB
  MBasicBlock *StackUnderflowBB =
      CurFunc->getOrCreateExceptionSetBB(common::ErrorCode::EVMStackUnderflow);

  // NewSize = StackSize - 32
  MInstruction *Const32 = createIntConstInstruction(I64Type, 32);
  MInstruction *NewSize = createInstruction<BinaryInstruction>(
      false, OP_sub, I64Type, StackSize, Const32);

  // If NewSize < 0, goto exception BB
  MInstruction *Zero = createIntConstInstruction(I64Type, 0);
  MInstruction *IsUnderflow = createInstruction<CmpInstruction>(
      false, CmpInstruction::ICMP_SLT, &Ctx.I64Type, NewSize, Zero);

  // Handle it in exception BB
  MBasicBlock *LoadBB = createBasicBlock();
  createInstruction<BrIfInstruction>(true, Ctx, IsUnderflow, StackUnderflowBB,
                                     LoadBB);
  addUniqueSuccessor(StackUnderflowBB);
  addSuccessor(LoadBB);
  setInsertBlock(LoadBB);

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
  createInstruction<BrInstruction>(true, Ctx, ReturnBB);
  addSuccessor(ReturnBB);
  setInsertBlock(ReturnBB);
  handleVoidReturn();
}

void EVMMirBuilder::drainGas() {
  MType *I64Type = EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);
  MPointerType *VoidPtrType = createVoidPtrType();
  MPointerType *I64PtrType = MPointerType::create(Ctx, Ctx.I64Type);

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

#ifdef ZEN_ENABLE_LINUX_PERF
  CurBB->setSourceOffset(CurPC);
  CurBB->setSourceName("SWITCH" + std::to_string(CurInstrIdx));
  CurInstrIdx++;
#endif // ZEN_ENABLE_LINUX_PERF

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
    return;
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
  if (!CurBB->empty()) {
    MInstruction *LastInst = *std::prev(CurBB->end());
    if (!LastInst->isTerminator()) {
      CurBB->addSuccessor(DestBB);
      createInstruction<BrInstruction>(true, Ctx, DestBB);
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

typename EVMMirBuilder::Operand EVMMirBuilder::handleMul(Operand MultiplicandOp,
                                                         Operand MultiplierOp) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  return callRuntimeFor<const intx::uint256 *, const intx::uint256 &,
                        const intx::uint256 &>(RuntimeFunctions.GetMul,
                                               MultiplicandOp, MultiplierOp);
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
  Result[0] = CmpResult;
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
  Result[0] = AndResult;
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
  Result[0] = FinalResult;
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

    // Calculate carry bits from the previous component
    // carry_bits = (prev_idx == K) ? (Value[K] >> remaining_bits) : 0
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
      MInstruction *CarryBits = createInstruction<BinaryInstruction>(
          false, OP_ushr, MirI64Type, PrevValue, RemainingBits);
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
    Result[I] = createInstruction<SelectInstruction>(
        false, MirI64Type, IsLargeShift, Zero,
        createInstruction<SelectInstruction>(false, MirI64Type, IsInBounds,
                                             CombinedValue, Zero));
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
          false, OP_shl, MirI64Type, NextValue,
          createInstruction<BinaryInstruction>(
              false, OP_sub, MirI64Type,
              createIntConstInstruction(MirI64Type, 64), ShiftMod64));
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
    Result[I] = createInstruction<SelectInstruction>(
        false, MirI64Type, IsLargeShift, Zero,
        createInstruction<SelectInstruction>(false, MirI64Type, IsInBounds,
                                             CombinedValue, Zero));
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

    // Calculate carry bits from the previous component (index-1)
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

      // Extract high bits from previous component as carry
      MInstruction *CarryBits = createInstruction<BinaryInstruction>(
          false, OP_ushr, MirI64Type, PrevValue,
          createInstruction<BinaryInstruction>(
              false, OP_sub, MirI64Type,
              createIntConstInstruction(MirI64Type, 64), ShiftMod64));
      CarryValue = createInstruction<SelectInstruction>(
          false, MirI64Type, IsMatch, CarryBits, CarryValue);
    }

    MInstruction *ShiftedValue = createInstruction<BinaryInstruction>(
        false, OP_sshr, MirI64Type, SrcValue, ShiftMod64);
    MInstruction *CombinedValue = createInstruction<BinaryInstruction>(
        false, OP_or, MirI64Type, ShiftedValue, CarryValue);

    Result[I] = createInstruction<SelectInstruction>(
        false, MirI64Type, IsLargeShift, LargeShiftResult,
        createInstruction<SelectInstruction>(false, MirI64Type, IsInBounds,
                                             CombinedValue, LargeShiftResult));
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
    ResultComponents[I] = createInstruction<SelectInstruction>(
        false, MirI64Type, NoExtension, ValueComponents[I], ComponentResult);
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
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  return callRuntimeFor<uint64_t>(RuntimeFunctions.GetGas);
}

typename EVMMirBuilder::Operand EVMMirBuilder::handleAddress() {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  return callRuntimeFor(RuntimeFunctions.GetAddress);
}

typename EVMMirBuilder::Operand EVMMirBuilder::handleBalance(Operand Address) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  return callRuntimeFor<const intx::uint256 *, const uint8_t *>(
      RuntimeFunctions.GetBalance, Address);
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
  callRuntimeFor<void, uint64_t, uint64_t, uint64_t>(
      RuntimeFunctions.SetCodeCopy, DestOffsetComponents, OffsetComponents,
      SizeComponents);
}

typename EVMMirBuilder::Operand
EVMMirBuilder::handleExtCodeSize(Operand Address) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  return callRuntimeFor<uint64_t, const uint8_t *>(
      RuntimeFunctions.GetExtCodeSize, Address);
}

typename EVMMirBuilder::Operand
EVMMirBuilder::handleExtCodeHash(Operand Address) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  return callRuntimeFor<const uint8_t *, const uint8_t *>(
      RuntimeFunctions.GetExtCodeHash, Address);
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
  normalizeOperandU64(Index);
  return callRuntimeFor<const uint8_t *, uint64_t>(RuntimeFunctions.GetBlobHash,
                                                   Index);
}

typename EVMMirBuilder::Operand EVMMirBuilder::handleBlobBaseFee() {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  return callRuntimeFor(RuntimeFunctions.GetBlobBaseFee);
}

typename EVMMirBuilder::Operand EVMMirBuilder::handleMSize() {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  return callRuntimeFor(RuntimeFunctions.GetMSize);
}
typename EVMMirBuilder::Operand
EVMMirBuilder::handleMLoad(Operand AddrComponents) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  normalizeOperandU64(AddrComponents);
  return callRuntimeFor<const intx::uint256 *, uint64_t>(
      RuntimeFunctions.GetMLoad, AddrComponents);
}
void EVMMirBuilder::handleMStore(Operand AddrComponents,
                                 Operand ValueComponents) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  normalizeOperandU64(AddrComponents);
  callRuntimeFor<void, uint64_t, const intx::uint256 &>(
      RuntimeFunctions.SetMStore, AddrComponents, ValueComponents);
}
void EVMMirBuilder::handleMStore8(Operand AddrComponents,
                                  Operand ValueComponents) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  normalizeOperandU64(AddrComponents);
  callRuntimeFor<void, uint64_t, const intx::uint256 &>(
      RuntimeFunctions.SetMStore8, AddrComponents, ValueComponents);
}
void EVMMirBuilder::handleMCopy(Operand DestAddrComponents,
                                Operand SrcAddrComponents,
                                Operand LengthComponents) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();

  auto IsConstZero = [](const Operand &Op) -> bool {
    if (!Op.isConstant()) {
      return false;
    }
    const auto &Val = Op.getConstValue();
    return Val[0] == 0 && Val[1] == 0 && Val[2] == 0 && Val[3] == 0;
  };

  if (IsConstZero(LengthComponents)) {
    return;
  }

  MBasicBlock *SkipCopyBB = nullptr;
  if (!LengthComponents.isConstant()) {
    MType *I64Type = EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);
    MInstruction *Zero = createIntConstInstruction(I64Type, 0);
    U256Inst Parts = extractU256Operand(LengthComponents);
    MInstruction *IsZero0 = createInstruction<CmpInstruction>(
        false, CmpInstruction::Predicate::ICMP_EQ, &Ctx.I64Type, Parts[0],
        Zero);
    MInstruction *IsZero1 = createInstruction<CmpInstruction>(
        false, CmpInstruction::Predicate::ICMP_EQ, &Ctx.I64Type, Parts[1],
        Zero);
    MInstruction *IsZero2 = createInstruction<CmpInstruction>(
        false, CmpInstruction::Predicate::ICMP_EQ, &Ctx.I64Type, Parts[2],
        Zero);
    MInstruction *IsZero3 = createInstruction<CmpInstruction>(
        false, CmpInstruction::Predicate::ICMP_EQ, &Ctx.I64Type, Parts[3],
        Zero);

    MInstruction *Cond01 = createInstruction<BinaryInstruction>(
        false, OP_and, I64Type, IsZero0, IsZero1);
    MInstruction *Cond23 = createInstruction<BinaryInstruction>(
        false, OP_and, I64Type, IsZero2, IsZero3);
    MInstruction *IsAllZero = createInstruction<BinaryInstruction>(
        false, OP_and, I64Type, Cond01, Cond23);

    MBasicBlock *CopyBB = createBasicBlock();
    SkipCopyBB = createBasicBlock();
    createInstruction<BrIfInstruction>(true, Ctx, IsAllZero, SkipCopyBB,
                                       CopyBB);
    addSuccessor(SkipCopyBB);
    addSuccessor(CopyBB);
    setInsertBlock(CopyBB);
  }

  normalizeOperandU64(DestAddrComponents);
  normalizeOperandU64(SrcAddrComponents);
  normalizeOperandU64(LengthComponents);
  callRuntimeFor<void, uint64_t, uint64_t, uint64_t>(
      RuntimeFunctions.SetMCopy, DestAddrComponents, SrcAddrComponents,
      LengthComponents);

  if (SkipCopyBB != nullptr) {
    createInstruction<BrInstruction>(true, Ctx, SkipCopyBB);
    addSuccessor(SkipCopyBB);
    setInsertBlock(SkipCopyBB);
  }
}

template <size_t NumTopics, typename... TopicArgs>
void EVMMirBuilder::handleLogWithTopics(Operand OffsetOp, Operand SizeOp,
                                        TopicArgs... Topics) {
  ZEN_STATIC_ASSERT(NumTopics <= 4);
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  normalizeOperandU64(OffsetOp);
  normalizeOperandU64(SizeOp);

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
}

typename EVMMirBuilder::Operand
EVMMirBuilder::handleCreate(Operand ValueOp, Operand OffsetOp, Operand SizeOp) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  normalizeOperandU64(OffsetOp);
  normalizeOperandU64(SizeOp);
  return callRuntimeFor<const uint8_t *, intx::uint128, uint64_t, uint64_t>(
      RuntimeFunctions.HandleCreate, ValueOp, OffsetOp, SizeOp);
}

typename EVMMirBuilder::Operand EVMMirBuilder::handleCreate2(Operand ValueOp,
                                                             Operand OffsetOp,
                                                             Operand SizeOp,
                                                             Operand SaltOp) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  normalizeOperandU64(OffsetOp);
  normalizeOperandU64(SizeOp);
  return callRuntimeFor<const uint8_t *, intx::uint128, uint64_t, uint64_t,
                        const uint8_t *>(RuntimeFunctions.HandleCreate2,
                                         ValueOp, OffsetOp, SizeOp, SaltOp);
}

typename EVMMirBuilder::Operand
EVMMirBuilder::handleCall(Operand GasOp, Operand ToAddrOp, Operand ValueOp,
                          Operand ArgsOffsetOp, Operand ArgsSizeOp,
                          Operand RetOffsetOp, Operand RetSizeOp) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  normalizeOperandU64(GasOp);
  normalizeOperandU64(ArgsOffsetOp);
  normalizeOperandU64(ArgsSizeOp);
  normalizeOperandU64(RetOffsetOp);
  normalizeOperandU64(RetSizeOp);

  return callRuntimeFor<uint64_t, uint64_t, const uint8_t *, intx::uint128,
                        uint64_t, uint64_t, uint64_t, uint64_t>(
      RuntimeFunctions.HandleCall, GasOp, ToAddrOp, ValueOp, ArgsOffsetOp,
      ArgsSizeOp, RetOffsetOp, RetSizeOp);
}

typename EVMMirBuilder::Operand
EVMMirBuilder::handleCallCode(Operand GasOp, Operand ToAddrOp, Operand ValueOp,
                              Operand ArgsOffsetOp, Operand ArgsSizeOp,
                              Operand RetOffsetOp, Operand RetSizeOp) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  normalizeOperandU64(GasOp);
  normalizeOperandU64(ArgsOffsetOp);
  normalizeOperandU64(ArgsSizeOp);
  normalizeOperandU64(RetOffsetOp);
  normalizeOperandU64(RetSizeOp);

  return callRuntimeFor<uint64_t, uint64_t, const uint8_t *, intx::uint128,
                        uint64_t, uint64_t, uint64_t, uint64_t>(
      RuntimeFunctions.HandleCallCode, GasOp, ToAddrOp, ValueOp, ArgsOffsetOp,
      ArgsSizeOp, RetOffsetOp, RetSizeOp);
}

void EVMMirBuilder::handleReturn(Operand MemOffsetComponents,
                                 Operand LengthComponents) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  normalizeOperandU64(MemOffsetComponents);
  normalizeOperandU64(LengthComponents);
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
  normalizeOperandU64(GasOp);
  normalizeOperandU64(ArgsOffsetOp);
  normalizeOperandU64(ArgsSizeOp);
  normalizeOperandU64(RetOffsetOp);
  normalizeOperandU64(RetSizeOp);

  return callRuntimeFor<uint64_t, uint64_t, const uint8_t *, uint64_t, uint64_t,
                        uint64_t, uint64_t>(RuntimeFunctions.HandleDelegateCall,
                                            GasOp, ToAddrOp, ArgsOffsetOp,
                                            ArgsSizeOp, RetOffsetOp, RetSizeOp);
}

typename EVMMirBuilder::Operand
EVMMirBuilder::handleStaticCall(Operand GasOp, Operand ToAddrOp,
                                Operand ArgsOffsetOp, Operand ArgsSizeOp,
                                Operand RetOffsetOp, Operand RetSizeOp) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  normalizeOperandU64(GasOp);
  normalizeOperandU64(ArgsOffsetOp);
  normalizeOperandU64(ArgsSizeOp);
  normalizeOperandU64(RetOffsetOp);
  normalizeOperandU64(RetSizeOp);

  return callRuntimeFor<uint64_t, uint64_t, const uint8_t *, uint64_t, uint64_t,
                        uint64_t, uint64_t>(RuntimeFunctions.HandleStaticCall,
                                            GasOp, ToAddrOp, ArgsOffsetOp,
                                            ArgsSizeOp, RetOffsetOp, RetSizeOp);
}

void EVMMirBuilder::handleRevert(Operand OffsetOp, Operand SizeOp) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  normalizeOperandU64(OffsetOp);
  normalizeOperandU64(SizeOp);
  callRuntimeFor<void, uint64_t, uint64_t>(RuntimeFunctions.SetRevert, OffsetOp,
                                           SizeOp);
}

void EVMMirBuilder::handleInvalid() {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  callRuntimeFor(RuntimeFunctions.HandleInvalid);
}
typename EVMMirBuilder::Operand
EVMMirBuilder::handleSLoad(Operand KeyComponents) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  return callRuntimeFor<const intx::uint256 *, const intx::uint256 &>(
      RuntimeFunctions.GetSLoad, KeyComponents);
}
void EVMMirBuilder::handleSStore(Operand KeyComponents,
                                 Operand ValueComponents) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  callRuntimeFor<void, const intx::uint256 &, const intx::uint256 &>(
      RuntimeFunctions.SetSStore, KeyComponents, ValueComponents);
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
}

typename EVMMirBuilder::Operand
EVMMirBuilder::handleKeccak256(Operand OffsetComponents,
                               Operand LengthComponents) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  normalizeOperandU64(OffsetComponents);
  normalizeOperandU64(LengthComponents);
  return callRuntimeFor<const uint8_t *, uint64_t, uint64_t>(
      RuntimeFunctions.GetKeccak256, OffsetComponents, LengthComponents);
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
  ZEN_ASSERT(PtrType->isPointer());

  Variable *PtrVar = storeInstructionInTemp(U256Instr, PtrType);
  const int32_t Offsets[] = {0, 8, 16, 24};
  MPointerType *U64PtrType = MPointerType::create(Ctx, Ctx.I64Type);

  for (int I = 0; I < static_cast<int>(EVM_ELEMENTS_COUNT); ++I) {
    MInstruction *BaseValue = loadVariable(PtrVar);
    MInstruction *BaseAddr = BaseValue;

    if (BaseValue->getType()->isPointer()) {
      BaseAddr = createInstruction<ConversionInstruction>(
          false, OP_ptrtoint, &Ctx.I64Type, BaseValue);
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

  // Precompute constants used for 64-bit byte swap
  MInstruction *Shift8 = createIntConstInstruction(I64Type, 8);
  MInstruction *Shift16 = createIntConstInstruction(I64Type, 16);
  MInstruction *Shift32 = createIntConstInstruction(I64Type, 32);
  MInstruction *MaskFF00FF00FF00FF00 =
      createIntConstInstruction(I64Type, 0xFF00FF00FF00FF00ULL);
  MInstruction *Mask00FF00FF00FF00FF =
      createIntConstInstruction(I64Type, 0x00FF00FF00FF00FFULL);
  MInstruction *MaskFFFF0000FFFF0000 =
      createIntConstInstruction(I64Type, 0xFFFF0000FFFF0000ULL);
  MInstruction *Mask0000FFFF0000FFFF =
      createIntConstInstruction(I64Type, 0x0000FFFF0000FFFFULL);

  auto ByteSwap64 = [&](MInstruction *Value) -> MInstruction * {
    // Perform 64-bit byte swap using standard mask/shift cascades
    MInstruction *LoShift = createInstruction<BinaryInstruction>(
        false, OP_shl, I64Type, Value, Shift8);
    MInstruction *HiShift = createInstruction<BinaryInstruction>(
        false, OP_ushr, I64Type, Value, Shift8);
    MInstruction *LowMasked = createInstruction<BinaryInstruction>(
        false, OP_and, I64Type, LoShift, MaskFF00FF00FF00FF00);
    MInstruction *HighMasked = createInstruction<BinaryInstruction>(
        false, OP_and, I64Type, HiShift, Mask00FF00FF00FF00FF);
    MInstruction *Stage1 = createInstruction<BinaryInstruction>(
        false, OP_or, I64Type, LowMasked, HighMasked);

    MInstruction *LowShift16 = createInstruction<BinaryInstruction>(
        false, OP_shl, I64Type, Stage1, Shift16);
    MInstruction *HighShift16 = createInstruction<BinaryInstruction>(
        false, OP_ushr, I64Type, Stage1, Shift16);
    MInstruction *LowMasked16 = createInstruction<BinaryInstruction>(
        false, OP_and, I64Type, LowShift16, MaskFFFF0000FFFF0000);
    MInstruction *HighMasked16 = createInstruction<BinaryInstruction>(
        false, OP_and, I64Type, HighShift16, Mask0000FFFF0000FFFF);
    MInstruction *Stage2 = createInstruction<BinaryInstruction>(
        false, OP_or, I64Type, LowMasked16, HighMasked16);

    MInstruction *LowShift32 = createInstruction<BinaryInstruction>(
        false, OP_shl, I64Type, Stage2, Shift32);
    MInstruction *HighShift32 = createInstruction<BinaryInstruction>(
        false, OP_ushr, I64Type, Stage2, Shift32);
    return createInstruction<BinaryInstruction>(false, OP_or, I64Type,
                                                LowShift32, HighShift32);
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
    throw std::runtime_error("Unsupported EVM binary opcode: " +
                             std::to_string(static_cast<int>(BinOpr)));
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

void EVMMirBuilder::normalizeOperandU64(Operand &Param) {
  if (Param.getType() != EVMType::UINT256) {
    return;
  }
  if (Param.isConstant()) {
    normalizeOperandU64Const(Param);
  } else {
    normalizeOperandU64NonConst(Param);
  }
}

void EVMMirBuilder::normalizeOperandU64Const(Operand &Param) {
  const auto &C = Param.getConstValue();
  bool FitsU64 = (C[1] == 0 && C[2] == 0 && C[3] == 0);

  MType *I64Type = EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);
  if (!FitsU64) {
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

void EVMMirBuilder::normalizeOperandU64NonConst(Operand &Param) {
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
  MBasicBlock *TrapBB = getOrCreateExceptionSetBB(ErrorCode::GasLimitExceeded);
  MBasicBlock *ContinueBB = createBasicBlock();
  createInstruction<BrIfInstruction>(true, Ctx, IsInvalid, TrapBB, ContinueBB);
  addUniqueSuccessor(TrapBB);
  addSuccessor(ContinueBB);
  setInsertBlock(ContinueBB);

  // Normalize Param to U256: [Selected, 0, 0, 0]
  U256Inst NewVal = {Parts[0], Zero, Zero, Zero};
  Param = Operand(NewVal, EVMType::UINT256);
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
  constexpr bool IS_VOID_RET = std::is_same_v<RetType, void>;

  MInstruction *CallInstr = createInstruction<ICallInstruction>(
      IS_VOID_RET, ReturnType, FuncAddrInst,
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
  constexpr bool IS_VOID_RET = std::is_same_v<RetType, void>;
  MInstruction *CallInstr =
      createInstruction<ICallInstruction>(IS_VOID_RET, ReturnType, FuncAddrInst,
                                          llvm::ArrayRef<MInstruction *>{Args});

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
  normalizeOperandU64(OffsetComponents);
  normalizeOperandU64(SizeComponents);
  callRuntimeFor<void, uint64_t, uint64_t, uint64_t>(
      RuntimeFunctions.SetCallDataCopy, DestOffsetComponents, OffsetComponents,
      SizeComponents);
}

void EVMMirBuilder::handleExtCodeCopy(Operand AddressComponents,
                                      Operand DestOffsetComponents,
                                      Operand OffsetComponents,
                                      Operand SizeComponents) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  normalizeOperandU64(DestOffsetComponents);
  normalizeOperandU64(OffsetComponents);
  normalizeOperandU64(SizeComponents);
  callRuntimeFor<void, const uint8_t *, uint64_t, uint64_t, uint64_t>(
      RuntimeFunctions.SetExtCodeCopy, AddressComponents, DestOffsetComponents,
      OffsetComponents, SizeComponents);
}

void EVMMirBuilder::handleReturnDataCopy(Operand DestOffsetComponents,
                                         Operand OffsetComponents,
                                         Operand SizeComponents) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  normalizeOperandU64(DestOffsetComponents);
  normalizeOperandU64(OffsetComponents);
  normalizeOperandU64(SizeComponents);
  callRuntimeFor<void, uint64_t, uint64_t, uint64_t>(
      RuntimeFunctions.SetReturnDataCopy, DestOffsetComponents,
      OffsetComponents, SizeComponents);
}

typename EVMMirBuilder::Operand EVMMirBuilder::handleReturnDataSize() {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  return callRuntimeFor<uint64_t>(RuntimeFunctions.GetReturnDataSize);
}

} // namespace COMPILER
