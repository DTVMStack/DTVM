// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "compiler/evm_frontend/evm_mir_compiler.h"
#include "action/evm_bytecode_visitor.h"
#include "compiler/evm_frontend/evm_imported.h"
#include "compiler/mir/basic_block.h"
#include "compiler/mir/constants.h"
#include "compiler/mir/function.h"
#include "compiler/mir/instructions.h"
#include "compiler/mir/type.h"
#include "evmc/evmc.hpp"
#include "evmc/instructions.h"
#include "runtime/evm_instance.h"

namespace COMPILER {

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

// ==================== EVMFrontendContext Implementation ====================

EVMFrontendContext::EVMFrontendContext() {
  // Initialize basic DMIR context
}

EVMFrontendContext::EVMFrontendContext(const EVMFrontendContext &OtherCtx)
    : CompileContext(OtherCtx), Bytecode(OtherCtx.Bytecode),
      BytecodeSize(OtherCtx.BytecodeSize) {}

// ==================== EVMMirBuilder Implementation ====================

EVMMirBuilder::EVMMirBuilder(CompilerContext &Context, MFunction &MFunc)
    : Ctx(Context), CurFunc(&MFunc) {}

bool EVMMirBuilder::compile(CompilerContext *Context) {
  EVMByteCodeVisitor<EVMMirBuilder> Visitor(*this, Context);
  return Visitor.compile();
}

void EVMMirBuilder::initEVM(CompilerContext *Context) {
  // Create entry basic block
  MBasicBlock *EntryBB = createBasicBlock();
  setInsertBlock(EntryBB);

  // Initialize instance address for JIT function calls
  // Get EVM instance pointer from function parameter 0 (like WASM)
  MType *I64Type = EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);
  InstanceAddr = createInstruction<ConversionInstruction>(
      false, OP_ptrtoint, I64Type,
      createInstruction<DreadInstruction>(false, createVoidPtrType(), 0));

  // Initialize program counter
  PC = 0;
}

void EVMMirBuilder::finalizeEVMBase() {
  // Ensure all basic blocks are properly terminated
  // TODO: invalid interface: MBasicBlock::isTerminated()
  // if (CurBB && !CurBB->isTerminated()) {
  //   // Add implicit return if not terminated
  //   createInstruction<ReturnInstruction>(true, &Ctx.VoidType);
  // }
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

EVMMirBuilder::Operand EVMMirBuilder::handlePush(const Bytes &Data) {
  U256Value Value = bytesToU256(Data);
  return Operand(Value);
}

EVMMirBuilder::Operand EVMMirBuilder::handleDup(uint8_t Index) {
  return peekOperand(Index - 1);
}

void EVMMirBuilder::handleSwap(uint8_t Index) {
  if (OperandStack.size() < Index + 1) {
    throw getError(common::ErrorCode::EVMStackUnderflow);
  }

  std::vector<Operand> Temp;
  for (uint8_t I = 0; I <= Index; ++I) {
    Temp.push_back(popOperand());
  }
  std::swap(Temp[0], Temp[Index]);

  for (int I = Index; I >= 0; --I) {
    pushOperand(Temp[I]);
  }
}

void EVMMirBuilder::handlePop() { popOperand(); }

EVMMirBuilder::Operand EVMMirBuilder::popOperand() {
  if (OperandStack.empty()) {
    throw getError(common::ErrorCode::EVMStackUnderflow);
  }
  Operand Result = OperandStack.top();
  OperandStack.pop();
  return Result;
}

EVMMirBuilder::Operand EVMMirBuilder::peekOperand(size_t Index) const {
  if (OperandStack.size() <= Index) {
    throw getError(common::ErrorCode::EVMStackUnderflow);
  }

  std::stack<Operand> StackCopy = OperandStack;
  size_t Depth = StackCopy.size() - Index - 1;
  while (Depth--) {
    StackCopy.pop();
  }
  return StackCopy.top();
}

// ==================== Control Flow Instruction Handlers ====================

void EVMMirBuilder::handleJump(Operand Dest) {
  MInstruction *DestInstr = extractOperand(Dest);

  // Create jump destination basic block
  MBasicBlock *JumpBB = createBasicBlock();

  // Create unconditional branch
  createInstruction<BrInstruction>(true, Ctx, JumpBB);
  addSuccessor(JumpBB);

  setInsertBlock(JumpBB);
}

void EVMMirBuilder::handleJumpI(Operand Dest, Operand Cond) {
  MInstruction *DestInstr = extractOperand(Dest);
  MInstruction *CondInstr = extractOperand(Cond);

  // Create conditional branch
  MBasicBlock *ThenBB = createBasicBlock();
  MBasicBlock *ElseBB = createBasicBlock();

  createInstruction<BrIfInstruction>(true, Ctx, CondInstr, ThenBB, ElseBB);
  addSuccessor(ThenBB);
  addSuccessor(ElseBB);

  setInsertBlock(ThenBB);
}

void EVMMirBuilder::handleJumpDest() {
  // JUMPDEST creates a valid jump target
  // In DMIR, this is handled by basic block boundaries
}

// ==================== Arithmetic Instruction Handlers ====================

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
  Result[0] = createInstruction<ConversionInstruction>(false, OP_uext,
                                                       MirI64Type, CmpResult);
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
  Result[0] = createInstruction<ConversionInstruction>(false, OP_uext,
                                                       MirI64Type, AndResult);
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

  for (int I = EVM_ELEMENTS_COUNT - 1; I >= 0; --I) {
    ZEN_ASSERT(LHS[I] && RHS[I]);

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

    MInstruction *CompResult = createInstruction<CmpInstruction>(
        false, LTPredicate, ResultType, LHS[I], RHS[I]);
    MInstruction *EqResult = createInstruction<CmpInstruction>(
        false, EQPredicate, ResultType, LHS[I], RHS[I]);

    if (FinalResult == nullptr) {
      FinalResult = CompResult;
    } else {
      // FinalResult = EqResult_prev ? CompResult : FinalResult
      FinalResult = createInstruction<SelectInstruction>(
          false, ResultType, EqResult, CompResult, FinalResult);
    }

    // Update equality check for next iteration
    if (I > 0) {
      MInstruction *NotEq = createInstruction<BinaryInstruction>(
          false, OP_xor, ResultType, EqResult, One);
      // Skip remaining iterations by breaking the loop if not equal
      MInstruction *IsNotEqual = createInstruction<BinaryInstruction>(
          false, OP_and, ResultType, NotEq, One);
      // Use select to keep current result if not equal, continue if equal
      FinalResult = createInstruction<SelectInstruction>(
          false, ResultType, IsNotEqual, CompResult, FinalResult);
    }
  }

  ZEN_ASSERT(FinalResult);
  Result[0] = createInstruction<ConversionInstruction>(false, OP_uext,
                                                       MirI64Type, FinalResult);
  for (size_t I = 1; I < EVM_ELEMENTS_COUNT; ++I) {
    Result[I] = Zero;
  }

  return Result;
}

EVMMirBuilder::Operand EVMMirBuilder::handleNot(const Operand &LHSOp) {
  U256Inst Result = {};
  U256Inst LHS = extractU256Operand(LHSOp);

  MType *MirI64Type =
      EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);

  for (size_t I = 0; I < EVM_ELEMENTS_COUNT; ++I) {
    Result[I] = createInstruction<NotInstruction>(false, MirI64Type, LHS[I]);
  }

  return Operand(Result, EVMType::UINT256);
}

// ==================== Environment Instruction Handlers ====================

typename EVMMirBuilder::Operand EVMMirBuilder::handlePC() {
  MType *UInt64Type =
      EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);
  MConstant *PCConstant = MConstantInt::get(Ctx, *UInt64Type, PC);

  MInstruction *Result =
      createInstruction<ConstantInstruction>(false, UInt64Type, *PCConstant);

  return Operand(Result, EVMType::UINT64);
}

typename EVMMirBuilder::Operand EVMMirBuilder::handleGas() {
  // For now, return a placeholder gas value
  // In a full implementation, this would access the execution context
  MType *UInt64Type =
      EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);
  MConstant *GasConstant = MConstantInt::get(Ctx, *UInt64Type, 1000000);

  MInstruction *Result =
      createInstruction<ConstantInstruction>(false, UInt64Type, *GasConstant);

  return Operand(Result, EVMType::UINT64);
}

typename EVMMirBuilder::Operand EVMMirBuilder::handleAddress() {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  return callRuntimeForBytes32(RuntimeFunctions.GetAddress);
}

typename EVMMirBuilder::Operand EVMMirBuilder::handleOrigin() {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  return callRuntimeForBytes32(RuntimeFunctions.GetOrigin);
}

typename EVMMirBuilder::Operand EVMMirBuilder::handleCaller() {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  return callRuntimeForBytes32(RuntimeFunctions.GetCaller);
}

typename EVMMirBuilder::Operand EVMMirBuilder::handleCallValue() {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  return callRuntimeForBytes32(RuntimeFunctions.GetCallValue);
}

typename EVMMirBuilder::Operand EVMMirBuilder::handleGasPrice() {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  return callRuntimeForU256(RuntimeFunctions.GetGasPrice);
}

typename EVMMirBuilder::Operand EVMMirBuilder::handleCallDataSize() {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  return callRuntimeForSize(RuntimeFunctions.GetCallDataSize);
}

typename EVMMirBuilder::Operand EVMMirBuilder::handleCodeSize() {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  return callRuntimeForSize(RuntimeFunctions.GetCodeSize);
}

// ==================== Private Helper Methods ====================

MInstruction *EVMMirBuilder::extractOperand(const Operand &Opnd) {
  if (Opnd.getInstr()) {
    return Opnd.getInstr();
  }

  if (Opnd.isU256MultiComponent()) {
    // For multi-component U256, we need to return a representative instruction
    // For now, return the low component as the primary representative
    // In a full implementation, this might need to be handled differently
    // depending on the context where extractOperand is called
    const auto &Components = Opnd.getU256Components();
    return Components[0]; // Return low component as primary
  }

  if (Opnd.getVar()) {
    // Read from variable with appropriate type handling
    Variable *Var = Opnd.getVar();
    MType *Type = EVMFrontendContext::getMIRTypeFromEVMType(Opnd.getType());

    // For UINT256, use EVMU256Type semantic awareness
    if (Opnd.getType() == EVMType::UINT256) {
      zen::common::EVMU256Type *U256Type = EVMFrontendContext::getEVMU256Type();
      // Note: U256Type provides semantic context for 256-bit operations

      // Check if this is a multi-component variable (should be handled
      // differently) For now, treat as single variable read
    }

    return createInstruction<DreadInstruction>(false, Type, Var->getVarIdx());
  }

  // Handle multi-component variable reads for U256
  if (Opnd.isU256MultiComponent() && Opnd.getType() == EVMType::UINT256) {
    // For multi-component variables, return the low component's read
    // instruction The full handling should be done by extractU256Components
    const auto &VarComponents = Opnd.getU256VarComponents();
    MType *I64Type = EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);
    return createInstruction<DreadInstruction>(false, I64Type,
                                               VarComponents[0]->getVarIdx());
  }

  ZEN_UNREACHABLE();
}

ConstantInstruction *
EVMMirBuilder::createUInt256ConstInstruction(const intx::uint256 &V) {
  // This method now returns just the low component instruction
  // For full U256 creation, use handlePush or createU256FromComponents

  // Get EVMU256Type for semantic awareness
  zen::common::EVMU256Type *U256Type = EVMFrontendContext::getEVMU256Type();

  MType *I64Type = EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);
  // Use lower 64 bits as the primary component
  uint64_t Value = static_cast<uint64_t>(V & 0xFFFFFFFFFFFFFFFFULL);
  MConstant *Constant = MConstantInt::get(Ctx, *I64Type, Value);
  return createInstruction<ConstantInstruction>(false, I64Type, *Constant);
}

typename EVMMirBuilder::Operand
EVMMirBuilder::createU256ConstOperand(const intx::uint256 &V) {
  // Get EVMU256Type to guide proper component creation
  zen::common::EVMU256Type *U256Type = EVMFrontendContext::getEVMU256Type();
  MType *I64Type = EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);

  // Use EVMU256Type's element count and structure
  uint64_t Components[U256Type->getElementsCount()];
  for (size_t I = 0; I < U256Type->getElementsCount(); ++I) {
    Components[I] =
        static_cast<uint64_t>((V >> (I * 64)) & 0xFFFFFFFFFFFFFFFFULL);
  }

  // Create constant instructions based on EVMU256Type's inner types
  U256Inst ComponentInstrs;
  for (size_t I = 0; I < U256Type->getElementsCount(); ++I) {
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

  return Result;
}

// ==================== EVMU256 Helper Methods ====================

typename EVMMirBuilder::Operand
EVMMirBuilder::createU256FromComponents(Operand Low, Operand MidLow,
                                        Operand MidHigh, Operand High) {
  // Extract MInstructions from the component operands
  U256Inst ComponentInstrs;
  ComponentInstrs[0] = extractOperand(Low);     // Low (bits 0-63)
  ComponentInstrs[1] = extractOperand(MidLow);  // Mid-low (bits 64-127)
  ComponentInstrs[2] = extractOperand(MidHigh); // Mid-high (bits 128-191)
  ComponentInstrs[3] = extractOperand(High);    // High (bits 192-255)

  return Operand(ComponentInstrs, EVMType::UINT256);
}

EVMMirBuilder::U256Value EVMMirBuilder::bytesToU256(const Bytes &Data) {
  return createU256FromBytes(Data.data(), Data.size());
}

///
/// The U256 value is decomposed into four 64-bit components arranged in
/// **little-endian** order. That is:
/// - Index 0: Low (least significant) 64 bits
/// - Index 1: Mid-low 64 bits
/// - Index 2: Mid-high 64 bits
/// - Index 3: High (most significant) 64 bits
///
/// For example, if the U256 value is represented as:
///   [High][Mid-high][Mid-low][Low]
/// then this function returns them in the order: [Low, Mid-low, Mid-high,
/// High].
///
/// If the input operand is a legacy single-component U256, only the low part
/// will be set; the other parts are initialized to zero.
///
std::array<typename EVMMirBuilder::Operand, 4>
EVMMirBuilder::extractU256Components(Operand U256Op) {
  if (U256Op.isU256MultiComponent()) {
    try {
      // Try to get instruction components first
      const auto &Components = U256Op.getU256Components();
      return {
          Operand(Components[0], EVMType::UINT64), // Low
          Operand(Components[1], EVMType::UINT64), // Mid-low
          Operand(Components[2], EVMType::UINT64), // Mid-high
          Operand(Components[3], EVMType::UINT64)  // High
      };
    } catch (...) {
      // Multi-component variable operand
      const auto &VarComponents = U256Op.getU256VarComponents();
      return {
          Operand(VarComponents[0], EVMType::UINT64), // Low
          Operand(VarComponents[1], EVMType::UINT64), // Mid-low
          Operand(VarComponents[2], EVMType::UINT64), // Mid-high
          Operand(VarComponents[3], EVMType::UINT64)  // High
      };
    }
  }

  // Legacy single-component U256, create 4 components where only low is set
  MInstruction *SingleInstr = extractOperand(U256Op);
  MType *I64Type = EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);

  // Create zero constants for the higher components
  MConstant *ZeroConstant = MConstantInt::get(Ctx, *I64Type, 0);
  MInstruction *ZeroInstr =
      createInstruction<ConstantInstruction>(false, I64Type, *ZeroConstant);

  return {
      Operand(SingleInstr, EVMType::UINT64), // Low component
      Operand(ZeroInstr, EVMType::UINT64),   // Mid-low = 0
      Operand(ZeroInstr, EVMType::UINT64),   // Mid-high = 0
      Operand(ZeroInstr, EVMType::UINT64)    // High = 0
  };
}

typename EVMMirBuilder::Operand
EVMMirBuilder::convertSingleInstrToU256Operand(MInstruction *SingleInstr) {
  // Convert single instruction to U256 with little-endian storage
  U256Inst Result = {};
  MType *I64Type = EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);

  // Convert the single instruction result to I64 and place it in low component
  Result[0] = createInstruction<ConversionInstruction>(false, OP_uext, I64Type,
                                                       SingleInstr);

  // Fill the remaining components with zeros
  MInstruction *Zero = createIntConstInstruction(I64Type, 0);
  for (size_t I = 1; I < EVM_ELEMENTS_COUNT; ++I) {
    Result[I] = Zero;
  }

  return Operand(Result, EVMType::UINT256);
}

typename EVMMirBuilder::Operand
EVMMirBuilder::convertU256InstrToU256Operand(MInstruction *U256Instr) {
  // Convert single U256 instruction (intx::uint256 from host interface)
  // to EVM's 4-component U256 representation: [low, mid_low, mid_high, high]
  //
  // EVM uses little-endian storage for U256:
  // - Component 0: bits 0-63   (lowest 64 bits)
  // - Component 1: bits 64-127
  // - Component 2: bits 128-191
  // - Component 3: bits 192-255 (highest 64 bits)

  U256Inst Result = {};
  MType *I64Type = EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);
  MType *U256Type = U256Instr->getType();

  // Component 0: Direct truncation for low 64 bits
  Result[0] = createInstruction<ConversionInstruction>(false, OP_trunc, I64Type,
                                                       U256Instr);

  // Components 1-3: Loop through bit shifts
  const uint64_t ShiftAmounts[] = {64, 128, 192};
  for (int I = 1; I < 4; ++I) {
    MInstruction *ShiftAmount =
        createIntConstInstruction(U256Type, ShiftAmounts[I - 1]);
    MInstruction *Shifted = createInstruction<BinaryInstruction>(
        false, OP_ushr, U256Type, U256Instr, ShiftAmount);
    Result[I] = createInstruction<ConversionInstruction>(false, OP_trunc,
                                                         I64Type, Shifted);
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

  // Load 32 bytes from memory pointer and convert to 4x64-bit components
  // Each component loads 8 bytes (64 bits) with big-endian byte ordering (EVM
  // standard)
  for (int I = 0; I < 4; ++I) {
    // Calculate offset for each 8-byte component (EVM uses big-endian: high
    // bytes first) Component 0 gets bytes 24-31 (low 64 bits), Component 3 gets
    // bytes 0-7 (high 64 bits)
    MInstruction *Offset = createIntConstInstruction(I64Type, (3 - I) * 8);
    MInstruction *ComponentPtr = createInstruction<BinaryInstruction>(
        false, OP_add, Bytes32Ptr->getType(), Bytes32Ptr, Offset);

    // Load 8 bytes as I64 (needs endianness handling for EVM big-endian format)
    Result[I] =
        createInstruction<LoadInstruction>(false, I64Type, ComponentPtr);
  }

  return Operand(Result, EVMType::UINT256);
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

typename EVMMirBuilder::Operand
EVMMirBuilder::callRuntimeForU256(U256Fn RuntimeFunc) {
  MType *I64Type = EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);
  MType *U256Type = EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT256);

  // Get function address and instance pointer
  uint64_t FuncAddr = getFunctionAddress(RuntimeFunc);
  MInstruction *FuncAddrInst = createIntConstInstruction(I64Type, FuncAddr);
  MInstruction *InstancePtr = getCurrentInstancePointer();

  MInstruction *CallInstr = createInstruction<ICallInstruction>(
      false, U256Type, FuncAddrInst,
      llvm::ArrayRef<MInstruction *>(InstancePtr));

  // Convert U256 result to 4-component representation
  return convertU256InstrToU256Operand(CallInstr);
}

typename EVMMirBuilder::Operand
EVMMirBuilder::callRuntimeForSize(SizeFn RuntimeFunc) {
  MType *I64Type = EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);

  // Get function address and instance pointer
  uint64_t FuncAddr = getFunctionAddress(RuntimeFunc);
  MInstruction *FuncAddrInst = createIntConstInstruction(I64Type, FuncAddr);
  MInstruction *InstancePtr = getCurrentInstancePointer();

  MInstruction *CallInstr = createInstruction<ICallInstruction>(
      false, I64Type, FuncAddrInst,
      llvm::ArrayRef<MInstruction *>(InstancePtr));

  // Convert size to U256 format (size in low component, zeros in high)
  return convertSingleInstrToU256Operand(CallInstr);
}

typename EVMMirBuilder::Operand
EVMMirBuilder::callRuntimeForBytes32(Bytes32Fn RuntimeFunc) {
  MType *I64Type = EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);
  MType *Bytes32Type =
      EVMFrontendContext::getMIRTypeFromEVMType(EVMType::BYTES32);

  // Get function address and instance pointer
  uint64_t FuncAddr = getFunctionAddress(RuntimeFunc);
  MInstruction *FuncAddrInst = createIntConstInstruction(I64Type, FuncAddr);
  MInstruction *InstancePtr = getCurrentInstancePointer();

  MInstruction *CallInstr = createInstruction<ICallInstruction>(
      false, Bytes32Type, FuncAddrInst,
      llvm::ArrayRef<MInstruction *>(InstancePtr));

  // Return as BYTES32 operand (pointer to existing memory)
  return Operand(CallInstr, EVMType::BYTES32);
}

MInstruction *EVMMirBuilder::getCurrentInstancePointer() {
  ZEN_ASSERT(InstanceAddr);
  // Convert instance address back to pointer type
  return createInstruction<ConversionInstruction>(
      false, OP_inttoptr, createVoidPtrType(), InstanceAddr);
}

} // namespace COMPILER
