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
  // Note: After padding 33 bytes 0x00, normal termination is sufficient
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
  U256Inst DestComponents = extractU256Operand(Dest);
  // Note: Extracted lowest 64 bits as jump destination,
  // but not used in MIR - address resolution handled by backend
  MInstruction *DestAddr = DestComponents[0];

  // Create jump destination basic block
  MBasicBlock *JumpBB = createBasicBlock();

  // Create unconditional branch
  createInstruction<BrInstruction>(true, Ctx, JumpBB);
  addSuccessor(JumpBB);

  setInsertBlock(JumpBB);
}

void EVMMirBuilder::handleJumpI(Operand Dest, Operand Cond) {
  U256Inst DestComponents = extractU256Operand(Dest);
  // Note: Extracted lowest 64 bits as jump destination,
  // but not used in MIR - address resolution handled by backend
  MInstruction *DestAddr = DestComponents[0];

  U256Inst CondComponents = extractU256Operand(Cond);
  MInstruction *CondNonZero = isU256GreaterOrEqual(CondComponents, 1);

  // Create conditional branch
  MBasicBlock *ThenBB = createBasicBlock();
  MBasicBlock *ElseBB = createBasicBlock();

  createInstruction<BrIfInstruction>(true, Ctx, CondNonZero, ThenBB, ElseBB);
  addSuccessor(ThenBB);
  addSuccessor(ElseBB);

  setInsertBlock(ThenBB);
}

void EVMMirBuilder::handleJumpDest() {
  // JUMPDEST creates a valid jump target
  // In DMIR, this is handled by basic block boundaries
}

// ==================== Arithmetic Instruction Handlers ====================

typename EVMMirBuilder::Operand EVMMirBuilder::handleMul(Operand MultiplicandOp,
                                                         Operand MultiplierOp) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  return callRuntimeFor<intx::uint256, intx::uint256, intx::uint256>(
      RuntimeFunctions.GetMul, MultiplicandOp, MultiplierOp);
}

typename EVMMirBuilder::Operand EVMMirBuilder::handleDiv(Operand DividendOp,
                                                         Operand DivisorOp) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  return callRuntimeFor<intx::uint256, intx::uint256, intx::uint256>(
      RuntimeFunctions.GetDiv, DividendOp, DivisorOp);
}

typename EVMMirBuilder::Operand EVMMirBuilder::handleSDiv(Operand DividendOp,
                                                          Operand DivisorOp) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  return callRuntimeFor<intx::uint256, intx::uint256, intx::uint256>(
      RuntimeFunctions.GetSDiv, DividendOp, DivisorOp);
}

typename EVMMirBuilder::Operand EVMMirBuilder::handleMod(Operand DividendOp,
                                                         Operand DivisorOp) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  return callRuntimeFor<intx::uint256, intx::uint256, intx::uint256>(
      RuntimeFunctions.GetMod, DividendOp, DivisorOp);
}

typename EVMMirBuilder::Operand EVMMirBuilder::handleSMod(Operand DividendOp,
                                                          Operand DivisorOp) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  return callRuntimeFor<intx::uint256, intx::uint256, intx::uint256>(
      RuntimeFunctions.GetSMod, DividendOp, DivisorOp);
}

typename EVMMirBuilder::Operand EVMMirBuilder::handleAddMod(Operand AugendOp,
                                                            Operand AddendOp,
                                                            Operand ModulusOp) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  return callRuntimeFor<intx::uint256, intx::uint256, intx::uint256,
                        intx::uint256>(RuntimeFunctions.GetAddMod, AugendOp,
                                       AddendOp, ModulusOp);
}

typename EVMMirBuilder::Operand
EVMMirBuilder::handleMulMod(Operand MultiplicandOp, Operand MultiplierOp,
                            Operand ModulusOp) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  return callRuntimeFor<intx::uint256, intx::uint256, intx::uint256,
                        intx::uint256>(RuntimeFunctions.GetMulMod,
                                       MultiplicandOp, MultiplierOp, ModulusOp);
}

typename EVMMirBuilder::Operand EVMMirBuilder::handleExp(Operand BaseOp,
                                                         Operand ExponentOp) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  return callRuntimeFor<intx::uint256, intx::uint256, intx::uint256>(
      RuntimeFunctions.GetExp, BaseOp, ExponentOp);
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

typename EVMMirBuilder::Operand EVMMirBuilder::handleNot(const Operand &LHSOp) {
  U256Inst Result = {};
  U256Inst LHS = extractU256Operand(LHSOp);

  MType *MirI64Type =
      EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);

  for (size_t I = 0; I < EVM_ELEMENTS_COUNT; ++I) {
    Result[I] = createInstruction<NotInstruction>(false, MirI64Type, LHS[I]);
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

  // Extract sign bit
  MInstruction *Const64 = createIntConstInstruction(MirI64Type, 64);
  MInstruction *ComponentIndex = createInstruction<BinaryInstruction>(
      false, OP_udiv, MirI64Type, SignBitPos, Const64);
  MInstruction *BitOffset = createInstruction<BinaryInstruction>(
      false, OP_urem, MirI64Type, SignBitPos, Const64);

  // Select appropriate component for sign bit
  MInstruction *SignComponent = ValueComponents[0];
  for (size_t I = 1; I < EVM_ELEMENTS_COUNT; ++I) {
    MInstruction *IsThisComponent = createInstruction<CmpInstruction>(
        false, CmpInstruction::Predicate::ICMP_EQ, &Ctx.I64Type, ComponentIndex,
        createIntConstInstruction(MirI64Type, I));
    SignComponent = createInstruction<SelectInstruction>(
        false, MirI64Type, IsThisComponent, ValueComponents[I], SignComponent);
  }

  // Extract sign bit
  MInstruction *Zero = createIntConstInstruction(MirI64Type, 0);
  MInstruction *One = createIntConstInstruction(MirI64Type, 1);
  MInstruction *SignMask = createInstruction<BinaryInstruction>(
      false, OP_shl, MirI64Type, One, BitOffset);
  MInstruction *SignBitValue = createInstruction<BinaryInstruction>(
      false, OP_and, MirI64Type, SignComponent, SignMask);
  MInstruction *IsNegative = createInstruction<CmpInstruction>(
      false, CmpInstruction::Predicate::ICMP_NE, &Ctx.I64Type, SignBitValue,
      Zero);

  // Create mask for sign extension
  MInstruction *LowMask = createInstruction<BinaryInstruction>(
      false, OP_sub, MirI64Type, SignMask, One);
  MInstruction *HighMask =
      createInstruction<NotInstruction>(false, MirI64Type, LowMask);

  U256Inst ResultComponents = {};
  for (size_t I = 0; I < EVM_ELEMENTS_COUNT; ++I) {
    // Apply sign extension mask if negative
    MInstruction *ExtendedValue = createInstruction<BinaryInstruction>(
        false, OP_or, MirI64Type, ValueComponents[I], HighMask);

    // Select between original and extended value
    MInstruction *ComponentResult = createInstruction<SelectInstruction>(
        false, MirI64Type, IsNegative, ExtendedValue, ValueComponents[I]);

    // Select between result and original based on NoExtension flag
    ResultComponents[I] = createInstruction<SelectInstruction>(
        false, MirI64Type, NoExtension, ValueComponents[I], ComponentResult);
  }

  return Operand(ResultComponents, EVMType::UINT256);
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
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  return callRuntimeFor<uint64_t>(RuntimeFunctions.GetGas);
}

typename EVMMirBuilder::Operand EVMMirBuilder::handleAddress() {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  return callRuntimeFor(RuntimeFunctions.GetAddress);
}

typename EVMMirBuilder::Operand EVMMirBuilder::handleBalance(Operand Address) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  return callRuntimeFor<intx::uint256, const uint8_t *>(
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
  return callRuntimeFor<intx::uint256, uint64_t>(RuntimeFunctions.GetMLoad,
                                                 AddrComponents);
}
void EVMMirBuilder::handleMStore(Operand AddrComponents,
                                 Operand ValueComponents) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  normalizeOperandU64(AddrComponents);
  callRuntimeFor<void, uint64_t, intx::uint256>(
      RuntimeFunctions.SetMStore, AddrComponents, ValueComponents);
}
void EVMMirBuilder::handleMStore8(Operand AddrComponents,
                                  Operand ValueComponents) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  normalizeOperandU64(AddrComponents);
  callRuntimeFor<void, uint64_t, intx::uint256>(
      RuntimeFunctions.SetMStore8, AddrComponents, ValueComponents);
}
void EVMMirBuilder::handleMCopy(Operand DestAddrComponents,
                                Operand SrcAddrComponents,
                                Operand LengthComponents) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  normalizeOperandU64(DestAddrComponents);
  normalizeOperandU64(SrcAddrComponents);
  normalizeOperandU64(LengthComponents);
  callRuntimeFor<void, uint64_t, uint64_t, uint64_t>(
      RuntimeFunctions.SetMCopy, DestAddrComponents, SrcAddrComponents,
      LengthComponents);
}
void EVMMirBuilder::handleReturn(Operand MemOffsetComponents,
                                 Operand LengthComponents) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  normalizeOperandU64(MemOffsetComponents);
  normalizeOperandU64(LengthComponents);
  callRuntimeFor<void, uint64_t, uint64_t>(
      RuntimeFunctions.SetReturn, MemOffsetComponents, LengthComponents);
}
void EVMMirBuilder::handleInvalid() {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  callRuntimeFor(RuntimeFunctions.HandleInvalid);
}
typename EVMMirBuilder::Operand
EVMMirBuilder::handleSLoad(Operand KeyComponents) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  return callRuntimeFor<intx::uint256, intx::uint256>(RuntimeFunctions.GetSLoad,
                                                      KeyComponents);
}
void EVMMirBuilder::handleSStore(Operand KeyComponents,
                                 Operand ValueComponents) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  callRuntimeFor<void, intx::uint256, intx::uint256>(
      RuntimeFunctions.SetSStore, KeyComponents, ValueComponents);
}
typename EVMMirBuilder::Operand EVMMirBuilder::handleTLoad(Operand Index) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  return callRuntimeFor<intx::uint256, intx::uint256>(RuntimeFunctions.GetTLoad,
                                                      Index);
}
void EVMMirBuilder::handleTStore(Operand Index, Operand ValueComponents) {
  const auto &RuntimeFunctions = getRuntimeFunctionTable();
  callRuntimeFor<void, intx::uint256, intx::uint256>(RuntimeFunctions.SetTStore,
                                                     Index, ValueComponents);
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

  // Auto-convert UINT64 operands to U256 when needed
  if (Opnd.getType() == EVMType::UINT64) {
    Operand U256Op = convertSingleInstrToU256Operand(Opnd.getInstr());
    return U256Op.getU256Components();
  }

  return Result;
}

// ==================== EVMU256 Helper Methods ====================

EVMMirBuilder::U256Value EVMMirBuilder::bytesToU256(const Bytes &Data) {
  return createU256FromBytes(Data.data(), Data.size());
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

MInstruction *EVMMirBuilder::isU256GreaterOrEqual(const U256Inst &Value,
                                                  uint64_t Threshold) {
  MType *MirI64Type =
      EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);
  MInstruction *Zero = createIntConstInstruction(MirI64Type, 0);

  // Check if any of the higher components are non-zero
  MInstruction *IsNonZeroHigh = Zero;
  for (size_t I = 1; I < EVM_ELEMENTS_COUNT; ++I) {
    MInstruction *IsNonZero = createInstruction<CmpInstruction>(
        false, CmpInstruction::Predicate::ICMP_NE, &Ctx.I64Type, Value[I],
        Zero);
    IsNonZeroHigh = createInstruction<BinaryInstruction>(
        false, OP_or, MirI64Type, IsNonZeroHigh, IsNonZero);
  }

  // Check if low component >= threshold
  MInstruction *ThresholdConst =
      createIntConstInstruction(MirI64Type, Threshold);
  MInstruction *IsLowLarge = createInstruction<CmpInstruction>(
      false, CmpInstruction::Predicate::ICMP_UGE, &Ctx.I64Type, Value[0],
      ThresholdConst);

  // Combine result: any high component non-zero OR low component >= threshold
  return createInstruction<BinaryInstruction>(false, OP_or, MirI64Type,
                                              IsNonZeroHigh, IsLowLarge);
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
  if constexpr (std::is_same_v<RetType, intx::uint256>) {
    return EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT256);
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
  if constexpr (std::is_same_v<RetType, intx::uint256>) {
    return convertU256InstrToU256Operand(CallInstr);
  } else if constexpr (std::is_same_v<RetType, const uint8_t *>) {
    return Operand(CallInstr, EVMType::BYTES32);
  } else if constexpr (std::is_same_v<RetType, uint64_t>) {
    return convertSingleInstrToU256Operand(CallInstr);
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
  uint64_t Selected = FitsU64 ? C[0] : UINT64_MAX; // sentinel for overflow

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

  // Select: valid -> low part; invalid -> UINT64_MAX (sentinel)
  MInstruction *AllOnes = createIntConstInstruction(I64Type, UINT64_MAX);
  MInstruction *Selected = createInstruction<SelectInstruction>(
      false, I64Type, IsU64, Parts[0], AllOnes);

  // Normalize Param to U256: [Selected, 0, 0, 0]
  U256Inst NewVal = {Selected, Zero, Zero, Zero};
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

  MInstruction *CallInstr = createInstruction<ICallInstruction>(
      false, ReturnType, FuncAddrInst,
      llvm::ArrayRef<MInstruction *>(InstancePtr));

  return convertCallResult<RetType>(CallInstr);
}

// Template function for single-argument runtime calls
template <typename ArgType>
EVMMirBuilder::U256Inst
EVMMirBuilder::convertOperandToInstruction(const Operand &Param) {
  EVMMirBuilder::U256Inst Result = {};

  if constexpr (std::is_same_v<ArgType, int64_t> ||
                std::is_same_v<ArgType, uint64_t>) {
    EVMMirBuilder::U256Inst Components = extractU256Operand(Param);
    Result[0] = Components[0];
  } else if constexpr (std::is_same_v<ArgType, const uint8_t *>) {
    Result[0] = Param.getInstr();
  } else if constexpr (std::is_same_v<ArgType, const intx::uint256> ||
                       std::is_same_v<ArgType, intx::uint256>) {
    const U256Value &U256Value = Param.getConstValue();
    MType *I64Type = EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);
    for (size_t I = 0; I < EVM_ELEMENTS_COUNT; ++I) {
      Result[I] = createIntConstInstruction(I64Type, U256Value[I]);
    }
  } else {
    ZEN_ASSERT(false &&
               "Unsupported argument type in convertOperandToInstruction");
  }

  return Result;
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

  auto PushOne = [this, &Args, &ParamsTuple]<std::size_t I>() {
    using ArgT = typename std::tuple_element<I, std::tuple<ArgTypes...>>::type;
    const Operand &Op = std::get<I>(ParamsTuple);

    if (Op.getType() == EVMType::UINT256 && Op.isU256MultiComponent()) {
      if constexpr (std::is_same_v<ArgT, const intx::uint256> ||
                    std::is_same_v<ArgT, intx::uint256>) {
        const auto &Components = Op.getU256Components();
        for (size_t Pos = 0; Pos < EVM_ELEMENTS_COUNT; ++Pos) {
          Args.push_back(Components[Pos]);
        }
      } else {
        auto Insts = convertOperandToInstruction<ArgT>(Op);
        for (auto *Inst : Insts)
          if (Inst)
            Args.push_back(Inst);
      }
    } else {
      auto Insts = convertOperandToInstruction<ArgT>(Op);
      for (auto *Inst : Insts)
        if (Inst)
          Args.push_back(Inst);
    }
  };

  constexpr std::size_t N = sizeof...(ArgTypes);
  [&]<std::size_t... I>(std::index_sequence<I...>) {
    (PushOne.template operator()<I>(), ...);
  }
  (std::make_index_sequence<N>{});

  MType *ReturnType = getMIRReturnType<RetType>();
  MInstruction *CallInstr = createInstruction<ICallInstruction>(
      /*isTail*/ false, ReturnType, FuncAddrInst,
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
