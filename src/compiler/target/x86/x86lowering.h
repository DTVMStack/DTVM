// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#ifndef COMPILER_TARGET_X86_X86LOWERING_H
#define COMPILER_TARGET_X86_X86LOWERING_H

#include "compiler/cgir/lowering.h"
#include "compiler/llvm-prebuild/Target/X86/X86Subtarget.h"
#include "llvm/ADT/DenseMap.h"

namespace COMPILER {

using namespace llvm;

class X86CgLowering : public CgLowering<X86CgLowering> {
public:
  X86CgLowering(CgFunction &MF);

  // ==================== Unary Expressions ====================

  CgRegister lowerClzExpr(llvm::MVT VT, CgRegister Operand);    // fallback
  CgRegister lowerCtzExpr(llvm::MVT VT, CgRegister Operand);    // fallback
  CgRegister lowerPopcntExpr(llvm::MVT VT, CgRegister Operand); // fallback
  CgRegister lowerNotExpr(llvm::MVT VT, CgRegister Operand);
  CgRegister lowerFPAbsExpr(MVT VT, CgRegister Operand);
  CgRegister lowerFPNegExpr(MVT VT, CgRegister Operand);
  CgRegister lowerFPSqrtExpr(MVT VT, CgRegister Operand);
  CgRegister lowerFPRoundExpr(MVT VT, Opcode MOpc, CgRegister Operand);

  // ==================== Binary Expressions ====================

  CgRegister lowerDivRemExpr(const MInstruction &LHS, const MInstruction &RHS,
                             const MType &Type, Opcode Opcode);
  CgRegister lowerShiftExpr(const MInstruction &LHS, const MInstruction &RHS,
                            const MType &Type, Opcode MOpc);
  CgRegister lowerFPMinMaxExpr(const MInstruction &LHS, const MInstruction &RHS,
                               const MType &Type, bool IsMax);
  CgRegister lowerFPCopySignExpr(const MInstruction &LHS,
                                 const MInstruction &RHS, const MType &Type);
  CgRegister lowerWasmOverflowBinaryExpr(const MInstruction &LHS,
                                         const MInstruction &RHS,
                                         const MType &Type, Opcode MOpc);

  // ==================== Conversion Expressions ====================

  CgRegister lowerIntTruncExpr(llvm::MVT VT, llvm::MVT RetVT,
                               CgRegister OperandReg);
  CgRegister lowerUExtExpr(llvm::MVT VT, llvm::MVT RetVT,
                           CgRegister OperandReg);
  CgRegister lowerFPTruncExpr(CgRegister OperandReg);
  CgRegister lowerFPExtExpr(CgRegister OperandReg);
  CgRegister lowerUIToFPExpr(llvm::MVT VT, llvm::MVT RetVT,
                             CgRegister OperandReg);
  CgRegister lowerSIToFPExpr(llvm::MVT VT, llvm::MVT RetVT,
                             CgRegister OperandReg);
  CgRegister lowerWasmFPToSIExpr(llvm::MVT VT, llvm::MVT RetVT,
                                 CgRegister OperandReg);
  CgRegister lowerWasmFPToUIExpr(llvm::MVT VT, llvm::MVT RetVT,
                                 CgRegister OperandReg);
  CgRegister lowerWasmFPToUI32Expr(llvm::MVT VT, llvm::MVT RetVT,
                                   CgRegister OperandReg);
  CgRegister lowerWasmFPToUI64Expr(llvm::MVT VT, llvm::MVT RetVT,
                                   CgRegister OperandReg);

  // ==================== Other Expressions ====================

  CgRegister lowerVariable(uint32_t VarIdx);
  CgRegister fastMaterializeConstant(const ConstantInstruction &Inst);
  CgRegister lowerCmpExpr(const CmpInstruction &Inst);
  CgRegister lowerSelectExpr(const SelectInstruction &Inst);
  CgRegister lowerWasmOverflowI128BinaryExpr(
      const WasmOverflowI128BinaryInstruction &Inst);
  CgRegister lowerEvmUmul128Expr(const EvmUmul128Instruction &Inst);
  CgRegister lowerEvmUmul128HiExpr(const EvmUmul128HiInstruction &Inst);
  CgRegister lowerAdcExpr(const AdcInstruction &Inst);

  // ==================== Memory Instructions ====================

  CgRegister lowerLoadExpr(const LoadInstruction &Inst);
  void lowerStoreStmt(const StoreInstruction &Inst);

  // ==================== Control Statements ====================

  void lowerBrStmt(const BrInstruction &Inst);
  void lowerBrIfStmt(const BrIfInstruction &Inst);
  void lowerSwitchStmt(const SwitchInstruction &Inst);
  CgRegister lowerCall(const CallInstructionBase &Inst);
  void lowerFormalArguments();
  void lowerReturnStmt(llvm::MVT VT, CgRegister OperandReg);

  // ==================== Wasm Check Statements ====================

  typedef WasmCheckMemoryAccessInstruction WasmCMAI;
  typedef WasmCheckStackBoundaryInstruction WasmCSBI;
  typedef WasmVisitStackGuardInstruction WasmVSGI;
  void lowerWasmCheckMemoryAccessStmt(const WasmCMAI &Inst);
  void lowerWasmCheckStackBoundaryStmt(const WasmCSBI &Inst);
  void lowerWasmVisitStackGuardStmt(const WasmVSGI &Inst);

  // ==================== FastISel Utilities from LLVM  ====================

#define override
#include "compiler/llvm-prebuild/Target/X86/X86GenFastISel.inc"
#undef override

private:
  // ==================== X86CgLowering Utilities ====================

  static unsigned X86ChooseCmpImmediateOpcode(MVT VT, int64_t Val);
  static unsigned X86ChooseCmpImmediateOpcode(MVT VT, const APInt &Value);
  static unsigned X86ChooseCmpOpcode(MVT VT);

  void lowerFastCompareExpr(const MInstruction *LHS, const MInstruction *RHS,
                            MVT VT);

  CgRegister X86MaterializeInt(const MConstantInt &IntConstant, MVT VT);
  CgRegister X86MaterializeInt(uint64_t Imm, MVT VT);
  CgRegister X86MaterializeFP(const MConstantFloat &FloatConstant, MVT VT);
  CgRegister fastMaterializeFloatZero(MVT VT);

  // Emit an unconditional branch to TargetBB
  void fastEmitBranch(CgBasicBlock *TargetBB);
  // Emit a conditional branch to TargetBB
  void fastEmitCondBranch(CgBasicBlock *TargetBB, unsigned CC);

  const X86Subtarget *Subtarget;
  const TargetRegisterInfo *TRI;
  llvm::DenseMap<const MInstruction *, CgRegister> Umul128HiRegs;
};

} // namespace COMPILER

#endif // COMPILER_TARGET_X86_X86LOWERING_H
