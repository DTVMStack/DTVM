// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "compiler/target/x86/x86lowering.h"
#include "compiler/target/x86/x86_constants.h"
#include "compiler/utils/array.h"

using namespace COMPILER;
using namespace llvm;

X86CgLowering::X86CgLowering(CgFunction &MF)
    : CgLowering(MF), Subtarget(&MF.getSubtarget<X86Subtarget>()),
      TRI(Subtarget->getRegisterInfo()) {
  lower();
#ifdef ZEN_ENABLE_MULTIPASS_JIT_LOGGING
  llvm::dbgs() << "\n########## CgIR Dump After Lowering (Instruction "
                  "Selection) ##########\n\n";
  MF.dump();
#endif
}

// ==================== Unary Expressions ====================

CgRegister X86CgLowering::lowerNotExpr(MVT VT, CgRegister Operand) {
  ZEN_ASSERT(VT.isInteger());
  // Bitwise NOT via XOR with all-ones mask of the same width
  uint64_t AllOnes = (VT == MVT::i8)    ? 0xFFull
                     : (VT == MVT::i16) ? 0xFFFFull
                     : (VT == MVT::i32) ? 0xFFFF'FFFFull
                                        : 0xFFFF'FFFF'FFFF'FFFFull;
  return fastEmit_ri_(VT, ISD::XOR, Operand, AllOnes, VT);
}

CgRegister X86CgLowering::lowerFPAbsExpr(MVT VT, CgRegister Operand) {
  const TargetRegisterClass *RC = TLI.getRegClassFor(VT);

  MVT IntVT = MVT::getIntegerVT(VT.getSizeInBits());
  const TargetRegisterClass *IntRC = TLI.getRegClassFor(IntVT);

  bool IsF32 = VT == MVT::f32;
  unsigned MOVriOpc = IsF32 ? X86::MOV32ri : X86::MOV64ri;
  unsigned ANDOpc = IsF32 ? X86::ANDPSrr : X86::ANDPDrr;
  uint64_t ANDMask = IsF32 ? INT32_MAX : INT64_MAX;

  CgRegister MaskIntReg = fastEmitInst_i(MOVriOpc, IntRC, ANDMask);
  CgRegister MaskFpReg = fastEmit_r(IntVT, VT, ISD::BITCAST, MaskIntReg);
  return fastEmitInst_rr(ANDOpc, RC, Operand, MaskFpReg);
}

// Refer to the following URL:
// https://github.com/llvm/llvm-project/blob/release%2F15.x/llvm/lib/CodeGen/SelectionDAG/FastISel.cpp#L1600-L1640
CgRegister X86CgLowering::lowerFPNegExpr(MVT VT, CgRegister Operand) {
  MVT IntVT = MVT::getIntegerVT(VT.getSizeInBits());
  CgRegister IntReg = fastEmit_r(VT, IntVT, ISD::BITCAST, Operand);
  uint64_t XORImm = UINT64_C(1) << (VT.getSizeInBits() - 1);
  CgRegister IntResultReg =
      fastEmit_ri_(IntVT, ISD::XOR, IntReg, XORImm, IntVT);
  return fastEmit_r(IntVT, VT, ISD::BITCAST, IntResultReg);
}

CgRegister X86CgLowering::lowerFPSqrtExpr(MVT VT, CgRegister Operand) {
  ZEN_ASSERT(VT.isFloatingPoint());
  unsigned SQRTOpc = VT == MVT::f32 ? X86::SQRTSSr : X86::SQRTSDr;
  const TargetRegisterClass *RC = TLI.getRegClassFor(VT);
  return fastEmitInst_r(SQRTOpc, RC, Operand);
}

CgRegister X86CgLowering::lowerFPRoundExpr(MVT VT, Opcode MOpc,
                                           CgRegister Operand) {
  ZEN_ASSERT(VT.isFloatingPoint());
  unsigned Opc = VT == MVT::f32 ? X86::ROUNDSSr : X86::ROUNDSDr;
  uint32_t RoundMode;
  switch (MOpc) {
  case OP_fpround_ceil:
    RoundMode = RoundUp;
    break;
  case OP_fpround_floor:
    RoundMode = RoundDown;
    break;
  case OP_fpround_trunc:
    RoundMode = RoundToZero;
    break;
  case OP_fpround_nearest:
    RoundMode = RoundToNearest;
    break;
  default:
    ZEN_ASSERT(false);
  }

  const TargetRegisterClass *RC = TLI.getRegClassFor(VT);
  return fastEmitInst_ri(Opc, RC, Operand, RoundMode);
}

// ==================== Binary Expressions ====================

CgRegister X86CgLowering::lowerDivRemExpr(const MInstruction &LHS,
                                          const MInstruction &RHS,
                                          const MType &Type, Opcode Opcode) {
  MVT RetVT = getMVT(Type);
  const TargetRegisterClass *RC = TLI.getRegClassFor(RetVT);
  CgRegister ResReg = createReg(RC);
  CgRegister LHSReg = lowerExpr(LHS);
  CgRegister RHSReg = lowerExpr(RHS);

  const unsigned NumTypes = 2; // i32, i64
  const unsigned NumOps = 4;   // SDiv, SRem, UDiv, URem
  const bool S = true;         // IsSigned
  const bool U = false;        // !IsSigned
  const unsigned Copy = TargetOpcode::COPY;
  unsigned MovRIOpc = Type.isI32() ? X86::MOV32ri : X86::MOV64ri;

  const struct DivRemEntry {
    unsigned LowInReg;  // low part of the register pair
    unsigned HighInReg; // high part of the register pair
    // The following portion depends on both the data type and the
    // operation.
    struct DivRemResult {
      unsigned OpDivRem;        // The specific DIV/IDIV opcode to use.
      unsigned OpSignExtend;    // Opcode for sign-extending lowreg into
                                // highreg, or copying a zero into highreg.
      unsigned OpCopy;          // Opcode for copying dividend into lowreg
      unsigned DivRemResultReg; // Register containing the desired result.
      bool IsOpSigned;          // Whether to use signed or unsigned form.
    } ResultTable[4];
  } OpTable[2] = {
      {X86::EAX,
       X86::EDX,
       {
           {X86::IDIV32r, X86::CDQ, Copy, X86::EAX, S},    // SDiv
           {X86::IDIV32r, X86::CDQ, Copy, X86::EDX, S},    // SRem
           {X86::DIV32r, X86::XOR32rr, Copy, X86::EAX, U}, // UDiv
           {X86::DIV32r, X86::XOR32rr, Copy, X86::EDX, U}, // URem
       }},                                                 // i32
      {X86::RAX,
       X86::RDX,
       {
           {X86::IDIV64r, X86::CQO, Copy, X86::RAX, S},    // SDiv
           {X86::IDIV64r, X86::CQO, Copy, X86::RDX, S},    // SRem
           {X86::DIV64r, X86::XOR64rr, Copy, X86::RAX, U}, // UDiv
           {X86::DIV64r, X86::XOR64rr, Copy, X86::RDX, U}, // URem
       }},                                                 // i64
  };

  unsigned TypeIndex, OpIndex;
  TypeIndex = Type.isI32() ? 0 : 1;

  switch (Opcode) {
  default:
    ZEN_ASSERT(false);
  case OP_sdiv:
    OpIndex = 0;
    break;
  case OP_srem:
    OpIndex = 1;
    break;
  case OP_udiv:
    OpIndex = 2;
    break;
  case OP_urem:
    OpIndex = 3;
    break;
  }

  const DivRemEntry &TypeEntry = OpTable[TypeIndex];
  const DivRemEntry::DivRemResult &OpEntry = TypeEntry.ResultTable[OpIndex];
  // Move op0 into low-order input register.
  SmallVector<CgOperand, 2> MOVLOperands{
      CgOperand::createRegOperand(TypeEntry.LowInReg, true),
      CgOperand::createRegOperand(LHSReg, false),
  };
  MF->createCgInstruction(*CurBB, TII.get(OpEntry.OpCopy), MOVLOperands);
  if (OpEntry.IsOpSigned) {
    SmallVector<CgOperand, 0> CDQOperands{};
    MF->createCgInstruction(*CurBB, TII.get(OpEntry.OpSignExtend), CDQOperands);
  } else {
    SmallVector<CgOperand, 3> XOROperands{
        CgOperand::createRegOperand(TypeEntry.HighInReg, true),
        CgOperand::createRegOperand(TypeEntry.HighInReg, CgOperand::Undef),
        CgOperand::createRegOperand(TypeEntry.HighInReg, CgOperand::Undef),
    };
    MF->createCgInstruction(*CurBB, TII.get(OpEntry.OpSignExtend), XOROperands);
  }

  // Generate the DIV/IDIV instruction.
  SmallVector<CgOperand, 1> DIVOperands{
      CgOperand::createRegOperand(RHSReg, false),
  };
  MF->createCgInstruction(*CurBB, TII.get(OpEntry.OpDivRem), DIVOperands);

  SmallVector<CgOperand, 2> RESOperands{
      CgOperand::createRegOperand(ResReg, true),
      CgOperand::createRegOperand(OpEntry.DivRemResultReg, false),
  };
  MF->createCgInstruction(*CurBB, TII.get(Copy), RESOperands);
  return ResReg;
}

CgRegister X86CgLowering::lowerShiftExpr(const MInstruction &LHS,
                                         const MInstruction &RHS,
                                         const MType &Type, Opcode MOpc) {
  MVT RetVT = getMVT(Type);
  const TargetRegisterClass *RC = TLI.getRegClassFor(RetVT);

  unsigned MOpcIndex;

  CgRegister LHSReg = lowerExpr(LHS);

  switch (MOpc) {
  case OP_shl:
    MOpcIndex = 0;
    break;
  case OP_sshr:
    MOpcIndex = 1;
    break;
  case OP_ushr:
    MOpcIndex = 2;
    break;
  case OP_rotl:
    MOpcIndex = 3;
    break;
  case OP_rotr:
    MOpcIndex = 4;
    break;
  default:
    ZEN_ABORT();
  }

  if (const auto *ConstInst = dyn_cast<ConstantInstruction>(&RHS)) {
    if (auto *IntConst = dyn_cast<MConstantInt>(&ConstInst->getConstant())) {
      static unsigned ISDShiftOpcs[5] = {
          ISD::SHL, ISD::SRA, ISD::SRL, ISD::ROTL, ISD::ROTR,
      };
      unsigned ISDOpc = ISDShiftOpcs[MOpcIndex];
      CgRegister ResultReg = fastEmit_ri_(
          RetVT, ISDOpc, LHSReg, IntConst->getValue().getZExtValue(), RetVT);
      if (ResultReg) {
        return ResultReg;
      }
    }
  }

  static unsigned ShiftOpcs[5][2] = {
      {X86::SHL64rCL, X86::SHL32rCL}, {X86::SAR64rCL, X86::SAR32rCL},
      {X86::SHR64rCL, X86::SHR32rCL}, {X86::ROL64rCL, X86::ROL32rCL},
      {X86::ROR64rCL, X86::ROR32rCL},
  };

  bool Is32Bits = Type.isI32();
  unsigned ShiftOpc = ShiftOpcs[MOpcIndex][Is32Bits];
  unsigned CReg = Is32Bits ? X86::ECX : X86::RCX;

  CgRegister RHSReg = lowerExpr(RHS);

  MF->createCgInstruction(*CurBB, TII.get(TargetOpcode::COPY), RHSReg, CReg);

  MF->createCgInstruction(*CurBB, TII.get(TargetOpcode::KILL), CReg, X86::CL);

  return fastEmitInst_r(ShiftOpc, RC, LHSReg);
}

CgRegister X86CgLowering::lowerFPMinMaxExpr(const MInstruction &LHS,
                                            const MInstruction &RHS,
                                            const MType &Type, bool IsMax) {
  MVT RetVT = getMVT(Type);
  const TargetRegisterClass *RC = TLI.getRegClassFor(RetVT);

  CgRegister LHSReg = lowerExpr(LHS);
  CgRegister RHSReg = lowerExpr(RHS);

  static unsigned MINMAXOpcs[2][2] = {
      {X86::MINSSrr, X86::MAXSSrr},
      {X86::MINSDrr, X86::MAXSDrr},
  };

  static unsigned MergeZeroOpcs[2][2] = {
      {X86::ORPSrr, X86::ANDPSrr},
      {X86::ORPDrr, X86::ANDPDrr},
  };

  bool IsF64 = Type.isF64();
  unsigned SubOpc = IsF64 ? X86::SUBSDrr : X86::SUBSSrr;
  unsigned CmpOpc = X86ChooseCmpOpcode(RetVT);
  unsigned MINMAXOpc = MINMAXOpcs[IsF64][IsMax];
  unsigned MergeZeroOpc = MergeZeroOpcs[IsF64][IsMax];

  CgBasicBlock *NaNMBB = MF->createCgBasicBlock();
  CgBasicBlock *MinMaxMBB = MF->createCgBasicBlock();
  CgBasicBlock *DoneMBB = MF->createCgBasicBlock();

  // Do a vucomisd to catch equality and NaNs, which both require special
  // handling. If the operands are ordered and inequal, we branch straight
  // to the min/max instruction. If we wanted, we could also branch for
  // less-than or greater-than here instead of using min/max, however
  // these conditions will sometimes be hard on the branch predictor.

  CgRegister FloatZeroReg = fastMaterializeFloatZero(RetVT);

  LHSReg = fastEmitInst_rr(SubOpc, RC, LHSReg, FloatZeroReg);

  RHSReg = fastEmitInst_rr(SubOpc, RC, RHSReg, FloatZeroReg);

  fastEmitNoDefInst_rr(CmpOpc, LHSReg, RHSReg);

  fastEmitCondBranch(MinMaxMBB, X86::CondCode::COND_NE);

  startNewBlockAfterBranch();

  fastEmitCondBranch(NaNMBB, X86::CondCode::COND_P);

  // Ordered and equal. The operands are bit-identical unless they are
  // zero and negative zero. These instructions merge the sign bits in
  // that case, and are no-ops otherwise.

  startNewBlockAfterBranch();

  CgRegister ResultReg = fastEmitInst_rr(MergeZeroOpc, RC, LHSReg, RHSReg);

  fastEmitBranch(DoneMBB);

  /* ********** [End] Compare BasicBlock ********** */

  /* ********** [Begin] NaN BasicBlock ********** */

  // x86's min/max are not symmetric; if either operand is a NaN, they
  // return the read-only operand. We need to return a NaN if either
  // operand is a NaN, so we explicitly check for a NaN in the read-write
  // operand.

  setInsertBlock(NaNMBB);

  fastEmitNoDefInst_rr(CmpOpc, LHSReg, LHSReg);

  MF->createCgInstruction(*CurBB, TII.get(TargetOpcode::COPY), LHSReg,
                          ResultReg);

  fastEmitCondBranch(DoneMBB, X86::CondCode::COND_P);
  CurBB->addSuccessorWithoutProb(MinMaxMBB); // fallthrough

  /* ********** [End] NaN BasicBlock ********** */

  /* ********** [Begin] Min-Max BasicBlock ********** */

  // When the values are inequal, or second is NaN, x86's min and max will
  // return the value we need.

  setInsertBlock(MinMaxMBB);

  MF->createCgInstruction(*CurBB, TII.get(MINMAXOpc), LHSReg, RHSReg,
                          ResultReg);
  CurBB->addSuccessorWithoutProb(DoneMBB); // fallthrough

  /* ********** [End] Min-Max BasicBlock ********** */

  /* ********** [Begin] Finally BasicBlock ********** */

  setInsertBlock(DoneMBB);

  return ResultReg;
}

CgRegister X86CgLowering::lowerFPCopySignExpr(const MInstruction &LHS,
                                              const MInstruction &RHS,
                                              const MType &Type) {
  MVT VT = getMVT(Type);
  const TargetRegisterClass *RC = TLI.getRegClassFor(VT);

  MVT IntVT = MVT::getIntegerVT(VT.getSizeInBits());
  const TargetRegisterClass *IntRC = TLI.getRegClassFor(IntVT);

  CgRegister LHSReg = lowerExpr(LHS);
  CgRegister RHSReg = lowerExpr(RHS);

  bool Is32Bits = Type.is32Bits();
  int64_t ClearSignMask = Is32Bits ? INT32_MAX : INT64_MAX;
  int64_t KeepSignMask = Is32Bits ? INT32_MIN : INT64_MIN;
  unsigned MOVriOpc = Is32Bits ? X86::MOV32ri : X86::MOV64ri;
  unsigned ANDOpc = Is32Bits ? X86::ANDPSrr : X86::ANDPDrr;
  unsigned OROpc = Is32Bits ? X86::ORPSrr : X86::ORPDrr;

  CgRegister MaskIntReg1 = fastEmitInst_i(MOVriOpc, IntRC, ClearSignMask);
  CgRegister MaskFpReg1 = fastEmit_r(IntVT, VT, ISD::BITCAST, MaskIntReg1);
  CgRegister LHSWithoutSign = fastEmitInst_rr(ANDOpc, RC, LHSReg, MaskFpReg1);

  CgRegister MaskIntReg2 = fastEmitInst_i(MOVriOpc, IntRC, KeepSignMask);
  CgRegister MaskFpReg2 = fastEmit_r(IntVT, VT, ISD::BITCAST, MaskIntReg2);
  CgRegister RHSSign = fastEmitInst_rr(ANDOpc, RC, RHSReg, MaskFpReg2);

  return fastEmitInst_rr(OROpc, RC, LHSWithoutSign, RHSSign);
}

// ==================== Conversion Expressions ====================

CgRegister X86CgLowering::lowerIntTruncExpr(llvm::MVT VT, llvm::MVT RetVT,
                                            CgRegister OperandReg) {
  // Avoid `SUBREG_TO_REG(EXTRACT_SUBREG(operand, sub_32bit), sub_32bit)`
  if (VT == MVT::i64 && RetVT == MVT::i32) {
    return fastEmitInst_r(X86::MOV32rr, &X86::GR32RegClass, OperandReg);
  }

  CgRegister ResultReg = fastEmit_r(VT, RetVT, ISD::TRUNCATE, OperandReg);
  if (!ResultReg) {
    throw getError(ErrorCode::NoMatchedInstruction);
  }
  return ResultReg;
}

// Refer to the following URL:
// https://github.com/llvm/llvm-project/blob/release%2F15.x/llvm/lib/Target/X86/X86FastISel.cpp#L1537-L1593
CgRegister X86CgLowering::lowerUExtExpr(llvm::MVT VT, llvm::MVT RetVT,
                                        CgRegister OperandReg) {
  if (RetVT == MVT::i64) {
    // Handle extension to 64-bits via sub-register shenanigans.
    unsigned Opc;

    switch (VT.SimpleTy) {
    case MVT::i8:
      Opc = X86::MOVZX32rr8;
      break;
    case MVT::i16:
      Opc = X86::MOVZX32rr16;
      break;
    case MVT::i32:
      Opc = X86::MOV32rr;
      break;
    default:
      llvm_unreachable("Unexpected zext to i64 source type");
    }

    CgRegister Result32Reg =
        fastEmitInst_r(Opc, &X86::GR32RegClass, OperandReg);

    return fastEmitInst_subregtoreg(&X86::GR64RegClass, Result32Reg,
                                    X86::sub_32bit);
  } else if (RetVT == MVT::i16) {
    // i8->i16 doesn't exist in the autogenerated isel table. Need to zero
    // extend to 32-bits and then extract down to 16-bits.
    CgRegister Result32Reg =
        fastEmitInst_r(X86::MOVZX32rr8, &X86::GR32RegClass, OperandReg);
    return fastEmitInst_extractsubreg(MVT::i16, Result32Reg, X86::sub_16bit);
  } else if (RetVT == MVT::i32) {
    return fastEmit_r(VT, RetVT, ISD::ZERO_EXTEND, OperandReg);
  } else {
    throw getErrorWithPhase(ErrorCode::UnexpectedType, ErrorPhase::Compilation,
                            ErrorSubphase::CgIREmission);
  }
}

CgRegister X86CgLowering::lowerFPExtExpr(CgRegister OperandReg) {
  return fastEmitInst_r(X86::CVTSS2SDrr, &X86::FR64RegClass, OperandReg);
}

CgRegister X86CgLowering::lowerFPTruncExpr(CgRegister OperandReg) {
  return fastEmitInst_r(X86::CVTSD2SSrr, &X86::FR32RegClass, OperandReg);
}

CgRegister X86CgLowering::lowerUIToFPExpr(llvm::MVT VT, llvm::MVT RetVT,
                                          CgRegister OperandReg) {
  const TargetRegisterClass *OpRC = TLI.getRegClassFor(VT);
  const TargetRegisterClass *RetRC = TLI.getRegClassFor(RetVT);

  // Use int64 to float/double conversion even if the operand is int32 due to
  // wasm spec
  static unsigned CVTOpcs[2][2] = {
      {X86::CVTSI642SSrr, X86::CVTSI642SDrr},
      {X86::CVTSI642SSrr, X86::CVTSI642SDrr},
  };

  bool IsI64Op = VT.SimpleTy == MVT::i64;
  bool IsF64Ret = RetVT.SimpleTy == MVT::f64;

  unsigned CVTOpc = CVTOpcs[IsI64Op][IsF64Ret];

  /*
   * Deal with converting unsigned 32-bits integer to float specially
   *
   * f32.convert_i32_u
   * f64.convert_i32_u
   */
  if (!IsI64Op) {
    CgRegister Operand64Reg = fastEmitInst_subregtoreg(
        &X86::GR64RegClass, OperandReg, X86::sub_32bit);
    return fastEmitInst_r(CVTOpc, RetRC, Operand64Reg);
  }

  /*
   * Deal with converting unsigned 64-bits integer to float specially
   *
   * f32.convert_i64_u
   * f64.convert_i64_u
   */

  CgBasicBlock *SignedMBB = MF->createCgBasicBlock();
  CgBasicBlock *DoneMBB = MF->createCgBasicBlock();

  // If the input's sign bit is not set we use cvtsq2ss/cvtsq2sd
  // directly. Else, we divide by 2 and keep the LSB, convert to double, and
  // multiply the result by 2.
  fastEmitNoDefInst_rr(X86::TEST64rr, OperandReg, OperandReg);

  fastEmitCondBranch(SignedMBB, X86::CondCode::COND_S);

  startNewBlockAfterBranch(); // Positive Handling MBB

  CgRegister ResultReg = createReg(RetRC);

  CgRegister CVTReg = fastEmitInst_r(CVTOpc, RetRC, OperandReg);

  MF->createCgInstruction(*CurBB, TII.get(TargetOpcode::COPY), CVTReg,
                          ResultReg);

  fastEmitBranch(DoneMBB);

  /* ********** [End] Current BasicBlock ********** */

  /* ********** [Begin] Signed BasicBlock ********** */

  setInsertBlock(SignedMBB); // Negative Handling MBB

  CgRegister SHRPreReg = fastEmitCopy(OpRC, OperandReg);
  CgRegister ShrReg = fastEmitInst_r(X86::SHR64r1, OpRC, SHRPreReg);

  CgRegister ANDPreReg =
      fastEmitInst_extractsubreg(MVT::i32, OperandReg, X86::sub_32bit);
  CgRegister ANDReg =
      fastEmitInst_ri(X86::AND32ri8, &X86::GR32RegClass, ANDPreReg, 1);
  CgRegister ANDPostReg =
      fastEmitInst_subregtoreg(OpRC, ANDReg, X86::sub_32bit);

  CgRegister OrReg = fastEmitInst_rr(X86::OR64rr, OpRC, ShrReg, ANDPostReg);

  CgRegister CVTReg2 = fastEmitInst_r(CVTOpc, RetRC, OrReg);

  unsigned FADDOpc = IsF64Ret ? X86::ADDSDrr : X86::ADDSSrr;
  CgRegister ADDReg = fastEmitInst_rr(FADDOpc, RetRC, CVTReg2, CVTReg2);
  MF->createCgInstruction(*CurBB, TII.get(TargetOpcode::COPY), ADDReg,
                          ResultReg);
  CurBB->addSuccessorWithoutProb(DoneMBB); // fallthrough

  /* ********** [End] Signed BasicBlock ********** */

  /* ********** [Begin] Done BasicBlock ********** */

  setInsertBlock(DoneMBB);
  return ResultReg;
}

CgRegister X86CgLowering::lowerSIToFPExpr(llvm::MVT VT, llvm::MVT RetVT,
                                          CgRegister OperandReg) {
  const TargetRegisterClass *RetRC = TLI.getRegClassFor(RetVT);

  static unsigned CVTOpcs[2][2] = {
      {X86::CVTSI2SSrr, X86::CVTSI2SDrr},
      {X86::CVTSI642SSrr, X86::CVTSI642SDrr},
  };

  bool IsI64Op = VT.SimpleTy == MVT::i64;
  bool IsF64Ret = RetVT.SimpleTy == MVT::f64;

  unsigned CVTOpc = CVTOpcs[IsI64Op][IsF64Ret];

  return fastEmitInst_r(CVTOpc, RetRC, OperandReg);
}

// ==================== Other Expressions ====================

CgRegister X86CgLowering::lowerVariable(uint32_t VarIdx) {
  MType *Type = _mir_func.getVariableType(VarIdx);
  llvm::MVT VT = getMVT(*Type);
  const llvm::TargetRegisterClass *RC = TLI.getRegClassFor(VT);
  return getOrCreateVarReg(VarIdx, RC);
}

CgRegister
X86CgLowering::fastMaterializeConstant(const ConstantInstruction &Inst) {
  MType &Type = *Inst.getType();
  MVT VT = getMVT(Type);
  const MConstant &Constant = Inst.getConstant();
  if (Type.isInteger()) {
    return X86MaterializeInt(cast<MConstantInt>(Constant), VT);
  } else if (Type.isFloat()) {
    return X86MaterializeFP(cast<MConstantFloat>(Constant), VT);
  }
  ZEN_ASSERT_TODO();
}

CgRegister X86CgLowering::X86MaterializeInt(const MConstantInt &IntConstant,
                                            MVT VT) {
  if (VT > MVT::i64) {
    throw getErrorWithPhase(ErrorCode::UnexpectedType, ErrorPhase::Compilation,
                            ErrorSubphase::CgIREmission);
  }

  uint64_t Imm = IntConstant.getValue().getZExtValue();
  return X86MaterializeInt(Imm, VT);
}

CgRegister X86CgLowering::X86MaterializeInt(uint64_t Imm, MVT VT) {
#ifndef ZEN_ENABLE_EVM
  if (Imm == 0) {
    CgRegister SrcReg = fastEmitInst_(X86::MOV32r0, &X86::GR32RegClass);
    switch (VT.SimpleTy) {
    default:
      llvm_unreachable("Unexpected value type");
    case MVT::i8:
      return fastEmitInst_extractsubreg(MVT::i8, SrcReg, X86::sub_8bit);
    case MVT::i16:
      return fastEmitInst_extractsubreg(MVT::i16, SrcReg, X86::sub_16bit);
    case MVT::i32:
      return SrcReg;
    case MVT::i64: {
      return fastEmitInst_subregtoreg(&X86::GR64RegClass, SrcReg,
                                      X86::sub_32bit);
    }
    }
  }
#endif // ZEN_ENABLE_EVM

  unsigned Opc = 0;
  switch (VT.SimpleTy) {
  default:
    llvm_unreachable("Unexpected value type");
  case MVT::i8:
    Opc = X86::MOV8ri;
    break;
  case MVT::i16:
    Opc = X86::MOV16ri;
    break;
  case MVT::i32:
    Opc = X86::MOV32ri;
    break;
  case MVT::i64: {
    if (isUInt<32>(Imm))
      Opc = X86::MOV32ri64;
    else if (isInt<32>(Imm))
      Opc = X86::MOV64ri32;
    else
      Opc = X86::MOV64ri;
    break;
  }
  }

  return fastEmitInst_i(Opc, TLI.getRegClassFor(VT), Imm);
}

CgRegister X86CgLowering::X86MaterializeFP(const MConstantFloat &FloatConstant,
                                           MVT VT) {
  if (FloatConstant.getValue().isExactlyValue(+0.0))
    return fastMaterializeFloatZero(VT);

  const APFloat &Val = FloatConstant.getValue();
  MVT IntVT;
  if (VT == MVT::f32) {
    IntVT = MVT::i32;
  } else {
    ZEN_ASSERT(VT == MVT::f64);
    IntVT = MVT::i64;
  }
  APInt IntVal = Val.bitcastToAPInt();
  CgRegister IntegerReg = X86MaterializeInt(IntVal.getZExtValue(), IntVT);
  CgRegister ResultReg = fastEmit_r(IntVT, VT, ISD::BITCAST, IntegerReg);
  if (!ResultReg) {
    throw getError(ErrorCode::NoMatchedInstruction);
  }
  return ResultReg;
}

CgRegister X86CgLowering::fastMaterializeFloatZero(MVT VT) {
  // MVT VT;
  // if (!isTypeLegal(CF->getType(), VT))
  //   return 0;

  // Get opcode and regclass for the given zero.
  unsigned Opc = 0;
  switch (VT.SimpleTy) {
  case MVT::f16:
    Opc = X86::FsFLD0SH;
    break;
  case MVT::f32:
    Opc = X86::FsFLD0SS;
    break;
  case MVT::f64:
    Opc = X86::FsFLD0SD;
    break;
  default:
    ZEN_ASSERT_TODO();
  }

  return fastEmitInst_(Opc, TLI.getRegClassFor(VT));
}

static std::pair<X86::CondCode, bool>
getX86ConditionCode(CmpInstruction::Predicate Predicate) {
  X86::CondCode CC = X86::COND_INVALID;
  bool NeedSwap = false;
  switch (Predicate) {
  default:
    break;
  // Floating-point Predicates
  case CmpInstruction::FCMP_UEQ:
    CC = X86::COND_E;
    break;
  case CmpInstruction::FCMP_OLT:
    NeedSwap = true;
    LLVM_FALLTHROUGH;
  case CmpInstruction::FCMP_OGT:
    CC = X86::COND_A;
    break;
  case CmpInstruction::FCMP_OLE:
    NeedSwap = true;
    LLVM_FALLTHROUGH;
  case CmpInstruction::FCMP_OGE:
    CC = X86::COND_AE;
    break;
  case CmpInstruction::FCMP_UGT:
    NeedSwap = true;
    LLVM_FALLTHROUGH;
  case CmpInstruction::FCMP_ULT:
    CC = X86::COND_B;
    break;
  case CmpInstruction::FCMP_UGE:
    NeedSwap = true;
    LLVM_FALLTHROUGH;
  case CmpInstruction::FCMP_ULE:
    CC = X86::COND_BE;
    break;
  case CmpInstruction::FCMP_ONE:
    CC = X86::COND_NE;
    break;
  case CmpInstruction::FCMP_UNO:
    CC = X86::COND_P;
    break;
  case CmpInstruction::FCMP_ORD:
    CC = X86::COND_NP;
    break;
  case CmpInstruction::FCMP_OEQ:
    LLVM_FALLTHROUGH;
  case CmpInstruction::FCMP_UNE:
    CC = X86::COND_INVALID;
    break;

  // Integer Predicates
  case CmpInstruction::ICMP_EQ:
    CC = X86::COND_E;
    break;
  case CmpInstruction::ICMP_NE:
    CC = X86::COND_NE;
    break;
  case CmpInstruction::ICMP_UGT:
    CC = X86::COND_A;
    break;
  case CmpInstruction::ICMP_UGE:
    CC = X86::COND_AE;
    break;
  case CmpInstruction::ICMP_ULT:
    CC = X86::COND_B;
    break;
  case CmpInstruction::ICMP_ULE:
    CC = X86::COND_BE;
    break;
  case CmpInstruction::ICMP_SGT:
    CC = X86::COND_G;
    break;
  case CmpInstruction::ICMP_SGE:
    CC = X86::COND_GE;
    break;
  case CmpInstruction::ICMP_SLT:
    CC = X86::COND_L;
    break;
  case CmpInstruction::ICMP_SLE:
    CC = X86::COND_LE;
    break;
  }
  return {CC, NeedSwap};
}

/// If we have a comparison with RHS as the RHS  of the comparison, return an
/// opcode that works for the compare (e.g. CMP32ri) otherwise return 0.
unsigned X86CgLowering::X86ChooseCmpImmediateOpcode(MVT VT, int64_t Val) {
  switch (VT.SimpleTy) {
  case MVT::i8:
    return X86::CMP8ri;
  case MVT::i16:
    if (isInt<8>(Val))
      return X86::CMP16ri8;
    return X86::CMP16ri;
  case MVT::i32:
    if (isInt<8>(Val))
      return X86::CMP32ri8;
    return X86::CMP32ri;
  case MVT::i64:
    if (isInt<8>(Val))
      return X86::CMP64ri8;
    // 64-bit comparisons are only valid if the immediate fits in a
    // 32-bit sext field.
    if (isInt<32>(Val))
      return X86::CMP64ri32;
    return 0;
  default:
    // Otherwise, we can't fold the immediate into this comparison.
    return 0;
  }
}

unsigned X86CgLowering::X86ChooseCmpImmediateOpcode(MVT VT,
                                                    const APInt &Value) {
  return X86ChooseCmpImmediateOpcode(VT, Value.getSExtValue());
}

unsigned X86CgLowering::X86ChooseCmpOpcode(MVT VT) {
  switch (VT.SimpleTy) {
  default:
    ZEN_UNREACHABLE();
  case MVT::i8:
    return X86::CMP8rr;
  case MVT::i16:
    return X86::CMP16rr;
  case MVT::i32:
    return X86::CMP32rr;
  case MVT::i64:
    return X86::CMP64rr;
  case MVT::f32:
    return X86::UCOMISSrr;
  case MVT::f64:
    return X86::UCOMISDrr;
  }
}

void X86CgLowering::lowerFastCompareExpr(const MInstruction *LHS,
                                         const MInstruction *RHS, MVT VT) {
  CgRegister LHSReg = lowerExpr(*LHS);

  // We have two options: compare with register or immediate. If the RHS of the
  // compare is an immediate that we can fold into this compare, use
  // CMPri/Testrr, otherwise use CMPrr.

  if (const auto *ConstInst = dyn_cast<ConstantInstruction>(RHS);
      ConstInst && ConstInst->getType()->isInteger()) {
    const MConstant &Constant = ConstInst->getConstant();
    const MConstantInt &ConstInt = cast<MConstantInt>(Constant);
    const APInt &Value = ConstInt.getValue();
    int64_t Imm = Value.getSExtValue();
    if (Imm == 0) {
      unsigned TestOpc =
          LHS->getType()->isI32() ? X86::TEST32rr : X86::TEST64rr;
      fastEmitNoDefInst_rr(TestOpc, LHSReg, LHSReg);
      return;
    } else if (unsigned CmpImmOpc = X86ChooseCmpImmediateOpcode(VT, Value);
               CmpImmOpc) {
      fastEmitNoDefInst_ri(CmpImmOpc, LHSReg, Value.getSExtValue());
      return;
    }
  }

  unsigned CompareOpc = X86ChooseCmpOpcode(VT);
  CgRegister RHSReg = lowerExpr(*RHS);
  fastEmitNoDefInst_rr(CompareOpc, LHSReg, RHSReg);
}

CgRegister X86CgLowering::lowerCmpExpr(const CmpInstruction &Inst) {
  CmpInstruction::Predicate Predicate = Inst.getPredicate();
  const MInstruction *LHS = Inst.getOperand<0>();
  const MInstruction *RHS = Inst.getOperand<1>();
  MVT VT = getMVT(*LHS->getType());

  // FCMP_OEQ and FCMP_UNE cannot be checked with a single instruction.
  static const uint16_t SETFOpcTable[2][3] = {
      {X86::COND_E, X86::COND_NP, X86::AND8rr},
      {X86::COND_NE, X86::COND_P, X86::OR8rr},
  };
  const uint16_t *SETFOpc = nullptr;
  switch (Predicate) {
  case CmpInstruction::FCMP_OEQ:
    SETFOpc = SETFOpcTable[0];
    break;
  case CmpInstruction::FCMP_UNE:
    SETFOpc = SETFOpcTable[1];
    break;
  default:
    break;
  }

  CgRegister Result8Reg;
  if (SETFOpc) { // FCMP_OEQ or FCMP_UNE
    lowerFastCompareExpr(LHS, RHS, VT);
    CgRegister FlagReg1 =
        fastEmitInst_i(X86::SETCCr, &X86::GR8RegClass, SETFOpc[0]);
    CgRegister FlagReg2 =
        fastEmitInst_i(X86::SETCCr, &X86::GR8RegClass, SETFOpc[1]);
    Result8Reg =
        fastEmitInst_rr(SETFOpc[2], &X86::GR8RegClass, FlagReg1, FlagReg2);
  } else {
    const auto [CC, SwapArgs] = getX86ConditionCode(Predicate);
    ZEN_ASSERT(CC <= X86::LAST_VALID_COND && "Unexpected condition code.");
    if (SwapArgs) {
      std::swap(LHS, RHS);
    }
    lowerFastCompareExpr(LHS, RHS, VT);
    Result8Reg = fastEmitInst_i(X86::SETCCr, &X86::GR8RegClass, CC);
  }

  if (Inst.getType()->isI8()) {
    return Result8Reg;
  }
  return fastEmitInst_r(X86::MOVZX32rr8, &X86::GR32RegClass, Result8Reg);
}

CgRegister X86CgLowering::lowerAdcExpr(const AdcInstruction &Inst) {
  // Use x86 flags with direct ADC without carry on operands
  // We can be certain that CF will always be produced by the preceding add or
  // by a chain of consecutive adc instructions, so CF injection can be omitted.
  const MInstruction *LHS = Inst.getOperand<0>();
  const MInstruction *RHS = Inst.getOperand<1>();

  MVT VT = getMVT(*Inst.getType());
  ZEN_ASSERT(VT.isInteger());
  const TargetRegisterClass *RC = TLI.getRegClassFor(VT);

  CgRegister LHSReg = lowerExpr(*LHS);
  CgRegister RHSReg = lowerExpr(*RHS);

  // Move LHS into destination and consume CF via ADC with RHS.
  CgRegister SumReg = fastEmitCopy(RC, LHSReg);
  switch (VT.SimpleTy) {
  case MVT::i8:
    MF->createCgInstruction(*CurBB, TII.get(X86::ADC8rr), SumReg, RHSReg,
                            SumReg);
    return SumReg;
  case MVT::i16:
    MF->createCgInstruction(*CurBB, TII.get(X86::ADC16rr), SumReg, RHSReg,
                            SumReg);
    return SumReg;
  case MVT::i32:
    MF->createCgInstruction(*CurBB, TII.get(X86::ADC32rr), SumReg, RHSReg,
                            SumReg);
    return SumReg;
  case MVT::i64:
    MF->createCgInstruction(*CurBB, TII.get(X86::ADC64rr), SumReg, RHSReg,
                            SumReg);
    return SumReg;
  default:
    // Should be unreachable: VT was validated in CF injection above.
    throw getError(ErrorCode::NoMatchedInstruction);
  }
}

CgRegister X86CgLowering::lowerSelectExpr(const SelectInstruction &Inst) {
  const MType &Type = *Inst.getType();
  const MInstruction *Cond = Inst.getOperand<0>();
  const MInstruction *LHS = Inst.getOperand<1>();
  const MInstruction *RHS = Inst.getOperand<2>();
  CgRegister LHSReg = lowerExpr(*LHS);
  CgRegister RHSReg = lowerExpr(*RHS);

  X86::CondCode CC = X86::COND_NE;

  if (const auto *CI = dyn_cast<CmpInstruction>(Cond); CI) {
    CmpInstruction::Predicate Predicate = CI->getPredicate();

    // FCMP_OEQ and FCMP_UNE cannot be checked with a single instruction.
    static const uint16_t SETFOpcTable[2][3] = {
        {X86::COND_NP, X86::COND_E, X86::TEST8rr},
        {X86::COND_P, X86::COND_NE, X86::OR8rr},
    };
    const uint16_t *SETFOpc = nullptr;
    switch (Predicate) {
    default:
      break;
    case CmpInstruction::FCMP_OEQ:
      SETFOpc = SETFOpcTable[0];
      Predicate = CmpInstruction::ICMP_NE;
      break;
    case CmpInstruction::FCMP_UNE:
      SETFOpc = SETFOpcTable[1];
      Predicate = CmpInstruction::ICMP_NE;
      break;
    }

    bool NeedSwap;
    std::tie(CC, NeedSwap) = getX86ConditionCode(Predicate);
    ZEN_ASSERT(CC <= X86::LAST_VALID_COND && "Unexpected condition code.");

    const MInstruction *CmpLHS = CI->getOperand<0>();
    const MInstruction *CmpRHS = CI->getOperand<1>();
    if (NeedSwap) {
      std::swap(CmpLHS, CmpRHS);
    }
    MVT CmpVT = getMVT(*CmpLHS->getType());
    lowerFastCompareExpr(CmpLHS, CmpRHS, CmpVT);

    if (SETFOpc) { // FCMP_OEQ or FCMP_UNE
      CgRegister FlagReg1 =
          fastEmitInst_i(X86::SETCCr, &X86::GR8RegClass, SETFOpc[0]);
      CgRegister FlagReg2 =
          fastEmitInst_i(X86::SETCCr, &X86::GR8RegClass, SETFOpc[1]);
      const llvm::MCInstrDesc &II = TII.get(SETFOpc[2]);
      if (II.getNumDefs()) {
        fastEmitInst_rr(SETFOpc[2], &X86::GR8RegClass, FlagReg2, FlagReg1);
      } else {
        fastEmitNoDefInst_rr(SETFOpc[2], FlagReg2, FlagReg1);
      }
    }
  } else {
    CgRegister CondReg = lowerExpr(*Cond);
    unsigned TESTOpc = Cond->getType()->isI8() ? X86::TEST8rr : X86::TEST32rr;
    fastEmitNoDefInst_rr(TESTOpc, CondReg, CondReg);
  }

  const TargetRegisterClass *RC = TLI.getRegClassFor(getMVT(Type));

  if (Type.isInteger()) {
    ZEN_ASSERT(Subtarget->canUseCMOV());
    unsigned Opc = X86::getCMovOpcode(TRI->getRegSizeInBits(*RC) / 8);
    return fastEmitInst_rri(Opc, RC, RHSReg, LHSReg, CC);
  } else {
    // Assign LHS as default value to Result
    CgRegister ResultReg = fastEmitCopy(RC, LHSReg);

    CgBasicBlock *SinkMBB = MF->createCgBasicBlock();

    // Jump to SinkMBB if the condition is not zero
    fastEmitCondBranch(SinkMBB, CC);

    /* ********** [End] Condition BasicBlock ********** */

    /* ********** [Begin] False BasicBlock ********** */

    // Overwrite Result with RHS in FalseMBB
    startNewBlockAfterBranch();
    MF->createCgInstruction(*CurBB, TII.get(TargetOpcode::COPY), RHSReg,
                            ResultReg);
    CurBB->addSuccessorWithoutProb(SinkMBB); // fallthrough

    /* ********** [End] False BasicBlock ********** */

    /* ********** [Begin] Finally BasicBlock ********** */

    setInsertBlock(SinkMBB);

    return ResultReg;
  }
}

// ==================== Memory Instructions ====================

static inline unsigned getMovMemToRegOpcode(MType::Kind SrcTypeKind,
                                            MType::Kind DestTypeKind,
                                            bool Sext) {
  // [Src(i8/i16/i32)][Dest(i32/i64)][Sext]
  static unsigned PartialOpcodes[3][2][2] = {
      {
          {X86::MOVZX32rm8, X86::MOVSX32rm8},
          {X86::MOVZX64rm8, X86::MOVSX64rm8},
      },
      {
          {X86::MOVZX32rm16, X86::MOVSX32rm16},
          {X86::MOVZX64rm16, X86::MOVSX64rm16},
      },
      {
          {X86::MOV32rm, X86::MOV32rm},
          {X86::MOV32rm, X86::MOVSX64rm32},
      },
  };

  switch (SrcTypeKind) {
  case MType::I8:
  case MType::I16:
  case MType::I32:
    return PartialOpcodes[SrcTypeKind - MType::I8][DestTypeKind - MType::I32]
                         [Sext];
  case MType::I64:
  case MType::POINTER_TYPE:
    return X86::MOV64rm;
  case MType::F32:
    return X86::MOVSSrm;
  case MType::F64:
    return X86::MOVSDrm;
  default:
    ZEN_ASSERT_TODO();
  }
}

static inline unsigned getMovMemToRegOpcode(MType::Kind TypeKind) {
  return getMovMemToRegOpcode(TypeKind, TypeKind, false);
}

static inline unsigned getMovRegToMemOpcode(MType::Kind TypeKind) {
  switch (TypeKind) {
  case MType::I8:
    return X86::MOV8mr;
  case MType::I16:
    return X86::MOV16mr;
  case MType::I32:
    return X86::MOV32mr;
  case MType::I64:
  case MType::POINTER_TYPE:
    return X86::MOV64mr;
  case MType::F32:
    return X86::MOVSSmr;
  case MType::F64:
    return X86::MOVSDmr;
  default:
    ZEN_ASSERT_TODO();
  }
}

CgRegister X86CgLowering::lowerLoadExpr(const LoadInstruction &Inst) {
  unsigned Opcode =
      getMovMemToRegOpcode(Inst.getSrcType()->getKind(),
                           Inst.getDestType()->getKind(), Inst.getSext());

  llvm::MVT VT = getMVT(*Inst.getType());
  CgRegister ResultReg = createReg(TLI.getRegClassFor(VT));
  CgRegister BaseReg = lowerExpr(*Inst.getBase());
  uint32_t Scale = Inst.getScale();
  const MInstruction *IndexExpr = Inst.getIndex();
  CgRegister IndexReg = X86::NoRegister;
  if (IndexExpr) {
    IndexReg = lowerExpr(*IndexExpr);
    if (IndexExpr->getType()->isI32()) {
      // Try enabling the zero-extends below if a memory access error occurs

      // IndexReg = fastEmitInst_r(X86::MOV32rr, &X86::GR32RegClass, IndexReg);
      IndexReg = fastEmitInst_subregtoreg(&X86::GR64RegClass, IndexReg,
                                          X86::sub_32bit);
    }
  }
  int32_t Displacement = Inst.getOffset();

  SmallVector<CgOperand, 6> LoadOperands{
      CgOperand::createRegOperand(ResultReg, true),
      CgOperand::createRegOperand(BaseReg, false),
      CgOperand::createImmOperand(Scale),
      CgOperand::createRegOperand(IndexReg, false),
      CgOperand::createImmOperand(Displacement),
      CgOperand::createRegOperand(X86::NoRegister, false), // Segment Register
  };

  MF->createCgInstruction(*CurBB, TII.get(Opcode), LoadOperands);
  return ResultReg;
}

void X86CgLowering::lowerStoreStmt(const StoreInstruction &Instr) {
  const MInstruction *Value = Instr.getValue();
  const MInstruction *Base = Instr.getBase();

  unsigned Opcode = getMovRegToMemOpcode(Value->getType()->getKind());

  CgRegister ValueReg = lowerExpr(*Value);
  CgRegister BaseReg = lowerExpr(*Base);
  uint32_t Scale = Instr.getScale();
  const MInstruction *IndexExpr = Instr.getIndex();
  CgRegister IndexReg = X86::NoRegister;
  if (IndexExpr) {
    IndexReg = lowerExpr(*IndexExpr);
    if (IndexExpr->getType()->isI32()) {
      // Try enabling the zero-extends below if a memory access error occurs

      // IndexReg = fastEmitInst_r(X86::MOV32rr, &X86::GR32RegClass, IndexReg);
      IndexReg = fastEmitInst_subregtoreg(&X86::GR64RegClass, IndexReg,
                                          X86::sub_32bit);
    }
  }
  int32_t Displacement = Instr.getOffset();

  SmallVector<CgOperand, 6> StoreOperands = {
      CgOperand::createRegOperand(BaseReg, false),
      CgOperand::createImmOperand(Scale),
      CgOperand::createRegOperand(IndexReg, false),
      CgOperand::createImmOperand(Displacement),
      CgOperand::createRegOperand(X86::NoRegister, false), // Segment Register
      CgOperand::createRegOperand(ValueReg, false),
  };

  MF->createCgInstruction(*CurBB, TII.get(Opcode), StoreOperands);
}

// ==================== Control Statements ====================

void X86CgLowering::fastEmitBranch(CgBasicBlock *TargetBB) {
  constexpr unsigned MachineInstOpcode = X86::JMP_1;
  SmallVector<CgOperand, 1> Operands{
      CgOperand::createMBB(TargetBB),
  };
  MF->createCgInstruction(*CurBB, TII.get(MachineInstOpcode), Operands);
  CurBB->addSuccessorWithoutProb(TargetBB);
}

void X86CgLowering::fastEmitCondBranch(CgBasicBlock *TargetBB, unsigned CC) {
  constexpr unsigned MachineInstOpcode = X86::JCC_1;
  SmallVector<CgOperand, 2> Operands{
      CgOperand::createMBB(TargetBB),
      CgOperand::createImmOperand(CC),
  };
  MF->createCgInstruction(*CurBB, TII.get(MachineInstOpcode), Operands);
  CurBB->addSuccessorWithoutProb(TargetBB);
}

void X86CgLowering::lowerBrStmt(const BrInstruction &Inst) {
  MBasicBlock *TargetBB = Inst.getTargetBlock();
  CgBasicBlock *TargetMBB = getOrCreateCgBB(TargetBB);
  fastEmitBranch(TargetMBB);
}

// TODO: optimize if the condition is comparison
void X86CgLowering::lowerBrIfStmt(const BrIfInstruction &Inst) {
  const MInstruction *Operand = Inst.getOperand<0>();
  CgRegister OperandReg = lowerExpr(*Operand);

  // Perform test instruction to determine the operand is zero or not
  unsigned TESTOpc = Operand->getType()->isI8() ? X86::TEST8rr : X86::TEST32rr;
  fastEmitNoDefInst_rr(TESTOpc, OperandReg, OperandReg);

  // Jump to the true basic block if the operand is not zero
  CgBasicBlock *TrueMBB = getOrCreateCgBB(Inst.getTrueBlock());
  fastEmitCondBranch(TrueMBB, X86::CondCode::COND_NE);

  if (Inst.hasFalseBlock()) {
    // Jump to the false basic block if the operand is zero
    CgBasicBlock *FalseMBB = getOrCreateCgBB(Inst.getFalseBlock());
    fastEmitBranch(FalseMBB);
  } else {
    startNewBlockAfterBranch();
  }
}

static unsigned getADDriOpcode(bool IsLP64, int64_t Imm) {
  if (IsLP64) {
    if (isInt<8>(Imm))
      return X86::ADD64ri8;
    return X86::ADD64ri32;
  } else {
    if (isInt<8>(Imm))
      return X86::ADD32ri8;
    return X86::ADD32ri;
  }
}

void X86CgLowering::lowerSwitchStmt(const SwitchInstruction &Inst) {
  uint32_t NumCases = Inst.getNumCases();
  const MBasicBlock *DefaultBB = Inst.getDefaultBlock();
  CgBasicBlock *DefaultMBB = getOrCreateCgBB(DefaultBB);

  bool AllTargetsSame = true;
  for (uint32_t I = 0; I < NumCases; I++) {
    if (Inst.getCaseBlock(I) != DefaultBB) {
      AllTargetsSame = false;
      break;
    }
  }
  if (AllTargetsSame) {
    fastEmitBranch(DefaultMBB);
    return;
  }

  ZEN_ASSERT(NumCases > 0 && "NumCases should be greater than 0");

  CompileVector<int64_t> CaseImmList(MF->getContext().MemPool);
  CompileVector<CgBasicBlock *> CaseMBBList(MF->getContext().MemPool);
  for (uint32_t I = 0; I < NumCases; I++) {
    const ConstantInstruction *CaseValue = Inst.getCaseValue(I);
    const APInt &CaseInt =
        llvm::cast<MConstantInt>(CaseValue->getConstant()).getValue();
    CaseImmList.push_back(CaseInt.getSExtValue());
    CgBasicBlock *CaseMBB = getOrCreateCgBB(Inst.getCaseBlock(I));
    CaseMBBList.push_back(CaseMBB);
  }

  const MInstruction *Operand = Inst.getOperand<0>();
  MVT VT = getMVT(*Operand->getType());
  CgRegister OperandReg = lowerExpr(*Operand);

  if (isJumpTableSuitable(CaseImmList)) {
    const TargetRegisterClass *RC = TLI.getRegClassFor(VT);
    CgRegister CaseReg = OperandReg;
    if (CaseImmList[0] != 0) {
      unsigned ADDriOpc = getADDriOpcode(VT == MVT::i64, -CaseImmList[0]);
      CaseReg = fastEmitInst_ri(ADDriOpc, RC, CaseReg, -CaseImmList[0]);
    }
    ZEN_ASSERT(NumCases >= 1);
    fastEmitNoDefInst_ri(X86::CMP32ri, CaseReg, NumCases - 1);
    fastEmitCondBranch(DefaultMBB, X86::CondCode::COND_A);

    startNewBlockAfterBranch();

    CgRegister LEAResultReg = createReg(&X86::GR64RegClass);
    uint32_t JTI = MF->createJumpTableIndex(CaseMBBList);
    SmallVector<CgOperand, 6> LEAOperands{
        CgOperand::createRegOperand(LEAResultReg, true),
        CgOperand::createRegOperand(X86::RIP, false),        // Base Register
        CgOperand::createImmOperand(0),                      // Scale
        CgOperand::createRegOperand(X86::NoRegister, false), // Index Register
        CgOperand::createJTI(JTI), // Offset(Jump Table Index)
        CgOperand::createRegOperand(X86::NoRegister, false), // Segment Register
    };
    MF->createCgInstruction(*CurBB, TII.get(X86::LEA64r), LEAOperands);

    CgRegister IndexReg = CaseReg;
    if (VT == MVT::i32) {
      IndexReg = fastEmitInst_subregtoreg(&X86::GR64RegClass, IndexReg,
                                          X86::sub_32bit);
    }
    CgRegister LoadResultReg = createReg(&X86::GR64RegClass);
    SmallVector<CgOperand, 6> LoadOperands{
        CgOperand::createRegOperand(LoadResultReg, true),
        CgOperand::createRegOperand(LEAResultReg, false),    // Base Register
        CgOperand::createImmOperand(4),                      // Scale: Rel32
        CgOperand::createRegOperand(IndexReg, false),        // Index Register
        CgOperand::createImmOperand(0),                      // Offset
        CgOperand::createRegOperand(X86::NoRegister, false), // Segment Register
    };
    MF->createCgInstruction(*CurBB, TII.get(X86::MOVSX64rm32), LoadOperands);

    CgRegister JumpTargetReg = fastEmitInst_rr(X86::ADD64rr, &X86::GR64RegClass,
                                               LoadResultReg, LEAResultReg);

    SmallVector<CgOperand, 2> JumpOperands{
        CgOperand::createRegOperand(JumpTargetReg, false),
    };
    MF->createCgInstruction(*CurBB, TII.get(X86::JMP64r), JumpOperands);
    for (CgBasicBlock *CaseMBB : CaseMBBList) {
      CurBB->addSuccessorWithoutProb(CaseMBB);
    }
    return;
  }

#ifdef ZEN_ENABLE_EVM
  // When NumCases is large, use binary search
  static constexpr uint32_t MinBinarySearchCases = 8;
  if (NumCases > MinBinarySearchCases) {
    // Sort the case list by case value
    for (uint32_t I = 0; I < NumCases - 1; I++) {
      for (uint32_t J = 0; J < NumCases - I - 1; J++) {
        if (CaseImmList[J] > CaseImmList[J + 1]) {
          std::swap(CaseImmList[J], CaseImmList[J + 1]);
          std::swap(CaseMBBList[J], CaseMBBList[J + 1]);
        }
      }
    }

    // Binary search context for iteration
    struct BinarySearchContext {
      CgBasicBlock *BB;
      uint32_t StartIdx;
      uint32_t EndIdx;
    };
    CompileVector<BinarySearchContext> SearchBlocks(MF->getContext().MemPool);

    // Initial search context
    SearchBlocks.push_back({nullptr, 0, NumCases - 1});

    // Binary search
    while (!SearchBlocks.empty()) {
      BinarySearchContext Context = SearchBlocks.back();
      SearchBlocks.pop_back();
      CgBasicBlock *CurrentBB = Context.BB;
      uint32_t StartIdx = Context.StartIdx;
      uint32_t EndIdx = Context.EndIdx;
      if (CurrentBB) {
        setInsertBlock(CurrentBB);
      }

      if (StartIdx == EndIdx) {
        // Only one case
        fastEmitNoDefInst_ri(X86::CMP32ri, OperandReg, CaseImmList[StartIdx]);
        fastEmitCondBranch(CaseMBBList[StartIdx], X86::CondCode::COND_E);
        fastEmitBranch(DefaultMBB);
      } else if (EndIdx - StartIdx == 1) {
        // Two cases
        fastEmitNoDefInst_ri(X86::CMP32ri, OperandReg, CaseImmList[StartIdx]);
        fastEmitCondBranch(CaseMBBList[StartIdx], X86::CondCode::COND_E);

        startNewBlockAfterBranch();
        fastEmitNoDefInst_ri(X86::CMP32ri, OperandReg, CaseImmList[EndIdx]);
        fastEmitCondBranch(CaseMBBList[EndIdx], X86::CondCode::COND_E);
        fastEmitBranch(DefaultMBB);
      } else {
        // Divide if more than 2 cases left
        uint32_t MidIdx = StartIdx + (EndIdx - StartIdx) / 2;
        int64_t MidValue = CaseImmList[MidIdx];

        // Compare with the middile value
        fastEmitNoDefInst_ri(X86::CMP32ri, OperandReg, MidValue);
        fastEmitCondBranch(CaseMBBList[MidIdx], X86::CondCode::COND_E);

        startNewBlockAfterBranch();
        fastEmitNoDefInst_ri(X86::CMP32ri, OperandReg, MidValue);
        // Create less branch basic block
        CgBasicBlock *LessBB = MF->createCgBasicBlock();
        fastEmitCondBranch(LessBB, X86::CondCode::COND_L);
        CurBB->addSuccessorWithoutProb(LessBB);
        SearchBlocks.push_back({LessBB, StartIdx, MidIdx - 1});

        // Create greater branch basic block
        CgBasicBlock *GreaterBB = MF->createCgBasicBlock();
        fastEmitBranch(GreaterBB);
        CurBB->addSuccessorWithoutProb(GreaterBB);
        SearchBlocks.push_back({GreaterBB, MidIdx + 1, EndIdx});
      }
    }
    fastEmitBranch(DefaultMBB);
    return;
  }
#endif // ZEN_ENABLE_EVM

  // Use naive compare and jump pattern
  for (uint32_t I = 0; I < NumCases; ++I) {
    fastEmitNoDefInst_ri(X86::CMP32ri, OperandReg, CaseImmList[I]);
    fastEmitCondBranch(CaseMBBList[I], X86::CondCode::COND_E);

    if (I == NumCases - 1) {
      fastEmitBranch(DefaultMBB);
    } else {
      startNewBlockAfterBranch();
    }
  }
}

static const MCPhysReg GPR8ArgRegs[] = {
    X86::DIL, X86::SIL, X86::DL, X86::CL, X86::R8B, X86::R9B,
};
static const MCPhysReg GPR16ArgRegs[] = {
    X86::DI, X86::SI, X86::DX, X86::CX, X86::R8W, X86::R9W,
};
static const MCPhysReg GPR32ArgRegs[] = {
    X86::EDI, X86::ESI, X86::EDX, X86::ECX, X86::R8D, X86::R9D,
};
static const MCPhysReg GPR64ArgRegs[] = {
    X86::RDI, X86::RSI, X86::RDX, X86::RCX, X86::R8, X86::R9,
};
static const MCPhysReg XMMArgRegs[] = {
    X86::XMM0, X86::XMM1, X86::XMM2, X86::XMM3,
    X86::XMM4, X86::XMM5, X86::XMM6, X86::XMM7,
};

static const uint32_t CSR_64_RegMask[] = {
    0x018003f0, 0x000c0180, 0x00000000, 0x00000000, 0x0000000f,
    0x00000000, 0x00000000, 0x0f000000, 0x0f0f0f0f,
};

static unsigned getCallFrameSize(const CallInstructionBase &Inst) {
  int32_t NumIntOperands = 0;
  int32_t NumFloatOperands = 0;
  const uint32_t NumOperands = Inst.getNumOperands();
  for (uint32_t i = 0; i < NumOperands; ++i) {
    MVT ArgVT = getMVT(*Inst.getOperand(i)->getType());
    if (ArgVT.isInteger()) {
      NumIntOperands++;
    } else {
      ZEN_ASSERT(ArgVT.isFloatingPoint());
      NumFloatOperands++;
    }
  }
  return (std::max(NumIntOperands - 6, 0)) * 8 +
         (std::max(NumFloatOperands - 8, 0)) * 8;
}

static MCPhysReg getReturnRegister(MVT VT) {
  MCPhysReg Reg;
  switch (VT.SimpleTy) {
  case MVT::i8:
    return X86::AL;
  case MVT::i16:
    return X86::AX;
  case MVT::i32:
    return X86::EAX;
  case MVT::i64:
    return X86::RAX;
  case MVT::f32:
  case MVT::f64:
    return X86::XMM0;
  case MVT::isVoid:
    return X86::NoRegister;
  default:
    ZEN_ASSERT_TODO();
  }
}

CgRegister X86CgLowering::lowerCall(const CallInstructionBase &Inst) {
  SmallVector<CgOperand, 8> CallOperands;

  bool IsIndirectCall = llvm::isa<ICallInstruction>(Inst);

  if (IsIndirectCall) {
    const auto &ICallInst = llvm::cast<ICallInstruction>(Inst);
    CgRegister CalleeAddrReg = lowerExpr(*ICallInst.getCalleeAddr());
    CallOperands.push_back(CgOperand::createRegOperand(CalleeAddrReg, false));
  } else {
    const auto &DCallInst = llvm::cast<CallInstruction>(Inst);
    CallOperands.push_back(
        CgOperand::createFuncOperand(DCallInst.getCalleeIdx()));
  }

  // Add a register mask operand representing the call-preserved registers.
  CallOperands.push_back(CgOperand::createRegMask(CSR_64_RegMask));

  OperandNum NumOperands = Inst.getNumOperands();
  SmallVector<CgRegister, 6> ArgVirtRegs;
  for (uint32_t i = 0; i < NumOperands; i++) {
    const MInstruction *Operand = Inst.getOperand(i);
    MVT VT = getMVT(*Operand->getType());
    const TargetRegisterClass *RC = TLI.getRegClassFor(VT);
    CgRegister OperandReg = lowerExpr(*Operand);
    CgRegister ArgVirtReg = fastEmitCopy(RC, OperandReg);
    ArgVirtRegs.push_back(ArgVirtReg);
  }

  unsigned StackAdjustNumBytes = getCallFrameSize(Inst);

  // Issue CALLSEQ_START
  unsigned AdjStackDown = TII.getCallFrameSetupOpcode();
  SmallVector<CgOperand, 3> StackDownOperands{
      CgOperand::createImmOperand(StackAdjustNumBytes),
      CgOperand::createImmOperand(0),
      CgOperand::createImmOperand(0),
  };
  MF->createCgInstruction(*CurBB, TII.get(AdjStackDown), StackDownOperands);

  uint32_t GPRIdx = 0;
  uint32_t FPRIdx = 0;
  uint32_t SpillIdx = 0;
  for (uint32_t i = 0; i < NumOperands; i++) {
    const MInstruction *Operand = Inst.getOperand(i);
    MType *Type = Operand->getType();
    CgRegister ArgVirtReg = ArgVirtRegs[i];
    bool NeedSpill = false;
    MCPhysReg ArgReg;
    if (Type->isI8() && GPRIdx < getArraySize(GPR8ArgRegs)) {
      ArgReg = GPR8ArgRegs[GPRIdx++];
    } else if (Type->isI16() && GPRIdx < getArraySize(GPR16ArgRegs)) {
      ArgReg = GPR16ArgRegs[GPRIdx++];
    } else if (Type->isI32() && GPRIdx < getArraySize(GPR32ArgRegs)) {
      ArgReg = GPR32ArgRegs[GPRIdx++];
    } else if ((Type->isI64() || Type->isPointer()) &&
               GPRIdx < getArraySize(GPR64ArgRegs)) {
      ArgReg = GPR64ArgRegs[GPRIdx++];
    } else if (Type->isFloat() && FPRIdx < getArraySize(XMMArgRegs)) {
      ArgReg = XMMArgRegs[FPRIdx++];
    } else {
      NeedSpill = true;
    }

    if (!NeedSpill) {
      MF->createCgInstruction(*CurBB, TII.get(TargetOpcode::COPY), ArgVirtReg,
                              ArgReg);
      CallOperands.push_back(CgOperand::createRegOperand(ArgReg, false, true));
    } else {
      SmallVector<CgOperand, 6> SpillOperands{
          CgOperand::createRegOperand(X86::RSP, false),
          CgOperand::createImmOperand(1),
          CgOperand::createRegOperand(X86::NoRegister, false),
          CgOperand::createImmOperand(SpillIdx * 8),
          CgOperand::createRegOperand(X86::NoRegister, false),
          CgOperand::createRegOperand(ArgVirtReg, false)};
      unsigned Opcode = getMovRegToMemOpcode(Type->getKind());
      MF->createCgInstruction(*CurBB, TII.get(Opcode), SpillOperands);
      SpillIdx++;
    }
  }

  MType *Type = Inst.getType();
  MVT VT = getMVT(*Type);
  CgRegister ReturnReg = getReturnRegister(VT);
  if (!Type->isVoid()) {
    // TODO: need more details of `setPhysRegsDeadExcept`
    CallOperands.push_back(CgOperand::createRegOperand(ReturnReg, true, true));
  }

  unsigned CALLOpc = IsIndirectCall ? X86::CALL64r : X86::CALL64pcrel32;
  MF->createCgInstruction(*CurBB, TII.get(CALLOpc), CallOperands);

  // Issue CALLSEQ_END
  unsigned AdjStackUp = TII.getCallFrameDestroyOpcode();
  SmallVector<CgOperand, 2> StackUpOperands{
      CgOperand::createImmOperand(StackAdjustNumBytes),
      CgOperand::createImmOperand(0),
  };
  MF->createCgInstruction(*CurBB, TII.get(AdjStackUp), StackUpOperands);

  if (!Type->isVoid()) {
    const TargetRegisterClass *RC = TLI.getRegClassFor(VT);
    return fastEmitCopy(RC, ReturnReg);
  }

  return X86::NoRegister;
}

void X86CgLowering::lowerFormalArguments() {
  MFunctionType *FuncType = _mir_func.getFunctionType();
  const auto &ParamTypes = FuncType->getParamTypes();
  uint32_t NumParams = FuncType->getNumParams();

  unsigned GPRIdx = 0;
  unsigned FPRIdx = 0;
  uint32_t ReloadIdx = 0;
  for (uint32_t i = 0; i < NumParams; ++i) {
    MType *Type = ParamTypes[i];
    MVT VT = getMVT(*Type);
    const TargetRegisterClass *RC = TLI.getRegClassFor(VT);
    CgRegister ParamVirtReg = getOrCreateVarReg(i, RC);
    bool NeedReload = false;
    MCPhysReg ParamReg;
    if (Type->isI8() && GPRIdx < getArraySize(GPR8ArgRegs)) {
      ParamReg = GPR8ArgRegs[GPRIdx++];
    } else if (Type->isI16() && GPRIdx < getArraySize(GPR16ArgRegs)) {
      ParamReg = GPR16ArgRegs[GPRIdx++];
    } else if (Type->isI32() && GPRIdx < getArraySize(GPR32ArgRegs)) {
      ParamReg = GPR32ArgRegs[GPRIdx++];
    } else if ((Type->isI64() || Type->isPointer()) &&
               GPRIdx < getArraySize(GPR64ArgRegs)) {
      ParamReg = GPR64ArgRegs[GPRIdx++];
    } else if (Type->isFloat() && FPRIdx < getArraySize(XMMArgRegs)) {
      ParamReg = XMMArgRegs[FPRIdx++];
    } else {
      NeedReload = true;
    }

    if (!NeedReload) {
      MF->createCgInstruction(*CurBB, TII.get(TargetOpcode::COPY), ParamReg,
                              ParamVirtReg);
      MF->getRegInfo().addLiveIn(ParamReg, ParamVirtReg);
    } else {
      unsigned Opcode = getMovMemToRegOpcode(Type->getKind());
      int FI = MF->getFrameInfo().CreateFixedObject(Type->getNumBytes(),
                                                    ReloadIdx * 8, true);
      SmallVector<CgOperand, 6> ReloadOperands{
          CgOperand::createRegOperand(ParamVirtReg, true),
          CgOperand::createFI(FI),
          CgOperand::createImmOperand(1),
          CgOperand::createRegOperand(X86::NoRegister, false),
          CgOperand::createImmOperand(0),
          CgOperand::createRegOperand(X86::NoRegister, false),
      };
      MF->createCgInstruction(*CurBB, TII.get(Opcode), ReloadOperands);
      ReloadIdx++;
      // unsigned StackSize = CCInfo.getNextStackOffset();
      // FuncInfo->setArgumentStackSize(StackSize);
    }
  }

#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
  // Insert explicit COPY from R14 to gas register variable
  VariableIdx GasVarIdx = _mir_func.getGasRegisterVarIdx();
  if (GasVarIdx != VariableIdx(-1)) {
    const TargetRegisterClass *RC = &X86::GR64RegClass;
    CgRegister GasVirtReg = getOrCreateVarReg(GasVarIdx, RC);
    // COPY from R14 (physical) to gas virtual register
    MF->createCgInstruction(*CurBB, TII.get(TargetOpcode::COPY), X86::R14,
                            GasVirtReg);
    // Mark R14 as live-in
    MF->getRegInfo().addLiveIn(X86::R14, GasVirtReg);
  }
#endif
}

void X86CgLowering::lowerReturnStmt(llvm::MVT VT, CgRegister OperandReg) {
  unsigned RETOpc = X86::RET64;

  SmallVector<CgOperand, 1> ReturnOperands;

  if (OperandReg.isValid()) {
    MCPhysReg ResultReg = getReturnRegister(VT);
    MF->createCgInstruction(*CurBB, TII.get(TargetOpcode::COPY), OperandReg,
                            ResultReg);
    // The operand of ret instruction is implicit
    ReturnOperands.push_back(
        CgOperand::createRegOperand(ResultReg, false, true));
  }

#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
  // Insert explicit COPY from gas register variable back to R14
  VariableIdx GasVarIdx = _mir_func.getGasRegisterVarIdx();
  if (GasVarIdx != VariableIdx(-1)) {
    const TargetRegisterClass *RC = &X86::GR64RegClass;
    CgRegister GasVirtReg = getOrCreateVarReg(GasVarIdx, RC);
    // COPY from gas virtual register to R14 (physical)
    MF->createCgInstruction(*CurBB, TII.get(TargetOpcode::COPY), GasVirtReg,
                            X86::R14);
  }
#endif

  MF->createCgInstruction(*CurBB, TII.get(RETOpc), ReturnOperands);
}
