// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#ifndef COMPILER_IR_CG_ISL_LOWERING_H
#define COMPILER_IR_CG_ISL_LOWERING_H

#include "compiler/cgir/cg_function.h"
#include "compiler/cgir/cg_operand.h"
#include "compiler/cgir/value_types.h"
#include "compiler/llvm-prebuild/Target/X86/X86Subtarget.h"
#include "compiler/mir/instructions.h"
#include "compiler/mir/opcode.h"
#include "llvm/CodeGen/TargetInstrInfo.h"
#include "llvm/CodeGen/TargetLowering.h"
#include "llvm/CodeGen/TargetOpcodes.h"
#include "llvm/CodeGen/TargetRegisterInfo.h"
#include "llvm/Support/MachineValueType.h"
#include <vector>
namespace COMPILER {

using namespace llvm;

template <typename T> class CgLowering {
public:
  CgLowering(CgFunction &cg_func)
      : _mir_func(cg_func.getFunction()), MF(&cg_func),
        TRI(cg_func.getRegisterInfo()), TII(cg_func.getTargetInstrInfo()),
        TLI(*cg_func.getContext().getSubtargetInfo().getTargetLowering()),
        MRI(cg_func.getRegInfo()),
        _expr_reg_map(_mir_func.getNumInstructions(), _mpool),
        _var_reg_map(_mir_func.getNumVariables(), _mpool),
        BBMap(_mir_func.getNumBasicBlocks(), nullptr, _mpool) {}

  void lower() {
    MBasicBlock *MEntryBB = _mir_func.getEntryBasicBlock();
    CgBasicBlock *EntryMBB = getOrCreateCgBB(MEntryBB);

    for (MBasicBlock *MIRBB : _mir_func) {
      ZEN_ASSERT(MIRBB);

      if (MIRBB == MEntryBB) {
        setInsertBlock(EntryMBB);
        SELF.lowerFormalArguments();
      } else {
        setInsertBlock(getOrCreateCgBB(MIRBB));
      }

      for (MInstruction *Instr : *MIRBB) {
        ZEN_ASSERT(Instr);
        lowerStmt(*Instr);
      }
    }

    auto &MRI = MF->getRegInfo();
    MRI.EmitLiveInCopies(EntryMBB);
    MRI.freezeReservedRegs(*MF);
  }

protected:
  static bool isJumpTableSuitable(const CompileVector<int64_t> &CaseImmList) {
    uint32_t NumCases = CaseImmList.size();
    // Consider using jump table only if NumCases > 3
    if (NumCases <= 3) {
      return false;
    }

    // Only use jump table when the list of case values is {n, n+1, n+2, ...}
    for (uint32_t I = 1; I < NumCases; ++I) {
      if (CaseImmList[I] - CaseImmList[I - 1] != 1) {
        return false;
      }
    }

    return true;
  }

  CgBasicBlock *getOrCreateCgBB(const MBasicBlock *MIRBB) {
    ZEN_ASSERT(MIRBB);
    uint32_t BBIdx = MIRBB->getIdx();
    ZEN_ASSERT(BBIdx < BBMap.size());
    CgBasicBlock *&CgBB = BBMap[BBIdx];
    if (CgBB) {
      return CgBB;
    }
    CgBB = MF->createCgBasicBlock();
#if defined(ZEN_ENABLE_EVM) && defined(ZEN_ENABLE_LINUX_PERF)
    CgBB->setSourceOffset(MIRBB->getSourceOffset());
    CgBB->setSourceName(MIRBB->getSourceName());
#endif // ZEN_ENABLE_EVM && ZEN_ENABLE_LINUX_PERF
    return CgBB;
  }

  void setInsertBlock(CgBasicBlock *CgBB) {
    CurBB = CgBB;
    MF->appendCgBasicBlock(CgBB);
  }

  // Start a new basic block after an unconditional branch(not a conditional)
  void startNewBlockAfterBranch() {
    CgBasicBlock *NewBB = MF->createCgBasicBlock();
    CurBB->addSuccessorWithoutProb(NewBB);
    setInsertBlock(NewBB);
  }

  void lowerStmt(const MInstruction &Inst) {
    switch (Inst.getKind()) {
    case MInstruction::DASSIGN:
      lowerDassignStmt(llvm::cast<DassignInstruction>(Inst));
      break;
    case MInstruction::STORE:
      SELF.lowerStoreStmt(llvm::cast<StoreInstruction>(Inst));
      break;
    case MInstruction::BR:
      SELF.lowerBrStmt(llvm::cast<BrInstruction>(Inst));
      break;
    case MInstruction::BR_IF:
      SELF.lowerBrIfStmt(llvm::cast<BrIfInstruction>(Inst));
      break;
    case MInstruction::SWITCH:
      SELF.lowerSwitchStmt(llvm::cast<SwitchInstruction>(Inst));
      break;
    case MInstruction::CALL:
      SELF.lowerCall(llvm::cast<CallInstructionBase>(Inst));
      break;
    case MInstruction::RETURN:
      lowerReturnStmt(llvm::cast<ReturnInstruction>(Inst));
      break;
    case MInstruction::WASM_CHECK:
      switch (Inst.getOpcode()) {
      case OP_wasm_check_memory_access:
        SELF.lowerWasmCheckMemoryAccessStmt(
            llvm::cast<WasmCheckMemoryAccessInstruction>(Inst));
        break;
      case OP_wasm_check_stack_boundary:
        SELF.lowerWasmCheckStackBoundaryStmt(
            llvm::cast<WasmCheckStackBoundaryInstruction>(Inst));
        break;
      case OP_wasm_visit_stack_guard:
        SELF.lowerWasmVisitStackGuardStmt(
            llvm::cast<WasmVisitStackGuardInstruction>(Inst));
        break;
      default:
        ZEN_ASSERT_TODO();
      }
      break;
    default:
      ZEN_ASSERT_TODO();
    }
  }

  void lowerReturnStmt(const ReturnInstruction &Inst) {
    const MInstruction *Operand = nullptr;
    MVT VT = getMVT(*Inst.getType());
    CgRegister OperandReg;

    if (Inst.getNumOperands() != 0) {
      Operand = Inst.getOperand<0>();
      OperandReg = lowerExpr(*Operand);
    }

    SELF.lowerReturnStmt(VT, OperandReg);
  }

  CgRegister lowerExpr(const MInstruction &Inst) {
    auto it = _expr_reg_map.find(&Inst);
    if (it != _expr_reg_map.end()) {
      return it->second;
    }
    Opcode Opcode = Inst.getOpcode();
    CgRegister ResultReg;
    switch (Inst.getKind()) {
    case MInstruction::CONSTANT:
      // Refer to issue #51
      ResultReg =
          SELF.fastMaterializeConstant(llvm::cast<ConstantInstruction>(Inst));
      break;
    case MInstruction::UNARY:
      ResultReg = lowerUnaryOpExpr(Inst, Opcode);
      break;
    case MInstruction::BINARY:
      ResultReg = lowerBinaryOpExpr(Inst, Opcode);
      break;
    case MInstruction::OVERFLOW_I128_BINARY:
      ResultReg = SELF.lowerWasmOverflowI128BinaryExpr(
          llvm::cast<WasmOverflowI128BinaryInstruction>(Inst));
      break;
    case MInstruction::ADC:
      ResultReg = SELF.lowerAdcExpr(llvm::cast<AdcInstruction>(Inst));
      break;
    case MInstruction::CMP:
      ResultReg = SELF.lowerCmpExpr(llvm::cast<CmpInstruction>(Inst));
      break;
    case MInstruction::CONVERSION:
      ResultReg = lowerConversionOpExpr(Inst, Opcode);
      break;
    case MInstruction::SELECT:
      ResultReg = SELF.lowerSelectExpr(llvm::cast<SelectInstruction>(Inst));
      break;
    case MInstruction::DREAD:
      ResultReg = lowerDreadExpr(llvm::cast<DreadInstruction>(Inst));
      break;
    case MInstruction::LOAD:
      ResultReg = SELF.lowerLoadExpr(llvm::cast<LoadInstruction>(Inst));
      break;
    case MInstruction::CALL:
      ResultReg = SELF.lowerCall(llvm::cast<CallInstructionBase>(Inst));
      break;
    default:
      ZEN_ASSERT_TODO();
    }
    _expr_reg_map[&Inst] = ResultReg;
    return ResultReg;
  }

  void lowerDassignStmt(const DassignInstruction &inst) {
    auto *opnd = inst.getOperand<0>();
    CgRegister reg_op = lowerExpr(*opnd);
    auto reg_class = MRI.getRegClass(reg_op);

    auto var_reg = getOrCreateVarReg(inst.getVarIdx(), reg_class);
    MF->createCgInstruction(*CurBB, TII.get(llvm::TargetOpcode::COPY), reg_op,
                            var_reg);
  }

  CgRegister lowerDreadExpr(const DreadInstruction &inst) {
    CgRegister ret;
    auto var_idx = inst.getVarIdx();
    auto it = _var_reg_map.find(var_idx);
    if (it != _var_reg_map.end()) {
      ret = it->second;
    } else {
      ret = SELF.lowerVariable(var_idx);
    }
    return ret;
  }

  CgRegister lowerUnaryOpExpr(const MInstruction &inst, Opcode Opcode) {
    const MInstruction *Operand = inst.getOperand<0>();

    CgRegister OperandReg = lowerExpr(*Operand);
    ZEN_ASSERT(_expr_reg_map.count(Operand));

    const MType &Type = *Operand->getType();
    bool IsInteger = Type.isInteger();
    llvm::MVT OperandVT = getMVT(Type);
    llvm::MVT RetVT = getMVT(Type);

    unsigned ISDOpcode;
    switch (Opcode) {
    case OP_not:
      return SELF.lowerNotExpr(OperandVT, OperandReg);
    case OP_clz:
      ISDOpcode = ISD::CTLZ;
      break;
    case OP_ctz:
      ISDOpcode = ISD::CTTZ;
      break;
    case OP_popcnt:
      ISDOpcode = ISD::CTPOP;
      break;
    case OP_bswap:
      ZEN_ASSERT(IsInteger);
      ISDOpcode = ISD::BSWAP;
      break;
    case OP_fpabs:
      ZEN_ASSERT(!IsInteger);
      return SELF.lowerFPAbsExpr(OperandVT, OperandReg);
    case OP_fpneg:
      ZEN_ASSERT(!IsInteger);
      return SELF.lowerFPNegExpr(OperandVT, OperandReg);
    case OP_fpsqrt:
      // TODO: use fastEmit_r(ISD::FSQRT,...) If AVX is disabled
      ZEN_ASSERT(!IsInteger);
      return SELF.lowerFPSqrtExpr(OperandVT, OperandReg);
    case OP_fpround_ceil:
    case OP_fpround_floor:
    case OP_fpround_trunc:
    case OP_fpround_nearest:
      ZEN_ASSERT(!IsInteger);
      return SELF.lowerFPRoundExpr(OperandVT, Opcode, OperandReg);
    default:
      ZEN_ASSERT_TODO();
    }

    CgRegister ResultReg =
        SELF.fastEmit_r(OperandVT, RetVT, ISDOpcode, OperandReg);
    if (!ResultReg) {
      // Fallback for some CPUs not supporting native clz/ctz/popcnt
      switch (Opcode) {
      case OP_clz:
        ResultReg = SELF.lowerClzExpr(OperandVT, OperandReg);
        break;
      case OP_ctz:
        ResultReg = SELF.lowerCtzExpr(OperandVT, OperandReg);
        break;
      case OP_popcnt:
        ResultReg = SELF.lowerPopcntExpr(OperandVT, OperandReg);
        break;
      default:
        throw getError(ErrorCode::NoMatchedInstruction);
      }
    }

    return ResultReg;
  }

  CgRegister lowerBinaryOpExpr(const MInstruction &Inst, Opcode Opcode) {
    const MType &Type = *Inst.getType();
    bool IsInteger = Type.isInteger();
    auto *LHS = Inst.getOperand<0>();
    auto *RHS = Inst.getOperand<1>();

    unsigned ISDOpcode = 0;
    switch (Opcode) {
    case OP_add:
      ISDOpcode = IsInteger ? ISD::ADD : ISD::FADD;
      break;
    case OP_sub:
      ISDOpcode = IsInteger ? ISD::SUB : ISD::FSUB;
      break;
    case OP_mul:
      ISDOpcode = IsInteger ? ISD::MUL : ISD::FMUL;
      break;
    case OP_fpdiv:
      ISDOpcode = ISD::FDIV;
      break;
    case OP_sdiv:
    case OP_udiv:
    case OP_srem:
    case OP_urem:
      return SELF.lowerDivRemExpr(*LHS, *RHS, Type, Opcode);
    case OP_and:
      ISDOpcode = ISD::AND;
      break;
    case OP_or:
      ISDOpcode = ISD::OR;
      break;
    case OP_xor:
      ISDOpcode = ISD::XOR;
      break;
    case OP_fpmin:
    case OP_fpmax: {
      ZEN_ASSERT(!IsInteger);
      bool isMax = Opcode == OP_fpmax;
      return SELF.lowerFPMinMaxExpr(*LHS, *RHS, Type, isMax);
    }
    case OP_fpcopysign:
      return SELF.lowerFPCopySignExpr(*LHS, *RHS, Type);
    case OP_shl:
    case OP_sshr:
    case OP_ushr:
    case OP_rotl:
    case OP_rotr:
      return SELF.lowerShiftExpr(*LHS, *RHS, Type, Opcode);
    case OP_wasm_sadd_overflow:
    case OP_wasm_uadd_overflow:
    case OP_wasm_ssub_overflow:
    case OP_wasm_usub_overflow:
    case OP_wasm_smul_overflow:
    case OP_wasm_umul_overflow:
      return SELF.lowerWasmOverflowBinaryExpr(*LHS, *RHS, Type, Opcode);
    default:
      ZEN_ASSERT_TODO();
    }
    llvm::MVT VT = getMVT(Type);

    if (auto *ConstInst = dyn_cast<ConstantInstruction>(LHS)) {
      if (auto *IntConst = dyn_cast<MConstantInt>(&ConstInst->getConstant())) {
        if (Inst.isCommutative()) {
          CgRegister Op1 = lowerExpr(*RHS);
          ZEN_ASSERT(_expr_reg_map.count(RHS));
          CgRegister ResultReg = fastEmit_ri_(
              VT, ISDOpcode, Op1, IntConst->getValue().getZExtValue(), VT);
          if (ResultReg) {
            return ResultReg;
          }
        }
      }
    }

    CgRegister Op0 = lowerExpr(*LHS);
    ZEN_ASSERT(_expr_reg_map.count(LHS));

    if (auto *ConstInst = dyn_cast<ConstantInstruction>(RHS)) {
      if (auto *IntConst = dyn_cast<MConstantInt>(&ConstInst->getConstant())) {
        CgRegister ResultReg = fastEmit_ri_(
            VT, ISDOpcode, Op0, IntConst->getValue().getZExtValue(), VT);
        if (ResultReg) {
          return ResultReg;
        }
      }
    }

    CgRegister op1 = lowerExpr(*RHS);
    ZEN_ASSERT(_expr_reg_map.count(RHS));

    CgRegister ResultReg = SELF.fastEmit_rr(VT, VT, ISDOpcode, Op0, op1);
    if (!ResultReg) {
      throw getError(ErrorCode::NoMatchedInstruction);
    }

    return ResultReg;
  }

  CgRegister lowerConversionOpExpr(const MInstruction &Inst, Opcode Opcode) {
    const MInstruction *Operand = Inst.getOperand<0>();

    CgRegister OperandReg = lowerExpr(*Operand);
    ZEN_ASSERT(_expr_reg_map.count(Operand));

    llvm::MVT VT = getMVT(*Operand->getType());
    llvm::MVT RetVT = getMVT(*Inst.getType());

    unsigned ISDOpcode;
    switch (Opcode) {
    case OP_inttoptr:
    case OP_ptrtoint:
      return OperandReg;
    case OP_trunc:
      return SELF.lowerIntTruncExpr(VT, RetVT, OperandReg);
    case OP_sext:
      ISDOpcode = ISD::SIGN_EXTEND;
      break;
    case OP_uext:
      return SELF.lowerUExtExpr(VT, RetVT, OperandReg);
    case OP_fptrunc:
      ZEN_ASSERT(VT == MVT::f64);
      ZEN_ASSERT(RetVT == MVT::f32);
      return SELF.lowerFPTruncExpr(OperandReg);
    case OP_fpext:
      ZEN_ASSERT(VT == MVT::f32);
      ZEN_ASSERT(RetVT == MVT::f64);
      return SELF.lowerFPExtExpr(OperandReg);
    case OP_sitofp:
      // ISD::SINT_TO_FP
      return SELF.lowerSIToFPExpr(VT, RetVT, OperandReg);
    case OP_uitofp:
      return SELF.lowerUIToFPExpr(VT, RetVT, OperandReg);
    case OP_bitcast:
      ISDOpcode = ISD::BITCAST;
      break;
    case OP_wasm_fptosi:
      return SELF.lowerWasmFPToSIExpr(VT, RetVT, OperandReg);
    case OP_wasm_fptoui:
      return SELF.lowerWasmFPToUIExpr(VT, RetVT, OperandReg);
    default:
      ZEN_ASSERT_TODO();
    }

    CgRegister ResultReg = SELF.fastEmit_r(VT, RetVT, ISDOpcode, OperandReg);
    if (!ResultReg) {
      throw getError(ErrorCode::NoMatchedInstruction);
    }

    return ResultReg;
  }

  Register fastEmit_ri_(MVT VT, unsigned Opcode, unsigned Op0, uint64_t Imm,
                        MVT ImmType) {
    // If this is a multiply by a power of two, emit this as a shift left.
    if (Opcode == ISD::MUL && isPowerOf2_64(Imm)) {
      Opcode = ISD::SHL;
      Imm = Log2_64(Imm);
    } else if (Opcode == ISD::UDIV && isPowerOf2_64(Imm)) {
      // div x, 8 -> srl x, 3
      Opcode = ISD::SRL;
      Imm = Log2_64(Imm);
    }

    // Horrible hack (to be removed), check to make sure shift amounts are
    // in-range.
    if ((Opcode == ISD::SHL || Opcode == ISD::SRA || Opcode == ISD::SRL ||
         Opcode == ISD::ROTL || Opcode == ISD::ROTR) &&
        Imm >= VT.getSizeInBits()) {
      return 0;
    }

    Register ResultReg = SELF.fastEmit_ri(VT, VT, Opcode, Op0, Imm);
    if (ResultReg) {
      return ResultReg;
    }
    Register MaterialReg =
        SELF.fastEmit_i(ImmType, ImmType, ISD::Constant, Imm);
    if (!MaterialReg) {
      throw getError(ErrorCode::NoMatchedInstruction);
    }

    return SELF.fastEmit_rr(VT, VT, Opcode, Op0, MaterialReg);
  }

  // Shortcut for "<vreg> = <opcode>"
  Register fastEmitInst_(unsigned MachineInstOpcode,
                         const TargetRegisterClass *RC) {
    Register ResultReg = createReg(RC);
    const MCInstrDesc &II = TII.get(MachineInstOpcode);
    SmallVector<CgOperand, 1> Operands{
        CgOperand::createRegOperand(ResultReg, true),
    };
    MF->createCgInstruction(*CurBB, II, Operands);
    return ResultReg;
  }

  // Shortcut for "(<vreg> =)? <opcode> <op0>"
  CgRegister fastEmitInst_r(unsigned MachineInstOpcode,
                            const llvm::TargetRegisterClass *RC, unsigned Op0) {
    const MCInstrDesc &II = TII.get(MachineInstOpcode);

    ZEN_ASSERT(RC && "Expecting Register class");
    CgRegister ResultReg = createReg(RC);
    // Op0 = constrainOperandRegClass(II, Op0, II.getNumDefs());

    if (II.getNumDefs() >= 1) {
      MF->createCgInstruction(*CurBB, II, Op0, ResultReg);
    } else {
      SmallVector<CgOperand, 1> Operands{
          CgOperand::createRegOperand(Op0, false),
      };
      MF->createCgInstruction(*CurBB, II, Operands);
      MF->createCgInstruction(*CurBB, TII.get(TargetOpcode::COPY),
                              II.ImplicitDefs[0], ResultReg);
    }

    return ResultReg;
  }

  // Shortcut for "(<vreg> =)? <opcode> <op0> <op1>"
  CgRegister fastEmitInst_rr(unsigned MachineInstOpcode,
                             const llvm::TargetRegisterClass *RC,
                             CgRegister Op0, CgRegister Op1) {
    const llvm::MCInstrDesc &II = TII.get(MachineInstOpcode);

    ZEN_ASSERT(RC && "Expecting Register class");
    CgRegister ResultReg = createReg(RC);
    // Op0 = constrainOperandRegClass(II, Op0, II.getNumDefs());
    // Op1 = constrainOperandRegClass(II, Op1, II.getNumDefs() + 1);

    if (II.getNumDefs() >= 1) {
      MF->createCgInstruction(*CurBB, II, Op0, Op1, ResultReg);
    } else {
      SmallVector<CgOperand, 2> Operands{
          CgOperand::createRegOperand(Op0, false),
          CgOperand::createRegOperand(Op1, false),
      };
      MF->createCgInstruction(*CurBB, II, Operands);
      MF->createCgInstruction(*CurBB, TII.get(TargetOpcode::COPY),
                              II.ImplicitDefs[0], ResultReg);
    }
    return ResultReg;
  }

  // Shortcut for "(<vreg> =)? <opcode> <op0> <imm>"
  CgRegister fastEmitInst_ri(unsigned MachineInstOpcode,
                             const llvm::TargetRegisterClass *RC, Register Op0,
                             uint64_t Imm) {
    const llvm::MCInstrDesc &II = TII.get(MachineInstOpcode);

    ZEN_ASSERT(RC && "Expecting Register class");
    CgRegister ResultReg = createReg(RC);
    // Op0 = constrainOperandRegClass(II, Op0, II.getNumDefs());

    if (II.getNumDefs() >= 1) {
      SmallVector<CgOperand, 3> Operands{
          CgOperand::createRegOperand(ResultReg, true),
          CgOperand::createRegOperand(Op0, false),
          CgOperand::createImmOperand(Imm),
      };
      MF->createCgInstruction(*CurBB, II, Operands);
    } else {
      SmallVector<CgOperand, 2> Operands{
          CgOperand::createRegOperand(Op0, false),
          CgOperand::createImmOperand(Imm),
      };
      MF->createCgInstruction(*CurBB, II, Operands);
      MF->createCgInstruction(*CurBB, TII.get(TargetOpcode::COPY),
                              II.ImplicitDefs[0], ResultReg);
    }
    return ResultReg;
  }

  // Shortcut for "(<vreg> =)? <opcode> <op0> <op1> <imm>"
  CgRegister fastEmitInst_rri(unsigned MachineInstOpcode,
                              const TargetRegisterClass *RC, unsigned Op0,
                              unsigned Op1, uint64_t Imm) {
    const MCInstrDesc &II = TII.get(MachineInstOpcode);

    ZEN_ASSERT(RC && "Expecting Register class");
    CgRegister ResultReg = createReg(RC);
    // Op0 = constrainOperandRegClass(II, Op0, II.getNumDefs());
    // Op1 = constrainOperandRegClass(II, Op1, II.getNumDefs() + 1);

    if (II.getNumDefs() >= 1) {
      SmallVector<CgOperand, 4> Operands{
          CgOperand::createRegOperand(ResultReg, true),
          CgOperand::createRegOperand(Op0, false),
          CgOperand::createRegOperand(Op1, false),
          CgOperand::createImmOperand(Imm),
      };
      MF->createCgInstruction(*CurBB, II, Operands);
    } else {
      SmallVector<CgOperand, 3> Operands{
          CgOperand::createRegOperand(Op0, false),
          CgOperand::createRegOperand(Op1, false),
          CgOperand::createImmOperand(Imm),
      };
      MF->createCgInstruction(*CurBB, II, Operands);
      MF->createCgInstruction(*CurBB, TII.get(TargetOpcode::COPY),
                              II.ImplicitDefs[0], ResultReg);
    }

    return ResultReg;
  }

  // Shortcut for "(<vreg> =)? <opcode> <imm>"
  CgRegister fastEmitInst_i(unsigned MachineInstOpcode,
                            const llvm::TargetRegisterClass *RC, uint64_t Imm) {
    const llvm::MCInstrDesc &II = TII.get(MachineInstOpcode);

    ZEN_ASSERT(RC && "Expecting Register class");
    CgRegister ResultReg = createReg(RC);

    if (II.getNumDefs() >= 1) {
      SmallVector<CgOperand, 2> Operands{
          CgOperand::createRegOperand(ResultReg, true),
          CgOperand::createImmOperand(Imm),
      };
      MF->createCgInstruction(*CurBB, II, Operands);
    } else {
      SmallVector<CgOperand, 1> Operands{
          CgOperand::createImmOperand(Imm),
      };
      MF->createCgInstruction(*CurBB, II, Operands);
      MF->createCgInstruction(*CurBB, TII.get(TargetOpcode::COPY),
                              II.ImplicitDefs[0], ResultReg);
    }
    return ResultReg;
  }

  // Shortcut for "<vreg> = EXTRACT_SUBREG 0 <op0:idx>"
  CgRegister fastEmitInst_extractsubreg(llvm::MVT RetVT, unsigned Op0,
                                        uint32_t Idx) {
    CgRegister ResultReg = createReg(TLI.getRegClassFor(RetVT));
    ZEN_ASSERT(Register::isVirtualRegister(Op0) &&
               "Cannot yet extract from physregs");
    // const TargetRegisterClass *RC = MRI.getRegClass(Op0);
    // MRI.constrainRegClass(Op0, TRI.getSubClassWithSubReg(RC, Idx));
    CgOperand RegOp = CgOperand::createRegOperand(Op0, false);
    RegOp.setSubReg(Idx);
    SmallVector<CgOperand, 2> Operands{
        CgOperand::createRegOperand(ResultReg, true),
        RegOp,
    };
    MF->createCgInstruction(*CurBB, TII.get(TargetOpcode::COPY), Operands);
    return ResultReg;
  }

  // Shortcut for "<vreg> = SUBREG_TO_REG 0 <op0> <idx>"
  CgRegister fastEmitInst_subregtoreg(const llvm::TargetRegisterClass *RC,
                                      unsigned Op0, uint32_t Idx) {
    Register ResultReg = createReg(RC);
    SmallVector<CgOperand, 4> Operands{
        CgOperand::createRegOperand(ResultReg, true),
        CgOperand::createImmOperand(0),
        CgOperand::createRegOperand(Op0, false),
        CgOperand::createImmOperand(Idx),
    };
    MF->createCgInstruction(*CurBB, TII.get(TargetOpcode::SUBREG_TO_REG),
                            Operands);
    return ResultReg;
  }

  CgRegister fastEmitCopy(const llvm::TargetRegisterClass *RC, unsigned Op0) {
    const MCInstrDesc &II = TII.get(TargetOpcode::COPY);
    ZEN_ASSERT(RC && "Expecting Register class");
    CgRegister ResultReg = createReg(RC);
    MF->createCgInstruction(*CurBB, II, Op0, ResultReg);
    return ResultReg;
  }

  void fastEmitNoDefInst_rr(unsigned MachineInstOpcode, CgRegister Op0,
                            CgRegister Op1) {
    const llvm::MCInstrDesc &II = TII.get(MachineInstOpcode);
    SmallVector<CgOperand, 2> Operands{
        CgOperand::createRegOperand(Op0, false),
        CgOperand::createRegOperand(Op1, false),
    };
    MF->createCgInstruction(*CurBB, II, Operands);
  }

  void fastEmitNoDefInst_ri(unsigned MachineInstOpcode, CgRegister Op0,
                            uint64_t Imm) {
    const llvm::MCInstrDesc &II = TII.get(MachineInstOpcode);
    SmallVector<CgOperand, 2> Operands{
        CgOperand::createRegOperand(Op0, false),
        CgOperand::createImmOperand(Imm),
    };
    MF->createCgInstruction(*CurBB, II, Operands);
  }

  CgRegister getOrCreateVarReg(uint32_t var_idx,
                               const llvm::TargetRegisterClass *reg_class) {
    auto pair = _var_reg_map.emplace(var_idx, 0);
    if (pair.second) {
      pair.first->second = createReg(reg_class);
    }
    return pair.first->second;
  }
  CgRegister createReg(const llvm::TargetRegisterClass *reg_class) {
    return MRI.createVirtualRegister(reg_class);
  }
  void updateVarReg(uint32_t var_idx, CgRegister reg,
                    const llvm::TargetRegisterClass *reg_class) {
    _var_reg_map[var_idx] = reg;
    MRI.setRegClass(reg, reg_class);
  }

  bool shouldOptForSize(const CgFunction *_MF) { return false; }

  CompileMemPool _mpool;
  MFunction &_mir_func;
  CgFunction *MF;
  const llvm::TargetRegisterInfo &TRI;
  const llvm::TargetInstrInfo &TII;
  const llvm::TargetLowering &TLI;

  CgRegisterInfo &MRI;
  CgBasicBlock *CurBB = nullptr;
  CompileUnorderedMap<const MInstruction *, CgRegister> _expr_reg_map;
  CompileUnorderedMap<uint32_t, CgRegister> _var_reg_map;
  // Map from MIR BB to CgIR BB; the key is the index of MIR BB
  CompileVector<CgBasicBlock *> BBMap;
};

} // namespace COMPILER

#endif // COMPILER_IR_CG_ISL_LOWERING_H
