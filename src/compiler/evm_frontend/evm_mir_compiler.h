// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef EVM_FRONTEND_EVM_MIR_COMPILER_H
#define EVM_FRONTEND_EVM_MIR_COMPILER_H

#include "action/vm_eval_stack.h"
#include "compiler/context.h"
#include "compiler/mir/function.h"
#include "compiler/mir/instructions.h"
#include "compiler/mir/pointer.h"
#include "evm/evm.h"
#include "evmc/instructions.h"
#include "intx/intx.hpp"
#include <vector>

// Forward declaration to avoid circular dependency
namespace COMPILER {
struct RuntimeFunctions;
} // namespace COMPILER

namespace zen::runtime {
class EVMInstance;
} // namespace zen::runtime

namespace COMPILER {

enum class EVMType : uint8_t {
  VOID,    // No value
  UINT8,   // Byte operations
  UINT32,  // Intermediate values
  UINT64,  // Gas calculations
  UINT256, // Main EVM type (256-bit integers) - maps to EVMU256Type from
           // common/type.h
  BYTES32, // 32-byte fixed arrays (address, origin, caller, callvalue)
  ADDRESS, // 20-byte Ethereum addresses
  BYTES,   // Dynamic byte arrays
};

class Variable;

using Byte = zen::common::Byte;

class EVMFrontendContext final : public CompileContext {
public:
  EVMFrontendContext();
  ~EVMFrontendContext() override = default;

  EVMFrontendContext(const EVMFrontendContext &OtherCtx);
  EVMFrontendContext &operator=(const EVMFrontendContext &OtherCtx) = delete;
  EVMFrontendContext(EVMFrontendContext &&OtherCtx) = delete;
  EVMFrontendContext &operator=(EVMFrontendContext &&OtherCtx) = delete;

  static MType *getMIRTypeFromEVMType(EVMType Type);
  static zen::common::EVMU256Type *getEVMU256Type();

  void setBytecode(const Byte *Code, size_t CodeSize) {
    Bytecode = Code;
    BytecodeSize = CodeSize;
  }

  const Byte *getBytecode() const { return Bytecode; }
  size_t getBytecodeSize() const { return BytecodeSize; }

  void setGasMeteringEnabled(bool Enabled) { GasMeteringEnabled = Enabled; }
  bool isGasMeteringEnabled() const { return GasMeteringEnabled; }

  void setGasChunkInfo(const uint32_t *ChunkEnd, const uint64_t *ChunkCost,
                       size_t Size) {
    GasChunkEnd = ChunkEnd;
    GasChunkCost = ChunkCost;
    GasChunkSize = Size;
  }
  const uint32_t *getGasChunkEnd() const { return GasChunkEnd; }
  const uint64_t *getGasChunkCost() const { return GasChunkCost; }
  size_t getGasChunkSize() const { return GasChunkSize; }
  bool hasGasChunks() const {
    return GasChunkEnd && GasChunkCost && GasChunkSize > 0;
  }

  void setRevision(evmc_revision Rev) { Revision = Rev; }
  evmc_revision getRevision() const { return Revision; }

#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
  void setGasRegisterEnabled(bool Enabled) { GasRegisterEnabled = Enabled; }
  bool isGasRegisterEnabled() const { return GasRegisterEnabled; }
#endif

private:
  const Byte *Bytecode = nullptr;
  size_t BytecodeSize = 0;
  bool GasMeteringEnabled = false;
  const uint32_t *GasChunkEnd = nullptr;
  const uint64_t *GasChunkCost = nullptr;
  size_t GasChunkSize = 0;
  evmc_revision Revision = zen::evm::DEFAULT_REVISION;
#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
  bool GasRegisterEnabled = false;
#endif
};

void buildEVMFunction(EVMFrontendContext &Context, MModule &MMod,
                      const runtime::EVMModule &EVMMod);

class EVMMirBuilder final {
public:
  typedef EVMFrontendContext CompilerContext;

  static constexpr size_t EVM_ELEMENTS_COUNT = 4;
  using Bytes = common::Bytes;
  // TODO: Simplify as array of 4 MIR instructions, optimize for dynamic later
  using U256Inst = std::array<MInstruction *, EVM_ELEMENTS_COUNT>;
  using U256Var = std::array<Variable *, EVM_ELEMENTS_COUNT>;
  /// U256 value representation as array of 4 x uint64_t
  using U256Value = std::array<uint64_t, EVM_ELEMENTS_COUNT>;
  using U256ConstInt = std::array<MConstantInt *, EVM_ELEMENTS_COUNT>;

  // Range classification for u256 operands.  Narrower ranges enable
  // single-instruction fast paths instead of expensive multi-limb arithmetic.
  enum class ValueRange : uint8_t {
    U64,  // Fits in 64 bits  (limbs [1..3] == 0)
    U128, // Fits in 128 bits (limbs [2..3] == 0)
    U256, // Full 256 bits — conservative default
  };

  EVMMirBuilder(CompilerContext &Context, MFunction &MFunc);

  class Operand {
  public:
    enum class DeferredKind : uint8_t {
      NONE,
      BITWISE_NOT,
      ZERO_TEST_EQ,
      ZERO_TEST_NE
    };

    Operand() = default;
    Operand(MInstruction *Instr, EVMType Type) : Instr(Instr), Type(Type) {}
    Operand(Variable *Var, EVMType Type) : Var(Var), Type(Type) {}

    // Constructor for EVMU256Type with 4 I64 components
    Operand(U256Inst Components, EVMType Type)
        : Type(Type), U256Components(Components), IsU256MultiComponent(true) {
      ZEN_ASSERT(Type == EVMType::UINT256 && "Multi-component only for U256");
    }

    // Constructor for U256 multi-component with explicit range
    Operand(U256Inst Components, EVMType Type, ValueRange Range)
        : Type(Type), Range(Range), U256Components(Components),
          IsU256MultiComponent(true) {
      ZEN_ASSERT(Type == EVMType::UINT256 && "Multi-component only for U256");
    }

    Operand(U256Var VarComponents, EVMType Type)
        : Type(Type), U256VarComponents(VarComponents),
          IsU256MultiComponent(true) {
      ZEN_ASSERT(Type == EVMType::UINT256 && "Multi-component only for U256");
    }

    Operand(const U256Value &ConstValue)
        : Type(EVMType::UINT256), ConstValue(ConstValue), IsConstant(true) {
      // Auto-derive range from constant value
      if (ConstValue[1] == 0 && ConstValue[2] == 0 && ConstValue[3] == 0) {
        Range = ValueRange::U64;
      } else if (ConstValue[2] == 0 && ConstValue[3] == 0) {
        Range = ValueRange::U128;
      } else {
        Range = ValueRange::U256;
      }
    }

    static Operand createDeferredBitwiseNot(U256Inst BaseComponents) {
      Operand Result;
      Result.Type = EVMType::UINT256;
      Result.DeferredValueKind = DeferredKind::BITWISE_NOT;
      Result.U256Components = BaseComponents;
      return Result;
    }

    static Operand createDeferredZeroTest(U256Inst BaseComponents,
                                          bool IsNegated) {
      Operand Result;
      Result.Type = EVMType::UINT256;
      Result.DeferredValueKind =
          IsNegated ? DeferredKind::ZERO_TEST_NE : DeferredKind::ZERO_TEST_EQ;
      Result.U256Components = BaseComponents;
      return Result;
    }

    MInstruction *getInstr() const { return Instr; }
    Variable *getVar() const { return Var; }
    EVMType getType() const { return Type; }

    bool isEmpty() const {
      return !Instr && !Var && !IsU256MultiComponent && !IsConstant &&
             DeferredValueKind == DeferredKind::NONE && Type == EVMType::VOID;
    }

    bool isU256MultiComponent() const { return IsU256MultiComponent; }
    bool isConstant() const { return IsConstant; }
    bool isZeroConstant() const {
      return IsConstant && ConstValue[0] == 0 && ConstValue[1] == 0 &&
             ConstValue[2] == 0 && ConstValue[3] == 0;
    }
    bool isOneConstant() const {
      return IsConstant && ConstValue[0] == 1 && ConstValue[1] == 0 &&
             ConstValue[2] == 0 && ConstValue[3] == 0;
    }
    bool isAllOnesConstant() const {
      return IsConstant && ConstValue[0] == UINT64_MAX &&
             ConstValue[1] == UINT64_MAX && ConstValue[2] == UINT64_MAX &&
             ConstValue[3] == UINT64_MAX;
    }
    bool isConstU64() const {
      return IsConstant && ConstValue[1] == 0 && ConstValue[2] == 0 &&
             ConstValue[3] == 0;
    }
    bool isDeferredValue() const {
      return DeferredValueKind != DeferredKind::NONE;
    }
    bool isDeferredBitwiseNot() const {
      return DeferredValueKind == DeferredKind::BITWISE_NOT;
    }
    bool isDeferredZeroTest() const {
      return DeferredValueKind == DeferredKind::ZERO_TEST_EQ ||
             DeferredValueKind == DeferredKind::ZERO_TEST_NE;
    }
    bool isDeferredZeroTestNegated() const {
      ZEN_ASSERT(isDeferredZeroTest() && "Not a deferred zero-test value");
      return DeferredValueKind == DeferredKind::ZERO_TEST_NE;
    }

    const U256Inst &getU256Components() const {
      ZEN_ASSERT(IsU256MultiComponent && "Not a multi-component U256");
      return U256Components;
    }
    const U256Var &getU256VarComponents() const {
      ZEN_ASSERT(IsU256MultiComponent && "Not a multi-component U256");
      return U256VarComponents;
    }
    const U256Value &getConstValue() const {
      ZEN_ASSERT(IsConstant && "Not a constant value");
      return ConstValue;
    }
    const U256Inst &getDeferredBaseComponents() const {
      ZEN_ASSERT(DeferredValueKind != DeferredKind::NONE &&
                 "Not a deferred value");
      return U256Components;
    }

    // Provable value range — narrower ranges enable fast arithmetic paths
    ValueRange getRange() const { return Range; }

    // Check whether both operands provably fit in u64
    static bool bothFitU64(const Operand &A, const Operand &B) {
      return A.getRange() == ValueRange::U64 && B.getRange() == ValueRange::U64;
    }

    constexpr bool isReg() { return false; }
    constexpr bool isTempReg() { return true; }

  private:
    MInstruction *Instr = nullptr;
    Variable *Var = nullptr;
    EVMType Type = EVMType::VOID;
    ValueRange Range = ValueRange::U256;

    // For EVMU256Type: 4 I64 components [0]=low, [1]=mid-low, [2]=mid-high,
    // [3]=high
    U256Inst U256Components = {};
    U256Var U256VarComponents = {};
    U256Value ConstValue = {};
    bool IsConstant = false;
    bool IsU256MultiComponent = false;
    DeferredKind DeferredValueKind = DeferredKind::NONE;
  };

  bool compile(CompilerContext *Context);
  void loadEVMInstanceAttr();
  void initEVM(CompilerContext *Context);
  void finalizeEVMBase();

  void meterOpcode(evmc_opcode Opcode, uint64_t PC);
  void meterOpcodeRange(uint64_t StartPC, uint64_t EndPCExclusive);
  bool isOpcodeDefined(evmc_opcode Opcode) const;
  void meterGas(uint64_t GasCost);

  // Complete jump implementation with jump table
  void createJumpTable();
  void implementConstantJump(uint64_t ConstDest, MBasicBlock *FailureBB);
  void implementIndirectJump(MInstruction *JumpTarget, MBasicBlock *FailureBB);

  void releaseOperand(Operand Opnd) {}

  // Block for stack check instructions
  void createStackCheckBlock(int32_t MinSize, int32_t MaxSize);

  // ==================== Stack Instruction Handlers ====================

  void stackPush(Operand PushValue);
  Operand stackPop();

  void stackSet(int32_t IndexFromTop, Operand SetValue);
  Operand stackGet(int32_t IndexFromTop);
  void setTrackedStackDepth(uint32_t Depth);
  Operand createStackEntryOperand();
  void assignStackEntryOperand(const Operand &Dest, const Operand &Value);
  Operand prepareStackPhiIncoming(const Operand &Value);
  void registerCurrentBlockPC(uint64_t BlockPC);
  Operand materializeStackMergeOperand(
      const std::vector<uint64_t> &PredBlockPCs,
      const std::vector<std::pair<uint64_t, Operand>> &IncomingValues);
  void assignStackMergeOperand(const Operand &Dest, uint64_t PredBlockPC,
                               const Operand &Value);
  void spillTrackedStack(const std::vector<Operand> &TrackedStack);
  void
  spillTrackedStackPreservingPrefix(const std::vector<Operand> &TrackedStack,
                                    uint32_t PrefixDepth);

  // PUSH0: place value 0 on stack
  // PUSH1-PUSH32: Push N bytes onto stack
  Operand handlePush(const Bytes &Data);

  // ==================== Control Flow Instruction Handlers ====================

  void handleStop();
  void handleVoidReturn();
  void handleJump(Operand Dest);
  void handleJumpI(Operand Dest, Operand Cond);
  void handleJumpDest(const uint64_t &PC);

  // ==================== Arithmetic Instruction Handlers ====================

  template <BinaryOperator Operator>
  Operand handleBinaryArithmetic(const Operand &LHSOp, const Operand &RHSOp) {
    // Phase 0: Constant folding
    if (LHSOp.isConstant() && RHSOp.isConstant()) {
      intx::uint256 L = u256ValueToIntx(LHSOp.getConstValue());
      intx::uint256 R = u256ValueToIntx(RHSOp.getConstValue());
      intx::uint256 Res;
      if constexpr (Operator == BinaryOperator::BO_ADD) {
        Res = L + R;
      } else if constexpr (Operator == BinaryOperator::BO_SUB) {
        Res = L - R;
      } else {
        ZEN_ASSERT_TODO();
      }
      return Operand(intxToU256Value(Res));
    }

    if constexpr (Operator == BinaryOperator::BO_ADD) {
      if (LHSOp.isZeroConstant()) {
        return RHSOp;
      }
      if (RHSOp.isZeroConstant()) {
        return LHSOp;
      }
    }

    if constexpr (Operator == BinaryOperator::BO_SUB) {
      if (RHSOp.isZeroConstant()) {
        return LHSOp;
      }
    }

    // Phase 1: Range-based u64 fast path for ADD
    // When both operands provably fit in u64, emit single ADD + carry
    // instead of the full 4-limb ADC chain.  Result fits in u128.
    if constexpr (Operator == BinaryOperator::BO_ADD) {
      if (Operand::bothFitU64(LHSOp, RHSOp) && !LHSOp.isConstant() &&
          !RHSOp.isConstant()) {
        MType *MirI64Type =
            EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);
        MInstruction *Zero = createIntConstInstruction(MirI64Type, 0);
        U256Inst LHS = extractU256Operand(LHSOp);
        U256Inst RHS = extractU256Operand(RHSOp);
        MInstruction *Sum = createInstruction<BinaryInstruction>(
            false, OP_add, MirI64Type, LHS[0], RHS[0]);
        Sum = protectUnsafeValue(Sum, MirI64Type);
        // Carry = (Sum < LHS[0]) ? 1 : 0
        MInstruction *CarryCmp = createInstruction<CmpInstruction>(
            false, CmpInstruction::ICMP_ULT, MirI64Type, Sum, LHS[0]);
        MInstruction *CarryExt = zeroExtendToI64(CarryCmp);
        U256Inst Result = {Sum, CarryExt, Zero, Zero};
        return Operand(Result, EVMType::UINT256, ValueRange::U128);
      }
    }

    // Phase 2: u64 fast path for ADD - share zero const for upper RHS limbs
    if constexpr (Operator == BinaryOperator::BO_ADD) {
      bool LHSIsU64 = LHSOp.isConstU64();
      bool RHSIsU64 = RHSOp.isConstU64();
      if (LHSIsU64 || RHSIsU64) {
        // ADD is commutative: normalize so the u64 const is on the RHS
        const Operand &FullOp = LHSIsU64 ? RHSOp : LHSOp;
        const Operand &U64Op = LHSIsU64 ? LHSOp : RHSOp;
        return handleAddU64Const(FullOp, U64Op);
      }
    }

    // Phase 2: u64 fast path for SUB (only when RHS is u64 const)
    if constexpr (Operator == BinaryOperator::BO_SUB) {
      if (RHSOp.isConstU64()) {
        return handleSubU64Const(LHSOp, RHSOp);
      }
    }

    U256Inst Result = {};
    U256Inst LHS = extractU256Operand(LHSOp);
    U256Inst RHS = extractU256Operand(RHSOp);
    MType *MirI64Type =
        EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);

    if constexpr (Operator == BinaryOperator::BO_ADD) {
      MInstruction *Carry = createIntConstInstruction(MirI64Type, 0);

      // Pre-materialize all operand components into variables before the
      // ADD/ADC carry chain to prevent flag-clobbering during x86 lowering.
      for (size_t I = 0; I < EVM_ELEMENTS_COUNT; ++I) {
        LHS[I] = protectUnsafeValue(LHS[I], MirI64Type);
        RHS[I] = protectUnsafeValue(RHS[I], MirI64Type);
      }

      for (size_t I = 0; I < EVM_ELEMENTS_COUNT; ++I) {
        if (I == 0) {
          MInstruction *LocalResult = createInstruction<BinaryInstruction>(
              false, OP_add, MirI64Type, LHS[I], RHS[I]);
          Result[I] = protectUnsafeValue(LocalResult, MirI64Type);
        } else {
          MInstruction *LocalResult = createInstruction<AdcInstruction>(
              false, MirI64Type, LHS[I], RHS[I], Carry);
          Result[I] = protectUnsafeValue(LocalResult, MirI64Type);
        }
      }
    } else if constexpr (Operator == BinaryOperator::BO_SUB) {
      // The borrow here is only used for constructing the sbb instruction.
      // We currently use sbb only in bo_sub, and since we can guarantee the
      // instructions are consecutive, there's no need to compute the borrow
      // in DMIR.
      MInstruction *Borrow = createIntConstInstruction(MirI64Type, 0);

      // Pre-materialize all operand components into variables before the
      // SUB/SBB borrow chain. This ensures that during x86 lowering, no
      // flag-modifying instructions (e.g. ADD for address computation in
      // BYTES32-to-U256 conversion) are emitted between the SUB and SBB
      // instructions that form the borrow chain. Without this, lazy
      // expression lowering of operands like BSWAP(LOAD(ADD(ptr, offset)))
      // would emit x86 ADD instructions that clobber the carry flag (CF).
      for (size_t I = 0; I < EVM_ELEMENTS_COUNT; ++I) {
        LHS[I] = protectUnsafeValue(LHS[I], MirI64Type);
        RHS[I] = protectUnsafeValue(RHS[I], MirI64Type);
      }

      for (size_t I = 0; I < EVM_ELEMENTS_COUNT; ++I) {
        if (I == 0) {
          MInstruction *LocalResult = createInstruction<BinaryInstruction>(
              false, OP_sub, MirI64Type, LHS[I], RHS[I]);
          Result[I] = protectUnsafeValue(LocalResult, MirI64Type);
        } else {
          MInstruction *LocalResult = createInstruction<SbbInstruction>(
              false, MirI64Type, LHS[I], RHS[I], Borrow);
          Result[I] = protectUnsafeValue(LocalResult, MirI64Type);
        }
      }
    } else {
      ZEN_ASSERT_TODO();
    }
    return Operand(Result, EVMType::UINT256);
  }

  Operand handleMul(Operand MultiplicandOp, Operand MultiplierOp);
  Operand handleDiv(Operand DividendOp, Operand DivisorOp);
  Operand handleSDiv(Operand DividendOp, Operand DivisorOp);
  Operand handleMod(Operand DividendOp, Operand DivisorOp);
  Operand handleSMod(Operand DividendOp, Operand DivisorOp);
  Operand handleAddMod(Operand AugendOp, Operand AddendOp, Operand ModulusOp);
  Operand handleMulMod(Operand MultiplicandOp, Operand MultiplierOp,
                       Operand ModulusOp);
  Operand handleExp(Operand BaseOp, Operand ExponentOp);
  template <CompareOperator Operator>
  Operand handleCompareOp(Operand LHSOp, Operand RHSOp) {
    // Phase 0: Constant folding
    if constexpr (Operator == CompareOperator::CO_EQZ) {
      if (LHSOp.isConstant()) {
        const auto &V = LHSOp.getConstValue();
        uint64_t R = (V[0] == 0 && V[1] == 0 && V[2] == 0 && V[3] == 0) ? 1 : 0;
        return Operand(U256Value{R, 0, 0, 0});
      }

      if (LHSOp.isDeferredZeroTest()) {
        return Operand::createDeferredZeroTest(
            LHSOp.getDeferredBaseComponents(),
            !LHSOp.isDeferredZeroTestNegated());
      }

      return Operand::createDeferredZeroTest(extractU256Operand(LHSOp), false);
    } else {
      if (LHSOp.isConstant() && RHSOp.isConstant()) {
        intx::uint256 L = u256ValueToIntx(LHSOp.getConstValue());
        intx::uint256 R = u256ValueToIntx(RHSOp.getConstValue());
        uint64_t Res = 0;
        if constexpr (Operator == CompareOperator::CO_EQ) {
          Res = (L == R) ? 1 : 0;
        } else if constexpr (Operator == CompareOperator::CO_LT) {
          Res = (L < R) ? 1 : 0;
        } else if constexpr (Operator == CompareOperator::CO_GT) {
          Res = (L > R) ? 1 : 0;
        } else if constexpr (Operator == CompareOperator::CO_LT_S) {
          bool Lneg = (LHSOp.getConstValue()[3] >> 63) != 0;
          bool Rneg = (RHSOp.getConstValue()[3] >> 63) != 0;
          if (Lneg != Rneg) {
            Res = Lneg ? 1 : 0;
          } else {
            Res = (L < R) ? 1 : 0;
          }
        } else if constexpr (Operator == CompareOperator::CO_GT_S) {
          bool Lneg = (LHSOp.getConstValue()[3] >> 63) != 0;
          bool Rneg = (RHSOp.getConstValue()[3] >> 63) != 0;
          if (Lneg != Rneg) {
            Res = Rneg ? 1 : 0;
          } else {
            Res = (L > R) ? 1 : 0;
          }
        }
        return Operand(U256Value{Res, 0, 0, 0});
      }
    }

    // Phase 3: u64 fast path for EQ
    if constexpr (Operator == CompareOperator::CO_EQ) {
      if (LHSOp.isConstU64() || RHSOp.isConstU64()) {
        const Operand &U64Op = LHSOp.isConstU64() ? LHSOp : RHSOp;
        const Operand &OtherOp = LHSOp.isConstU64() ? RHSOp : LHSOp;
        return handleCompareEqU64(OtherOp, U64Op.getConstValue()[0]);
      }
    }

    // Phase 3: u64 fast path for unsigned LT/GT
    if constexpr (Operator == CompareOperator::CO_LT) {
      if (RHSOp.isConstU64()) {
        return handleCompareLtRhsU64(LHSOp, RHSOp.getConstValue()[0]);
      }
      if (LHSOp.isConstU64()) {
        return handleCompareGtRhsU64(RHSOp, LHSOp.getConstValue()[0]);
      }
    }
    if constexpr (Operator == CompareOperator::CO_GT) {
      if (RHSOp.isConstU64()) {
        return handleCompareGtRhsU64(LHSOp, RHSOp.getConstValue()[0]);
      }
      if (LHSOp.isConstU64()) {
        return handleCompareLtRhsU64(RHSOp, LHSOp.getConstValue()[0]);
      }
    }

    U256Inst Result = handleCompareImpl<Operator>(LHSOp, RHSOp, &Ctx.I64Type);
    // Comparison results are always 0 or 1
    return Operand(Result, EVMType::UINT256, ValueRange::U64);
  }

  // EVM bitwise opcode: and, or, xor
  template <BinaryOperator Operator>
  Operand handleBitwiseOp(const Operand &LHSOp, const Operand &RHSOp) {
    // Phase 0: Constant folding
    if (LHSOp.isConstant() && RHSOp.isConstant()) {
      const auto &L = LHSOp.getConstValue();
      const auto &R = RHSOp.getConstValue();
      U256Value Res;
      for (size_t I = 0; I < EVM_ELEMENTS_COUNT; ++I) {
        if constexpr (Operator == BinaryOperator::BO_AND) {
          Res[I] = L[I] & R[I];
        } else if constexpr (Operator == BinaryOperator::BO_OR) {
          Res[I] = L[I] | R[I];
        } else if constexpr (Operator == BinaryOperator::BO_XOR) {
          Res[I] = L[I] ^ R[I];
        }
      }
      return Operand(Res);
    }

    if constexpr (Operator == BinaryOperator::BO_AND) {
      if (LHSOp.isZeroConstant() || RHSOp.isZeroConstant()) {
        return Operand(U256Value{0, 0, 0, 0});
      }
      if (LHSOp.isAllOnesConstant()) {
        return RHSOp;
      }
      if (RHSOp.isAllOnesConstant()) {
        return LHSOp;
      }
    }

    if constexpr (Operator == BinaryOperator::BO_OR ||
                  Operator == BinaryOperator::BO_XOR) {
      if (LHSOp.isZeroConstant()) {
        return RHSOp;
      }
      if (RHSOp.isZeroConstant()) {
        return LHSOp;
      }
    }

    // Phase 1: u64 fast path for AND - upper limbs are annihilated to 0
    if constexpr (Operator == BinaryOperator::BO_AND) {
      if (LHSOp.isConstU64() || RHSOp.isConstU64()) {
        const Operand &U64Op = LHSOp.isConstU64() ? LHSOp : RHSOp;
        const Operand &OtherOp = LHSOp.isConstU64() ? RHSOp : LHSOp;
        U256Inst Other = extractU256Operand(OtherOp);
        MType *MirI64Type =
            EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);
        MInstruction *U64Val =
            createIntConstInstruction(MirI64Type, U64Op.getConstValue()[0]);
        MInstruction *Zero = createIntConstInstruction(MirI64Type, 0);
        U256Inst Result = {};
        Result[0] =
            protectUnsafeValue(createInstruction<BinaryInstruction>(
                                   false, OP_and, MirI64Type, Other[0], U64Val),
                               MirI64Type);
        for (size_t I = 1; I < EVM_ELEMENTS_COUNT; ++I) {
          Result[I] = Zero;
        }
        return Operand(Result, EVMType::UINT256, ValueRange::U64);
      }

      // Non-constant AND with a U128 mask: result fits in U128
      if (LHSOp.getRange() <= ValueRange::U128 ||
          RHSOp.getRange() <= ValueRange::U128) {
        // AND narrows to the smaller operand range
        ValueRange NarrowRange = std::min(LHSOp.getRange(), RHSOp.getRange());
        U256Inst LHS = extractU256Operand(LHSOp);
        U256Inst RHS = extractU256Operand(RHSOp);
        MType *MirI64Type =
            EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);
        MInstruction *Zero = createIntConstInstruction(MirI64Type, 0);
        U256Inst Result = {};
        for (size_t I = 0; I < EVM_ELEMENTS_COUNT; ++I) {
          if (NarrowRange == ValueRange::U64 && I >= 1) {
            Result[I] = Zero;
          } else if (NarrowRange == ValueRange::U128 && I >= 2) {
            Result[I] = Zero;
          } else {
            Result[I] = protectUnsafeValue(
                createInstruction<BinaryInstruction>(false, OP_and, MirI64Type,
                                                     LHS[I], RHS[I]),
                MirI64Type);
          }
        }
        return Operand(Result, EVMType::UINT256, NarrowRange);
      }
    }

    // Phase 1: u64 fast path for OR/XOR - upper limbs pass through (identity)
    if constexpr (Operator == BinaryOperator::BO_OR ||
                  Operator == BinaryOperator::BO_XOR) {
      if (LHSOp.isConstU64() || RHSOp.isConstU64()) {
        const Operand &U64Op = LHSOp.isConstU64() ? LHSOp : RHSOp;
        const Operand &OtherOp = LHSOp.isConstU64() ? RHSOp : LHSOp;
        U256Inst Other = extractU256Operand(OtherOp);
        MType *MirI64Type =
            EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);
        MInstruction *U64Val =
            createIntConstInstruction(MirI64Type, U64Op.getConstValue()[0]);
        U256Inst Result = {};
        Result[0] = protectUnsafeValue(
            createInstruction<BinaryInstruction>(false, getMirOpcode(Operator),
                                                 MirI64Type, Other[0], U64Val),
            MirI64Type);
        for (size_t I = 1; I < EVM_ELEMENTS_COUNT; ++I) {
          Result[I] = Other[I];
        }
        return Operand(Result, EVMType::UINT256);
      }
    }

    U256Inst Result = {};
    U256Inst LHS = extractU256Operand(LHSOp);
    U256Inst RHS = extractU256Operand(RHSOp);
    MType *MirI64Type =
        EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);
    for (size_t I = 0; I < EVM_ELEMENTS_COUNT; ++I) {
      MInstruction *LocalResult = createInstruction<BinaryInstruction>(
          false, getMirOpcode(Operator), MirI64Type, LHS[I], RHS[I]);
      Result[I] = protectUnsafeValue(LocalResult, MirI64Type);
    }
    return Operand(Result, EVMType::UINT256);
  }

  Operand handleNot(const Operand &LHSOp);

  Operand handleClz(const Operand &ValueOp);

  Operand handleByte(Operand IndexOp, Operand ValueOp);

  Operand handleSignextend(Operand IndexOp, Operand ValueOp);

  template <BinaryOperator Operator>
  Operand handleShift(Operand ShiftOp, Operand ValueOp) {
    // Phase 0: Constant folding
    if (ShiftOp.isConstant() && ValueOp.isConstant()) {
      intx::uint256 ShiftVal = u256ValueToIntx(ShiftOp.getConstValue());
      intx::uint256 Value = u256ValueToIntx(ValueOp.getConstValue());
      intx::uint256 Res;
      if (ShiftVal >= 256) {
        if constexpr (Operator == BinaryOperator::BO_SHR_S) {
          bool SignBit = (ValueOp.getConstValue()[3] >> 63) != 0;
          Res = SignBit ? ~intx::uint256(0) : intx::uint256(0);
        } else {
          Res = intx::uint256(0);
        }
      } else {
        auto Amt = static_cast<unsigned>(ShiftVal);
        if constexpr (Operator == BinaryOperator::BO_SHL) {
          Res = Value << Amt;
        } else if constexpr (Operator == BinaryOperator::BO_SHR_U) {
          Res = Value >> Amt;
        } else if constexpr (Operator == BinaryOperator::BO_SHR_S) {
          bool SignBit = (ValueOp.getConstValue()[3] >> 63) != 0;
          Res = Value >> Amt;
          if (SignBit && Amt > 0) {
            intx::uint256 Mask = ~intx::uint256(0) << (256 - Amt);
            Res |= Mask;
          }
        }
      }
      return Operand(intxToU256Value(Res));
    }

    U256Inst Shift = extractU256Operand(ShiftOp);
    U256Inst Value = extractU256Operand(ValueOp);

    // Check if shift amount >= 256
    // (EVM spec: result is 0 for SHL/SHR, sign-extended for SAR)
    MInstruction *IsLargeShift = isU256GreaterOrEqual(Shift, 256);

    // Use only low 64 bits as shift amount
    MInstruction *ShiftAmount = Shift[0];

    U256Inst Result = {};

    if constexpr (Operator == BinaryOperator::BO_SHL) {
      Result = handleLeftShift(Value, ShiftAmount, IsLargeShift);
    } else if constexpr (Operator == BinaryOperator::BO_SHR_U) {
      Result = handleLogicalRightShift(Value, ShiftAmount, IsLargeShift);
    } else if constexpr (Operator == BinaryOperator::BO_SHR_S) {
      Result = handleArithmeticRightShift(Value, ShiftAmount, IsLargeShift);
    }

    return Operand(Result, EVMType::UINT256);
  }

  // ==================== Environment Instruction Handlers ====================

  Operand handlePC(const uint64_t &PC);
  Operand handleGas();
  Operand handleAddress();
  Operand handleBalance(Operand Address);
  Operand handleOrigin();
  Operand handleCaller();
  Operand handleCallValue();
  Operand handleCallDataLoad(Operand Offset);
  Operand handleCallDataSize();
  Operand handleCodeSize();
  void handleCodeCopy(Operand DestOffsetComponents, Operand OffsetComponents,
                      Operand SizeComponents);
  Operand handleGasPrice();
  Operand handleExtCodeSize(Operand Address);
  Operand handleExtCodeHash(Operand Address);
  Operand handleBlockHash(Operand BlockNumber);
  Operand handleCoinBase();
  Operand handleTimestamp();
  Operand handleNumber();
  Operand handlePrevRandao();
  Operand handleGasLimit();
  Operand handleChainId();
  Operand handleSelfBalance();
  Operand handleBaseFee();
  Operand handleBlobHash(Operand Index);
  Operand handleBlobBaseFee();
  Operand handleMSize();
  Operand handleMLoad(Operand AddrComponents);
  void handleMStore(Operand AddrComponents, Operand ValueComponents);
  void handleMStore8(Operand AddrComponents, Operand ValueComponents);
  void handleMCopy(Operand DestAddrComponents, Operand SrcAddrComponents,
                   Operand LengthComponents);
  void handleCallDataCopy(Operand DestOffsetComponents,
                          Operand OffsetComponents, Operand SizeComponents);
  void handleExtCodeCopy(Operand AddressComponents,
                         Operand DestOffsetComponents, Operand OffsetComponents,
                         Operand SizeComponents);
  void handleReturnDataCopy(Operand DestOffsetComponents,
                            Operand OffsetComponents, Operand SizeComponents);
  Operand handleReturnDataSize();
  void dumpMemoryCompileStats() const;
  void beginMemoryCompileBlock(uint64_t EntryPC);
  void setMemoryCompileBlockConstPrecheckPlan(uint64_t MaxRequiredSize,
                                              uint64_t CoveredDirectOps);
  void
  setMemoryCompileBlockLinearPrecheckPlan(uint64_t AccessWidth,
                                          uint64_t CoveredDirectOps,
                                          bool ValueEqualsFirstAddr = false);
  void prepareLinearBlockMemoryPrecheck(Operand StrideComponents);
  void noteMemoryOpcodeInBlock(evmc_opcode Opcode, uint64_t PC);
  void noteHelperOpcodeInBlock(evmc_opcode Opcode, uint64_t PC);
  void endMemoryCompileBlock();
  template <size_t NumTopics, typename... TopicArgs>
  void handleLogWithTopics(Operand OffsetOp, Operand SizeOp,
                           TopicArgs... Topics);
  Operand handleCreate(Operand ValueOp, Operand OffsetOp, Operand SizeOp);
  Operand handleCreate2(Operand ValueOp, Operand OffsetOp, Operand SizeOp,
                        Operand SaltOp);
  Operand handleCall(Operand GasOp, Operand ToAddrOp, Operand ValueOp,
                     Operand ArgsOffsetOp, Operand ArgsSizeOp,
                     Operand RetOffsetOp, Operand RetSizeOp);
  Operand handleCallCode(Operand GasOp, Operand ToAddrOp, Operand ValueOp,
                         Operand ArgsOffsetOp, Operand ArgsSizeOp,
                         Operand RetOffsetOp, Operand RetSizeOp);
  void handleReturn(Operand MemOffsetComponents, Operand LengthComponents);
  Operand handleDelegateCall(Operand GasOp, Operand ToAddrOp,
                             Operand ArgsOffsetOp, Operand ArgsSizeOp,
                             Operand RetOffsetOp, Operand RetSizeOp);
  Operand handleStaticCall(Operand GasOp, Operand ToAddrOp,
                           Operand ArgsOffsetOp, Operand ArgsSizeOp,
                           Operand RetOffsetOp, Operand RetSizeOp);
  void handleRevert(Operand OffsetOp, Operand SizeOp);
  void handleInvalid();
  void handleUndefined();
  void handleTrap(ErrorCode ErrCode);
  Operand handleKeccak256(Operand OffsetComponents, Operand LengthComponents);
  Operand handleSLoad(Operand KeyComponents);
  void handleSStore(Operand KeyComponents, Operand ValueComponents);
  Operand handleTLoad(Operand Index);
  void handleTStore(Operand Index, Operand ValueComponents);
  void handleSelfDestruct(Operand Beneficiary);

  // ==================== Fallback Methods ====================

  // Fallback to interpreter execution
  void fallbackToInterpreter(uint64_t targetPC);

  // ==================== Runtime Interface for JIT ====================

private:
  // ==================== Operand Methods ====================

  U256Inst extractU256Operand(const Operand &Opnd);

  // ==================== MIR Util Methods ====================

  MPointerType *createVoidPtrType() const {
    return MPointerType::create(Ctx, Ctx.VoidType);
  }

  Variable *storeInstructionInTemp(MInstruction *Value, MType *Type);
  MInstruction *loadVariable(Variable *Var);
  MInstruction *protectUnsafeValue(MInstruction *Value, MType *Type);
  MInstruction *loadProtectedInstancePointer(int32_t Offset);
  MInstruction *getProtectedFieldAddress(MInstruction *BasePtr, int32_t Offset,
                                         MType *PointerType);
  MInstruction *loadProtectedU64Field(MInstruction *BasePtr, int32_t Offset);
  Operand loadProtectedBytes32FieldAsU256(MInstruction *BasePtr,
                                          int32_t Offset);
  Operand loadProtectedAddressFieldAsU256(MInstruction *BasePtr,
                                          int32_t Offset);
  MInstruction *getHostArgScratchPtr(std::size_t ScratchSlot);
  PhiInstruction *createPendingPhi(MType *Type, size_t NumIncoming);
  size_t getPhiIncomingSlot(PhiInstruction *Phi, uint64_t PredBlockPC) const;

  template <class T, typename... Arguments>
  T *createInstruction(bool IsStmt, Arguments &&...Args) {
    return CurFunc->createInstruction<T>(IsStmt, *CurBB,
                                         std::forward<Arguments>(Args)...);
  }

  ConstantInstruction *createIntConstInstruction(MType *Type, uint64_t V) {
    return createInstruction<ConstantInstruction>(
        false, Type, *MConstantInt::get(Ctx, *Type, V));
  }

  LoadInstruction *getInstanceElement(MType *ValueType, uint32_t Scale,
                                      MInstruction *Index, int32_t Offset);

  LoadInstruction *getInstanceElement(MType *ValueType, int32_t Offset) {
    return getInstanceElement(ValueType, 1, nullptr, Offset);
  }

  StoreInstruction *setInstanceElement(MType *ValueType, MInstruction *Value,
                                       int32_t Offset);

  MInstruction *getInstanceStackTopInt();
  MInstruction *getInstanceStackPeekInt(int32_t IndexFromTop);
  void drainGas();

  // Create a full U256 operand from intx::uint256 value
  Operand createU256ConstOperand(const intx::uint256 &V);

  MBasicBlock *createBasicBlock() { return CurFunc->createBasicBlock(); }

  void setInsertBlock(MBasicBlock *BB) {
    CurBB = BB;
    // Check if this basic block is already in the function's BasicBlocks list
    // to avoid duplicate insertion
    if (std::find(CurFunc->begin(), CurFunc->end(), BB) == CurFunc->end()) {
      CurFunc->appendBlock(BB);
    }
  }

  void addSuccessor(MBasicBlock *Succ) { CurBB->addSuccessor(Succ); }

  void addUniqueSuccessor(MBasicBlock *Succ) {
    auto E = CurBB->successors().end();
    auto It = std::find(CurBB->successors().begin(), E, Succ);
    if (It == E) {
      CurBB->addSuccessor(Succ);
    }
  }

  MBasicBlock *getOrCreateExceptionSetBB(ErrorCode ErrCode) {
    return CurFunc->getOrCreateExceptionSetBB(ErrCode);
  }

  // ==================== EVMU256 Helper Methods ====================

  MInstruction *zeroExtendToI64(MInstruction *Value);

  void extractU256ComponentsExplicit(uint64_t *Components,
                                     const intx::uint256 &Value,
                                     size_t NumComponents) {
    for (size_t I = 0; I < NumComponents; ++I) {
      Components[I] =
          static_cast<uint64_t>((Value >> (I * 64)) & 0xFFFFFFFFFFFFFFFFULL);
    }
  }

  // Check if 256-bit value is greater than or equal to threshold
  MInstruction *isU256GreaterOrEqual(const U256Inst &Value, uint64_t Threshold);

  U256ConstInt createU256Constants(const U256Value &Value);
  /// Create u256 value from bytes with big-endian conversion
  U256Value createU256FromBytes(const Byte *Data, size_t Length);

  U256Value bytesToU256(const Bytes &Data);

  template <CompareOperator Operator>
  U256Inst handleCompareImpl(Operand LHSOp, [[maybe_unused]] Operand RHSOp,
                             MType *ResultType) {
    ZEN_ASSERT(ResultType == &Ctx.I64Type);
    U256Inst LHS = extractU256Operand(LHSOp);
    U256Inst RHS = {};

    if constexpr (Operator == CompareOperator::CO_EQZ) {
      return handleCompareEQZ(LHS, ResultType);
    } else if constexpr (Operator == CompareOperator::CO_EQ) {
      RHS = extractU256Operand(RHSOp);
      return handleCompareEQ(LHS, RHS, ResultType);
    } else {
      RHS = extractU256Operand(RHSOp);
      return handleCompareGT_LT(LHS, RHS, ResultType, Operator);
    }
  }

  U256Inst handleCompareEQZ(const U256Inst &LHS, MType *ResultType,
                            bool IsNegated = false);

  U256Inst handleCompareEQ(const U256Inst &LHS, const U256Inst &RHS,
                           MType *ResultType);

  U256Inst handleCompareGT_LT( // NOLINT(readability-identifier-naming)
      const U256Inst &LHS, const U256Inst &RHS, MType *ResultType,
      CompareOperator Operator);

  U256Inst handleLeftShift(const U256Inst &Value, MInstruction *ShiftAmount,
                           MInstruction *IsLargeShift);

  U256Inst handleLogicalRightShift(const U256Inst &Value,
                                   MInstruction *ShiftAmount,
                                   MInstruction *IsLargeShift);

  U256Inst handleArithmeticRightShift(const U256Inst &Value,
                                      MInstruction *ShiftAmount,
                                      MInstruction *IsLargeShift);

  // U256Value <-> intx::uint256 conversion helpers
  static intx::uint256 u256ValueToIntx(const U256Value &V) {
    return (intx::uint256(V[3]) << 192) | (intx::uint256(V[2]) << 128) |
           (intx::uint256(V[1]) << 64) | intx::uint256(V[0]);
  }
  static U256Value intxToU256Value(const intx::uint256 &V) {
    U256Value R;
    for (size_t I = 0; I < EVM_ELEMENTS_COUNT; ++I)
      R[I] = static_cast<uint64_t>(V >> (I * 64));
    return R;
  }

  // u64 fast path helpers
  Operand handleAddU64Const(const Operand &FullOp, const Operand &U64ConstOp);
  Operand handleSubU64Const(const Operand &LHSOp, const Operand &U64ConstRHSOp);
  Operand handleCompareEqU64(const Operand &FullOp, uint64_t U64Val);
  Operand handleCompareLtRhsU64(const Operand &LHSOp, uint64_t RhsU64);
  Operand handleCompareGtRhsU64(const Operand &LHSOp, uint64_t RhsU64);

  // Helper functions for inline U256 multiplication
  MInstruction *createEvmUmul128(MInstruction *LHS, MInstruction *RHS);
  MInstruction *createEvmUmul128Hi(MInstruction *MulInst);

  // Helper functions for inline U256/U64 division
  MInstruction *createEvmUdiv128By64(MInstruction *Hi, MInstruction *Lo,
                                     MInstruction *Divisor);
  MInstruction *createEvmUrem128By64(MInstruction *DivInst);
  Operand handleDivU64Divisor(const Operand &DividendOp, uint64_t Divisor);
  Operand handleModU64Divisor(const Operand &DividendOp, uint64_t Divisor);
  Operand handleDivU64Dividend(uint64_t Dividend, const Operand &DivisorOp);
  Operand handleModU64Dividend(uint64_t Dividend, const Operand &DivisorOp);

  // General u256 div/mod with runtime divisor-size branching.
  // WantQuotient=true returns quotient (DIV), false returns remainder (MOD).
  Operand handleDivModGeneral(const Operand &DividendOp,
                              const Operand &DivisorOp, bool WantQuotient);

  // ==================== EVM to MIR Opcode Mapping ====================

  Opcode getMirOpcode(BinaryOperator BinOpr);

  // ==================== Helper Methods ====================

  // Runtime calls using template functions

  // Template versions of runtime calls
  template <typename RetType>
  Operand callRuntimeFor(RetType (*RuntimeFunc)(runtime::EVMInstance *));

  template <typename ArgType>
  U256Inst convertOperandToInstruction(const Operand &Param);

  MInstruction *packU256Argument(const Operand &Param, std::size_t ScratchSlot);

  template <typename ArgType>
  void appendRuntimeArg(std::vector<MInstruction *> &Args, const Operand &Param,
                        std::size_t &ScratchCursor);

  template <typename RetType, typename... ArgTypes, typename... ParamTypes>
  Operand callRuntimeFor(RetType (*RuntimeFunc)(runtime::EVMInstance *,
                                                ArgTypes...),
                         const ParamTypes &...Params);

  // Helper template functions for runtime call type mapping
  template <typename RetType> MType *getMIRReturnType();

  template <typename RetType>
  Operand convertCallResult(MInstruction *CallInstr);

  // Detect and normalize a UINT256 operand when used as UINT64.
  // For constants, follow EVM semantics (no hard throw; clamp appropriately).
  // For non-constants, generate SelectInstruction to produce UINT64_MAX on
  // overflow.
  void normalizeOperandU64(Operand &Param, uint64_t *Value = nullptr);

  // Split normalization for const and non-const U256.
  void normalizeOperandU64Const(Operand &Param, uint64_t *Value = nullptr);
  void normalizeOperandU64NonConst(Operand &Param, uint64_t *Value = nullptr);
  MInstruction *extractKnownU64LowOperand(const Operand &Opnd);
  void normalizeOffsetWithSize(Operand &Offset, Operand &Size);

  Operand convertSingleInstrToU256Operand(MInstruction *SingleInstr);
  Operand convertU256InstrToU256Operand(MInstruction *U256Instr);
  Operand convertBytes32ToU256Operand(const Operand &Bytes32Op);

  // Helper functions for operand conversion
  template <size_t N>
  U256Inst convertOperandToUNInstruction(const Operand &Param);

  MBasicBlock *getOrCreateIndirectJumpBB(uint64_t SourceBlockPC);
  void registerPhiIncomingBlock(uint64_t TargetBlockPC, uint64_t PredBlockPC,
                                MBasicBlock *PredBB);
  void registerDynamicJumpPhiIncomingBlock(uint64_t TargetBlockPC,
                                           uint64_t PredBlockPC,
                                           MBasicBlock *PredBB);
  MBasicBlock *getPhiIncomingBlock(uint64_t TargetBlockPC,
                                   uint64_t PredBlockPC) const;
  uint64_t getCanonicalJumpDestPC(uint64_t TargetBlockPC) const;
  MBasicBlock *resolvePhiIncomingPredecessorBB(uint64_t TargetBlockPC,
                                               MBasicBlock *DirectPredBB) const;
  MBasicBlock *
  resolveReachablePhiIncomingPredecessorBB(uint64_t TargetBlockPC,
                                           MBasicBlock *CandidateBB) const;

  CompilerContext &Ctx;
  MFunction *CurFunc = nullptr;
  MBasicBlock *CurBB = nullptr;
  MBasicBlock *ReturnBB = nullptr;
#ifdef ZEN_ENABLE_LINUX_PERF
  uint64_t CurPC = 0;
  uint32_t CurInstrIdx = 0;
#endif

  // Instance address for JIT function calls
  MInstruction *InstanceAddr = nullptr;
  // exit when has exception
  MBasicBlock *ExceptionReturnBB = nullptr;
  const evmc_instruction_metrics *InstructionMetrics = nullptr;
  const char *const *InstructionNames = nullptr;

  // Jump table for dynamic jumps
  bool HasIndirectJump = false;
  // Entry blocks for jump targets (may be tiny thunks for shared JUMPDEST
  // bodies).
  std::map<uint64_t, MBasicBlock *> JumpDestTable;
  std::map<uint64_t, uint64_t> JumpDestCanonicalPCTable;
  // Canonical execution blocks for JUMPDEST opcodes in linear decode.
  std::map<uint64_t, MBasicBlock *> JumpDestBodyTable;
  // Cached skipped-metering for merged consecutive JUMPDEST runs.
  // Cache it so meterOpcodeRange(S, E) doesn't have to re-scan the same run.
  std::vector<uint32_t> JumpDestRunLastPC;   // [S] = E, else invalid sentinel
  std::vector<uint64_t> JumpDestRunSkipCost; // [S] = sum cost for [S, E)
  MBasicBlock *DefaultJumpBB = nullptr;      // For invalid jump destinations

  std::map<uint64_t, std::vector<MBasicBlock *>> JumpHashTable;
  std::map<uint64_t, std::vector<uint64_t>> JumpHashReverse;
  uint64_t HashMask = 0;
  Variable *JumpTargetVar = nullptr;
  std::map<uint64_t, MBasicBlock *> IndirectJumpBBs;

  // Stack check block for stack overflow/underflow checking
  MBasicBlock *StackCheckBB = nullptr;
  Variable *StackTopVar = nullptr;
  Variable *StackSizeVar = nullptr;
  Variable *MemoryBaseVar = nullptr;
  Variable *MemorySizeVar = nullptr;
  uint64_t CurrentBlockPC = 0;
  std::map<uint64_t, MBasicBlock *> BlockEntryTable;
  std::map<uint64_t, std::map<uint64_t, MBasicBlock *>>
      DynamicPhiIncomingBlockTable;
  std::map<PhiInstruction *, std::map<uint64_t, size_t>> PhiIncomingSlotMap;
  std::map<VariableIdx, PhiInstruction *> StackMergePhiVarMap;

  struct MemoryCompileStats {
    uint64_t MLoadExpandCount = 0;
    uint64_t MStoreExpandCount = 0;
    uint64_t MStore8ExpandCount = 0;
    uint64_t MCopyExpandCount = 0;
    uint64_t BlockConstPrecheckCount = 0;
    uint64_t BlockLinearPrecheckCount = 0;
    uint64_t PrecheckedMLoadOpCount = 0;
    uint64_t PrecheckedMStoreOpCount = 0;
    uint64_t MStoreAddrValueAliasReuseCount = 0;
    uint64_t LinearU64AddrFastPathCount = 0;
    uint64_t LinearU64MLoadFastPathCount = 0;
    uint64_t LinearU64MStoreFastPathCount = 0;

    uint64_t ReloadMemorySizeCount = 0;
    uint64_t GetMemoryDataPointerCount = 0;
    uint64_t MemoryBaseInstanceLoadCount = 0;
    uint64_t MemoryBaseCacheUseCount = 0;

    uint64_t ExpandNeedExpandCFGCount = 0;
  };
  bool hasMemoryCompileStats() const;
  MemoryCompileStats MemStats;

  struct MemoryBlockCompileStats {
    bool Active = false;
    bool HasMemoryEvent = false;
    bool DirectMemoryOnlyCandidate = true;
    bool HasHelperBarrier = false;

    uint64_t BlockSeqId = 0;
    uint64_t BlockEntryPC = 0;
    uint64_t FirstMemoryEventPC = 0;
    uint64_t LastMemoryEventPC = 0;

    uint64_t DirectMemoryOpCount = 0;
    uint64_t MLoadCount = 0;
    uint64_t MStoreCount = 0;
    uint64_t MStore8Count = 0;
    uint64_t MSizeCount = 0;
    uint64_t MCopyCount = 0;

    uint64_t HelperSensitiveOpCount = 0;
    uint64_t LogCount = 0;
    uint64_t KeccakCount = 0;
    uint64_t CopyFamilyCount = 0;
    uint64_t CallFamilyCount = 0;
    uint64_t CreateFamilyCount = 0;

    uint64_t ExpandCallCount = 0;
    uint64_t NeedExpandCFGCount = 0;
    uint64_t GetMemPtrCount = 0;
    uint64_t MemoryBaseInstanceLoadCount = 0;
    uint64_t MemoryBaseCacheUseCount = 0;
    uint64_t ReloadMemSizeCount = 0;
    uint64_t BlockConstPrecheckCount = 0;
    uint64_t BlockLinearPrecheckCount = 0;
    uint64_t PrecheckedDirectOpCount = 0;
    uint64_t PrecheckedMLoadOpCount = 0;
    uint64_t PrecheckedMStoreOpCount = 0;
    uint64_t MStoreAddrValueAliasReuseCount = 0;
    uint64_t LinearU64AddrFastPathCount = 0;
    uint64_t LinearU64MLoadFastPathCount = 0;
    uint64_t LinearU64MStoreFastPathCount = 0;
  };
  void noteBlockMemoryEventPC(uint64_t PC);
  bool hasCurrentMemoryBlockStats() const;
  struct MemoryBlockConstPrecheckPlan {
    bool Active = false;
    bool Emitted = false;
    uint64_t MaxRequiredSize = 0;
    uint64_t CoveredDirectOpsTotal = 0;
    uint64_t CoveredDirectOpsRemaining = 0;
  };
  struct MemoryBlockLinearPrecheckPlan {
    bool Active = false;
    bool Emitted = false;
    bool HasPendingStride = false;
    bool ValueEqualsFirstAddr = false;
    uint64_t AccessWidth = 0;
    uint64_t CoveredDirectOpsTotal = 0;
    uint64_t CoveredDirectOpsRemaining = 0;
    Operand PendingStrideComponents;
  };
  bool tryConsumeConstBlockMemoryPrecheck();
  bool tryConsumeLinearBlockMemoryPrecheck(MInstruction *FirstAddr,
                                           MInstruction *OrderingDep);
  uint64_t NextMemoryBlockSeqId = 0;
  MemoryBlockCompileStats CurBlockMemStats;
  MemoryBlockConstPrecheckPlan CurBlockConstPrecheckPlan;
  MemoryBlockLinearPrecheckPlan CurBlockLinearPrecheckPlan;

  // Helper methods for memory operations
  MInstruction *getMemoryDataPointer();
  MInstruction *getDirectMemoryDataPointer(bool PreferCachedBase);
  MInstruction *getMemorySize();
  void reloadMemorySizeFromInstance();
  void expandMemoryIR(MInstruction *RequiredSize, MInstruction *Overflow);
  void chargeDynamicGasIR(MInstruction *GasCost);
  void chargeMemoryExpansionGasIR(MInstruction *CurrentSize,
                                  MInstruction *NewSize);
  MInstruction *calculateMemoryGasCostIR(MInstruction *SizeInBytes);

  // Chunk gas metering
  const uint32_t *GasChunkEnd = nullptr;
  const uint64_t *GasChunkCost = nullptr;
  size_t GasChunkSize = 0;

#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
  // Gas register variable - keeps gas value in R14 during execution
  Variable *GasRegVar = nullptr;

  // Gas register management methods
  void initGasRegister();
  void syncGasToMemory();
  void syncGasToMemoryFull();
  void reloadGasFromMemory();

  // Get the variable index for gas register (used during lowering)
  VariableIdx getGasRegisterVarIdx() const {
    return GasRegVar ? GasRegVar->getVarIdx() : VariableIdx(-1);
  }
#endif

  // ==================== Interface Helper Methods ====================

  // Helper method to get instance pointer as instruction
  MInstruction *getCurrentInstancePointer();
};

} // namespace COMPILER

#endif // EVM_FRONTEND_EVM_MIR_COMPILER_H
