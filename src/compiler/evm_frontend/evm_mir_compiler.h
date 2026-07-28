// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef EVM_FRONTEND_EVM_MIR_COMPILER_H
#define EVM_FRONTEND_EVM_MIR_COMPILER_H

#include "action/vm_eval_stack.h"
#include "compiler/context.h"
#include "compiler/evm_frontend/evm_memory_facts.h"
#include "compiler/evm_frontend/evm_memory_grouping.h"
#include "compiler/evm_frontend/evm_value_range.h"
#include "compiler/mir/function.h"
#include "compiler/mir/instructions.h"
#include "compiler/mir/pointer.h"
#include "evm/evm.h"
#include "evmc/instructions.h"
#include "intx/intx.hpp"
#include <algorithm>
#include <cstdint>
#include <map>
#include <memory>
#include <unordered_map>
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
                       const uint64_t *ChunkCostSPP, size_t Size) {
    GasChunkEnd = ChunkEnd;
    GasChunkCost = ChunkCost;
    GasChunkCostSPP = ChunkCostSPP;
    GasChunkSize = Size;
  }
  const uint32_t *getGasChunkEnd() const { return GasChunkEnd; }
  const uint64_t *getGasChunkCost() const { return GasChunkCost; }
  const uint64_t *getGasChunkCostSPP() const { return GasChunkCostSPP; }
  size_t getGasChunkSize() const { return GasChunkSize; }
  bool hasGasChunks() const {
    return GasChunkEnd && GasChunkCost && GasChunkSize > 0;
  }

  void setResolvedJumpTargets(
      const std::unordered_map<uint32_t, uint32_t> *Targets) {
    ResolvedJumpTargets = Targets;
  }
  const std::unordered_map<uint32_t, uint32_t> *getResolvedJumpTargets() const {
    return ResolvedJumpTargets;
  }

  void setRevision(evmc_revision Rev) { Revision = Rev; }
  evmc_revision getRevision() const { return Revision; }
  void setMemoryLinearStrideSkipLeadingZeroLimbStores(uint8_t Count) {
    MemoryLinearStrideSkipLeadingZeroLimbStores = Count;
  }
  uint8_t getMemoryLinearStrideSkipLeadingZeroLimbStores() const {
    return MemoryLinearStrideSkipLeadingZeroLimbStores;
  }

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
  const uint64_t *GasChunkCostSPP = nullptr;
  size_t GasChunkSize = 0;
  const std::unordered_map<uint32_t, uint32_t> *ResolvedJumpTargets = nullptr;
  evmc_revision Revision = zen::evm::DEFAULT_REVISION;
  uint8_t MemoryLinearStrideSkipLeadingZeroLimbStores = 0;
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
  using JumpTargetPCList = std::vector<uint64_t>;

  // Range classification for u256 operands.  Narrower ranges enable
  // single-instruction fast paths instead of expensive multi-limb arithmetic.
  using ValueRange = EVMValueRange;

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
        : Type(Type), U256Components(Components), IsU256MultiComponent(true),
          IsU256InstructionBacked(true) {
      ZEN_ASSERT(Type == EVMType::UINT256 && "Multi-component only for U256");
    }

    // Constructor for U256 multi-component with explicit range
    Operand(U256Inst Components, EVMType Type, ValueRange Range)
        : Type(Type), Range(Range), U256Components(Components),
          IsU256MultiComponent(true), IsU256InstructionBacked(true) {
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
                                          bool IsNegated,
                                          ValueRange BaseRange) {
      Operand Result;
      Result.Type = EVMType::UINT256;
      Result.DeferredValueKind =
          IsNegated ? DeferredKind::ZERO_TEST_NE : DeferredKind::ZERO_TEST_EQ;
      Result.U256Components = BaseComponents;
      Result.DeferredBaseRange = BaseRange;
      // The deferred value materializes to 0/1, so it structurally fits u64
      // regardless of the base's range.
      Result.Range = ValueRange::U64;
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
    bool isU256InstructionBacked() const { return IsU256InstructionBacked; }
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
    ValueRange getDeferredBaseRange() const {
      ZEN_ASSERT(isDeferredZeroTest() && "Not a deferred zero-test value");
      return DeferredBaseRange;
    }

    // Provable value range — narrower ranges enable fast arithmetic paths
    ValueRange getRange() const { return Range; }
    void setRange(ValueRange NewRange) { Range = NewRange; }

    // Check whether both operands provably fit in u64
    static bool bothFitU64(const Operand &A, const Operand &B) {
      return A.getRange() == ValueRange::U64 && B.getRange() == ValueRange::U64;
    }

    static ValueRange maxRange(const Operand &A, const Operand &B) {
      return std::max(A.getRange(), B.getRange());
    }

    // One tier wider in the U64<U128<U256 lattice: U64->U128, else U256. Shared
    // by the u64-const ADD/MUL result ranges (u64+u64 < 2^65, u64*u64 < 2^128).
    static ValueRange widenOneTier(ValueRange R) {
      return R == ValueRange::U64 ? ValueRange::U128 : ValueRange::U256;
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
    bool IsU256InstructionBacked = false;
    DeferredKind DeferredValueKind = DeferredKind::NONE;
    // Range of the base value of a deferred zero-test (the value being tested),
    // used to narrow the OR-fold when materialized.
    ValueRange DeferredBaseRange = ValueRange::U256;
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
  void
  implementIndirectJump(MInstruction *JumpTarget, MBasicBlock *FailureBB,
                        const JumpTargetPCList *CandidateTargets = nullptr);

  void releaseOperand(Operand Opnd) {}

  // Block for stack check instructions
  void createStackCheckBlock(int32_t MinSize, int32_t MaxSize);

  // ==================== Stack Instruction Handlers ====================

  void stackPush(Operand PushValue);
  Operand stackPop();

  void stackSet(int32_t IndexFromTop, Operand SetValue);
  Operand stackGet(int32_t IndexFromTop);
  void setTrackedStackDepth(uint32_t Depth);
  Operand createStackEntryOperand(ValueRange Range = ValueRange::U256);
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
  void handleJump(Operand Dest,
                  const JumpTargetPCList *CandidateTargets = nullptr);
  void handleJumpI(Operand Dest, Operand Cond,
                   const JumpTargetPCList *CandidateTargets = nullptr);
  void handleJumpDest(const uint64_t &PC, bool HasLiveFallthrough);

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
#ifdef ZEN_ENABLE_MULTIPASS_JIT_LOGGING
        ++MemStats.AddFastRangeU64Count;
#endif // ZEN_ENABLE_MULTIPASS_JIT_LOGGING
        return Operand(Result, EVMType::UINT256, ValueRange::U128);
      }
    }

    // Phase 1: Range-based u64 fast path for SUB.
    // When both operands provably fit in u64, (a - b) mod 2^256 has only one
    // meaningful limb of difference plus a borrow that sign-fills the upper
    // 192 bits: limb0 = wrapping_sub(a0, b0); limbs[1..3] = 0 - borrow, where
    // borrow = (a0 <u b0). In i64, 0 - 1 = 0xFFFFFFFFFFFFFFFF, so on underflow
    // the upper limbs become all-ones (the wrapped 2^256 - (b - a)). The result
    // is NOT provably narrow, so it carries the default U256 range.
    if constexpr (Operator == BinaryOperator::BO_SUB) {
      if (Operand::bothFitU64(LHSOp, RHSOp) && !LHSOp.isConstant() &&
          !RHSOp.isConstant()) {
        MType *MirI64Type =
            EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);
        MInstruction *Zero = createIntConstInstruction(MirI64Type, 0);
        U256Inst LHS = extractU256Operand(LHSOp);
        U256Inst RHS = extractU256Operand(RHSOp);
        // No SBB chain here (the borrow is an explicit compare), so no
        // flag-protection barrier is needed and Diff has a single consumer.
        MInstruction *Diff = createInstruction<BinaryInstruction>(
            false, OP_sub, MirI64Type, LHS[0], RHS[0]);
        // Borrow = (LHS[0] < RHS[0]) ? 1 : 0
        MInstruction *BorrowCmp = createInstruction<CmpInstruction>(
            false, CmpInstruction::ICMP_ULT, MirI64Type, LHS[0], RHS[0]);
        MInstruction *BorrowExt = zeroExtendToI64(BorrowCmp);
        // Fill = 0 - borrow; all-ones on underflow, zero otherwise.
        MInstruction *Fill = createInstruction<BinaryInstruction>(
            false, OP_sub, MirI64Type, Zero, BorrowExt);
        // Materialize Fill once and re-read it per upper limb (the
        // conservative multi-use pattern, matching stackPop/stackGet).
        Variable *FillVar = storeInstructionInTemp(Fill, MirI64Type);
        U256Inst Result = {Diff, loadVariable(FillVar), loadVariable(FillVar),
                           loadVariable(FillVar)};
#ifdef ZEN_ENABLE_MULTIPASS_JIT_LOGGING
        ++MemStats.SubFastRangeU64Count;
#endif // ZEN_ENABLE_MULTIPASS_JIT_LOGGING
        return Operand(Result, EVMType::UINT256);
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
#ifdef ZEN_ENABLE_MULTIPASS_JIT_LOGGING
        ++MemStats.AddFastConstU64Count;
#endif // ZEN_ENABLE_MULTIPASS_JIT_LOGGING
        return handleAddU64Const(FullOp, U64Op);
      }
    }

    // Phase 2: u64 fast path for SUB (only when RHS is u64 const)
    if constexpr (Operator == BinaryOperator::BO_SUB) {
      if (RHSOp.isConstU64()) {
#ifdef ZEN_ENABLE_MULTIPASS_JIT_LOGGING
        ++MemStats.SubFastConstU64Count;
#endif // ZEN_ENABLE_MULTIPASS_JIT_LOGGING
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
#ifdef ZEN_ENABLE_MULTIPASS_JIT_LOGGING
    if constexpr (Operator == BinaryOperator::BO_ADD) {
      ++MemStats.AddFullCount;
    } else if constexpr (Operator == BinaryOperator::BO_SUB) {
      ++MemStats.SubFullCount;
    }
#endif // ZEN_ENABLE_MULTIPASS_JIT_LOGGING
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
  // EIP-160 dynamic gas for a constant-exponent EXP (GasPerByte * significant
  // exponent bytes). Static + public so the const-fold path and tests share it.
  static uint64_t constExpDynamicGas(const intx::uint256 &Exponent,
                                     evmc_revision Rev);
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
        // Flip-negation reuses the same base; propagate its range unchanged.
        return Operand::createDeferredZeroTest(
            LHSOp.getDeferredBaseComponents(),
            !LHSOp.isDeferredZeroTestNegated(), LHSOp.getDeferredBaseRange());
      }

      return Operand::createDeferredZeroTest(extractU256Operand(LHSOp), false,
                                             LHSOp.getRange());
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

    // Phase 3: u64 fast path for signed LT/GT. A u64 constant is a
    // non-negative signed-256 value (limbs[1..3] == 0).
    if constexpr (Operator == CompareOperator::CO_LT_S) {
      if (RHSOp.isConstU64()) {
        return handleCompareSltRhsU64(LHSOp, RHSOp.getConstValue()[0]);
      }
      if (LHSOp.isConstU64()) {
        // c <_s x  <=>  x >_s c
        return handleCompareSgtRhsU64(RHSOp, LHSOp.getConstValue()[0]);
      }
    }
    if constexpr (Operator == CompareOperator::CO_GT_S) {
      if (RHSOp.isConstU64()) {
        return handleCompareSgtRhsU64(LHSOp, RHSOp.getConstValue()[0]);
      }
      if (LHSOp.isConstU64()) {
        // c >_s x  <=>  x <_s c
        return handleCompareSltRhsU64(RHSOp, LHSOp.getConstValue()[0]);
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
        // OR/XOR with a u64 constant: limbs[1..3] pass through as the same
        // MInstruction pointers from OtherOp, so the value range of those
        // limbs is preserved exactly. max(U64, OtherOp.range) = OtherOp.range.
        return Operand(Result, EVMType::UINT256, OtherOp.getRange());
      }

      // Phase 2: range-narrowed OR/XOR for non-constant operands. Constants
      // with u64 magnitude were already handled above.
      MType *MirI64Type =
          EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);
      if (!LHSOp.isConstant() && !RHSOp.isConstant() &&
          Operand::bothFitU64(LHSOp, RHSOp)) {
        // Both upper limbs are semantically zero, so OR/XOR of them is zero.
        U256Inst LHS = extractU256Operand(LHSOp);
        U256Inst RHS = extractU256Operand(RHSOp);
        MInstruction *Zero = createIntConstInstruction(MirI64Type, 0);
        U256Inst Result = {};
        Result[0] = protectUnsafeValue(
            createInstruction<BinaryInstruction>(false, getMirOpcode(Operator),
                                                 MirI64Type, LHS[0], RHS[0]),
            MirI64Type);
        for (size_t I = 1; I < EVM_ELEMENTS_COUNT; ++I) {
          Result[I] = Zero;
        }
        return Operand(Result, EVMType::UINT256, ValueRange::U64);
      }
      if (!LHSOp.isConstant() && !RHSOp.isConstant() &&
          ((LHSOp.getRange() == ValueRange::U64) ^
           (RHSOp.getRange() == ValueRange::U64))) {
        // Exactly one side is u64: its upper limbs are semantically zero, so
        // OR/XOR with them is identity on the wide side's upper limbs.
        const Operand &U64Op =
            LHSOp.getRange() == ValueRange::U64 ? LHSOp : RHSOp;
        const Operand &WideOp =
            LHSOp.getRange() == ValueRange::U64 ? RHSOp : LHSOp;
        U256Inst Narrow = extractU256Operand(U64Op);
        U256Inst Wide = extractU256Operand(WideOp);
        U256Inst Result = {};
        Result[0] = protectUnsafeValue(
            createInstruction<BinaryInstruction>(
                false, getMirOpcode(Operator), MirI64Type, Narrow[0], Wide[0]),
            MirI64Type);
        for (size_t I = 1; I < EVM_ELEMENTS_COUNT; ++I) {
          Result[I] = Wide[I];
        }
        return Operand(Result, EVMType::UINT256, WideOp.getRange());
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
    if constexpr (Operator == BinaryOperator::BO_OR ||
                  Operator == BinaryOperator::BO_XOR) {
      ValueRange ResultRange = Operand::maxRange(LHSOp, RHSOp);
      return Operand(Result, EVMType::UINT256, ResultRange);
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

    // Static large-shift resolution: when the shift amount is a compile-time
    // constant, the >= 256 guard is statically decidable. For SHL/SHR_U a
    // constant amount >= 256 yields an identically-zero result for any value
    // (EVM spec), mirroring the Phase-0 both-const fold above. SHR_S keeps the
    // generic flow because its fill depends on the value's sign bit.
    bool ConstAmountBelowLimit = false;
    if (ShiftOp.isConstant()) {
      intx::uint256 Amount = u256ValueToIntx(ShiftOp.getConstValue());
      if (Amount >= 256) {
        if constexpr (Operator == BinaryOperator::BO_SHL ||
                      Operator == BinaryOperator::BO_SHR_U) {
          return Operand(U256Value{0, 0, 0, 0});
        }
      } else {
        ConstAmountBelowLimit = true;
      }
    }

    U256Inst Shift = extractU256Operand(ShiftOp);
    U256Inst Value = extractU256Operand(ValueOp);

    // Check if shift amount >= 256
    // (EVM spec: result is 0 for SHL/SHR, sign-extended for SAR)
    // When the amount is a constant < 256, the guard is statically false:
    // pass IsLargeShift = nullptr so the helper skips the per-limb Select.
    MInstruction *IsLargeShift = nullptr;
    if (!ConstAmountBelowLimit) {
      IsLargeShift = isU256GreaterOrEqual(Shift, 256);
    }

    // Use only low 64 bits as shift amount
    MInstruction *ShiftAmount = Shift[0];

    // Number of live source limbs implied by the value operand's range. A limb
    // with index >= LiveLimbs is semantically zero under the Range contract,
    // letting the const-amount SHL/SHR_U paths drop dead source terms.
    size_t LiveLimbs = 4;
    switch (ValueOp.getRange()) {
    case ValueRange::U64:
      LiveLimbs = 1;
      break;
    case ValueRange::U128:
      LiveLimbs = 2;
      break;
    default:
      LiveLimbs = 4;
      break;
    }

    U256Inst Result = {};

    if constexpr (Operator == BinaryOperator::BO_SHL) {
      Result = handleLeftShift(Value, ShiftAmount, IsLargeShift, LiveLimbs);
    } else if constexpr (Operator == BinaryOperator::BO_SHR_U) {
      Result =
          handleLogicalRightShift(Value, ShiftAmount, IsLargeShift, LiveLimbs);
    } else if constexpr (Operator == BinaryOperator::BO_SHR_S) {
      Result = handleArithmeticRightShift(Value, ShiftAmount, IsLargeShift);
    }

    // Unsigned right shift cannot widen: an N-bit value shifted right yields an
    // at-most-N-bit value. SHL widens by construction; SAR sign-fills upper
    // limbs; both keep the conservative U256 default.
    if constexpr (Operator == BinaryOperator::BO_SHR_U) {
      return Operand(Result, EVMType::UINT256, ValueOp.getRange());
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
  void beginMemoryCompileBlock(uint64_t EntryPC,
                               uint64_t BodyEndPC = UINT64_MAX);
  void setMemoryCompileBlockConstPrecheckPlan(uint64_t MaxRequiredSize,
                                              uint64_t CoveredDirectOps);
  void
  setMemoryCompileBlockLinearPrecheckPlan(uint64_t AccessWidth,
                                          uint64_t CoveredDirectOps,
                                          bool ValueEqualsFirstAddr = false);
  void noteLargeStaticWorkspaceVerifierResult(
      uint64_t Candidates, uint64_t VerifiedSegments, uint64_t VerifiedOps,
      uint64_t VerifiedMLoadOps, uint64_t VerifiedMStoreOps,
      uint64_t VerifiedMStore8Ops, uint64_t MaxRequiredSize, uint64_t Rejected,
      uint64_t RejectDynamicOffset, uint64_t RejectUnknownBase,
      uint64_t RejectUnboundedInterval, uint64_t RejectOverflowRisk,
      uint64_t RejectSideEffect, uint64_t RejectHelperByteExactRisk,
      uint64_t RejectTooFewOps);
  void setMemoryCompileBlockLargeStaticWorkspacePrecheckPlan(
      uint64_t FirstCoveredPC, uint64_t LastCoveredPC, uint64_t MaxRequiredSize,
      uint64_t CoveredDirectOps, uint64_t CoveredMLoadOps,
      uint64_t CoveredMStoreOps, uint64_t CoveredMStore8Ops);
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
  void setMemoryFacts(const MemoryFacts &Facts) {
    MemoryFactsData = Facts;
#ifdef ZEN_ENABLE_EVM_MEMORY_PLAN_FRAMEWORK
    MemoryAnalysis = std::make_unique<MemoryAnalysisView>(MemoryFactsData);
    MemoryExpansionPlans =
        std::make_unique<MemoryExpansionPlanner>(*MemoryAnalysis);
#else
    MemoryAnalysis.reset();
    MemoryExpansionPlans.reset();
#endif
  }
  const MemoryFacts &getMemoryFacts() const { return MemoryFactsData; }
  Operand handleKeccak256(Operand OffsetComponents, Operand LengthComponents);
  Operand handleKeccak256TwoWord(Operand OffsetComponents, Operand Word0,
                                 Operand Word1);
  Operand handleKeccak256CallDataConstSlot(Operand OffsetComponents,
                                           Operand CallDataOffset,
                                           Operand SlotWord);
  Operand handleKeccak256CallerConstSlot(Operand OffsetComponents,
                                         Operand SlotWord);
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
      return handleCompareEQZ(LHS, ResultType, false, LHSOp.getRange());
    } else if constexpr (Operator == CompareOperator::CO_EQ) {
      RHS = extractU256Operand(RHSOp);
      return handleCompareEQ(LHS, RHS, ResultType);
    } else {
      RHS = extractU256Operand(RHSOp);
      return handleCompareGT_LT(LHS, RHS, ResultType, Operator);
    }
  }

  U256Inst handleCompareEQZ(const U256Inst &LHS, MType *ResultType,
                            bool IsNegated = false,
                            ValueRange BaseRange = ValueRange::U256);
  MInstruction *createJumpCondition(const Operand &Cond);

  U256Inst handleCompareEQ(const U256Inst &LHS, const U256Inst &RHS,
                           MType *ResultType);

  U256Inst handleCompareGT_LT( // NOLINT(readability-identifier-naming)
      const U256Inst &LHS, const U256Inst &RHS, MType *ResultType,
      CompareOperator Operator);

  U256Inst handleLeftShift(const U256Inst &Value, MInstruction *ShiftAmount,
                           MInstruction *IsLargeShift, size_t LiveLimbs = 4);

  U256Inst handleLogicalRightShift(const U256Inst &Value,
                                   MInstruction *ShiftAmount,
                                   MInstruction *IsLargeShift,
                                   size_t LiveLimbs = 4);

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
  Operand handleCompareSltRhsU64(const Operand &LHSOp, uint64_t RhsU64);
  Operand handleCompareSgtRhsU64(const Operand &LHSOp, uint64_t RhsU64);

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
  // Emits host soft-error checks in check mode after runtime call.
  template <typename RetType>
  Operand callRuntimeForWithErrorCheck(
      RetType (*RuntimeFunc)(runtime::EVMInstance *));

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
  // Emits host soft-error checks in check mode after runtime call.
  template <typename RetType, typename... ArgTypes, typename... ParamTypes>
  Operand callRuntimeForWithErrorCheck(
      RetType (*RuntimeFunc)(runtime::EVMInstance *, ArgTypes...),
      const ParamTypes &...Params);
  void emitRuntimeSoftErrorCheck(MInstruction *InstancePtr);
  void emitRuntimeNullPointerCheck(MInstruction *PtrValue);

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
  MInstruction *anchorDirectMemoryPointer(MInstruction *Ptr);
  MInstruction *extractKnownU64LowOperand(const Operand &Opnd);
  void checkStaticModeIR();
  void normalizeOffsetWithSize(Operand &Offset, Operand &Size);
  void preExpandMemoryRange(Operand &Offset, Operand &Size);

  Operand convertSingleInstrToU256Operand(MInstruction *SingleInstr);
  Operand convertU256InstrToU256Operand(MInstruction *U256Instr);
  Operand convertBytes32ToU256Operand(const Operand &Bytes32Op);
  Operand loadU256FromBytes32PointerDisplaced(MInstruction *Bytes32Ptr);
  Operand loadU256FromBytes32BaseDisplaced(MInstruction *BytesBasePtr,
                                           uint64_t BaseOffset);
  void storeU256ToBytes32Pointer(MInstruction *Bytes32Ptr,
                                 const U256Inst &ValueParts,
                                 uint64_t SkipLeadingZeroLimbStores = 0);
  void storeU256ToBytes32BaseDisplaced(MInstruction *BytesBasePtr,
                                       uint64_t BaseOffset,
                                       const U256Inst &ValueParts,
                                       uint64_t SkipLeadingZeroLimbStores = 0);

  // Helper functions for operand conversion
  template <size_t N>
  U256Inst convertOperandToUNInstruction(const Operand &Param);

  MBasicBlock *
  getOrCreateIndirectJumpBB(uint64_t SourceBlockPC,
                            const JumpTargetPCList *CandidateTargets = nullptr);
  MBasicBlock *getOrCreateSharedIndirectJumpBB();
  MBasicBlock *buildIndirectJumpBB(uint64_t SourceBlockPC,
                                   const JumpTargetPCList *CandidateTargets,
                                   bool RegisterDynamicPhi);
  bool shouldUseSharedDynamicDispatch() const;
  void linkJumpDestEntryThunkIfNeeded(MBasicBlock *TargetBB);
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
  MBasicBlock *resolveReachablePredecessorBB(MBasicBlock *TargetBB,
                                             MBasicBlock *CandidateBB) const;

  CompilerContext &Ctx;
  MFunction *CurFunc = nullptr;
  MBasicBlock *CurBB = nullptr;
  MemoryFacts MemoryFactsData;
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
  // Lazily linked entry thunks for non-canonical JUMPDEST targets in a merged
  // consecutive-JUMPDEST run. The thunk block exists so JumpDestTable can point
  // at the raw target, but its CFG edge to the shared body is only registered
  // when a real jump/dispatch edge targets the thunk.
  std::map<MBasicBlock *, MBasicBlock *> JumpDestEntryThunkBodyTable;
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
  MBasicBlock *SharedIndirectJumpBB = nullptr;

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

  // Stack-merge phis and the loop-header block they belong to. A merge phi's
  // incoming block is resolved eagerly when each predecessor edge's stack
  // state is assigned (materializeStackMergeOperand / assignStackMergeOperand).
  // For a loop back-edge this assignment happens before the predecessor's
  // terminator wires the real CFG edge into the loop header, so the resolved
  // incoming block can be the predecessor EVM block's entry MIR block rather
  // than its terminator MIR block. finalizeStackMergePhiIncomingBlocks()
  // re-resolves every recorded incoming block against the now-complete CFG.
  std::vector<std::pair<PhiInstruction *, MBasicBlock *>> StackMergePhiBlocks;
  void finalizeStackMergePhiIncomingBlocks();

  struct MemoryCompileStats {
    uint64_t MLoadExpandCount = 0;
    uint64_t MStoreExpandCount = 0;
    uint64_t MStore8ExpandCount = 0;
    uint64_t MCopyExpandCount = 0;
    uint64_t MCopyGuaranteedElisionCount = 0;
    uint64_t MemoryDSEStoreCandidates = 0;
    uint64_t MemoryDSEEliminatedWrites = 0;
    uint64_t MemoryLoadForwardCandidates = 0;
    uint64_t MemoryLoadForwarded = 0;
    uint64_t BlockConstPrecheckCount = 0;
    uint64_t BlockLinearPrecheckCount = 0;
    uint64_t PrecheckedMLoadOpCount = 0;
    uint64_t PrecheckedMStoreOpCount = 0;
    uint64_t PrecheckedMStore8OpCount = 0;
    uint64_t PrecheckedMCopyOpCount = 0;
    uint64_t MemoryExpansionPlanCount = 0;
    uint64_t MemoryExpansionPlanPrecheckCount = 0;
    uint64_t MemoryExpansionPlanGroupingCount = 0;
    uint64_t MemoryExpansionPlanLinearRegionCount = 0;
    uint64_t MemoryExpansionPlanReusableCount = 0;
    uint64_t MemoryExpansionPlanCoveredOps = 0;
    uint64_t MemoryExpansionPlanCoveredMLoadOps = 0;
    uint64_t MemoryExpansionPlanCoveredMStoreOps = 0;
    uint64_t MemoryExpansionPlanCoveredMStore8Ops = 0;
    uint64_t MemoryExpansionPlanCoveredMCopyOps = 0;
    uint64_t MemoryExpansionPlanRequiredSizeSum = 0;
    uint64_t MemoryExpansionPlanRequiredSizeMax = 0;
    uint64_t MemoryExpansionPlanEstimatedReducedExpansions = 0;
    uint64_t MemoryExpansionPlanGroupingCandidates = 0;
    uint64_t MemoryExpansionPlanLinearRegionCandidates = 0;
    uint64_t MemoryExpansionPlanPrecheckCandidates = 0;
    uint64_t MemoryExpansionPlanRejectedNoCandidate = 0;
    uint64_t MemoryExpansionPlanRejectedUnknownInterval = 0;
    uint64_t MemoryExpansionPlanRejectedInvalidRange = 0;
    uint64_t MemoryExpansionPlanRejectedOverflow = 0;
    uint64_t MemoryExpansionPlanRejectedTooLarge = 0;
    uint64_t MemoryExpansionPlanRejectedZeroSize = 0;
    uint64_t MemoryExpansionPlanRejectedUnprofitable = 0;
    uint64_t MemoryExpansionPlanLinearRegionRejectedNotStraightLine = 0;
    uint64_t MemoryExpansionPlanLinearRegionRejectedBranchingHead = 0;
    uint64_t MemoryExpansionPlanLinearRegionRejectedMergeSuccessor = 0;
    uint64_t MemoryExpansionPlanLinearRegionRejectedBackedgeOrNonForward = 0;
    uint64_t MemoryExpansionPlanLinearRegionRejectedHardBarrier = 0;
    uint64_t MemoryExpansionPlanLinearRegionRejectedNoHeadMemoryOp = 0;
    uint64_t MemoryExpansionPlanLinearRegionRejectedUnknownInterval = 0;
    uint64_t MemoryExpansionPlanLinearRegionRejectedNonDirectMemoryOp = 0;
    uint64_t MemoryExpansionPlanLinearRegionRejectedTooFewOps = 0;
    uint64_t MemoryExpansionPlanLinearRegionRejectedUnprofitable = 0;
    uint64_t MemoryExpansionPlanLinearRegionRejectedBarrierMSize = 0;
    uint64_t MemoryExpansionPlanLinearRegionRejectedBarrierGas = 0;
    uint64_t MemoryExpansionPlanLinearRegionRejectedBarrierCall = 0;
    uint64_t MemoryExpansionPlanLinearRegionRejectedBarrierCreate = 0;
    uint64_t MemoryExpansionPlanLinearRegionRejectedBarrierReturn = 0;
    uint64_t MemoryExpansionPlanLinearRegionRejectedBarrierRevert = 0;
    uint64_t MemoryExpansionPlanLinearRegionRejectedBarrierLog = 0;
    uint64_t MemoryExpansionPlanLinearRegionRejectedBarrierStorage = 0;
    uint64_t MemoryExpansionPlanLinearRegionRejectedBarrierSelfDestruct = 0;
    uint64_t MemoryExpansionPlanLinearRegionRejectedBarrierInvalid = 0;
    uint64_t MemoryExpansionPlanLinearRegionRejectedBarrierUnknownEffect = 0;
    uint64_t MemoryExpansionPlanLinearRegionRejectedBarrierEscape = 0;
    uint64_t MemoryExpansionPlanLinearRegionPrefixCandidateBlocks = 0;
    uint64_t MemoryExpansionPlanLinearRegionPrefixCandidateOps = 0;
    uint64_t MemoryExpansionPlanLinearRegionPrefixAcceptedBlocks = 0;
    uint64_t MemoryExpansionPlanLinearRegionPrefixAcceptedOps = 0;
    uint64_t MemoryExpansionPlanLinearRegionPrefixRejectedTooShort = 0;
    uint64_t MemoryExpansionPlanLinearRegionPrefixRejectedNoHeadMemoryOp = 0;
    uint64_t MemoryExpansionPlanLinearRegionPrefixBranchingAfterSafePrefix = 0;
    uint64_t MemoryExpansionPlanLinearRegionPrefixMergeAfterSafePrefix = 0;
    uint64_t MemoryExpansionPlanLinearRegionPrefixTerminalAfterSafePrefix = 0;
    uint64_t MemoryExpansionPlanLinearRegionPrefixMissingSuccessorBlock = 0;
    uint64_t MemoryExpansionPlanLinearRegionPrefixBackedgeAfterSafePrefix = 0;
    uint64_t MemoryExpansionPlanLinearRegionPrefixBarrierAfterSafePrefix = 0;
    uint64_t MemoryExpansionPlanLinearRegionRejectedBranchingHeadNoSafePrefix =
        0;
    uint64_t MemoryExpansionPlanLinearRegionRejectedMergeSuccessorNoSafePrefix =
        0;
    uint64_t MemoryExpansionPlanLinearRegionHeadCandidateBlocks = 0;
    uint64_t MemoryExpansionPlanLinearRegionHeadSkippedEmptyBlocks = 0;
    uint64_t MemoryExpansionPlanLinearRegionHeadSelectedNonEntryBlock = 0;
    uint64_t MemoryExpansionPlanLinearRegionHeadRejectedPredecessorNotStraight =
        0;
    uint64_t MemoryExpansionPlanLinearRegionHeadRejectedHeadNotDominatingChain =
        0;
    uint64_t MemoryExpansionPlanLinearRegionHeadRejectedEntryGuaranteeMissing =
        0;
    uint64_t MStoreAddrValueAliasReuseCount = 0;
    uint64_t LinearU64AddrFastPathCount = 0;
    uint64_t LinearU64MLoadFastPathCount = 0;
    uint64_t LinearU64MStoreFastPathCount = 0;
    uint64_t ConstBasePtrInitCount = 0;
    uint64_t ConstBasePtrReuseCount = 0;
    uint64_t ConstDispBytes32MLoadCount = 0;
    uint64_t ConstDispBytes32MStoreCount = 0;
    uint64_t DispBytes32MLoadCount = 0;
    uint64_t DispBytes32MStoreCount = 0;
    uint64_t MStoreZeroLimbStoreCount = 0;
    uint64_t MStoreOverlapElidedLimbCount = 0;

    uint64_t ReloadMemorySizeCount = 0;
    uint64_t GetMemoryDataPointerCount = 0;
    uint64_t MemoryBaseInstanceLoadCount = 0;
    uint64_t MemoryBaseCacheUseCount = 0;

    uint64_t ExpandNeedExpandCFGCount = 0;

    uint64_t SmallFrameCandidateTotal = 0;
    uint64_t SmallFramePrecheckedTotal = 0;
    uint64_t SmallFrameOffsetConstTotal = 0;
    uint64_t SmallFrameOffsetKnownU64Total = 0;
    uint64_t SmallFrameMLoadCandidate = 0;
    uint64_t SmallFrameMStoreCandidate = 0;
    uint64_t SmallFrameMStore8Candidate = 0;
    uint64_t SmallFrameFallbackUnknownOffset = 0;
    uint64_t SmallFrameFallbackOver128 = 0;
    uint64_t SmallFrameFallbackNoPrecheck = 0;
    uint64_t SmallFrameFallbackOverflow = 0;
    uint64_t SmallFrameFallbackDynamicSize = 0;
    uint64_t SmallFrameFallbackGasOrMemorySemanticsUncertain = 0;

    uint64_t HashPrepRegionCandidateCount = 0;
    uint64_t HashPrepRegionCandidateOpCount = 0;
    uint64_t HashPrepRegionVerifiedCount = 0;
    uint64_t HashPrepRegionVerifiedOpCount = 0;
    uint64_t HashPrepKeccakConstRangeCount = 0;
    uint64_t HashPrepKeccakRange0_64Count = 0;
    uint64_t HashPrepKeccakDynamicRangeCount = 0;
    uint64_t HashPrepKeccakOver128Count = 0;
    uint64_t HashPrepRegionVerifiedTwoWordPreimageCount = 0;
    uint64_t HashPrepRegionVerifiedMultiHashCount = 0;
    uint64_t HashPrepRegionRejectedDynamicOffset = 0;
    uint64_t HashPrepRegionRejectedRangeOver128 = 0;
    uint64_t HashPrepRegionRejectedNonTwoWordRange = 0;
    uint64_t HashPrepRegionRejectedOrderingRisk = 0;
    uint64_t HashPrepRegionRejectedAliasRisk = 0;
    uint64_t HashPrepRegionRejectedInterveningWrite = 0;
    uint64_t HashPrepRegionRejectedByteExactRisk = 0;
    uint64_t HashPrepRegionRejectedMissingTwoWordStores = 0;
    uint64_t HashPrepRegionRejectedAliasOrInterveningWrite = 0;

    uint64_t HashPrepLiftSimCandidateRegionCount = 0;
    uint64_t HashPrepLiftSimCandidateOpCount = 0;
    uint64_t HashPrepLiftSimCoveredRegionCount = 0;
    uint64_t HashPrepLiftSimCoveredOpCount = 0;
    uint64_t HashPrepLiftSimSafeToLiftRegionCount = 0;
    uint64_t HashPrepLiftSimSafeToLiftOpCount = 0;
    uint64_t HashPrepLiftSimRejectedRegionCount = 0;
    uint64_t HashPrepLiftSimRejectedOpCount = 0;

    uint64_t HashPrepMarkerCandidateRegionCount = 0;
    uint64_t HashPrepMarkerCandidateOpCount = 0;
    uint64_t HashPrepMarkerMarkedRegionCount = 0;
    uint64_t HashPrepMarkerCoveredOpCount = 0;
    uint64_t HashPrepMarkerCoveredMStoreOpCount = 0;
    uint64_t HashPrepMarkerCoveredMLoadOpCount = 0;
    uint64_t HashPrepMarkerCoveredKeccakOpCount = 0;
    uint64_t HashPrepMarkerRejectedRegionCount = 0;
    uint64_t HashPrepMarkerRejectedOpCount = 0;
    uint64_t HashPrepMarkerRejectedNon0_64Range = 0;
    uint64_t HashPrepMarkerRejectedDynamicOffset = 0;
    uint64_t HashPrepMarkerRejectedAliasOrInterveningWrite = 0;
    uint64_t HashPrepMarkerRejectedMixedPredecessor = 0;
    uint64_t HashPrepMarkerRejectedByteExactRisk = 0;
    uint64_t HashPrepMarkerRejectedGasMemorySemantics = 0;
    uint64_t HashPrepMarkerRejectedPointerInstability = 0;
    uint64_t HashPrepMarkerRejectedUnknownHelper = 0;

    // Arithmetic fast-path tier hit counters. Increments are gated by
    // ZEN_ENABLE_MULTIPASS_JIT_LOGGING; the fields always exist.
    uint64_t AddFastRangeU64Count = 0;
    uint64_t AddFastConstU64Count = 0;
    uint64_t AddFullCount = 0;
    uint64_t SubFastRangeU64Count = 0;
    uint64_t SubFastConstU64Count = 0;
    uint64_t SubFullCount = 0;
    uint64_t MulFastRangeU64Count = 0;
    uint64_t MulFastConstU64Count = 0;
    uint64_t MulFullCount = 0;
    uint64_t DivFastRangeU64Count = 0;
    uint64_t DivFastConstU64Count = 0;
    uint64_t DivFullCount = 0;
    uint64_t ModFastRangeU64Count = 0;
    uint64_t ModFastConstU64Count = 0;
    uint64_t ModFullCount = 0;

    // U128-consumer opportunity counters: incremented on the genuine
    // full-limb fallback when one operand has proven range U128 and the
    // other is <= U128, i.e. a 128-bit half-width path could have applied.
    uint64_t MulU128OpportunityCount = 0;
    uint64_t DivU128OpportunityCount = 0;
    uint64_t ModU128OpportunityCount = 0;

    uint64_t LargeStaticWorkspaceCandidateCount = 0;
    uint64_t LargeStaticWorkspaceVerifiedSegmentCount = 0;
    uint64_t LargeStaticWorkspaceVerifiedOpCount = 0;
    uint64_t LargeStaticWorkspaceVerifiedMLoadOpCount = 0;
    uint64_t LargeStaticWorkspaceVerifiedMStoreOpCount = 0;
    uint64_t LargeStaticWorkspaceVerifiedMStore8OpCount = 0;
    uint64_t LargeStaticWorkspaceMaxRequiredSize = 0;
    uint64_t LargeStaticWorkspaceRejectedCount = 0;
    uint64_t LargeStaticWorkspaceRejectDynamicOffset = 0;
    uint64_t LargeStaticWorkspaceRejectUnknownBase = 0;
    uint64_t LargeStaticWorkspaceRejectUnboundedInterval = 0;
    uint64_t LargeStaticWorkspaceRejectOverflowRisk = 0;
    uint64_t LargeStaticWorkspaceRejectSideEffect = 0;
    uint64_t LargeStaticWorkspaceRejectHelperByteExactRisk = 0;
    uint64_t LargeStaticWorkspaceRejectTooFewOps = 0;
    uint64_t LargeStaticWorkspaceLoweringCandidateCount = 0;
    uint64_t LargeStaticWorkspaceLoweringEnabledRegionCount = 0;
    uint64_t LargeStaticWorkspaceLoweringPrecheckedOpCount = 0;
    uint64_t LargeStaticWorkspaceLoweringPrecheckedMLoadOpCount = 0;
    uint64_t LargeStaticWorkspaceLoweringPrecheckedMStoreOpCount = 0;
    uint64_t LargeStaticWorkspaceLoweringDispMLoadOpCount = 0;
    uint64_t LargeStaticWorkspaceLoweringDispMStoreOpCount = 0;
    uint64_t LargeStaticWorkspaceLoweringFallbackRegionCount = 0;
    uint64_t LargeStaticWorkspaceLoweringDisabledByGateCount = 0;
    uint64_t LargeStaticWorkspaceLoweringUnsafePrecheckPositionCount = 0;
  };
  bool hasMemoryCompileStats() const;
  bool hasArithCompileStats() const;
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
    uint64_t PrecheckedMStore8OpCount = 0;
    uint64_t PrecheckedMCopyOpCount = 0;
    bool HasMemoryExpansionPlan = false;
    uint64_t MemoryExpansionPlanKind = 0;
    uint64_t MemoryExpansionPlanReusable = 0;
    uint64_t MemoryExpansionPlanCoveredOps = 0;
    uint64_t MemoryExpansionPlanCoveredMLoadOps = 0;
    uint64_t MemoryExpansionPlanCoveredMStoreOps = 0;
    uint64_t MemoryExpansionPlanCoveredMStore8Ops = 0;
    uint64_t MemoryExpansionPlanCoveredMCopyOps = 0;
    uint64_t MemoryExpansionPlanRequiredBegin = 0;
    uint64_t MemoryExpansionPlanRequiredEnd = 0;
    uint64_t MemoryExpansionPlanRequiredSize = 0;
    uint64_t MemoryExpansionPlanEstimatedReducedExpansions = 0;
    uint64_t MStoreAddrValueAliasReuseCount = 0;
    uint64_t LinearU64AddrFastPathCount = 0;
    uint64_t LinearU64MLoadFastPathCount = 0;
    uint64_t LinearU64MStoreFastPathCount = 0;
    uint64_t ConstBasePtrInitCount = 0;
    uint64_t ConstBasePtrReuseCount = 0;
    uint64_t ConstDispBytes32MLoadCount = 0;
    uint64_t ConstDispBytes32MStoreCount = 0;
    uint64_t DispBytes32MLoadCount = 0;
    uint64_t DispBytes32MStoreCount = 0;
    uint64_t MStoreZeroLimbStoreCount = 0;
    uint64_t MStoreOverlapElidedLimbCount = 0;

    uint64_t SmallFrameCandidateCount = 0;
    uint64_t SmallFramePrecheckedCount = 0;
    uint64_t SmallFrameFallbackNoPrecheckCount = 0;
    uint64_t SmallFrameFallbackDynamicSizeCount = 0;
    uint64_t SmallFrameFallbackOver128Count = 0;
    uint64_t SmallFrameNoPrecheckMLoadCount = 0;
    uint64_t SmallFrameNoPrecheckMStoreCount = 0;
    uint64_t SmallFrameNoPrecheckMStore8Count = 0;

    bool HashPrepPendingMStore0 = false;
    bool HashPrepPendingMStore32 = false;
    bool HashPrepPendingUnsupportedWrite = false;
    bool HashPrepPendingAliasRisk = false;
    bool HashPrepPendingInterveningWrite = false;
    uint64_t HashPrepKeccakConstRangeCount = 0;
    uint64_t HashPrepKeccakRange0_64Count = 0;
    uint64_t HashPrepKeccakDynamicRangeCount = 0;
    uint64_t HashPrepKeccakOver128Count = 0;
    uint64_t HashPrepKeccakNonTwoWordRangeCount = 0;
    uint64_t HashPrepVerifiedKeccakCount = 0;
    uint64_t HashPrepRejectedOrderingRiskCount = 0;
    uint64_t HashPrepRejectedAliasRiskCount = 0;
    uint64_t HashPrepRejectedInterveningWriteCount = 0;
    uint64_t HashPrepRejectedByteExactRiskCount = 0;
    uint64_t HashPrepRejectedMissingTwoWordStoresCount = 0;
    uint64_t HashPrepRejectedAliasOrInterveningWriteCount = 0;

    bool HashPrepMarkerCandidate = false;
    bool HashPrepMarkerMarked = false;
    uint64_t HashPrepMarkerId = 0;
    uint64_t HashPrepMarkerRangeBegin = 0;
    uint64_t HashPrepMarkerRangeEnd = 0;
    uint64_t HashPrepMarkerCoveredOpCount = 0;
    uint64_t HashPrepMarkerCoveredMStoreOpCount = 0;
    uint64_t HashPrepMarkerCoveredMLoadOpCount = 0;
    uint64_t HashPrepMarkerCoveredKeccakOpCount = 0;
    uint64_t HashPrepMarkerRejectedReason = 0;

    uint64_t LargeStaticWorkspaceCandidateCount = 0;
    uint64_t LargeStaticWorkspaceVerifiedSegmentCount = 0;
    uint64_t LargeStaticWorkspaceVerifiedOpCount = 0;
    uint64_t LargeStaticWorkspaceVerifiedMLoadOpCount = 0;
    uint64_t LargeStaticWorkspaceVerifiedMStoreOpCount = 0;
    uint64_t LargeStaticWorkspaceVerifiedMStore8OpCount = 0;
    uint64_t LargeStaticWorkspaceMaxRequiredSize = 0;
    uint64_t LargeStaticWorkspaceRejectedCount = 0;
    uint64_t LargeStaticWorkspaceRejectDynamicOffset = 0;
    uint64_t LargeStaticWorkspaceRejectUnknownBase = 0;
    uint64_t LargeStaticWorkspaceRejectUnboundedInterval = 0;
    uint64_t LargeStaticWorkspaceRejectOverflowRisk = 0;
    uint64_t LargeStaticWorkspaceRejectSideEffect = 0;
    uint64_t LargeStaticWorkspaceRejectHelperByteExactRisk = 0;
    uint64_t LargeStaticWorkspaceRejectTooFewOps = 0;
    uint64_t LargeStaticWorkspaceLoweringCandidateCount = 0;
    uint64_t LargeStaticWorkspaceLoweringEnabledRegionCount = 0;
    uint64_t LargeStaticWorkspaceLoweringPrecheckedOpCount = 0;
    uint64_t LargeStaticWorkspaceLoweringPrecheckedMLoadOpCount = 0;
    uint64_t LargeStaticWorkspaceLoweringPrecheckedMStoreOpCount = 0;
    uint64_t LargeStaticWorkspaceLoweringDispMLoadOpCount = 0;
    uint64_t LargeStaticWorkspaceLoweringDispMStoreOpCount = 0;
    uint64_t LargeStaticWorkspaceLoweringFallbackRegionCount = 0;
    uint64_t LargeStaticWorkspaceLoweringDisabledByGateCount = 0;
    uint64_t LargeStaticWorkspaceLoweringUnsafePrecheckPositionCount = 0;
  };
  void noteBlockMemoryEventPC(uint64_t PC);
  bool hasCurrentMemoryBlockStats() const;
  struct MemoryBlockConstPrecheckPlan {
    bool Active = false;
    bool Emitted = false;
    bool HasAnchoredBasePtr = false;
    uint64_t MaxRequiredSize = 0;
    uint64_t CoveredDirectOpsTotal = 0;
    uint64_t CoveredDirectOpsRemaining = 0;
    std::vector<uint32_t> CoveredOpIds;
    bool HasOpPCRange = false;
    uint64_t FirstOpPC = 0;
    uint64_t LastOpPC = 0;
    Variable *AnchoredBasePtrVar = nullptr;
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
  struct MemoryBlockLargeStaticWorkspacePrecheckPlan {
    bool Active = false;
    bool Emitted = false;
    bool FallbackCounted = false;
    bool HasAnchoredBasePtr = false;
    uint64_t FirstCoveredPC = 0;
    uint64_t LastCoveredPC = 0;
    uint64_t MaxRequiredSize = 0;
    uint64_t CoveredDirectOpsTotal = 0;
    uint64_t CoveredDirectOpsRemaining = 0;
    uint64_t CoveredMLoadOpsTotal = 0;
    uint64_t CoveredMStoreOpsTotal = 0;
    uint64_t CoveredMStore8OpsTotal = 0;
    Variable *AnchoredBasePtrVar = nullptr;
  };
  bool tryConsumeConstBlockMemoryPrecheck();
  bool tryConsumeLinearBlockMemoryPrecheck(MInstruction *FirstAddr,
                                           MInstruction *OrderingDep);
  bool tryConsumeLargeStaticWorkspacePrecheck(evmc_opcode Opcode,
                                              bool OffsetWasConst,
                                              uint64_t ConstOffset,
                                              uint64_t AccessSize);
  bool tryUseGuaranteedMinBytesExpansionElision(bool OffsetWasConst,
                                                uint64_t ConstOffset,
                                                uint64_t AccessSize);
  void applyMemoryExpansionPlan(const MemoryExpansionPlan &Plan);
  void noteMemoryExpansionPlan(const MemoryExpansionPlan &Plan);
  void noteMemoryExpansionPlanDiagnostics(
      const MemoryExpansionPlanDiagnostics &Diag);
  uint64_t NextHashPrepMarkerId = 0;
  enum class SmallFrameMemoryOp : uint8_t { MLoad, MStore, MStore8 };
  void noteSmallFrameMemoryOp(SmallFrameMemoryOp Op, bool OffsetWasConst,
                              uint64_t ConstOffset, bool OffsetKnownU64,
                              uint64_t AccessSize, bool UsedSharedPrecheck);
  void noteKeccak256MemoryAccess(bool OffsetWasConstU64, uint64_t ConstOffset,
                                 bool LengthWasConstU64, uint64_t ConstLength);
  uint64_t NextMemoryBlockSeqId = 0;
  uint64_t CurrentMemoryOpPC = 0;
  uint64_t CurrentBlockGuaranteedMinBytes = 0;
  std::map<uint64_t, Operand> CurrentBlockMStoreValues;
  MemoryBlockCompileStats CurBlockMemStats;
  MemoryBlockConstPrecheckPlan CurBlockConstPrecheckPlan;
  MemoryBlockLinearPrecheckPlan CurBlockLinearPrecheckPlan;
  MemoryBlockLargeStaticWorkspacePrecheckPlan
      CurBlockLargeStaticWorkspacePrecheckPlan;
  std::unique_ptr<MemoryAnalysisView> MemoryAnalysis;
  std::unique_ptr<MemoryExpansionPlanner> MemoryExpansionPlans;

  // Helper methods for memory operations
  MInstruction *getMemoryDataPointer();
  MInstruction *getDirectMemoryDataPointer(bool PreferCachedBase);
  MInstruction *getConstBlockDirectMemoryBasePtr();
  MInstruction *getLargeStaticWorkspaceDirectMemoryBasePtr();
  MInstruction *getMemorySize();
  void reloadMemorySizeFromInstance();
  void expandMemoryIR(MInstruction *RequiredSize, MInstruction *Overflow);
  void preExpandKeccakTwoWordMemory(Operand &OffsetComponents);
  void preExpandCopyMemory(Operand &DestOffsetComponents,
                           Operand &SizeComponents);
  void chargeWordCopyGasIR(MInstruction *Size);
  void chargeDynamicGasIR(MInstruction *GasCost);
  void chargeKeccakWordGasIR(MInstruction *Length);
  void chargeMemoryExpansionGasIR(MInstruction *CurrentSize,
                                  MInstruction *NewSize);
  MInstruction *calculateMemoryGasCostIR(MInstruction *SizeInBytes);

  // Chunk gas metering
  const uint32_t *GasChunkEnd = nullptr;
  const uint64_t *GasChunkCost = nullptr;
  const uint64_t *GasChunkCostSPP = nullptr;
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
