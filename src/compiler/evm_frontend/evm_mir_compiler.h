// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef EVM_FRONTEND_EVM_MIR_COMPILER_H
#define EVM_FRONTEND_EVM_MIR_COMPILER_H

#include "action/vm_eval_stack.h"
#include "compiler/context.h"
#include "compiler/mir/function.h"
#include "compiler/mir/instructions.h"
#include "compiler/mir/pointer.h"
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

private:
  const Byte *Bytecode = nullptr;
  size_t BytecodeSize = 0;
  bool GasMeteringEnabled = false;
  const uint32_t *GasChunkEnd = nullptr;
  const uint64_t *GasChunkCost = nullptr;
  size_t GasChunkSize = 0;
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

  EVMMirBuilder(CompilerContext &Context, MFunction &MFunc);

  class Operand {
  public:
    Operand() = default;
    Operand(MInstruction *Instr, EVMType Type) : Instr(Instr), Type(Type) {}
    Operand(Variable *Var, EVMType Type) : Var(Var), Type(Type) {}

    // Constructor for EVMU256Type with 4 I64 components
    Operand(U256Inst Components, EVMType Type)
        : Type(Type), U256Components(Components), IsU256MultiComponent(true) {
      ZEN_ASSERT(Type == EVMType::UINT256 && "Multi-component only for U256");
    }

    Operand(U256Var VarComponents, EVMType Type)
        : Type(Type), U256VarComponents(VarComponents),
          IsU256MultiComponent(true) {
      ZEN_ASSERT(Type == EVMType::UINT256 && "Multi-component only for U256");
    }

    Operand(const U256Value &ConstValue)
        : Type(EVMType::UINT256), ConstValue(ConstValue), IsConstant(true) {}

    MInstruction *getInstr() const { return Instr; }
    Variable *getVar() const { return Var; }
    EVMType getType() const { return Type; }

    bool isEmpty() const {
      return !Instr && !Var && !IsU256MultiComponent && !IsConstant &&
             Type == EVMType::VOID;
    }

    bool isU256MultiComponent() const { return IsU256MultiComponent; }
    bool isConstant() const { return IsConstant; }

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

    constexpr bool isReg() { return false; }
    constexpr bool isTempReg() { return true; }

  private:
    MInstruction *Instr = nullptr;
    Variable *Var = nullptr;
    EVMType Type = EVMType::VOID;

    // For EVMU256Type: 4 I64 components [0]=low, [1]=mid-low, [2]=mid-high,
    // [3]=high
    U256Inst U256Components = {};
    U256Var U256VarComponents = {};
    U256Value ConstValue = {};
    bool IsConstant = false;
    bool IsU256MultiComponent = false;
  };

  bool compile(CompilerContext *Context);
  void loadEVMInstanceAttr();
  void initEVM(CompilerContext *Context);
  void finalizeEVMBase();

  void meterOpcode(evmc_opcode Opcode, uint64_t PC);
  void meterGas(uint64_t GasCost);

  // Complete jump implementation with jump table
  void createJumpTable();
  void implementConstantJump(uint64_t ConstDest, MBasicBlock *FailureBB);
  void implementIndirectJump(MInstruction *JumpTarget, MBasicBlock *FailureBB);

  void releaseOperand(Operand Opnd) {}

  // Block for stack check instructions
  void createStackCheckBlock();
  void updateStackCheckBlock(int32_t MinSize, int32_t MaxSize);

  // ==================== Stack Instruction Handlers ====================

  void stackPush(Operand PushValue);
  Operand stackPop();

  void stackSet(int32_t IndexFromTop, Operand SetValue);
  Operand stackGet(int32_t IndexFromTop);

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
    U256Inst Result = {};
    U256Inst LHS = extractU256Operand(LHSOp);
    U256Inst RHS = extractU256Operand(RHSOp);
    MType *MirI64Type =
        EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);

    if constexpr (Operator == BinaryOperator::BO_ADD) {
      // u256 in little-endian order: [low64, mid64_1, mid64_2, high64]

      // The carry here is only used for constructing the adc instruction.
      // We currently use adc only in bo_add, and since we can guarantee the
      // instructions are consecutive, there's no need to compute the carry
      // in DMIR.
      MInstruction *Carry = createIntConstInstruction(MirI64Type, 0);

      for (size_t I = 0; I < EVM_ELEMENTS_COUNT; ++I) {
        if (I == 0) {
          // First component: use regular ADD without carry
          MInstruction *LocalResult = createInstruction<BinaryInstruction>(
              false, OP_add, MirI64Type, LHS[I], RHS[I]);
          Result[I] = protectUnsafeValue(LocalResult, MirI64Type);
        } else {
          // Subsequent components: use ADC (without carry)
          // The carry here is only used for constructing the adc instruction.
          MInstruction *LocalResult = createInstruction<AdcInstruction>(
              false, MirI64Type, LHS[I], RHS[I], Carry);
          Result[I] = protectUnsafeValue(LocalResult, MirI64Type);
        }
      }
    } else if constexpr (Operator == BinaryOperator::BO_SUB) {
      MInstruction *Borrow = createIntConstInstruction(MirI64Type, 0);

      for (size_t I = 0; I < EVM_ELEMENTS_COUNT; ++I) {
        // Sub: LHS[I] - RHS[I] - Borrow
        MInstruction *Diff1 = createInstruction<BinaryInstruction>(
            false, OP_sub, MirI64Type, LHS[I], RHS[I]);
        MInstruction *Diff2 = createInstruction<BinaryInstruction>(
            false, OP_sub, MirI64Type, Diff1, Borrow);

        Result[I] = Diff2;

        // (LHS[I] < RHS[I]) || (Diff1 < Borrow)
        if (I < EVM_ELEMENTS_COUNT - 1) {
          auto LTPredicate = CmpInstruction::Predicate::ICMP_ULT;
          MInstruction *Borrow1 = createInstruction<CmpInstruction>(
              false, LTPredicate, &Ctx.I64Type, LHS[I], RHS[I]);
          MInstruction *Borrow2 = createInstruction<CmpInstruction>(
              false, LTPredicate, &Ctx.I64Type, Diff1, Borrow);
          // NOLINTBEGIN(readability-identifier-naming)
          MInstruction *Borrow1_64 = zeroExtendToI64(Borrow1);
          MInstruction *Borrow2_64 = zeroExtendToI64(Borrow2);
          // NOLINTEND(readability-identifier-naming)

          Borrow = createInstruction<BinaryInstruction>(
              false, OP_or, MirI64Type, Borrow1_64, Borrow2_64);
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
    U256Inst Result = handleCompareImpl<Operator>(LHSOp, RHSOp, &Ctx.I64Type);
    return Operand(Result, EVMType::UINT256);
  }

  // EVM bitwise opcode: and, or, xor
  template <BinaryOperator Operator>
  Operand handleBitwiseOp(const Operand &LHSOp, const Operand &RHSOp) {
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

  Operand handleByte(Operand IndexOp, Operand ValueOp);

  Operand handleSignextend(Operand IndexOp, Operand ValueOp);

  template <BinaryOperator Operator>
  Operand handleShift(Operand ShiftOp, Operand ValueOp) {
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
  void handleTrap(ErrorCode ErrCode);
  Operand handleKeccak256(Operand OffsetComponents, Operand LengthComponents);
  Operand handleSLoad(Operand KeyComponents);
  void handleSStore(Operand KeyComponents, Operand ValueComponents);
  Operand handleTLoad(Operand Index);
  void handleTStore(Operand Index, Operand ValueComponents);
  void handleSelfDestruct(Operand Beneficiary);

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

  U256Inst handleCompareEQZ(const U256Inst &LHS, MType *ResultType);

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
  void normalizeOperandU64(Operand &Param);

  // Split normalization for const and non-const U256.
  void normalizeOperandU64Const(Operand &Param);
  void normalizeOperandU64NonConst(Operand &Param);

  Operand convertSingleInstrToU256Operand(MInstruction *SingleInstr);
  Operand convertU256InstrToU256Operand(MInstruction *U256Instr);
  Operand convertBytes32ToU256Operand(const Operand &Bytes32Op);

  // Helper functions for operand conversion
  template <size_t N>
  U256Inst convertOperandToUNInstruction(const Operand &Param);

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

  // Jump table for dynamic jumps
  std::map<uint64_t, MBasicBlock *> JumpDestTable;
  MBasicBlock *DefaultJumpBB = nullptr; // For invalid jump destinations

  std::map<uint64_t, std::vector<MBasicBlock *>> JumpHashTable;
  std::map<uint64_t, std::vector<uint64_t>> JumpHashReverse;
  uint64_t HashMask = 0;

  // Stack check block for stack overflow/underflow checking
  MBasicBlock *StackCheckBB = nullptr;
  Variable *StackTopVar = nullptr;
  Variable *StackSizeVar = nullptr;

  // Chunk gas metering
  const uint32_t *GasChunkEnd = nullptr;
  const uint64_t *GasChunkCost = nullptr;
  size_t GasChunkSize = 0;

  // ==================== Interface Helper Methods ====================

  // Helper method to get instance pointer as instruction
  MInstruction *getCurrentInstancePointer();
};

} // namespace COMPILER

#endif // EVM_FRONTEND_EVM_MIR_COMPILER_H
