// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef EVM_FRONTEND_EVM_MIR_COMPILER_H
#define EVM_FRONTEND_EVM_MIR_COMPILER_H

#include "action/vm_eval_stack.h"
#include "compiler/context.h"
#include "compiler/mir/function.h"
#include "compiler/mir/instructions.h"
#include "compiler/mir/pointer.h"
#include "intx/intx.hpp"

// Forward declaration to avoid circular dependency
namespace COMPILER {
struct RuntimeFunctions;
using U256Fn = intx::uint256 (*)(zen::runtime::EVMInstance *);
using Bytes32Fn = const uint8_t *(*)(zen::runtime::EVMInstance *);
using SizeFn = uint64_t (*)(zen::runtime::EVMInstance *);
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

private:
  const Byte *Bytecode = nullptr;
  size_t BytecodeSize = 0;
};

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

  void initEVM(CompilerContext *Context);
  void finalizeEVMBase();

  void releaseOperand(Operand Opnd) {}

  // ==================== Stack Instruction Handlers ====================

  // PUSH0: place value 0 on stack
  // PUSH1-PUSH32: Push N bytes onto stack
  Operand handlePush(const Bytes &Data);

  // DUP1-DUP16: Duplicate Nth stack item
  Operand handleDup(uint8_t Index);

  // SWAP1-SWAP16: Swap top with Nth+1 stack item
  void handleSwap(uint8_t Index);

  // POP: Remove top stack item
  void handlePop();

  // ==================== Control Flow Instruction Handlers ====================

  void handleStop() {
    createInstruction<ReturnInstruction>(true, &Ctx.VoidType, nullptr);
  }

  void handleJump(Operand Dest);
  void handleJumpI(Operand Dest, Operand Cond);
  void handleJumpDest();

  // ==================== Arithmetic Instruction Handlers ====================

  template <BinaryOperator Operator>
  Operand handleBinaryArithmetic(const Operand &LHSOp, const Operand &RHSOp) {
    U256Inst Result = {};
    U256Inst LHS = extractU256Operand(LHSOp);
    U256Inst RHS = extractU256Operand(RHSOp);
    MType *MirI64Type =
        EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);

    if constexpr (Operator == BinaryOperator::BO_ADD) {
      // u256 in little-endian order: [low64, med64_1, med64_2, high64]
      MInstruction *Carry = createIntConstInstruction(MirI64Type, 0);

      for (size_t I = 0; I < EVM_ELEMENTS_COUNT; ++I) {
        if (I == 0) {
          // First component: use regular ADD without carry
          Result[I] = createInstruction<BinaryInstruction>(
              false, OP_add, MirI64Type, LHS[I], RHS[I]);
        } else {
          // Subsequent components: use ADC (add with carry)
          Result[I] = createInstruction<AdcInstruction>(false, MirI64Type,
                                                        LHS[I], RHS[I], Carry);
        }

        // Calculate carry for next iteration (except for the last component)
        if (I < EVM_ELEMENTS_COUNT - 1) {
          // Carry = (Result[I] < LHS[I]) for unsigned overflow detection
          auto LTPredicate = CmpInstruction::Predicate::ICMP_ULT;
          MInstruction *CarryFlag = createInstruction<CmpInstruction>(
              false, LTPredicate, &Ctx.I64Type, Result[I], LHS[I]);

          // Convert boolean to i64 for next iteration
          Carry = createInstruction<ConversionInstruction>(
              false, OP_uext, MirI64Type, CarryFlag);
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

          MInstruction *Borrow1_64 = createInstruction<ConversionInstruction>(
              false, OP_uext, MirI64Type, Borrow1);
          MInstruction *Borrow2_64 = createInstruction<ConversionInstruction>(
              false, OP_uext, MirI64Type, Borrow2);

          Borrow = createInstruction<BinaryInstruction>(
              false, OP_or, MirI64Type, Borrow1_64, Borrow2_64);
        }
      }
    } else {
      ZEN_ASSERT_TODO();
    }
    return Operand(Result, EVMType::UINT256);
  }

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
    for (size_t I = 0; I < EVM_ELEMENTS_COUNT; ++I) {
      Result[I] = createInstruction<BinaryInstruction>(
          false, getMirOpcode(Operator),
          EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64), LHS[I],
          RHS[I]);
    }
    return Operand(Result, EVMType::UINT256);
  }

  Operand handleNot(const Operand &LHSOp);

  // ==================== Environment Instruction Handlers ====================

  Operand handlePC();
  Operand handleGas();
  Operand handleAddress();
  Operand handleOrigin();
  Operand handleCaller();
  Operand handleCallValue();
  Operand handleGasPrice();
  Operand handleCallDataSize();
  Operand handleCodeSize();

  // ==================== Runtime Interface for JIT ====================

private:
  // ==================== Operand Methods ====================

  void pushOperand(const Operand &Op) { OperandStack.push(Op); }
  Operand popOperand();
  Operand peekOperand(size_t Index = 0) const;
  size_t getStackSize() const { return OperandStack.size(); }

  MInstruction *extractOperand(const Operand &Opnd);
  U256Inst extractU256Operand(const Operand &Opnd);

  Operand createTempStackOperand(EVMType Type) {
    if (Type == EVMType::UINT256) {
      // For U256, create 4 I64 variables to represent the full 256-bit value
      MType *I64Type =
          EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);
      U256Var VarComponents;
      for (size_t I = 0; I < EVM_ELEMENTS_COUNT; ++I) {
        VarComponents[I] = CurFunc->createVariable(I64Type);
      }
      return Operand(VarComponents, Type);
    } else {
      // For other types, use single variable
      MType *Mtype = EVMFrontendContext::getMIRTypeFromEVMType(Type);
      Variable *TempVar = CurFunc->createVariable(Mtype);
      return Operand(TempVar, Type);
    }
  }

  // ==================== MIR Util Methods ====================

  MPointerType *createVoidPtrType() const {
    return MPointerType::create(Ctx, Ctx.VoidType);
  }

  template <class T, typename... Arguments>
  T *createInstruction(bool IsStmt, Arguments &&...Args) {
    return CurFunc->createInstruction<T>(IsStmt, *CurBB,
                                         std::forward<Arguments>(Args)...);
  }

  ConstantInstruction *createIntConstInstruction(MType *Type, uint64_t V) {
    return createInstruction<ConstantInstruction>(
        false, Type, *MConstantInt::get(Ctx, *Type, V));
  }

  ConstantInstruction *createUInt256ConstInstruction(const intx::uint256 &V);

  // Create a full U256 operand from intx::uint256 value
  Operand createU256ConstOperand(const intx::uint256 &V);

  MBasicBlock *createBasicBlock() { return CurFunc->createBasicBlock(); }

  void setInsertBlock(MBasicBlock *BB) {
    CurBB = BB;
    CurFunc->appendBlock(BB);
  }

  void addSuccessor(MBasicBlock *Succ) { CurBB->addSuccessor(Succ); }

  // ==================== EVMU256 Helper Methods ====================

  // Create a 256-bit value from 4 x I64 components
  Operand createU256FromComponents(Operand Low, Operand MidLow, Operand MidHigh,
                                   Operand High);

  // Extract I64 components from U256 operand (for operations that need
  // component access)
  std::array<Operand, EVM_ELEMENTS_COUNT> extractU256Components(Operand U256Op);

  void extractU256ComponentsExplicit(uint64_t *Components,
                                     const intx::uint256 &Value,
                                     size_t NumComponents) {
    for (size_t I = 0; I < NumComponents; ++I) {
      Components[I] =
          static_cast<uint64_t>((Value >> (I * 64)) & 0xFFFFFFFFFFFFFFFFULL);
    }
  }

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

  U256Inst handleCompareGT_LT(const U256Inst &LHS, const U256Inst &RHS,
                              MType *ResultType, CompareOperator Operator);

  // ==================== EVM to MIR Opcode Mapping ====================

  Opcode getMirOpcode(BinaryOperator BinOpr);

  // ==================== Helper Methods ====================

  // Runtime calls for different return types
  Operand callRuntimeForU256(U256Fn RuntimeFunc);
  Operand callRuntimeForBytes32(Bytes32Fn RuntimeFunc);
  Operand callRuntimeForSize(SizeFn RuntimeFunc);

  Operand convertSingleInstrToU256Operand(MInstruction *SingleInstr);
  Operand convertU256InstrToU256Operand(MInstruction *U256Instr);
  Operand convertBytes32ToU256Operand(const Operand &Bytes32Op);

  CompilerContext &Ctx;
  MFunction *CurFunc = nullptr;
  MBasicBlock *CurBB = nullptr;
  std::stack<Operand> OperandStack;

  // Instance address for JIT function calls
  MInstruction *InstanceAddr = nullptr;

  // Program counter for current instruction
  uint64_t PC = 0;

  // ==================== Interface Helper Methods ====================

  // Helper method to get instance pointer as instruction
  MInstruction *getCurrentInstancePointer();
};

} // namespace COMPILER

#endif // EVM_FRONTEND_EVM_MIR_COMPILER_H
