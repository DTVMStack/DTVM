// Copyright (C) 2021-2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "compiler/evm_frontend/evm_eval_stack.h"

namespace COMPILER {

enum class EVMType : uint8_t {
  VOID,    // No value
  UINT8,   // Byte operations
  UINT32,  // Intermediate values
  UINT64,  // Gas calculations
  UINT256, // Main EVM type (256-bit integers) - maps to EVMU256Type from
           // common/type.h
  ADDRESS, // 20-byte Ethereum addresses
  BYTES,   // Dynamic byte arrays
};

class Variable;

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

  void setBytecode(const uint8_t *Code, size_t CodeSize) {
    Bytecode = Code;
    BytecodeSize = CodeSize;
  }

  const uint8_t *getBytecode() const { return Bytecode; }
  size_t getBytecodeSize() const { return BytecodeSize; }

private:
  const uint8_t *Bytecode = nullptr;
  size_t BytecodeSize = 0;
};

class EVMMirBuilder final {
public:
  typedef EVMFrontendContext CompilerContext;

  EVMMirBuilder(CompilerContext &Context, MFunction &MFunc);

  class Operand {
  public:
    Operand() = default;
    Operand(MInstruction *Instr, EVMType Type) : Instr(Instr), Type(Type) {}
    Operand(Variable *Var, EVMType Type) : Var(Var), Type(Type) {}

    // Constructor for EVMU256Type with 4 I64 components
    Operand(std::array<MInstruction *, 4> Components, EVMType Type)
        : Type(Type), U256Components(Components), IsU256MultiComponent(true) {
      ZEN_ASSERT(Type == EVMType::UINT256 && "Multi-component only for U256");
    }

    Operand(std::array<Variable *, 4> VarComponents, EVMType Type)
        : Type(Type), U256VarComponents(VarComponents),
          IsU256MultiComponent(true) {
      ZEN_ASSERT(Type == EVMType::UINT256 && "Multi-component only for U256");
    }

    MInstruction *getInstr() const { return Instr; }
    Variable *getVar() const { return Var; }
    EVMType getType() const { return Type; }

    bool isEmpty() const {
      return !Instr && !Var && !IsU256MultiComponent && Type == EVMType::VOID;
    }

    bool isU256MultiComponent() const { return IsU256MultiComponent; }
    const std::array<MInstruction *, 4> &getU256Components() const {
      ZEN_ASSERT(IsU256MultiComponent && "Not a multi-component U256");
      return U256Components;
    }
    const std::array<Variable *, 4> &getU256VarComponents() const {
      ZEN_ASSERT(IsU256MultiComponent && "Not a multi-component U256");
      return U256VarComponents;
    }

    constexpr bool isReg() { return false; }
    constexpr bool isTempReg() { return true; }

  private:
    MInstruction *Instr = nullptr;
    Variable *Var = nullptr;
    EVMType Type = EVMType::VOID;

    // For EVMU256Type: 4 I64 components [0]=low, [1]=mid-low, [2]=mid-high,
    // [3]=high
    bool IsU256MultiComponent = false;
    std::array<MInstruction *, 4> U256Components = {};
    std::array<Variable *, 4> U256VarComponents = {};
  };

  bool compile(CompilerContext *Context);

  void initEVM(CompilerContext *Context);
  void finalizeEVMBase();

  void releaseOperand(Operand Opnd) {}

  // ==================== Stack Instruction Handlers ====================

  // PUSH1-PUSH32: Push N bytes onto stack
  Operand handlePush(const uint8_t *Data, size_t NumBytes);

  // DUP1-DUP16: Duplicate Nth stack item
  void handleDup(uint32_t N);

  // SWAP1-SWAP16: Swap top with Nth+1 stack item
  void handleSwap(uint32_t N);

  // POP: Remove top stack item
  void handlePop();

  // ==================== Control Flow Instruction Handlers ====================

  void handleJump(Operand Dest);
  void handleJumpI(Operand Dest, Operand Cond);
  void handleJumpDest();

  // ==================== Arithmetic Instruction Handlers ====================

  template <evmc_opcode OpCode>
  Operand handleBinaryArithmetic(Operand LHSOp, Operand RHSOp);

  // ==================== Environment Instruction Handlers ====================

  Operand handlePC();
  Operand handleGas();

private:
  // ==================== Operand Methods ====================

  MInstruction *extractOperand(const Operand &Opnd);

  Operand createTempStackOperand(EVMType Type) {
    if (Type == EVMType::UINT256) {
      // For U256, create 4 I64 variables to represent the full 256-bit value
      MType *I64Type =
          EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);
      std::array<Variable *, 4> VarComponents;
      for (size_t i = 0; i < 4; ++i) {
        VarComponents[i] = CurFunc->createVariable(I64Type);
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
  std::array<Operand, 4> extractU256Components(Operand U256Op);

  void extractU256ComponentsExplicit(uint64_t *components,
                                     const uint256_t &value,
                                     size_t numComponents) {
    for (size_t i = 0; i < numComponents; ++i) {
      components[i] =
          static_cast<uint64_t>((value >> (i * 64)) & 0xFFFFFFFFFFFFFFFFULL);
    }
  }

  // ==================== EVM to MIR Opcode Mapping ====================

  Opcode getEVMBinaryOpcode(evmc_opcode EVMOp);

  CompilerContext &Ctx;
  MFunction *CurFunc = nullptr;
  MBasicBlock *CurBB = nullptr;
  EVMEvalStack<Operand> EvalStack;

  // Program counter for current instruction
  uint64_t PC = 0;
};

} // namespace COMPILER
