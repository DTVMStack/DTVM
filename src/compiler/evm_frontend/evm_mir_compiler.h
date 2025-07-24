#include "compiler/context.h"
#include "compiler/mir/constants.h"
#include "compiler/mir/function.h"
#include "compiler/mir/instructions.h"
#include "compiler/mir/opcode.h"
#include "compiler/mir/pointer.h"
#include "evmc/evmc.h"
#include "intx/intx.hpp"

namespace COMPILER {

class Variable;

class EVMFrontendContext final : public CompileContext {
public:
  EVMFrontendContext();
  ~EVMFrontendContext() override = default;

  EVMFrontendContext(const EVMFrontendContext &OtherCtx);
  EVMFrontendContext &operator=(const EVMFrontendContext &OtherCtx) = delete;
  EVMFrontendContext(EVMFrontendContext &&OtherCtx) = delete;
  EVMFrontendContext &operator=(EVMFrontendContext &&OtherCtx) = delete;

  // todo: static MType *getMIRTypeFromEVMType(EVMType Type);

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

    MInstruction *getInstr() const { return Instr; }
    Variable *getVar() const { return Var; }
    EVMType getType() const { return Type; }
    bool isEmpty() const { return !Instr && !Var && Type == EVMType::VOID; }

    constexpr bool isReg() { return false; }
    constexpr bool isTempReg() { return true; }

  private:
    MInstruction *Instr = nullptr;
    Variable *Var = nullptr;
    EVMType Type = EVMType::VOID;
  };

  template <class T>
  class EVMEvalStack {
  public:
    void push(const T &Item) { Stack.emplace_back(Item); }
    
    T pop() {
      if (Stack.empty()) {
        throw std::runtime_error("EVM stack underflow");
      }
      T Item = Stack.back();
      Stack.pop_back();
      return Item;
    }

    T &peek(size_t Index = 0) {
      if (Index >= Stack.size()) {
        throw std::runtime_error("EVM stack underflow");
      }
      return Stack[Stack.size() - 1 - Index];
    }

    size_t size() const { return Stack.size(); }
    bool empty() const { return Stack.empty(); }

  private:
    std::vector<T> Stack;
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

  // ==================== Environment Instruction Handlers ====================

  Operand handlePC();
  Operand handleGas();

private:
  // ==================== Operand Methods ====================

  MInstruction *extractOperand(const Operand &Opnd);

  Operand createTempStackOperand(EVMType Type) {
    MType *Mtype; // todo: getMIRTypeFromEVMType(EVMType::UINT256);
    Variable *TempVar = CurFunc->createVariable(Mtype);
    return Operand(TempVar, Type);
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

  MBasicBlock *createBasicBlock() { return CurFunc->createBasicBlock(); }

  void setInsertBlock(MBasicBlock *BB) {
    CurBB = BB;
    CurFunc->appendBlock(BB);
  }

  void addSuccessor(MBasicBlock *Succ) { CurBB->addSuccessor(Succ); }

  CompilerContext &Ctx;
  MFunction *CurFunc = nullptr;
  MBasicBlock *CurBB = nullptr;
  EVMEvalStack<Operand> EvalStack;

  // Program counter for current instruction
  uint64_t PC = 0;
};

} // namespace COMPILER

#endif // EVM_FRONTEND_EVM_MIR_COMPILER_H