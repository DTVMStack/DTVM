#include "compiler/evm_frontend/evm_mir_compiler.h"
#include "evmc/evmc.h"
#include "evmc/instructions.h"
#include "intx/intx.hpp"

namespace COMPILER {

template <typename IRBuilder> class EVMByteCodeVisitor {
  typedef typename IRBuilder::CompilerContext CompilerContext;
  typedef typename IRBuilder::Operand Operand;
  typedef typename IRBuilder::template EVMEvalStack<Operand> EvalStack;

public:
  EVMByteCodeVisitor(IRBuilder &Builder, CompilerContext *Ctx)
      : Builder(Builder), Ctx(Ctx) {
    ZEN_ASSERT(Ctx);
  }

  bool compile() {
    Builder.initEVM(Ctx);
    bool Ret = decode();
    Builder.finalizeEVMBase();
    return Ret;
  }

private:
  void push(Operand Opnd) {
    Stack.push(Opnd);
  }

  Operand pop() {
    if (Stack.empty()) {
      throw std::runtime_error("EVM stack underflow");
    }
    Operand Opnd = Stack.pop();
    Builder.releaseOperand(Opnd);
    return Opnd;
  }

  Operand peek(size_t Index = 0) {
    return Stack.peek(Index);
  }

  bool decode() {
    const uint8_t *Bytecode = Ctx->getBytecode();
    size_t BytecodeSize = Ctx->getBytecodeSize();
    const uint8_t *Ip = Bytecode;
    const uint8_t *IpEnd = Bytecode + BytecodeSize;

    while (Ip < IpEnd) {
      evmc_opcode Opcode = static_cast<evmc_opcode>(*Ip);
      PC = Ip - Bytecode;
      Ip++;

      switch (Opcode) {
      // Stack operations
      case OP_PUSH1: case OP_PUSH2: case OP_PUSH3: case OP_PUSH4:
      case OP_PUSH5: case OP_PUSH6: case OP_PUSH7: case OP_PUSH8:
      case OP_PUSH9: case OP_PUSH10: case OP_PUSH11: case OP_PUSH12:
      case OP_PUSH13: case OP_PUSH14: case OP_PUSH15: case OP_PUSH16:
      case OP_PUSH17: case OP_PUSH18: case OP_PUSH19: case OP_PUSH20:
      case OP_PUSH21: case OP_PUSH22: case OP_PUSH23: case OP_PUSH24:
      case OP_PUSH25: case OP_PUSH26: case OP_PUSH27: case OP_PUSH28:
      case OP_PUSH29: case OP_PUSH30: case OP_PUSH31: case OP_PUSH32: {
        uint32_t NumBytes = Opcode - OP_PUSH1 + 1;
        if (Ip + NumBytes > IpEnd) {
          throw std::runtime_error("Unexpected end of bytecode in PUSH");
        }
        Operand Result = Builder.handlePush(Ip, NumBytes);
        push(Result);
        Ip += NumBytes;
        break;
      }

      case OP_DUP1: case OP_DUP2: case OP_DUP3: case OP_DUP4:
      case OP_DUP5: case OP_DUP6: case OP_DUP7: case OP_DUP8:
      case OP_DUP9: case OP_DUP10: case OP_DUP11: case OP_DUP12:
      case OP_DUP13: case OP_DUP14: case OP_DUP15: case OP_DUP16: {
        uint32_t N = Opcode - OP_DUP1 + 1;
        if (Stack.size() < N) {
          throw std::runtime_error("EVM stack underflow in DUP");
        }
        Operand Value = peek(N - 1);
        push(Value);
        break;
      }

      case OP_SWAP1: case OP_SWAP2: case OP_SWAP3: case OP_SWAP4:
      case OP_SWAP5: case OP_SWAP6: case OP_SWAP7: case OP_SWAP8:
      case OP_SWAP9: case OP_SWAP10: case OP_SWAP11: case OP_SWAP12:
      case OP_SWAP13: case OP_SWAP14: case OP_SWAP15: case OP_SWAP16: {
        uint32_t N = Opcode - OP_SWAP1 + 1;
        if (Stack.size() < N + 1) {
          throw std::runtime_error("EVM stack underflow in SWAP");
        }
        Builder.handleSwap(N);
        break;
      }

      case OP_POP: {
        if (Stack.empty()) {
          throw std::runtime_error("EVM stack underflow in POP");
        }
        pop();
        Builder.handlePop();
        break;
      }

      // Arithmetic operations
      case OP_ADD: {
        // Operand A = pop();
        // Operand B = pop();
        // TODO: handleBinaryArithmetic
        // Operand Result = Builder.template handleBinaryArithmetic<OP_ADD>(A, B);
        // push(Result);
        break;
      }

      // Control flow operations
      case OP_JUMP: {
        Operand Dest = pop();
        Builder.handleJump(Dest);
        break;
      }

      case OP_JUMPI: {
        Operand Dest = pop();
        Operand Cond = pop();
        Builder.handleJumpI(Dest, Cond);
        break;
      }

      case OP_JUMPDEST: {
        Builder.handleJumpDest();
        break;
      }

      // Environment operations
      case OP_PC: {
        Operand Result = Builder.handlePC();
        push(Result);
        break;
      }

      case OP_GAS: {
        Operand Result = Builder.handleGas();
        push(Result);
        break;
      }

      // Halt operations
      case OP_STOP:
      case OP_RETURN:
      case OP_REVERT:
        // End execution
        return true;

      case OP_INVALID:
        throw std::runtime_error("Invalid EVM opcode");

      default:
        throw std::runtime_error("Unimplemented EVM opcode: " + std::to_string(static_cast<int>(Opcode)));
      }
    }

    return true;
  }

  IRBuilder &Builder;
  CompilerContext *Ctx;
  EvalStack Stack;
  uint64_t PC = 0;
};

} // namespace COMPILER

#endif // EVM_FRONTEND_EVM_BYTECODE_VISITOR_H