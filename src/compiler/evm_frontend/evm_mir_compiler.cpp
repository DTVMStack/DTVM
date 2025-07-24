#include "compiler/evm_frontend/evm_mir_compiler.h"
#include "compiler/evm_frontend/evm_bytecode_visitor.h"
#include "compiler/mir/basic_block.h"
#include "compiler/mir/constants.h"
#include "compiler/mir/function.h"
#include "compiler/mir/instructions.h"
#include "compiler/mir/type.h"
#include "evmc/instructions.h"

namespace COMPILER {

// ==================== EVMFrontendContext Implementation ====================

EVMFrontendContext::EVMFrontendContext() {
  // Initialize basic DMIR context
}

EVMFrontendContext::EVMFrontendContext(const EVMFrontendContext &OtherCtx)
    : CompileContext(OtherCtx), Bytecode(OtherCtx.Bytecode),
      BytecodeSize(OtherCtx.BytecodeSize) {}

// ==================== EVMMirBuilder Implementation ====================

EVMMirBuilder::EVMMirBuilder(CompilerContext &Context,
                                             MFunction &MFunc)
    : Ctx(Context), CurFunc(&MFunc) {}

bool EVMMirBuilder::compile(CompilerContext *Context) {
  EVMByteCodeVisitor<EVMMirBuilder> Visitor(*this, Context);
  return Visitor.compile();
}

void EVMMirBuilder::initEVM(CompilerContext *Context) {
  // Create entry basic block
  MBasicBlock *EntryBB = createBasicBlock();
  setInsertBlock(EntryBB);
  
  // Initialize program counter
  PC = 0;
}

void EVMMirBuilder::finalizeEVMBase() {
  // Ensure all basic blocks are properly terminated
  if (CurBB && !CurBB->isTerminated()) {
    // Add implicit return if not terminated
    createInstruction<RetInstruction>(true, &Ctx.VoidType);
  }
}

// ==================== Stack Instruction Handlers ====================

typename EVMMirBuilder::Operand
EVMMirBuilder::handlePush(const uint8_t *Data, size_t NumBytes) {
  // Convert bytes to uint256 value
  intx::uint256 Value = 0;
  for (size_t I = 0; I < NumBytes; ++I) {
    Value = (Value << 8) | Data[I];
  }

  // Create constant instruction
  MType *UInt256Type; // todo: getMIRTypeFromEVMType(EVMType::UINT256);
  MConstant *Constant = MConstantInt::get(Ctx, *UInt256Type, 
                                          static_cast<uint64_t>(Value & 0xFFFFFFFFFFFFFFFFULL));
  
  MInstruction *Result = createInstruction<ConstantInstruction>(
      false, UInt256Type, *Constant);
  
  return Operand(Result, EVMType::UINT256);
}

void EVMMirBuilder::handleDup(uint32_t N) {
  // DUP is handled in the visitor by manipulating the evaluation stack
  // No DMIR instruction needed
}

void EVMMirBuilder::handleSwap(uint32_t N) {
  // SWAP is handled in the visitor by manipulating the evaluation stack
  // No DMIR instruction needed
}

void EVMMirBuilder::handlePop() {
  // POP is handled in the visitor by removing from evaluation stack
  // No DMIR instruction needed
}

// ==================== Control Flow Instruction Handlers ====================

void EVMMirBuilder::handleJump(Operand Dest) {
  MInstruction *DestInstr = extractOperand(Dest);
  
  // Create jump destination basic block
  MBasicBlock *JumpBB = createBasicBlock();
  
  // Create unconditional branch
  createInstruction<BrInstruction>(true, Ctx, JumpBB);
  addSuccessor(JumpBB);
  
  setInsertBlock(JumpBB);
}

void EVMMirBuilder::handleJumpI(Operand Dest, Operand Cond) {
  MInstruction *DestInstr = extractOperand(Dest);
  MInstruction *CondInstr = extractOperand(Cond);
  
  // Create conditional branch
  MBasicBlock *ThenBB = createBasicBlock();
  MBasicBlock *ElseBB = createBasicBlock();
  
  createInstruction<BrIfInstruction>(true, Ctx, CondInstr, ThenBB, ElseBB);
  addSuccessor(ThenBB);
  addSuccessor(ElseBB);
  
  setInsertBlock(ThenBB);
}

void EVMMirBuilder::handleJumpDest() {
  // JUMPDEST creates a valid jump target
  // In DMIR, this is handled by basic block boundaries
}

// ==================== Environment Instruction Handlers ====================

typename EVMMirBuilder::Operand EVMMirBuilder::handlePC() {
  MType *UInt64Type; // todo: getMIRTypeFromEVMType(EVMType::UINT256);
  MConstant *PCConstant = MConstantInt::get(Ctx, *UInt64Type, PC);
  
  MInstruction *Result = createInstruction<ConstantInstruction>(
      false, UInt64Type, *PCConstant);
  
  return Operand(Result, EVMType::UINT64);
}

typename EVMMirBuilder::Operand EVMMirBuilder::handleGas() {
  // For now, return a placeholder gas value
  // In a full implementation, this would access the execution context
  MType *UInt64Type; // todo: getMIRTypeFromEVMType(EVMType::UINT256);
  MConstant *GasConstant = MConstantInt::get(Ctx, *UInt64Type, 1000000);
  
  MInstruction *Result = createInstruction<ConstantInstruction>(
      false, UInt64Type, *GasConstant);
  
  return Operand(Result, EVMType::UINT64);
}

// ==================== Private Helper Methods ====================

MInstruction *EVMMirBuilder::extractOperand(const Operand &Opnd) {
  if (Opnd.getInstr()) {
    return Opnd.getInstr();
  }
  
  if (Opnd.getVar()) {
    // Read from variable
    Variable *Var = Opnd.getVar();
    MType *Type; // todo: getMIRTypeFromEVMType(EVMType::UINT256);
    return createInstruction<DreadInstruction>(false, Type, Var->getVarIdx());
  }
  
  ZEN_UNREACHABLE();
}

ConstantInstruction *
EVMMirBuilder::createUInt256ConstInstruction(const intx::uint256 &V) {
  MType *UInt256Type; // todo: getMIRTypeFromEVMType(EVMType::UINT256);
  // For simplicity, truncate to uint64 for now
  uint64_t Value = static_cast<uint64_t>(V & 0xFFFFFFFFFFFFFFFFULL);
  MConstant *Constant = MConstantInt::get(Ctx, *UInt256Type, Value);
  return createInstruction<ConstantInstruction>(false, UInt256Type, *Constant);
}

} // namespace COMPILER