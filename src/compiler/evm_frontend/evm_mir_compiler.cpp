#include "compiler/evm_frontend/evm_mir_compiler.h"
#include "compiler/evm_frontend/evm_bytecode_visitor.h"
#include "compiler/mir/basic_block.h"
#include "compiler/mir/constants.h"
#include "compiler/mir/function.h"
#include "compiler/mir/instructions.h"
#include "compiler/mir/type.h"
#include "evmc/instructions.h"

namespace COMPILER {

zen::common::EVMU256Type *EVMFrontendContext::getEVMU256Type() {
  static zen::common::EVMU256Type U256Type;
  return &U256Type;
}

MType *EVMFrontendContext::getMIRTypeFromEVMType(EVMType Type) {
  switch (Type) {
  case EVMType::VOID:
    return &VoidType;
  case EVMType::UINT8:
    return &I8Type;
  case EVMType::UINT32:
    return &I32Type;
  case EVMType::UINT64:
    return &I64Type;
  case EVMType::UINT256:
    // U256 is represented as I64 for MIR operations, but we use EVMU256Type
    // to track the semantic meaning and provide proper 256-bit operations
    return &I64Type; // Primary component for MIR operations
  case EVMType::ADDRESS:
    return &I64Type; // Address as 64-bit value for simplicity
  case EVMType::BYTES:
    return &I32Type; // Byte array pointer
  default:
    throw getErrorWithPhase(ErrorCode::UnexpectedType, ErrorPhase::Compilation,
                            ErrorSubphase::MIREmission);
  }
}

// ==================== EVMFrontendContext Implementation ====================

EVMFrontendContext::EVMFrontendContext() {
  // Initialize basic DMIR context
}

EVMFrontendContext::EVMFrontendContext(const EVMFrontendContext &OtherCtx)
    : CompileContext(OtherCtx), Bytecode(OtherCtx.Bytecode),
      BytecodeSize(OtherCtx.BytecodeSize) {}

// ==================== EVMMirBuilder Implementation ====================

EVMMirBuilder::EVMMirBuilder(CompilerContext &Context, MFunction &MFunc)
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

typename EVMMirBuilder::Operand EVMMirBuilder::handlePush(const uint8_t *Data,
                                                          size_t NumBytes) {
  // Convert bytes to uint256 value
  intx::uint256 Value = 0;
  for (size_t I = 0; I < NumBytes; ++I) {
    Value = (Value << 8) | Data[I];
  }

  // Get EVMU256Type to guide 4-component creation
  zen::common::EVMU256Type *U256Type = EVMFrontendContext::getEVMU256Type();
  MType *I64Type = EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);

  // Use EVMU256Type's structure to extract components properly
  // EVMU256Type defines 4 I64 elements, so we extract accordingly
  uint64_t Components[4]; // u256
  const auto &InnerTypes = U256Type->getInnerTypes();

  // Extract components based on EVMU256Type's bit layout (256 bits total)
  extractU256ComponentsExplicit(Components, Value,
                                U256Type->getElementsCount());

  // Create constant instructions using EVMU256Type's inner type information
  std::array<MInstruction *, 4> ComponentInstrs;
  for (size_t i = 0; i < U256Type->getElementsCount(); ++i) {
    // Verify we're using the correct inner type (should be I64)
    ZEN_ASSERT(U256Type->getInnerType(i) == &zen::common::WASMType::I64 &&
               "EVMU256Type inner type mismatch");

    MConstant *Constant = MConstantInt::get(Ctx, *I64Type, Components[i]);
    ComponentInstrs[i] =
        createInstruction<ConstantInstruction>(false, I64Type, *Constant);
  }

  return Operand(ComponentInstrs, EVMType::UINT256);
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

// ==================== Arithmetic Instruction Handlers ====================

template <evmc_opcode OpCode>
typename EVMMirBuilder::Operand
EVMMirBuilder::handleBinaryArithmetic(Operand LHSOp, Operand RHSOp) {
  // Get EVMU256Type for semantic awareness and verify our assumptions
  zen::common::EVMU256Type *U256Type = EVMFrontendContext::getEVMU256Type();

  // Extract 4 components from both operands using EVMU256Type structure
  auto LHSComponents = extractU256Components(LHSOp);
  auto RHSComponents = extractU256Components(RHSOp);

  MType *I64Type = EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);
  std::array<MInstruction *, U256Type->getElementsCount()> ResultComponents;

  switch (OpCode) {
  case OP_ADD: {
    // Implement 256-bit addition using EVMU256Type's element structure
    // For now, simplified implementation: add each component separately
    // TODO: Implement proper carry propagation for full 256-bit addition
    for (size_t i = 0; i < U256Type->getElementsCount(); ++i) {
      MInstruction *LHS = extractOperand(LHSComponents[i]);
      MInstruction *RHS = extractOperand(RHSComponents[i]);
      ResultComponents[i] = createInstruction<BinaryInstruction>(
          false, OP_add, I64Type, LHS, RHS);
    }
    break;
  }
  case OP_SUB: {
    // Implement 256-bit subtraction using EVMU256Type's element structure
    // For now, simplified implementation: subtract each component separately
    // TODO: Implement proper borrow propagation for full 256-bit subtraction
    for (size_t i = 0; i < U256Type->getElementsCount(); ++i) {
      MInstruction *LHS = extractOperand(LHSComponents[i]);
      MInstruction *RHS = extractOperand(RHSComponents[i]);
      ResultComponents[i] = createInstruction<BinaryInstruction>(
          false, OP_sub, I64Type, LHS, RHS);
    }
    break;
  }
  case OP_AND:
  case OP_OR:
  case OP_XOR: {
    // Bitwise operations can be done component-wise using EVMU256Type structure
    Opcode MIROpcode = getEVMBinaryOpcode(OpCode);
    for (size_t i = 0; i < U256Type->getElementsCount(); ++i) {
      MInstruction *LHS = extractOperand(LHSComponents[i]);
      MInstruction *RHS = extractOperand(RHSComponents[i]);
      ResultComponents[i] = createInstruction<BinaryInstruction>(
          false, MIROpcode, I64Type, LHS, RHS);
    }
    break;
  }
  default: {
    // For other operations (MUL, DIV, etc.), implement as needed
    // For now, fall back to component-wise operation on low component only
    MInstruction *LHS = extractOperand(LHSComponents[0]);
    MInstruction *RHS = extractOperand(RHSComponents[0]);
    Opcode MIROpcode = getEVMBinaryOpcode(OpCode);

    ResultComponents[0] = createInstruction<BinaryInstruction>(
        false, MIROpcode, I64Type, LHS, RHS);

    // Set higher components to zero for simplicity, using EVMU256Type element
    // count
    MConstant *ZeroConstant = MConstantInt::get(Ctx, *I64Type, 0);
    for (size_t i = 1; i < U256Type->getElementsCount(); ++i) {
      ResultComponents[i] =
          createInstruction<ConstantInstruction>(false, I64Type, *ZeroConstant);
    }
    break;
  }
  }

  return Operand(ResultComponents, EVMType::UINT256);
}

// Explicit template instantiation for ADD
template typename EVMMirBuilder::Operand
EVMMirBuilder::handleBinaryArithmetic<OP_ADD>(Operand LHSOp, Operand RHSOp);

// ==================== Environment Instruction Handlers ====================

typename EVMMirBuilder::Operand EVMMirBuilder::handlePC() {
  MType *UInt64Type =
      EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);
  MConstant *PCConstant = MConstantInt::get(Ctx, *UInt64Type, PC);

  MInstruction *Result =
      createInstruction<ConstantInstruction>(false, UInt64Type, *PCConstant);

  return Operand(Result, EVMType::UINT64);
}

typename EVMMirBuilder::Operand EVMMirBuilder::handleGas() {
  // For now, return a placeholder gas value
  // In a full implementation, this would access the execution context
  MType *UInt64Type =
      EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);
  MConstant *GasConstant = MConstantInt::get(Ctx, *UInt64Type, 1000000);

  MInstruction *Result =
      createInstruction<ConstantInstruction>(false, UInt64Type, *GasConstant);

  return Operand(Result, EVMType::UINT64);
}

// ==================== Private Helper Methods ====================

MInstruction *EVMMirBuilder::extractOperand(const Operand &Opnd) {
  if (Opnd.getInstr()) {
    return Opnd.getInstr();
  }

  if (Opnd.isU256MultiComponent()) {
    // For multi-component U256, we need to return a representative instruction
    // For now, return the low component as the primary representative
    // In a full implementation, this might need to be handled differently
    // depending on the context where extractOperand is called
    const auto &Components = Opnd.getU256Components();
    return Components[0]; // Return low component as primary
  }

  if (Opnd.getVar()) {
    // Read from variable with appropriate type handling
    Variable *Var = Opnd.getVar();
    MType *Type = EVMFrontendContext::getMIRTypeFromEVMType(Opnd.getType());

    // For UINT256, use EVMU256Type semantic awareness
    if (Opnd.getType() == EVMType::UINT256) {
      zen::common::EVMU256Type *U256Type = EVMFrontendContext::getEVMU256Type();
      // Note: U256Type provides semantic context for 256-bit operations

      // Check if this is a multi-component variable (should be handled
      // differently) For now, treat as single variable read
    }

    return createInstruction<DreadInstruction>(false, Type, Var->getVarIdx());
  }

  // Handle multi-component variable reads for U256
  if (Opnd.isU256MultiComponent() && Opnd.getType() == EVMType::UINT256) {
    // For multi-component variables, return the low component's read
    // instruction The full handling should be done by extractU256Components
    const auto &VarComponents = Opnd.getU256VarComponents();
    MType *I64Type = EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);
    return createInstruction<DreadInstruction>(false, I64Type,
                                               VarComponents[0]->getVarIdx());
  }

  ZEN_UNREACHABLE();
}

ConstantInstruction *
EVMMirBuilder::createUInt256ConstInstruction(const intx::uint256 &V) {
  // This method now returns just the low component instruction
  // For full U256 creation, use handlePush or createU256FromComponents

  // Get EVMU256Type for semantic awareness
  zen::common::EVMU256Type *U256Type = EVMFrontendContext::getEVMU256Type();

  MType *I64Type = EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);
  // Use lower 64 bits as the primary component
  uint64_t Value = static_cast<uint64_t>(V & 0xFFFFFFFFFFFFFFFFULL);
  MConstant *Constant = MConstantInt::get(Ctx, *I64Type, Value);
  return createInstruction<ConstantInstruction>(false, I64Type, *Constant);
}

typename EVMMirBuilder::Operand
EVMMirBuilder::createU256ConstOperand(const intx::uint256 &V) {
  // Get EVMU256Type to guide proper component creation
  zen::common::EVMU256Type *U256Type = EVMFrontendContext::getEVMU256Type();
  MType *I64Type = EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);

  // Use EVMU256Type's element count and structure
  uint64_t Components[U256Type->getElementsCount()];
  for (size_t i = 0; i < U256Type->getElementsCount(); ++i) {
    Components[i] =
        static_cast<uint64_t>((V >> (i * 64)) & 0xFFFFFFFFFFFFFFFFULL);
  }

  // Create constant instructions based on EVMU256Type's inner types
  std::array<MInstruction *, 4> ComponentInstrs;
  for (size_t i = 0; i < U256Type->getElementsCount(); ++i) {
    MConstant *Constant = MConstantInt::get(Ctx, *I64Type, Components[i]);
    ComponentInstrs[i] =
        createInstruction<ConstantInstruction>(false, I64Type, *Constant);
  }

  return Operand(ComponentInstrs, EVMType::UINT256);
}

// ==================== EVMU256 Helper Methods ====================

typename EVMMirBuilder::Operand
EVMMirBuilder::createU256FromComponents(Operand Low, Operand MidLow,
                                        Operand MidHigh, Operand High) {
  // Extract MInstructions from the component operands
  std::array<MInstruction *, 4> ComponentInstrs;
  ComponentInstrs[0] = extractOperand(Low);     // Low (bits 0-63)
  ComponentInstrs[1] = extractOperand(MidLow);  // Mid-low (bits 64-127)
  ComponentInstrs[2] = extractOperand(MidHigh); // Mid-high (bits 128-191)
  ComponentInstrs[3] = extractOperand(High);    // High (bits 192-255)

  return Operand(ComponentInstrs, EVMType::UINT256);
}

///
/// The U256 value is decomposed into four 64-bit components arranged in
/// **little-endian** order. That is:
/// - Index 0: Low (least significant) 64 bits
/// - Index 1: Mid-low 64 bits
/// - Index 2: Mid-high 64 bits
/// - Index 3: High (most significant) 64 bits
///
/// For example, if the U256 value is represented as:
///   [High][Mid-high][Mid-low][Low]
/// then this function returns them in the order: [Low, Mid-low, Mid-high,
/// High].
///
/// If the input operand is a legacy single-component U256, only the low part
/// will be set; the other parts are initialized to zero.
///
std::array<typename EVMMirBuilder::Operand, 4>
EVMMirBuilder::extractU256Components(Operand U256Op) {
  if (U256Op.isU256MultiComponent()) {
    try {
      // Try to get instruction components first
      const auto &Components = U256Op.getU256Components();
      return {
          Operand(Components[0], EVMType::UINT64), // Low
          Operand(Components[1], EVMType::UINT64), // Mid-low
          Operand(Components[2], EVMType::UINT64), // Mid-high
          Operand(Components[3], EVMType::UINT64)  // High
      };
    } catch (...) {
      // Multi-component variable operand
      const auto &VarComponents = U256Op.getU256VarComponents();
      return {
          Operand(VarComponents[0], EVMType::UINT64), // Low
          Operand(VarComponents[1], EVMType::UINT64), // Mid-low
          Operand(VarComponents[2], EVMType::UINT64), // Mid-high
          Operand(VarComponents[3], EVMType::UINT64)  // High
      };
    }
  }

  // Legacy single-component U256, create 4 components where only low is set
  MInstruction *SingleInstr = extractOperand(U256Op);
  MType *I64Type = EVMFrontendContext::getMIRTypeFromEVMType(EVMType::UINT64);

  // Create zero constants for the higher components
  MConstant *ZeroConstant = MConstantInt::get(Ctx, *I64Type, 0);
  MInstruction *ZeroInstr =
      createInstruction<ConstantInstruction>(false, I64Type, *ZeroConstant);

  return {
      Operand(SingleInstr, EVMType::UINT64), // Low component
      Operand(ZeroInstr, EVMType::UINT64),   // Mid-low = 0
      Operand(ZeroInstr, EVMType::UINT64),   // Mid-high = 0
      Operand(ZeroInstr, EVMType::UINT64)    // High = 0
  };
}

// ==================== EVM to MIR Opcode Mapping ====================

Opcode EVMMirBuilder::getEVMBinaryOpcode(evmc_opcode EVMOp) {
  switch (EVMOp) {
  case OP_ADD:
    return OP_add;
  case OP_SUB:
    return OP_sub;
  case OP_MUL:
    return OP_mul;
  case OP_DIV:
    return OP_udiv;
  case OP_MOD:
    return OP_urem;
  case OP_AND:
    return OP_and;
  case OP_OR:
    return OP_or;
  case OP_XOR:
    return OP_xor;
  default:
    throw std::runtime_error("Unsupported EVM binary opcode: " +
                             std::to_string(static_cast<int>(EVMOp)));
  }
}

} // namespace COMPILER
