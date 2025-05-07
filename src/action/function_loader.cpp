// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "action/function_loader.h"
#include "utils/others.h"
#include "utils/wasm.h"

namespace zen::action {

using namespace common;
using namespace runtime;
using namespace utils;

bool FunctionLoader::ControlBlockType::isBalanced() const {
  ZEN_ASSERT(!TypeVariant.valueless_by_exception());
  if (TypeVariant.index() == 0) {
    return std::get<WASMType>(TypeVariant) == WASMType::VOID;
  }
  const TypeEntry *Type = std::get<const TypeEntry *>(TypeVariant);
  uint32_t NumParamTypes = Type->NumParams;
  uint32_t NumReturnTypes = Type->NumReturns;
  const WASMType *ParamTypes = Type->getParamTypes();
  const WASMType *ReturnTypes = Type->ReturnTypes;
  return NumParamTypes == NumReturnTypes &&
         std::memcmp(ParamTypes, ReturnTypes,
                     NumParamTypes * sizeof(WASMType)) == 0;
}

std::pair<uint32_t, const WASMType *>
FunctionLoader::ControlBlockType::getParamTypes() const {
  ZEN_ASSERT(!TypeVariant.valueless_by_exception());
  if (TypeVariant.index() == 0) {
    return {0, nullptr};
  }
  const TypeEntry *Type = std::get<const TypeEntry *>(TypeVariant);
  return {Type->NumParams, Type->getParamTypes()};
}

std::pair<uint32_t, const WASMType *>
FunctionLoader::ControlBlockType::getReturnTypes() const {
  ZEN_ASSERT(!TypeVariant.valueless_by_exception());
  if (TypeVariant.index() == 0) {
    const WASMType *TypeAddr = std::get_if<WASMType>(&TypeVariant);
    ZEN_ASSERT(TypeAddr);
    uint32_t NumReturns = *TypeAddr == WASMType::VOID ? 0 : 1;
    return {NumReturns, NumReturns ? TypeAddr : nullptr};
  }
  const TypeEntry *Type = std::get<const TypeEntry *>(TypeVariant);
  return {
      static_cast<uint32_t>(Type->NumReturns),
      Type->ReturnTypes,
  };
}

std::string FunctionLoader::getTypeErrorMsg(WASMType ExpectedType,
                                            WASMType ActualType) {
  std::string ErrMsg;
  ErrMsg += "expect ";
  ErrMsg += getWASMTypeString(ExpectedType);
  ErrMsg += " but got ";
  ErrMsg += getWASMTypeString(ActualType);
  return ErrMsg;
}

bool FunctionLoader::checkMemoryAlign(uint8_t Opcode, uint32_t Align) {
  static constexpr uint8_t Aligns[] = {
#define DEFINE_WASM_OPCODE(NAME, OPCODE, TEXT, ALIGN) ALIGN,
#include "common/wasm_defs/opcode_loadstore.def"
#undef DEFINE_WASM_OPCODE
  };
  ZEN_ASSERT(Opcode >= I32_LOAD);
  ZEN_ASSERT(Opcode <= I64_STORE32);
  return Align <= Aligns[Opcode - I32_LOAD];
}

void FunctionLoader::pushBlock(common::LabelType LabelType,
                               ControlBlockType BlockType,
                               const Byte *StartPtr) {
  ControlBlocks.emplace_back(ControlBlock{
      false,
      LabelType,
      BlockType,
      StartPtr,
      nullptr,
      nullptr,
      StackSize,
      static_cast<uint32_t>(ValueTypes.size()),
#ifdef ZEN_ENABLE_DWASM
      0,
#endif
  });
  // Save cast because ControlBlocks.size() < UINT32_MAX
  uint32_t CurStackDepth = static_cast<uint32_t>(ControlBlocks.size());
  MaxBlockDepth = std::max(MaxBlockDepth, CurStackDepth);
}

WASMType FunctionLoader::popValueType(WASMType Type) {
  const ControlBlock &Block = ControlBlocks.back();

  ZEN_ASSERT(ValueTypes.size() >= Block.InitNumValues);
  if (ValueTypes.size() == Block.InitNumValues) {
    if (Block.StackPolymorphic) {
      return WASMType::ANY;
    }
    throw getError(ErrorCode::TypeMismatchStackSize);
  }

  if (ValueTypes.back() == WASMType::ANY) {
    // ZEN_ASSERT(Type != WASMType::ANY);
    if (Type == WASMType::ANY) {
      throw getError(ErrorCode::TypeMismatch);
    }
  } else if (Type == WASMType::ANY) {
    Type = ValueTypes.back();
  } else if (ValueTypes.back() != Type) {
    const std::string &ErrMsg = getTypeErrorMsg(Type, ValueTypes.back());
    throw getErrorWithExtraMessage(ErrorCode::TypeMismatch, ErrMsg);
  }

  uint32_t TypeSize = getWASMTypeSize(Type);
  if (subOverflow(StackSize, TypeSize, StackSize)) {
    throw getError(ErrorCode::TypeMismatchStackSize);
  }
  ValueTypes.pop_back();

  return Type;
}

void FunctionLoader::pushBlockParamTypes() {
  ZEN_ASSERT(!ControlBlocks.empty());
  ControlBlock &Block = ControlBlocks.back();
  const auto [NumParamTypes, ParamTypes] = Block.BlockType.getParamTypes();
  if (NumParamTypes > 0 && ParamTypes) {
    for (uint32_t I = 0; I < NumParamTypes; ++I) {
      pushValueType(ParamTypes[I]);
    }
  }
}

void FunctionLoader::checkTopTypes(ControlBlock &Block, uint32_t NumTypes,
                                   const WASMType *Types, bool IsBranch) {
  uint32_t AvailStackSize;
  if (subOverflow(StackSize, Block.InitStackSize, AvailStackSize)) {
    throw getError(ErrorCode::TypeMismatchStackSize);
  }

  if (Block.StackPolymorphic) {
    for (int32_t I = static_cast<int32_t>(NumTypes) - 1; I >= 0; --I) {
      popValueType(Types[I]);
    }

    for (uint32_t I = 0; I < NumTypes; ++I) {
      pushValueType(Types[I]);
    }

    if (ValueTypes.size() - Block.InitNumValues < NumTypes ||
        (!IsBranch && (ValueTypes.size() - Block.InitNumValues != NumTypes))) {
      throw getError(ErrorCode::TypeMismatchStackSize);
    }

    // Use int32_t to prevent downflow
    for (int32_t I = static_cast<int32_t>(NumTypes) - 1; I >= 0; --I) {
      if (ValueTypes.back() != Types[I]) {
        throw getErrorWithExtraMessage(
            ErrorCode::TypeMismatch,
            getTypeErrorMsg(Types[I], ValueTypes.back()));
      }
    }

    return;
  }

  /* Check stack cell num equals return cell num */
  uint32_t NumReturnCells = 0;
  for (uint32_t I = 0; I < NumTypes; ++I) {
    NumReturnCells += getWASMTypeCellNum(Types[I]);
  }

  if (AvailStackSize >> 2 != NumReturnCells) {
    throw getError(ErrorCode::TypeMismatchStackSize);
  }

  checkTargetBlockStack(NumTypes, Types, AvailStackSize);
}

void FunctionLoader::checkTargetBlockStack(uint32_t NumTypes,
                                           const WASMType *Types,
                                           uint32_t AvailStackSize) {
  /* Check stack top values match target block type */
  std::vector<WASMType> FuncValueTypes(ValueTypes);
  for (int32_t I = static_cast<int32_t>(NumTypes) - 1; I >= 0; --I) {
    WASMType RetType = Types[I];
    uint32_t TypeSize = getWASMTypeSize(RetType);
    if (TypeSize > AvailStackSize) {
      throw getError(ErrorCode::TypeMismatchExpectDataStackEmpty);
    }
    WASMType Type = FuncValueTypes.back();
    FuncValueTypes.pop_back();
    if (Type != RetType) {
      throw getErrorWithExtraMessage(ErrorCode::TypeMismatch,
                                     getTypeErrorMsg(Type, RetType));
    }
    if (subOverflow(AvailStackSize, TypeSize, AvailStackSize)) {
      throw getError(ErrorCode::TypeMismatchStackSize);
    }
  }
}

void FunctionLoader::checkBlockStack() {
  ZEN_ASSERT(!ControlBlocks.empty());
  ControlBlock &Block = ControlBlocks.back();
  ControlBlockType BlockType = Block.BlockType;
  const auto [NumReturnTypes, ReturnTypes] = BlockType.getReturnTypes();
  checkTopTypes(Block, NumReturnTypes, ReturnTypes, false);
}

const FunctionLoader::ControlBlock &FunctionLoader::checkBranch() {
  uint32_t Depth = readU32();
  if (ControlBlocks.size() <= Depth) {
    throw getError(ErrorCode::UnknownLabel);
  }

  const auto &TargetBlock = ControlBlocks[ControlBlocks.size() - Depth - 1];
  const ControlBlockType &BlockType = TargetBlock.BlockType;

  uint32_t NumTypes = 0;
  const WASMType *Types;
  if (TargetBlock.LabelType == LABEL_LOOP) {
    std::tie(NumTypes, Types) = BlockType.getParamTypes();
  } else {
    std::tie(NumTypes, Types) = BlockType.getReturnTypes();
  }

  const ControlBlock &CurBlock = ControlBlocks.back();
  if (CurBlock.StackPolymorphic) {
    for (int32_t I = static_cast<int32_t>(NumTypes) - 1; I >= 0; --I) {
      popValueType(Types[I]);
    }

    for (uint32_t I = 0; I < NumTypes; ++I) {
      pushValueType(Types[I]);
    }

    return TargetBlock;
  }

  uint32_t AvailStackSize = StackSize - CurBlock.InitStackSize;
  checkTargetBlockStack(NumTypes, Types, AvailStackSize);

  return TargetBlock;
}

WASMType FunctionLoader::readLocal() {
  uint32_t LocalIdx = readU32();
  uint32_t NumParams = FuncTypeEntry.NumParams;
  // The overflow has been checked in module loader
  if (LocalIdx >= NumParams + FuncCodeEntry.NumLocals) {
    throw getError(ErrorCode::UnknownLocal);
  }
  if (LocalIdx < NumParams) {
    return FuncTypeEntry.getParamTypes()[LocalIdx];
  }
  return FuncCodeEntry.LocalTypes[LocalIdx - NumParams];
}

void FunctionLoader::load() {
  pushBlock(LABEL_FUNCTION, ControlBlockType(&FuncTypeEntry), Ptr);
#ifdef ZEN_ENABLE_DWASM
  uint32_t NumOpcodes = 0;
#endif
#ifdef ZEN_ENABLE_MULTIPASS_JIT
  std::vector<bool> CalleeIdxBitset(Mod.NumImportFunctions, true);
  CalleeIdxBitset.resize(Mod.getNumTotalFunctions(), false);
  std::vector<uint32_t> CalleeIdxSeq;
#endif
  while (Ptr < End) {
    uint8_t Opcode = to_underlying(readByte());
    switch (Opcode) {
    case UNREACHABLE:
      resetStack();
      setStackPolymorphic(true);
      break;
    case NOP:
      break;
    case IF:
      popValueType(WASMType::I32);
      [[fallthrough]];
    case BLOCK:
    case LOOP: {
      WASMType Type = readBlockType();
      ControlBlockType BlockType = Type;
      auto BlockLabelTy = static_cast<LabelType>(LABEL_BLOCK + Opcode - BLOCK);
      pushBlock(BlockLabelTy, BlockType, Ptr);

      pushBlockParamTypes();
      break;
    }
    case ELSE: {
      ControlBlock &Block = ControlBlocks.back();
      if (Block.LabelType != LABEL_IF) {
        throw getError(ErrorCode::ElseMismatchIf);
      }
      checkBlockStack();
      Block.ElsePtr = Ptr - 1;
      resetStack();
      setStackPolymorphic(false);
      pushBlockParamTypes();
      break;
    }
    case BR:
      checkBranch();
      resetStack();
      setStackPolymorphic(true);
      break;
    case BR_IF:
      popValueType(WASMType::I32);
      checkBranch();
      break;
    case BR_TABLE: {
      uint32_t NumTargets = readU32();

      popValueType(WASMType::I32);

      uint32_t ExpectedNumTypes = 0;
      const WASMType *ExpectedTypes = nullptr;
      for (uint32_t I = 0; I <= NumTargets; ++I) {
        const ControlBlock &TargetBlock = checkBranch();
        const LabelType &TargetLabelType = TargetBlock.LabelType;
        const ControlBlockType &TargetBlockType = TargetBlock.BlockType;
        if (I == 0) {
          if (TargetLabelType != LABEL_LOOP) {
            std::tie(ExpectedNumTypes, ExpectedTypes) =
                TargetBlockType.getReturnTypes();
          }
        } else {
          uint32_t ActualNumTypes = 0;
          const WASMType *ActualTypes = nullptr;
          if (TargetLabelType != LABEL_LOOP) {
            std::tie(ActualNumTypes, ActualTypes) =
                TargetBlockType.getReturnTypes();
          }
          if ((ExpectedNumTypes != ActualNumTypes) ||
              (ExpectedNumTypes != 0 && (std::memcmp(ExpectedTypes, ActualTypes,
                                                     ExpectedNumTypes) != 0))) {
            throw getError(ErrorCode::TypeMismatchBrTableTargets);
          }
        }
      }

      resetStack();
      setStackPolymorphic(true);
      break;
    }
    case END: {
      ControlBlock &Block = ControlBlocks.back();
      checkBlockStack();

      // block in if satisfies param types == return types
      if (Block.LabelType == LABEL_IF && !Block.ElsePtr) {
        if (!Block.BlockType.isBalanced()) {
          throw getError(ErrorCode::TypeMismatchElseMissing);
        }
      }

      if (Block.LabelType == LABEL_FUNCTION) {
        ZEN_ASSERT(ControlBlocks.size() == 1);
        popBlock();
        if (Ptr < End) {
          throw getError(ErrorCode::OpcodesRemainAfterEndOfFunction);
        }
      } else {
        Block.EndPtr = Ptr - 1;
        popBlock();
        ZEN_ASSERT(!ControlBlocks.empty());
        setStackPolymorphic(false);
      }

      break;
    }
    case GET_LOCAL: {
      WASMType LocalType = readLocal();
      pushValueType(LocalType);
      break;
    }
    case SET_LOCAL: {
      WASMType LocalType = readLocal();
      popValueType(LocalType);
      break;
    }
    case TEE_LOCAL: {
      WASMType LocalType = readLocal();
      popValueType(LocalType);
      pushValueType(LocalType);
      break;
    }
    case GET_GLOBAL: {
      uint32_t GlobalIdx = readU32();
      if (!Mod.isValidGlobal(GlobalIdx)) {
        throw getError(ErrorCode::UnknownGlobal);
      }
      if (GlobalIdx < Mod.getNumImportGlobals()) {
        throw getError(ErrorCode::UnsupportedImport);
      }
      WASMType GlobalType = Mod.getGlobalType(GlobalIdx);
      pushValueType(GlobalType);
      FuncCodeEntry.Stats |= Module::SF_global;
      break;
    }
    case SET_GLOBAL: {
      uint32_t GlobalIdx = readU32();
      if (!Mod.isValidGlobal(GlobalIdx)) {
        throw getError(ErrorCode::UnknownGlobal);
      }
      int32_t InternalGlobalIdx =
          int32_t(GlobalIdx) - Mod.getNumImportGlobals();
      if (InternalGlobalIdx < 0) {
        throw getError(ErrorCode::UnsupportedImport);
      }
      const auto &Global = Mod.getInternalGlobal(InternalGlobalIdx);
      if (!Global.Mutable) {
        throw getError(ErrorCode::GlobalIsImmutable);
      }
      popValueType(Global.Type);
      FuncCodeEntry.Stats |= Module::SF_global;
      break;
    }
    case MEMORY_SIZE: {
      if (!hasMemory()) {
        throw getError(ErrorCode::UnknownMemory);
      }

      uint8_t MemIdx = to_underlying(readByte());
      if (MemIdx != 0x00) {
        throw getError(ErrorCode::ZeroFlagExpected);
      }

      pushValueType(WASMType::I32);

      FuncCodeEntry.Stats |= Module::SF_memory;

      break;
    }
    case MEMORY_GROW: {
      if (!hasMemory()) {
        throw getError(ErrorCode::UnknownMemory);
      }

      uint8_t MemIdx = to_underlying(readByte());
      if (MemIdx != 0x00) {
        throw getError(ErrorCode::ZeroFlagExpected);
      }

      popAndPushValueType(1, WASMType::I32, WASMType::I32);

      FuncCodeEntry.Stats |= Module::SF_memory;

      break;
    }
    case I32_CONST: {
      [[maybe_unused]] uint32_t I32 = readI32();
      pushValueType(WASMType::I32);
      break;
    }
    case I64_CONST: {
      [[maybe_unused]] uint64_t I64 = readI64();
      pushValueType(WASMType::I64);
      break;
    }
    case F32_CONST: {
      [[maybe_unused]] float F32 = readF32();
      pushValueType(WASMType::F32);
      break;
    }
    case F64_CONST: {
      [[maybe_unused]] double F64 = readF64();
      pushValueType(WASMType::F64);
      break;
    }
    case I32_EQZ:
      popAndPushValueType(1, WASMType::I32, WASMType::I32);
      break;
    case I32_EQ:
    case I32_NE:
    case I32_LT_S:
    case I32_LT_U:
    case I32_GT_S:
    case I32_GT_U:
    case I32_LE_S:
    case I32_LE_U:
    case I32_GE_S:
    case I32_GE_U:
      popAndPushValueType(2, WASMType::I32, WASMType::I32);
      break;
    case I64_EQZ:
      popAndPushValueType(1, WASMType::I64, WASMType::I32);
      break;
    case I64_EQ:
    case I64_NE:
    case I64_LT_S:
    case I64_GT_S:
    case I64_LT_U:
    case I64_GT_U:
    case I64_LE_S:
    case I64_LE_U:
    case I64_GE_S:
    case I64_GE_U:
      popAndPushValueType(2, WASMType::I64, WASMType::I32);
      break;
    case F32_EQ:
    case F32_NE:
    case F32_LT:
    case F32_GT:
    case F32_LE:
    case F32_GE:
      popAndPushValueType(2, WASMType::F32, WASMType::I32);
      break;
    case F64_EQ:
    case F64_NE:
    case F64_LT:
    case F64_GT:
    case F64_LE:
    case F64_GE:
      popAndPushValueType(2, WASMType::F64, WASMType::I32);
      break;
    case I32_CLZ:
    case I32_CTZ:
    case I32_POPCNT:
      popAndPushValueType(1, WASMType::I32, WASMType::I32);
      break;
    case I32_ADD:
    case I32_SUB:
    case I32_MUL:
    case I32_DIV_S:
    case I32_DIV_U:
    case I32_REM_S:
    case I32_REM_U:
    case I32_AND:
    case I32_OR:
    case I32_XOR:
    case I32_SHL:
    case I32_SHR_S:
    case I32_SHR_U:
    case I32_ROTL:
    case I32_ROTR:
      popAndPushValueType(2, WASMType::I32, WASMType::I32);
      break;
    case I64_ADD:
    case I64_SUB:
    case I64_MUL:
    case I64_DIV_S:
    case I64_DIV_U:
    case I64_REM_S:
    case I64_REM_U:
    case I64_AND:
    case I64_OR:
    case I64_XOR:
    case I64_SHL:
    case I64_SHR_S:
    case I64_SHR_U:
    case I64_ROTL:
    case I64_ROTR:
      popAndPushValueType(2, WASMType::I64, WASMType::I64);
      break;
    case I64_CLZ:
    case I64_CTZ:
    case I64_POPCNT:
      popAndPushValueType(1, WASMType::I64, WASMType::I64);
      break;
    case F32_ABS:
    case F32_NEG:
    case F32_CEIL:
    case F32_FLOOR:
    case F32_TRUNC:
    case F32_NEAREST:
    case F32_SQRT:
      popAndPushValueType(1, WASMType::F32, WASMType::F32);
      break;
    case F32_ADD:
    case F32_SUB:
    case F32_MUL:
    case F32_DIV:
    case F32_MIN:
    case F32_MAX:
    case F32_COPYSIGN:
      popAndPushValueType(2, WASMType::F32, WASMType::F32);
      break;
    case F64_ABS:
    case F64_NEG:
    case F64_CEIL:
    case F64_FLOOR:
    case F64_TRUNC:
    case F64_NEAREST:
    case F64_SQRT:
      popAndPushValueType(1, WASMType::F64, WASMType::F64);
      break;
    case F64_ADD:
    case F64_SUB:
    case F64_MUL:
    case F64_DIV:
    case F64_MIN:
    case F64_MAX:
    case F64_COPYSIGN:
      popAndPushValueType(2, WASMType::F64, WASMType::F64);
      break;
    case I32_WRAP_I64:
      popAndPushValueType(1, WASMType::I64, WASMType::I32);
      break;
    case I32_TRUNC_S_F32:
    case I32_TRUNC_U_F32:
      popAndPushValueType(1, WASMType::F32, WASMType::I32);
      break;
    case I32_TRUNC_S_F64:
    case I32_TRUNC_U_F64:
      popAndPushValueType(1, WASMType::F64, WASMType::I32);
      break;
    case I64_EXTEND_S_I32:
    case I64_EXTEND_U_I32:
      popAndPushValueType(1, WASMType::I32, WASMType::I64);
      break;
    case I64_TRUNC_S_F32:
    case I64_TRUNC_U_F32:
      popAndPushValueType(1, WASMType::F32, WASMType::I64);
      break;
    case I64_TRUNC_S_F64:
    case I64_TRUNC_U_F64:
      popAndPushValueType(1, WASMType::F64, WASMType::I64);
      break;
    case F32_CONVERT_S_I32:
    case F32_CONVERT_U_I32:
      popAndPushValueType(1, WASMType::I32, WASMType::F32);
      break;
    case F32_CONVERT_S_I64:
    case F32_CONVERT_U_I64:
      popAndPushValueType(1, WASMType::I64, WASMType::F32);
      break;
    case F32_DEMOTE_F64:
      popAndPushValueType(1, WASMType::F64, WASMType::F32);
      break;
    case F64_CONVERT_S_I32:
    case F64_CONVERT_U_I32:
      popAndPushValueType(1, WASMType::I32, WASMType::F64);
      break;
    case F64_CONVERT_S_I64:
    case F64_CONVERT_U_I64:
      popAndPushValueType(1, WASMType::I64, WASMType::F64);
      break;
    case F64_PROMOTE_F32:
      popAndPushValueType(1, WASMType::F32, WASMType::F64);
      break;
    case I32_REINTERPRET_F32:
      popAndPushValueType(1, WASMType::F32, WASMType::I32);
      break;
    case I64_REINTERPRET_F64:
      popAndPushValueType(1, WASMType::F64, WASMType::I64);
      break;
    case F32_REINTERPRET_I32:
      popAndPushValueType(1, WASMType::I32, WASMType::F32);
      break;
    case F64_REINTERPRET_I64:
      popAndPushValueType(1, WASMType::I64, WASMType::F64);
      break;
    case I32_EXTEND8_S:
    case I32_EXTEND16_S:
      popAndPushValueType(1, WASMType::I32, WASMType::I32);
      break;
    case I64_EXTEND8_S:
    case I64_EXTEND16_S:
    case I64_EXTEND32_S:
      popAndPushValueType(1, WASMType::I64, WASMType::I64);
      break;
    case I32_LOAD:
    case I64_LOAD:
    case F32_LOAD:
    case F64_LOAD:
    case I32_LOAD8_S:
    case I32_LOAD8_U:
    case I32_LOAD16_S:
    case I32_LOAD16_U:
    case I64_LOAD8_S:
    case I64_LOAD8_U:
    case I64_LOAD16_S:
    case I64_LOAD16_U:
    case I64_LOAD32_S:
    case I64_LOAD32_U:
    case I32_STORE:
    case I64_STORE:
    case F32_STORE:
    case F64_STORE:
    case I32_STORE8:
    case I32_STORE16:
    case I64_STORE8:
    case I64_STORE16:
    case I64_STORE32: {
      if (!hasMemory()) {
        throw getError(ErrorCode::UnknownMemory);
      }

      uint32_t Align = readU32();
      [[maybe_unused]] uint32_t Offset = readU32();
      if (!checkMemoryAlign(Opcode, Align)) {
        throw getError(ErrorCode::AlignMustLargerThanNatural);
      }

      switch (Opcode) {
      case I32_LOAD:
      case I32_LOAD8_S:
      case I32_LOAD8_U:
      case I32_LOAD16_S:
      case I32_LOAD16_U:
        popAndPushValueType(1, WASMType::I32, WASMType::I32);
        break;
      case I64_LOAD:
      case I64_LOAD8_S:
      case I64_LOAD8_U:
      case I64_LOAD16_S:
      case I64_LOAD16_U:
      case I64_LOAD32_S:
      case I64_LOAD32_U:
        popAndPushValueType(1, WASMType::I32, WASMType::I64);
        break;
      case F32_LOAD:
        popAndPushValueType(1, WASMType::I32, WASMType::F32);
        break;
      case F64_LOAD:
        popAndPushValueType(1, WASMType::I32, WASMType::F64);
        break;
      case I32_STORE:
      case I32_STORE8:
      case I32_STORE16:
        popValueType(WASMType::I32);
        popValueType(WASMType::I32);
        break;
      case I64_STORE:
      case I64_STORE8:
      case I64_STORE16:
      case I64_STORE32:
        popValueType(WASMType::I64);
        popValueType(WASMType::I32);
        break;
      case F32_STORE:
        popValueType(WASMType::F32);
        popValueType(WASMType::I32);
        break;
      case F64_STORE:
        popValueType(WASMType::F64);
        popValueType(WASMType::I32);
        break;
      }
      FuncCodeEntry.Stats |= Module::SF_memory;
      break;
    }
    case DROP: {
      WASMType Type = popValueType(WASMType::ANY);
      if (Type == WASMType::I64 || Type == WASMType::F64) {
        Byte *OpcodePtr = const_cast<Byte *>(Ptr - 1);
        *OpcodePtr = Byte(DROP_64);
      }
      break;
    }
    case SELECT: {
      popValueType(WASMType::I32);

      WASMType Type1 = popValueType(WASMType::ANY);
      WASMType Type2 = popValueType(WASMType::ANY);

      if (Type1 != Type2 && Type1 != WASMType::ANY && Type2 != WASMType::ANY) {
        throw getError(ErrorCode::TypeMismatchSelectStackEmpty);
      }

      WASMType Type = Type1 != WASMType::ANY ? Type1 : Type2;
      if (Type == WASMType::I64 || Type == WASMType::F64) {
        Byte *OpcodePtr = const_cast<Byte *>(Ptr - 1);
        *OpcodePtr = Byte(SELECT_64);
      }
      pushValueType(Type);

      break;
    }
    case RETURN: {
      int32_t NumReturns = static_cast<int32_t>(FuncTypeEntry.NumReturns);
      for (int32_t I = NumReturns - 1; I >= 0; --I) {
        popValueType(FuncTypeEntry.ReturnTypes[I]);
      }
      resetStack();
      setStackPolymorphic(true);
      break;
    }
    case CALL: {
      uint32_t CalleeIdx = readU32();
      if (!Mod.isValidFunc(CalleeIdx)) {
        throw getErrorWithExtraMessage(ErrorCode::UnknownFunction,
                                       '#' + std::to_string(CalleeIdx));
      }
      const TypeEntry *CalleeFuncType = Mod.getFunctionType(CalleeIdx);
      int32_t NumParams = static_cast<int32_t>(CalleeFuncType->NumParams);
      for (int32_t I = NumParams; I > 0; --I) {
        const WASMType *ParamTypes = CalleeFuncType->getParamTypes();
        popValueType(ParamTypes[I - 1]);
      }
      for (uint32_t I = 0; I < CalleeFuncType->NumReturns; ++I) {
        pushValueType(CalleeFuncType->ReturnTypes[I]);
      }
#ifdef ZEN_ENABLE_MULTIPASS_JIT
      if (!CalleeIdxBitset[CalleeIdx]) {
        CalleeIdxBitset[CalleeIdx] = true;
        CalleeIdxSeq.push_back(CalleeIdx);
      }
#endif
      break;
    }
    case CALL_INDIRECT: {
      uint32_t TypeIdx = readU32();
      if (!Mod.isValidType(TypeIdx)) {
        throw getError(ErrorCode::UnknownTypeIdx);
      }

      uint8_t TableIdx = to_underlying(readByte());
      if (TableIdx != 0) {
        throw getError(ErrorCode::ZeroFlagExpected);
      }
      if (!Mod.isValidTable(TableIdx)) {
        throw getError(ErrorCode::UnknownTable);
      }

      popValueType(WASMType::I32);

      TypeEntry *CalleeFuncType = Mod.getDeclaredType(TypeIdx);

      int32_t NumParams = static_cast<int32_t>(CalleeFuncType->NumParams);
      for (int32_t I = NumParams; I > 0; --I) {
        const WASMType *ParamTypes = CalleeFuncType->getParamTypes();
        popValueType(ParamTypes[I - 1]);
      }

      for (uint32_t I = 0; I < CalleeFuncType->NumReturns; ++I) {
        pushValueType(CalleeFuncType->ReturnTypes[I]);
      }
#ifdef ZEN_ENABLE_MULTIPASS_JIT
      const auto &LikelyCalleeIdxs = Mod.TypedFuncRefs[TypeIdx];
      for (uint32_t CalleeIdx : LikelyCalleeIdxs) {
        if (!CalleeIdxBitset[CalleeIdx]) {
          CalleeIdxBitset[CalleeIdx] = true;
          CalleeIdxSeq.push_back(CalleeIdx);
        }
      }
#endif
      FuncCodeEntry.Stats |= Module::SF_table;
      break;
    }
    default:
      throw getErrorWithExtraMessage(ErrorCode::UnsupportedOpcode,
                                     getOpcodeHexString(Opcode));
    }

#ifdef ZEN_ENABLE_DWASM
    size_t CurBlockDepth = ControlBlocks.size();
    // check children blocks number
    if (Opcode >= BLOCK && Opcode <= IF) {
      ZEN_ASSERT(CurBlockDepth >= 2); // 1 for function body, 1 for the block
      ControlBlock &PreBlock = ControlBlocks[CurBlockDepth - 2];
      if (++PreBlock.NumChildBlocks > PresetMaxNumSameLevelBlocks) {
        throw getError(ErrorCode::DWasmBlockTooLarge);
      }
    }
    // check block nested depth
    if (CurBlockDepth > 1 + PresetMaxBlockDepth) {
      throw getError(ErrorCode::DWasmBlockNestedTooDeep);
    }
    // check func body children number
    if (++NumOpcodes > PresetMaxNumOpcodesOfFunction) {
      throw getError(ErrorCode::DWasmFuncBodyTooLarge);
    }
#endif
  }

#if defined(ZEN_ENABLE_DWASM) && defined(ZEN_ENABLE_JIT)
  FuncCodeEntry.JITStackCost += MaxStackSize * 8;
#endif

  if (ControlBlocks.size() > 0) {
    throw getError(ErrorCode::BlockStackNotEmptyAtEndOfFunction);
  }

  if (Ptr != End) {
    throw getError(ErrorCode::UnexpectedEnd);
  }

#ifdef ZEN_ENABLE_MULTIPASS_JIT
  Mod.CallSeqMap[FuncIdx] = std::move(CalleeIdxSeq);
#endif

  FuncCodeEntry.MaxStackSize = MaxStackSize;
  FuncCodeEntry.MaxBlockDepth = MaxBlockDepth;
}

} // namespace zen::action
