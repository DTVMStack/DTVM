// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_ACTION_FUNCTION_LOADER_H
#define ZEN_ACTION_FUNCTION_LOADER_H

#include "action/loader_common.h"

namespace zen::action {

class FunctionLoader final : public LoaderCommon {

  using ErrorCode = common::ErrorCode;
  using WASMType = common::WASMType;

  class ControlBlockType {
    using TypeEntry = runtime::TypeEntry;

  public:
    ControlBlockType() = default;
    ControlBlockType(WASMType Type) : TypeVariant(Type) {}
    ControlBlockType(const TypeEntry *Type) : TypeVariant(Type) {}

    template <typename T> ControlBlockType &operator=(T &&Type) {
      TypeVariant = std::forward<T>(Type);
      return *this;
    }

#ifdef ZEN_ENABLE_WASI_MULTI_VALUE
    // Check if this block type is a type index (multi-value)
    bool isTypeIndex() const {
      return TypeVariant.index() == 1 &&
             std::holds_alternative<const TypeEntry *>(TypeVariant);
    }
#endif

    // Means the block has the same popped types and pushed types
    bool isBalanced() const;

    std::pair<uint32_t, const WASMType *> getParamTypes() const;
    std::pair<uint32_t, const WASMType *> getReturnTypes() const;

  private:
    common::Variant<WASMType, const TypeEntry *> TypeVariant;
  };

  struct ControlBlock {
    bool StackPolymorphic = false;
    common::LabelType LabelType;
    ControlBlockType BlockType;
    const Byte *StartPtr;
    const Byte *ElsePtr;
    const Byte *EndPtr;
    // Total size of the stack at the start of the block
    uint32_t InitStackSize;
    // Number of values on the stack at the start of the block
    uint32_t InitNumValues;
#ifdef ZEN_ENABLE_DWASM
    uint32_t NumChildBlocks;
#endif
  };

public:
  explicit FunctionLoader(runtime::Module &M, const Byte *PtrStart,
                          const Byte *PtrEnd, uint32_t FuncIdx,
                          const runtime::TypeEntry &TE, runtime::CodeEntry &CE)
      : LoaderCommon(M, PtrStart, PtrEnd), FuncIdx(FuncIdx), FuncTypeEntry(TE),
        FuncCodeEntry(CE) {}

  void load();

private:
  static bool checkMemoryAlign(uint8_t Opcode, uint32_t Align);

  static std::string getTypeErrorMsg(WASMType ExpectedType,
                                     WASMType ActualType);

  bool hasMemory() { return Mod.getNumTotalMemories() != 0; }

  void pushBlock(common::LabelType LabelType, ControlBlockType BlockType,
                 const Byte *StartPtr);

  void popBlock() {
    ZEN_ASSERT(!ControlBlocks.empty());
    ControlBlocks.pop_back();
  }

  void resetStack() {
    ZEN_ASSERT(!ControlBlocks.empty());
    const ControlBlock &Block = ControlBlocks.back();
    StackSize = Block.InitStackSize;
    ValueTypes.resize(Block.InitNumValues);
  }

  void setStackPolymorphic(bool Polymorphic) {
    ZEN_ASSERT(!ControlBlocks.empty());
    ControlBlock &Block = ControlBlocks.back();
    Block.StackPolymorphic = Polymorphic;
  }

  WASMType popValueType(WASMType Type);

  void pushValueType(WASMType Type) {
    ValueTypes.push_back(Type);
    StackSize += getWASMTypeSize(Type);
    MaxStackSize = std::max(MaxStackSize, StackSize);
  }

  void popAndPushValueType(uint32_t NumPops, WASMType PoppedType,
                           WASMType PushedType) {
    for (uint32_t I = 0; I < NumPops; ++I) {
      popValueType(PoppedType);
    }
    pushValueType(PushedType);
  }

  void pushBlockParamTypes();

  void checkTopTypes(ControlBlock &Block, uint32_t NumTypes,
                     const WASMType *Types, bool IsBranch);

  void checkTargetBlockStack(uint32_t NumTypes, const WASMType *Types,
                             uint32_t AvailStackCells);

  void checkBlockStack();

  const ControlBlock &checkBranch();

  WASMType readLocal();

  uint32_t FuncIdx;
  const runtime::TypeEntry &FuncTypeEntry;
  runtime::CodeEntry &FuncCodeEntry;

  uint32_t StackSize = 0;
  uint32_t MaxStackSize = 0;
  uint32_t MaxBlockDepth = 0;
  std::vector<ControlBlock> ControlBlocks;
  std::vector<WASMType> ValueTypes;
};

} // namespace zen::action

#endif // ZEN_ACTION_FUNCTION_LOADER_H
