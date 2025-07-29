// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_ACTION_INTERPRETER_H
#define ZEN_ACTION_INTERPRETER_H

#include "common/defines.h"
#include "common/enums.h"
#include "runtime/destroyer.h"
#include "runtime/object.h"

namespace zen {

namespace runtime {
struct FunctionInstance;
class Instance;
class Runtime;
} // namespace runtime

namespace action {

struct BlockInfo {
  const uint8_t *TargetAddr;
  uint32_t *ValueStackPtr;
  uint32_t CellNum;
  common::LabelType LabelType;
};

struct InterpFrame {
  runtime::FunctionInstance *FuncInst;
  const uint8_t *Ip;

  // value stack
  uint32_t *ValueBasePtr;
  uint32_t *ValueStackPtr;
  uint32_t *ValueBoundary;

  // control stack
  BlockInfo *CtrlBasePtr;
  BlockInfo *CtrlStackPtr;
  BlockInfo *CtrlBoundary;

  uint32_t *LocalPtr;
  InterpFrame *PrevFrame;

  template <typename T> inline T valuePeek(uint32_t *ValStackPtr) {
    ZEN_ASSERT((sizeof(T) & 0x03) == 0);
    ZEN_ASSERT(ValStackPtr >= (ValueBasePtr + (sizeof(T) >> 2)));
    uint32_t *Ptr = ValStackPtr - (sizeof(T) >> 2);
    return *(T *)(Ptr);
  }

  template <typename T> inline void valuePush(uint32_t *&ValStackPtr, T V) {
    // TODO: align for 64 bit read
    ZEN_ASSERT((sizeof(T) & 0x03) == 0);
    *(T *)(ValStackPtr) = V;
    ValStackPtr += (sizeof(V) >> 2);
    ZEN_ASSERT(ValStackPtr <= ValueBoundary);
  }

  template <typename T>
  inline T valueGet(uint32_t *ValStackPtr, uint32_t *Ptr) {
    // TODO: align for 64 bit read
    ZEN_ASSERT((sizeof(T) & 0x03) == 0);
    ZEN_ASSERT(Ptr < ValStackPtr);
    ZEN_ASSERT(ValStackPtr >= (Ptr + (sizeof(T) >> 2)));
    ZEN_ASSERT(Ptr >= LocalPtr);
    return *(T *)Ptr;
  }

  template <typename T>
  inline void valueSet(uint32_t *ValStackPtr, uint32_t *Ptr, T V) {
    // TODO: align for 64 bit read
    ZEN_ASSERT((sizeof(T) & 0x03) == 0);
    ZEN_ASSERT(Ptr < ValStackPtr);
    *(T *)Ptr = V;
    return;
  }

  template <typename T> inline T valuePop(uint32_t *&ValStackPtr) {
    // TODO: align for 64 bit read
    ZEN_ASSERT((sizeof(T) & 0x03) == 0);
    ZEN_ASSERT(ValStackPtr >= (ValueBasePtr + (sizeof(T) >> 2)));
    ValStackPtr -= (sizeof(T) >> 2);
    return *(T *)(ValStackPtr);
  }

  uint32_t *getValueBp() { return ValueBasePtr; }

  void blockPush(BlockInfo *&ControlStackPtr, const uint8_t *TargetAddr,
                 uint32_t *ValStackPtr, uint32_t CellNum,
                 common::LabelType LabelType) {
    ZEN_ASSERT(ControlStackPtr <= CtrlBoundary);
    ControlStackPtr->TargetAddr = TargetAddr;
    ControlStackPtr->ValueStackPtr = ValStackPtr;
    ControlStackPtr->CellNum = CellNum;
    ControlStackPtr->LabelType = LabelType;
    ControlStackPtr++;
  }

  void blockPop(BlockInfo *&ControlStackPtr) { --ControlStackPtr; }

  void blockPop(BlockInfo *&ControlStackPtr, uint32_t *&ValStackPtr,
                const uint8_t *&Ip, int32_t Depth) {
    ZEN_ASSERT(ControlStackPtr - (Depth + 1) >= CtrlBasePtr);

    uint32_t *ValStackPtrOld = ValStackPtr;

    ControlStackPtr -= Depth;

    BlockInfo *CurBlock = (ControlStackPtr - 1);

    ValStackPtr = CurBlock->ValueStackPtr;
    Ip = CurBlock->TargetAddr;

    if (CurBlock->LabelType != common::LABEL_LOOP) {
      uint32_t CellNum = (ControlStackPtr - 1)->CellNum;

      std::memcpy(ValStackPtr, ValStackPtrOld - CellNum, CellNum << 2);
      ValStackPtr += CellNum;
    }
  }
};

class InterpStack : public runtime::RuntimeObject<InterpStack> {
  friend class RuntimeObjectDestroyer;

public:
  uint8_t *TopBoundary = nullptr;
  uint8_t *Top = nullptr;
  uint8_t *Bottom = nullptr;

protected:
  InterpStack(runtime::Runtime &RT) : RuntimeObject(RT){};

public:
  static runtime::RuntimeObjectUniquePtr<InterpStack>
  newInterpStack(runtime::Runtime &RT, uint64_t StackSize) {
    uint64_t TotalSize = sizeof(InterpStack) + StackSize;
    void *Buf = RT.allocate(TotalSize);
    ZEN_ASSERT(Buf);

    InterpStack *Stack = new (Buf) InterpStack(RT);
    Stack->Bottom = reinterpret_cast<uint8_t *>(Stack) + sizeof(InterpStack);
    Stack->Top = Stack->Bottom;
    Stack->TopBoundary = Stack->Top + StackSize;

    return runtime::RuntimeObjectUniquePtr<InterpStack>(Stack);
  }

  template <typename T> inline void push(T V) {
    // TODO: align for 64 bit read
    *(T *)(Top) = V;
    Top += sizeof(V);
    ZEN_ASSERT(Top <= TopBoundary);
  }

  template <typename T> inline T pop() {
    // TODO: align for 64 bit read
    ZEN_ASSERT(Top >= Bottom + sizeof(T));
    Top -= sizeof(T);
    return *(T *)(Top);
  }
  uint8_t *top() { return Top; }
};

class InterpreterExecContext {
private:
  runtime::Instance *ModInst;
  InterpStack *Stack;
  InterpFrame *CurFrame = nullptr;

public:
  InterpreterExecContext(runtime::Instance *ModInst, InterpStack *Stack)
      : ModInst(ModInst), Stack(Stack){};

  InterpFrame *allocFrame(runtime::FunctionInstance *FuncInst,
                          uint32_t *LocalPtr);
  void freeFrame(runtime::FunctionInstance *FuncInst, InterpFrame *Frame);

  InterpFrame *getCurFrame() { return CurFrame; }
  void setCurFrame(InterpFrame *Frame) { CurFrame = Frame; }

  InterpStack *getInterpStack() { return Stack; }

  runtime::Instance *getInstance() { return ModInst; }
}; // InterpreterExecContext

class BaseInterpreter {
private:
  InterpreterExecContext &Context;

public:
  BaseInterpreter(InterpreterExecContext &Context) : Context(Context) {}
  void interpret();
};

} // namespace action
} // namespace zen

#endif // ZEN_ACTION_INTERPRETER_H
