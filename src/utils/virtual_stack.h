// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_UTILS_VIRTUAL_STACK_H
#define ZEN_UTILS_VIRTUAL_STACK_H

#include "common/type.h"
#include "platform/platform.h"
#include <csetjmp>
#include <queue>
#include <vector>

namespace zen::runtime {
class Instance;
#ifdef ZEN_ENABLE_EVM
class EVMInstance;
#endif // ZEN_ENABLE_EVM
} // namespace zen::runtime

namespace zen::utils {
using namespace common;
using namespace runtime;

class StackMemPool {
public:
  // The maximum number of VStackItem that can be used simultaneously.
  static constexpr size_t MAX_STACK_ITEM_NUM = 100;

#ifndef ZEN_ENABLE_OCCLUM
  static constexpr size_t MaxCodeSize = INT32_MAX;
#else
  // for occlum, we need to limit the code size to avoid mmap failure
  // need enough stack for instance call instance
  static constexpr size_t MaxCodeSize = 640 * 1024 * 1024; // 640MB
#endif // ZEN_ENABLE_OCCLUM
  static constexpr size_t PageSize = 4096;
  StackMemPool(size_t ItemSize);
  ~StackMemPool();
  NONCOPYABLE(StackMemPool);
  void *allocate(bool AllowReadWrite, bool *IsReused = nullptr);
  void deallocate(void *Ptr);

private:
  size_t EachStackSize;
  uint8_t *MemStart;
  uint8_t *MemEnd;
  uint8_t *MemPageEnd;
  std::queue<void *> FreeObjects;
  common::Mutex Mutex;
#ifndef ZEN_ENABLE_SGX
  std::condition_variable AvailableCountCV;
#endif // ZEN_ENABLE_SGX
  size_t AvailableCount;
};

struct VirtualStackInfo;

typedef void (*InVirtualStackFuncPtr)(zen::utils::VirtualStackInfo *StackInfo);

/**
 * VirtualStackInfo usage
 * VirtualStackInfo StackInfo(...);
 * StackInfo.allocate(); // if you dan't want to run, no need to allocate
 * StackInfo.runInVirtualStack(logicFunc)
 */
struct VirtualStackInfo {
  // all stack infos put into bytes pointed by AllInfo
  uint8_t *AllInfo = nullptr;
  uint8_t *AllocatedMem = nullptr;
  uint8_t *StackMemoryTop = nullptr;
  // pointed to the offset in AllInfo[0:8)
  uint64_t *NewRspPtr = nullptr;
  // pointed to the offset in AllInfo[8:16)
  uint64_t *NewRbpPtr = nullptr;
  // pointed to the offset in AllInfo[16:24)
  uint64_t *OldRspPtr = nullptr;

  // arguments backed up to call in virtual stack (WASM)
  Instance *SavedInst = nullptr;
  uint32_t SavedFuncIdx;
  const std::vector<TypedValue> *SavedArgs = nullptr;
  std::vector<TypedValue> *SavedResults = nullptr;

#ifdef ZEN_ENABLE_EVM
  // Saved pointers for EVM virtual stack usage.
  // Using void* to avoid pulling EVM-specific headers (evmc.h, evm_instance.h)
  // into this utility header.
  void *SavedPtr1 = nullptr; // EVMInstance*    (the EVM execution instance)
  void *SavedPtr2 = nullptr; // evmc_message*   (the EVM call message)
  void *SavedPtr3 =
      nullptr; // evmc::Result*   (output slot for execution result)
#endif         // ZEN_ENABLE_EVM

  jmp_buf JmpBufBefore;
  // func to run in virtual stack
  InVirtualStackFuncPtr FuncInStack;

  // constructor for WASM
  VirtualStackInfo(Instance *Inst, uint32_t FuncIdx,
                   const std::vector<TypedValue> *Args,
                   std::vector<TypedValue> *Results)
      : SavedInst(Inst), SavedFuncIdx(FuncIdx), SavedArgs(Args),
        SavedResults(Results) {
    allocate();
  }

#ifdef ZEN_ENABLE_EVM
  // constructor for EVM
  VirtualStackInfo() { allocate(); }
#endif // ZEN_ENABLE_EVM

  void allocate();
  void deallocate();
  ~VirtualStackInfo();

  void __attribute__((noinline)) runInVirtualStack(InVirtualStackFuncPtr Func);

  // setjmp saved register info in stack, so need to rollback stack to origin
  // stack when setjmp
  void __attribute__((noinline)) rollbackStack();
};

// utils func to check enough stack for dwasm
// noinline because to avoid check stack before start virtual stack
uint8_t __attribute__((noinline)) checkDwasmStackEnough();
} // namespace zen::utils

extern "C" {
void *startWasmFuncStack(void *StackInfo, uint8_t *NewRsp, uint64_t *OldRspPtr,
                         jmp_buf *JmpBuf,
                         zen::utils::InVirtualStackFuncPtr Func);
void *rollbackWasmVirtualStack(void *StackInfo, uint64_t OldRsp,
                               jmp_buf *JmpBuf);
}

#endif // ZEN_UTILS_VIRTUAL_STACK_H
