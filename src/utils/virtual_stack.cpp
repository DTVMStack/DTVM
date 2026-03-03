// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "utils/virtual_stack.h"
#include "common/mem_pool.h"
#include "runtime/instance.h"

namespace zen::utils {

constexpr size_t StackMemorySize = 9 * 1024 * 1024; // 9MB > dwasm 8MB

StackMemPool::StackMemPool(size_t ItemSize)
    : EachStackSize(ItemSize), AvailableCount(MAX_STACK_ITEM_NUM) {
#ifdef ZEN_ENABLE_CPU_EXCEPTION
  int DefaultProtMode = PROT_NONE;
#else
  int DefaultProtMode = PROT_READ | PROT_WRITE;
#endif // ZEN_ENABLE_CPU_EXCEPTION

  MemStart = reinterpret_cast<uint8_t *>(platform::mmap(
      NULL, MaxCodeSize, DefaultProtMode, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0));

  MemEnd = MemStart;
  MemPageEnd = MemStart;
}
StackMemPool::~StackMemPool() { platform::munmap(MemStart, MaxCodeSize); }

void *StackMemPool::allocate(bool AllowReadWrite, bool *IsReused) {
  common::UniqueLock<common::Mutex> Lock(Mutex);
#ifndef ZEN_ENABLE_SGX
  AvailableCountCV.wait(Lock, [this]() { return AvailableCount > 0; });
#endif // ZEN_ENABLE_SGX
  --AvailableCount;

  if (!FreeObjects.empty()) {
    auto *Result = FreeObjects.front();
    FreeObjects.pop();
    if (IsReused)
      *IsReused = true;
    return Result;
  }
  if (IsReused)
    *IsReused = false;
  constexpr size_t Align = 16;
  uint8_t *Ptr = reinterpret_cast<uint8_t *>(
      ZEN_ALIGN(reinterpret_cast<uintptr_t>(MemEnd), Align));
  size_t NewSize = reinterpret_cast<uintptr_t>(Ptr) + EachStackSize -
                   reinterpret_cast<uintptr_t>(MemStart);
  if (NewSize > MaxCodeSize) {
    ZEN_ABORT(); // not supported, exit
  }
  MemEnd = MemStart + NewSize;
  if (MemEnd > MemPageEnd) {
    uint8_t *NewMemPageEnd = reinterpret_cast<uint8_t *>(
        ZEN_ALIGN(reinterpret_cast<uintptr_t>(MemEnd), PageSize));
#ifdef ZEN_ENABLE_CPU_EXCEPTION
    // when not in cpu exception mode, the default prot mode is rw
    if (AllowReadWrite) {
      platform::mprotect(MemPageEnd, NewMemPageEnd - MemPageEnd,
                         PROT_READ | PROT_WRITE);
    }
#endif // ZEN_ENABLE_CPU_EXCEPTION
    MemPageEnd = NewMemPageEnd;
  }
  return Ptr;
}

void StackMemPool::deallocate(void *Ptr) {
  if (!Ptr) {
    return;
  }
#ifndef ZEN_ENABLE_SGX
  common::UniqueLock<common::Mutex> Lock(Mutex);
#endif // ZEN_ENABLE_SGX
  ZEN_ASSERT(AvailableCount < MAX_STACK_ITEM_NUM);

  ++AvailableCount;

  FreeObjects.push(Ptr);
}

static StackMemPool *getVirtualStackPool() {
  // stack allocate 2 * needed size, the first part used as stack, the second
  // part used to protect read/write by cpu
  // can't be less, even not enable cpu exception
  static StackMemPool StackPool(StackMemorySize * 2);
  return &StackPool;
}

void VirtualStackInfo::allocate() {
  if (AllInfo) {
    return;
  }
  auto *MemPool = getVirtualStackPool();
  bool IsReused = false;
  AllocatedMem = (uint8_t *)MemPool->allocate(true, &IsReused);
  AllInfo = AllocatedMem + StackMemorySize;
  // [AllocatedMem, AllInfo) is disabled visiting
  // [AllInfo, StackMemoryTop) is available stack memory
  if (!IsReused) {
    platform::mprotect(AllocatedMem, StackMemorySize, PROT_NONE);
  }

  // when update sp/rsp register, we need copy old frame to new frame, then
  // the new frame rsp should have enough frame to store
  size_t FrameSizeForBackup = 100 * 1024;
  NewRspPtr = (uint64_t *)(AllInfo);
  NewRbpPtr = (uint64_t *)(AllInfo + 8);
  OldRspPtr = (uint64_t *)(AllInfo + 16);
  // -128(<-16) to leave enough memory to store prev frame info. use -128 to
  // make the addr aligned
  StackMemoryTop = (uint8_t *)AllInfo + StackMemorySize - FrameSizeForBackup;
  *((uint64_t *)NewRbpPtr) = (uint64_t)StackMemoryTop;
}

void VirtualStackInfo::deallocate() {
  if (AllocatedMem) {
    getVirtualStackPool()->deallocate(AllocatedMem);
    AllInfo = nullptr;
    AllocatedMem = nullptr;
  }
}

VirtualStackInfo::~VirtualStackInfo() { deallocate(); }

static void __attribute__((noinline))
virtualStackFuncAndRollbackStack(VirtualStackInfo *StackInfo) {
  StackInfo->FuncInStack(StackInfo);
  // jmp back to caller
  StackInfo->rollbackStack();
}

void VirtualStackInfo::runInVirtualStack(InVirtualStackFuncPtr Func) {
  this->FuncInStack = Func;

  int JmpRet = ::setjmp(JmpBufBefore);
  if (JmpRet == 0) {
#if defined(ZEN_ENABLE_STACK_CHECK_CPU) and defined(ZEN_ENABLE_VIRTUAL_STACK)
    SavedInst->pushVirtualStack(this);
#endif
    startWasmFuncStack(this, (uint8_t *)StackMemoryTop, (uint64_t *)OldRspPtr,
                       &JmpBufBefore, virtualStackFuncAndRollbackStack);
  }
}

void VirtualStackInfo::rollbackStack() {
  auto *ResultJmpBuf = (jmp_buf *)rollbackWasmVirtualStack(
      this, *(uint64_t *)(OldRspPtr), &JmpBufBefore);
#if defined(ZEN_ENABLE_STACK_CHECK_CPU) and defined(ZEN_ENABLE_VIRTUAL_STACK)
  SavedInst->popVirtualStack();
#endif
  ::longjmp(*ResultJmpBuf, 1);
}

uint8_t checkDwasmStackEnough() {
  uint8_t Stack[8 * 1024 * 1024];
  Stack[8 * 1024 * 1024 - 1] = 0;
  Stack[0] = 7;
  return Stack[0];
}

} // namespace zen::utils