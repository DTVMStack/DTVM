// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "utils/virtual_stack.h"
#include "common/mem_pool.h"
#include "runtime/instance.h"
#include "utils/logging.h"

namespace zen::utils {

constexpr size_t StackMemorySize = 32 * 1024 * 1024;
constexpr size_t StackGuardMemorySize = 64 * 1024;

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
  static StackMemPool StackPool(StackGuardMemorySize + StackMemorySize);
  return &StackPool;
}

void VirtualStackInfo::allocate() {
  if (AllInfo) {
    return;
  }
  auto *MemPool = getVirtualStackPool();
  bool IsReused = false;
  AllocatedMem = (uint8_t *)MemPool->allocate(true, &IsReused);
  AllInfo = AllocatedMem + StackGuardMemorySize;
  // [AllocatedMem, AllInfo) is the guard page.
  // [AllInfo, StackMemoryTop) is available stack memory.
  if (!IsReused) {
    platform::mprotect(AllocatedMem, StackGuardMemorySize, PROT_NONE);
  }

  // when update sp/rsp register, we need copy old frame to new frame, then
  // the new frame rsp should have enough frame to store
  size_t FrameSizeForBackup = 100 * 1024;
  NewRspPtr = &SavedNewRsp;
  NewRbpPtr = &SavedNewRbp;
  OldRspPtr = &SavedOldRsp;
  // -128(<-16) to leave enough memory to store prev frame info. use -128 to
  // make the addr aligned
  StackMemoryTop = (uint8_t *)AllInfo + StackMemorySize - FrameSizeForBackup;
  *NewRspPtr = reinterpret_cast<uint64_t>(StackMemoryTop);
  *NewRbpPtr = reinterpret_cast<uint64_t>(StackMemoryTop);
  *OldRspPtr = 0;
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
  const uint64_t OldRsp = *OldRspPtr;
  if (OldRsp < 0x10000000000ULL || (OldRsp & 0xf) != 0) {
#ifdef ZEN_ENABLE_EVM
    ZEN_LOG_ERROR(
        "virtual stack rollback rejected: this=%p allocated=%p all=%p top=%p "
        "old_rsp_ptr=%p old_rsp=0x%llx saved_inst=%p saved1=%p saved2=%p "
        "saved3=%p",
        this, AllocatedMem, AllInfo, StackMemoryTop, OldRspPtr,
        static_cast<unsigned long long>(OldRsp), SavedInst, SavedPtr1,
        SavedPtr2, SavedPtr3);
#else
    ZEN_LOG_ERROR(
        "virtual stack rollback rejected: this=%p allocated=%p all=%p top=%p "
        "old_rsp_ptr=%p old_rsp=0x%llx saved_inst=%p",
        this, AllocatedMem, AllInfo, StackMemoryTop, OldRspPtr,
        static_cast<unsigned long long>(OldRsp), SavedInst);
#endif
    ZEN_ABORT();
  }
  auto *ResultJmpBuf =
      (jmp_buf *)rollbackWasmVirtualStack(this, OldRsp, &JmpBufBefore);
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
