// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "compiler/stub/stub_builder.h"
#include "compiler/compiler.h"

using namespace COMPILER;

/// \note thread safe
void JITStubBuilder::updateStubJmpTargetPtr(uint8_t *CurStubCodePtr,
                                            uint8_t *TargetPtr) {
  // -5 because the jmp instructions has 5 bytes
  int64_t CallRelOffset = TargetPtr - CurStubCodePtr - 5;
  ZEN_ASSERT(CallRelOffset <= UINT32_MAX);
  int32_t CallRelOffsetI32 = static_cast<int32_t>(CallRelOffset);

  /// Atomic write of the 4-byte offset in `jmp` instruction is required.
  /// `__atomic_store_n` is optimized to `mov` and `mfence` in gcc 9, which does
  /// not ensure atomicity. Hence, we use inline assembly for guaranteed
  /// atomicity.

  /// \note x86_64 only
  asm volatile(
      "xchgl %0, 1(%1)" // +1 because the jmp instructions first byte is opcode
      :
      : "r"(CallRelOffsetI32), "r"(CurStubCodePtr)
      : "memory");
}

static uint64_t
compileOnRequestTrampoline([[maybe_unused]] zen::runtime::Instance *Inst,
                           uint8_t *NextFuncStubCodePtr) {
  auto *LJITComiler = Inst->getModule()->getLazyJITCompiler();
  ZEN_ASSERT(LJITComiler);

  // NextFuncStubCodePtr is the start address of the next stub, so we need to
  // subtract the size of each stub to get the start address of the current stub
  uint8_t *CurFuncStubCodePtr = reinterpret_cast<uint8_t *>(
      NextFuncStubCodePtr - JITStubBuilder::EachStubCodeSize);

  uint8_t *FuncJITCodePtr =
      LJITComiler->compileFunctionOnRequest(CurFuncStubCodePtr);

  // Return new jited code addr to re-entry in stub trampoline
  return reinterpret_cast<uint64_t>(FuncJITCodePtr);
}

void JITStubBuilder::compileStubResolver() {
  const uint8_t *StubResolverPtr =
      reinterpret_cast<const uint8_t *>(stubResolver);
  ZEN_ASSERT(StubResolverPtr);
  size_t StubResolverCodeSize =
      reinterpret_cast<uint8_t *>(stubResolverEnd) - StubResolverPtr;

  uint8_t *NewStubResolverPtr = reinterpret_cast<uint8_t *>(
      CodeMPool.allocate(StubResolverCodeSize, common::CodeMemPool::PageSize));
  ZEN_ASSERT(NewStubResolverPtr);

  // Use std::copy to avoid misaligned src addresses in memcpy
  std::copy(StubResolverPtr, StubResolverPtr + StubResolverCodeSize,
            NewStubResolverPtr);

  uint8_t *StubResolverPatchPointPtr =
      reinterpret_cast<uint8_t *>(stubResolverPatchPoint);
  auto *NewStubResolverPatchPointPtr =
      NewStubResolverPtr + (StubResolverPatchPointPtr - StubResolverPtr);
  uint64_t TrampolineFuncAddr =
      reinterpret_cast<uint64_t>(compileOnRequestTrampoline);

  // Update compileOnRequestTrampoline function address in copied stubResolver
  // code, +2 because moveabsq first 2 bytes is opcode
  std::memcpy(NewStubResolverPatchPointPtr + 2, &TrampolineFuncAddr, 8);

  platform::mprotect(NewStubResolverPtr, StubResolverCodeSize,
                     PROT_READ | PROT_EXEC);
  this->StubResolverPtr = NewStubResolverPtr;
}

void JITStubBuilder::allocateStubSpace(uint32_t NumInternalFunctions) {
  TotalStubCodeSize = NumInternalFunctions * EachStubCodeSize;
  StubsCodePtr = reinterpret_cast<uint8_t *>(
      CodeMPool.allocate(TotalStubCodeSize, common::CodeMemPool::PageSize));
  platform::mprotect(StubsCodePtr, TotalStubCodeSize, PROT_WRITE);
}

void JITStubBuilder::finalizeStubs() {
  platform::mprotect(StubsCodePtr, TotalStubCodeSize, PROT_WRITE | PROT_EXEC);
}

void JITStubBuilder::compileFunctionToStub(uint32_t FuncIdx) {
  uint8_t *CurFuncStubCodePtr = StubsCodePtr + FuncIdx * EachStubCodeSize;

  uint8_t *StubTmplPtr = reinterpret_cast<uint8_t *>(&stubTemplate);

  // Use std::copy to avoid misaligned src addresses in memcpy
  std::copy(StubTmplPtr, reinterpret_cast<uint8_t *>(stubTemplateEnd),
            CurFuncStubCodePtr);

  // Update the first instruction(jmp instruction) of trampoline default to
  // jumping to the next instruction
  std::memset(CurFuncStubCodePtr + 1, 0, 4);

  uint8_t *StubTmplPatchPointPtr =
      reinterpret_cast<uint8_t *>(stubTemplatePatchPoint);

  uint8_t *NewStubTmplPatchPointPtr =
      CurFuncStubCodePtr + (StubTmplPatchPointPtr - StubTmplPtr);
  // -5 because the call instructions has 5 bytes
  int64_t CallRelOffset = StubResolverPtr - NewStubTmplPatchPointPtr - 5;
  ZEN_ASSERT(CallRelOffset <= UINT32_MAX);

  // StubResolver not too far, use call(0xe8) offset
  int32_t CallRelOffsetI32 = static_cast<int32_t>(CallRelOffset);
  std::memcpy(NewStubTmplPatchPointPtr + 1, &CallRelOffsetI32, 4);
}
