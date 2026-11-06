// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "compiler/stub/stub_builder.h"
#include "compiler/compiler.h"

using namespace COMPILER;

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
  // jumping to the next instruction (rel32 == stub_jmp::kTrampolineRel32)
  int32_t TrampolineRel32 = stub_jmp::kTrampolineRel32;
  std::memcpy(CurFuncStubCodePtr + 1, &TrampolineRel32,
              sizeof(TrampolineRel32));

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

namespace {
// JMP active; push r11; movabs counter,r11; lock decq (r11); pop r11;
// JE cold; then a normal tail (RET for loops, JMP Fast for entry gates).
void counterPrefix(uint8_t *Code, uint64_t *Counter) {
  const uint8_t Bytes[] = {
      0xe9, 0, 0,    0,    0,    0x41, 0x53, 0x49, 0xbb, 0,    0, 0, 0, 0, 0,
      0,    0, 0xf0, 0x49, 0xff, 0x0b, 0x41, 0x5b, 0x0f, 0x84, 0, 0, 0, 0};
  std::memcpy(Code, Bytes, sizeof(Bytes));
  const auto Address = reinterpret_cast<uint64_t>(Counter);
  std::memcpy(Code + 9, &Address, 8);
}
void relativeJump(uint8_t *At, uint8_t *Target) {
  At[0] = 0xe9;
  const int32_t Offset = stub_jmp::computeRel32(At, Target);
  std::memcpy(At + 1, &Offset, 4);
}
} // namespace

uint8_t *JITStubBuilder::compileEntryCounterGate(uint64_t *Counter,
                                                 uint8_t *Fast, uint8_t *Stub) {
  auto *Code = static_cast<uint8_t *>(CodeMPool.allocate(
      common::CodeMemPool::PageSize, common::CodeMemPool::PageSize));
  counterPrefix(Code, Counter);
  // JE at 23 is six bytes; cold starts after the five-byte normal JMP.
  const int32_t ColdOffset = 5;
  std::memcpy(Code + 25, &ColdOffset, 4);
  relativeJump(Code + 29, Fast);
  relativeJump(Code + 34, Stub + 5); // existing register-saving resolver
  platform::mprotect(Code, common::CodeMemPool::PageSize,
                     PROT_READ | PROT_EXEC);
  return Code;
}

uint8_t *
JITStubBuilder::compileLoopCounterGate(uint64_t *Counter, void *Cookie,
                                       void (*Callback)(void *) noexcept) {
  auto *Code = static_cast<uint8_t *>(CodeMPool.allocate(
      common::CodeMemPool::PageSize, common::CodeMemPool::PageSize));
  counterPrefix(Code, Counter);
  const int32_t ColdOffset = 1;
  std::memcpy(Code + 25, &ColdOffset, 4);
  Code[29] = 0xc3;
  auto *Cold = reinterpret_cast<uint8_t *>(privateLoopCold);
  const size_t Size = reinterpret_cast<uint8_t *>(privateLoopColdEnd) - Cold;
  std::memcpy(Code + 30, Cold, Size);
  const uint64_t CookieAddr = reinterpret_cast<uint64_t>(Cookie);
  const uint64_t CallbackAddr = reinterpret_cast<uint64_t>(Callback);
  std::memcpy(Code + 30 +
                  (reinterpret_cast<uint8_t *>(privateLoopColdCookie) - Cold) +
                  2,
              &CookieAddr, 8);
  std::memcpy(
      Code + 30 +
          (reinterpret_cast<uint8_t *>(privateLoopColdCallback) - Cold) + 2,
      &CallbackAddr, 8);
  // Only this gate's first jump is subsequently patched, just like lazy stubs.
  platform::mprotect(Code, common::CodeMemPool::PageSize,
                     PROT_READ | PROT_WRITE | PROT_EXEC);
  return Code;
}
