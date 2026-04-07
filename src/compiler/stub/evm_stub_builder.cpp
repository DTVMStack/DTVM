// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "compiler/stub/evm_stub_builder.h"
#include "compiler/evm_lazy_compiler.h"
#include "platform/map.h"
#include "runtime/evm_instance.h"

// External declarations for assembly stub templates (from stub_x86_64.S)
extern "C" {
void stubResolver();
void stubResolverPatchPoint();
void stubResolverEnd();

void stubTemplate();
void stubTemplatePatchPoint();
void stubTemplateEnd();
}

using namespace COMPILER;

/// \note thread safe
void EVMSegmentStubBuilder::updateStubJmpTargetPtr(uint8_t *CurStubCodePtr,
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

EVMSegmentStubBuilder::EVMSegmentStubBuilder(
    zen::common::CodeMemPool &CodeMemPool)
    : CodeMPool(CodeMemPool) {}

void EVMSegmentStubBuilder::allocateStubSpace(uint32_t NumSegments) {
  size_t TotalStubCodeSize = NumSegments * EachStubCodeSize;
  StubsCodePtr = reinterpret_cast<uint8_t *>(
      CodeMPool.allocate(TotalStubCodeSize, common::CodeMemPool::PageSize));

  // Check if allocation succeeded
  if (!StubsCodePtr) {
    ZEN_LOG_ERROR("EVM lazy compile: Failed to allocate stub space");
    return;
  }

  zen::platform::mprotect(StubsCodePtr, TotalStubCodeSize,
                          PROT_WRITE | PROT_EXEC);
}

/// Trampoline function called by stub resolver to compile a segment on demand.
/// This function is called when a stub's jump target hasn't been patched yet.
/// It compiles the segment and returns the compiled code address.
static uint64_t
compileSegmentOnRequestTrampoline([[maybe_unused]] zen::runtime::Instance *Inst,
                                  uint8_t *NextStubCodePtr) {
  // Validate instance pointer
  if (!Inst) {
    ZEN_LOG_ERROR("EVM lazy compile: Instance pointer is null in trampoline");
    return 0;
  }

  // For EVM, the instance pointer is actually an EVMInstance.
  // We use reinterpret_cast since Instance and EVMInstance don't share
  // a polymorphic base class (they use CRTP pattern).
  auto *EVMInst = reinterpret_cast<zen::runtime::EVMInstance *>(Inst);

  // Validate module pointer
  auto *EVMMod = EVMInst->getModule();
  if (!EVMMod) {
    ZEN_LOG_ERROR("EVM lazy compile: Module pointer is null in trampoline");
    return 0;
  }

  // Validate lazy compiler
  auto *LJITCompiler = EVMMod->getLazyEVMJITCompiler();
  if (!LJITCompiler) {
    ZEN_LOG_ERROR("EVM lazy compile: LazyJITCompiler is null in trampoline");
    return 0;
  }

  // Validate stub builder
  auto *StubBuilder = LJITCompiler->getStubBuilder();
  if (!StubBuilder) {
    ZEN_LOG_ERROR("EVM lazy compile: StubBuilder is null in trampoline");
    return 0;
  }

  // NextStubCodePtr is the address of the instruction after the call in the
  // stub. For the stub template (10 bytes total):
  //   offset 0: jmp offset (5 bytes)
  //   offset 5: call resolver (5 bytes)
  //   offset 10: next stub starts here
  // So NextStubCodePtr = CurStubCodePtr + EachStubCodeSize
  uint8_t *CurStubCodePtr =
      NextStubCodePtr - EVMSegmentStubBuilder::EachStubCodeSize;

  // Get segment index from stub code pointer
  uint32_t SegmentIdx = StubBuilder->getSegmentIdxByStubCodePtr(CurStubCodePtr);

  // Compile the segment on demand
  uint8_t *SegmentJITCodePtr =
      LJITCompiler->compileSegmentOnRequest(SegmentIdx);

  // Return compiled code address for re-entry in stub trampoline
  return reinterpret_cast<uint64_t>(SegmentJITCodePtr);
}

void EVMSegmentStubBuilder::compileStubResolver(LazyEVMJITCompiler *Compiler) {
  const uint8_t *StubResolverSrcPtr =
      reinterpret_cast<const uint8_t *>(stubResolver);
  ZEN_ASSERT(StubResolverSrcPtr);
  size_t StubResolverCodeSize =
      reinterpret_cast<uint8_t *>(stubResolverEnd) - StubResolverSrcPtr;

  uint8_t *NewStubResolverPtr = reinterpret_cast<uint8_t *>(
      CodeMPool.allocate(StubResolverCodeSize, common::CodeMemPool::PageSize));
  ZEN_ASSERT(NewStubResolverPtr);

  // Use std::copy to avoid misaligned src addresses in memcpy
  std::copy(StubResolverSrcPtr, StubResolverSrcPtr + StubResolverCodeSize,
            NewStubResolverPtr);

  uint8_t *StubResolverPatchPointPtr =
      reinterpret_cast<uint8_t *>(stubResolverPatchPoint);
  auto *NewStubResolverPatchPointPtr =
      NewStubResolverPtr + (StubResolverPatchPointPtr - StubResolverSrcPtr);
  uint64_t TrampolineFuncAddr =
      reinterpret_cast<uint64_t>(compileSegmentOnRequestTrampoline);

  // Update compileSegmentOnRequestTrampoline function address in copied
  // stubResolver code, +2 because moveabsq first 2 bytes is opcode
  std::memcpy(NewStubResolverPatchPointPtr + 2, &TrampolineFuncAddr, 8);

  zen::platform::mprotect(NewStubResolverPtr, StubResolverCodeSize,
                          PROT_READ | PROT_EXEC);
  this->StubResolverPtr = NewStubResolverPtr;
}

void EVMSegmentStubBuilder::compileSegmentToStub(uint32_t SegmentIdx,
                                                 uint32_t StartPC) {
  uint8_t *CurStubCodePtr = StubsCodePtr + SegmentIdx * EachStubCodeSize;

  // For jump dest
  const uint8_t *StubTmplPtr = reinterpret_cast<const uint8_t *>(&stubTemplate);

  // Use std::copy to avoid misaligned src addresses in memcpy
  std::copy(StubTmplPtr, reinterpret_cast<const uint8_t *>(stubTemplateEnd),
            CurStubCodePtr);

  // Initialize the jmp instruction to jump to next instruction (offset = 0)
  // This means jmp will fall through to the call instruction
  // After compilation, this will be patched to jump to the actual code
  std::memset(CurStubCodePtr + 1, 0, 4);

  // Call stubResolver template
  uint8_t *StubTmplPatchPointPtr =
      reinterpret_cast<uint8_t *>(stubTemplatePatchPoint);

  // Call stubResolver ptr
  uint8_t *NewStubTmplPatchPointPtr =
      CurStubCodePtr + (StubTmplPatchPointPtr - StubTmplPtr);
  // -5 because x86-64 call instruction uses RIP-relative addressing:
  // the relative offset is calculated from the instruction following the call,
  // not from the call instruction itself. Since call is 5 bytes (E8 + 4-byte
  // offset), we subtract 5 to get the correct relative offset.
  int64_t CallRelOffset = StubResolverPtr - NewStubTmplPatchPointPtr - 5;
  ZEN_ASSERT(CallRelOffset <= UINT32_MAX);

  // StubResolver not too far, use call(0xe8) offset
  int32_t CallRelOffsetI32 = static_cast<int32_t>(CallRelOffset);
  std::memcpy(NewStubTmplPatchPointPtr + 1, &CallRelOffsetI32, 4);
}