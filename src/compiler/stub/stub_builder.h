// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef COMPILER_STUB_STUB_BUILDER_H
#define COMPILER_STUB_STUB_BUILDER_H

#include "compiler/common/common_defs.h"
#include "compiler/stub/stub_jmp_target.h"

namespace COMPILER {

class JITStubBuilder : public NonCopyable {
public:
  JITStubBuilder(zen::common::CodeMemPool &CodeMemPool)
      : CodeMPool(CodeMemPool) {}

  /// Unconditional GreedyRA (or single-thread) stub publish. Tear-free, not
  /// monotonic by itself. Thread-safe vs concurrent FastRA CAS from trampoline.
  static void updateStubJmpTargetPtr(uint8_t *CurStubCodePtr,
                                     uint8_t *TargetPtr) {
    stub_jmp::updateTarget(CurStubCodePtr, TargetPtr);
  }

  /// FastRA publish: succeed only while the stub still points at the
  /// trampoline. After GreedyRA (or another FastRA) is installed, returns
  /// false and leaves the stub unchanged.
  static bool tryUpdateStubJmpTargetIfTrampoline(uint8_t *CurStubCodePtr,
                                                 uint8_t *TargetPtr) {
    return stub_jmp::tryUpdateTargetIfTrampoline(CurStubCodePtr, TargetPtr);
  }

  void allocateStubSpace(uint32_t NumInternalFunctions);

  void compileStubResolver();

  void compileFunctionToStub(uint32_t FuncIdx);

  void finalizeStubs();

  uint8_t *getFuncStubCodePtr(uint32_t FuncIdx) const {
    return StubsCodePtr + FuncIdx * EachStubCodeSize;
  }

  uint32_t getFuncIdxByStubCodePtr(uint8_t *FuncStubCodePtr) const {
    return (FuncStubCodePtr - StubsCodePtr) / EachStubCodeSize;
  }

  static const size_t EachStubCodeSize = 10;

private:
  zen::common::CodeMemPool &CodeMPool;
  // each module has one stub resolver
  // need put it in module's code ptr so the relative offset in int32 range
  uint8_t *StubResolverPtr = nullptr;
  uint8_t *StubsCodePtr = nullptr;
  size_t TotalStubCodeSize = 0;
};

} // namespace COMPILER

extern "C" {
void stubResolver();
void stubResolverPatchPoint();
void stubResolverEnd();

void stubTemplate();
void stubTemplatePatchPoint();
void stubTemplateEnd();
}

#endif // COMPILER_STUB_STUB_BUILDER_H