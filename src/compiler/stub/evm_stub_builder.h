// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef COMPILER_STUB_EVM_STUB_BUILDER_H
#define COMPILER_STUB_EVM_STUB_BUILDER_H

#include "compiler/common/common_defs.h"

namespace COMPILER {

class LazyEVMJITCompiler;

/// EVM segment stub builder for lazy compilation.
///
/// Similar to JITStubBuilder for WASM, but adapted for EVM's segment-based
/// structure. Each JUMPDEST segment gets a stub that can trigger on-demand
/// compilation when first jumped to.
class EVMSegmentStubBuilder : public NonCopyable {
public:
  EVMSegmentStubBuilder(zen::common::CodeMemPool &CodeMemPool);

  /// Thread-safe update of stub jump target.
  /// Used to patch a stub to jump directly to compiled code.
  static void updateStubJmpTargetPtr(uint8_t *CurStubCodePtr,
                                     uint8_t *TargetPtr);

  /// Allocate memory for all segment stubs.
  void allocateStubSpace(uint32_t NumSegments);

  /// Compile the stub resolver that calls compileSegmentOnRequest.
  void compileStubResolver(LazyEVMJITCompiler *Compiler);

  /// Generate stub code for a specific segment.
  void compileSegmentToStub(uint32_t SegmentIdx, uint32_t StartPC);

  /// Get the stub code pointer for a segment.
  uint8_t *getSegmentStubCodePtr(uint32_t SegmentIdx) const {
    return StubsCodePtr + SegmentIdx * EachStubCodeSize;
  }

  /// Get segment index from stub code pointer.
  uint32_t getSegmentIdxByStubCodePtr(uint8_t *StubCodePtr) const {
    return static_cast<uint32_t>((StubCodePtr - StubsCodePtr) /
                                 EachStubCodeSize);
  }

  static constexpr size_t EachStubCodeSize = 10;

private:
  zen::common::CodeMemPool &CodeMPool;
  // Stub resolver code that calls compileSegmentOnRequest
  uint8_t *StubResolverPtr = nullptr;
  // Base pointer for all segment stubs
  uint8_t *StubsCodePtr = nullptr;
};

} // namespace COMPILER

#endif // COMPILER_STUB_EVM_STUB_BUILDER_H